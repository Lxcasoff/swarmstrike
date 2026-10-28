"""The tools the swarm is given.

Agents do not get a shell. They get a recipe book, a fact graph and — where the
contract allows it — three tiers of ad-hoc execution in decreasing order of
what can be guaranteed. Every path into a target goes through ToolExecutor,
which checks the engagement contract before anything runs.

The recipe surface follows CyberStrikeAI's declarative tool recipes
(Apache-2.0; see NOTICE). Growing the tool set means adding a YAML file, not
changing this module.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

from ..engagement import Engagement
from ..killswitch import KillSwitch
from ..knowledge import Finding, KnowledgeBase
from ..knowledge.db import FactError
from .executor import ExecutionRefused, ToolExecutor
from .recipes import RecipeBook, RecipeError, load_recipes

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
READS_TARGET = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)
TOUCHES_TARGET = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
WRITES_STATE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)


def _text(payload: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload}]}


def _error(payload: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload}], "is_error": True}


def _refused(detail: str) -> dict[str, Any]:
    """A refusal is information for the agent, not a crash."""
    return _error(
        f"REFUSED: {detail}\n\n"
        f"Do not retry this and do not look for another route to the same target. "
        f"Either narrow it to something the contract authorizes, or record the "
        f"finding as theoretical with the reason it could not be proven."
    )


@dataclass
class CampaignContext:
    """What the tools act on. One per campaign."""

    engagement: Engagement
    executor: ToolExecutor
    kb: KnowledgeBase
    killswitch: KillSwitch
    book: RecipeBook = field(default_factory=load_recipes)
    on_event: Callable[[str, dict[str, Any]], None] | None = None

    def emit(self, event: str, **payload: Any) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)


# ===========================================================================
#  Toolbox: the recipe book and the three execution tiers
# ===========================================================================
def build_toolbox_tools(ctx: CampaignContext) -> list[Any]:
    """The toolbox tools, as SdkMcpTool objects.

    Returned separately from the server so the handlers can be called
    directly in tests: a tool whose refusal path is never exercised is a
    refusal path nobody has checked.
    """
    @tool(
        "list_tools",
        "List the assessment tools this engagement authorizes, with their "
        "parameters. Call this before assuming a tool exists — the contract "
        "decides which are available, and a red team phase that is switched off "
        "hides its tools entirely.",
        {"agent": str, "domain": str, "search": str},
        annotations=READ_ONLY,
    )
    async def list_tools(args: dict[str, Any]) -> dict[str, Any]:
        domain = (args.get("domain") or "").strip() or None
        needle = (args.get("search") or "").strip().lower()

        available = ctx.book.available_to(ctx.engagement, [domain] if domain else None)
        if needle:
            available = [
                r for r in available
                if needle in r.name.lower() or needle in r.summary.lower()
            ]

        if not available:
            return _text(
                "No tool matches. Either the domain or search term is wrong, or the "
                "contract does not authorize that class of work — check "
                "rules_of_engagement in the briefing."
            )

        by_risk: dict[str, list[dict[str, Any]]] = {}
        for recipe in available:
            by_risk.setdefault(recipe.risk.value, []).append(recipe.for_agent())

        withheld = len(ctx.book) - len(available)
        payload = {
            "available": by_risk,
            "note": (
                f"{withheld} further tool(s) exist but are not authorized by this "
                f"engagement's contract."
                if withheld else "Every shipped tool is authorized here."
            ),
        }
        return _text(json.dumps(payload, indent=2))

    @tool(
        "describe_tool",
        "Full description of one tool: every parameter, what it is for, and the "
        "guidance on when it is the right choice and what it costs.",
        {"agent": str, "tool": str},
        annotations=READ_ONLY,
    )
    async def describe_tool(args: dict[str, Any]) -> dict[str, Any]:
        try:
            recipe = ctx.book.get(args["tool"])
        except RecipeError as exc:
            return _error(str(exc))

        allowed, reason = recipe.authorize(ctx.engagement)
        return _text(json.dumps({
            **recipe.for_agent(),
            "description": recipe.description,
            "authorized": allowed,
            "authorization": reason,
            "defaults": recipe.defaults,
            "timeout_s": recipe.timeout_s,
        }, indent=2))

    @tool(
        "run_tool",
        "Run one of the authorized tools. Pass parameters as a JSON object "
        "using the names from list_tools. Values are typed and checked, and the "
        "command is built as an argument vector — never write shell syntax into "
        "a parameter.",
        {"agent": str, "tool": str, "parameters": str},
        annotations=TOUCHES_TARGET,
    )
    async def run_tool(args: dict[str, Any]) -> dict[str, Any]:
        try:
            recipe = ctx.book.get(args["tool"])
        except RecipeError as exc:
            return _error(str(exc))

        allowed, reason = recipe.authorize(ctx.engagement)
        if not allowed:
            return _refused(f"{recipe.name} is a {recipe.risk.value} tool. {reason}")

        raw = (args.get("parameters") or "{}").strip() or "{}"
        try:
            supplied = json.loads(raw)
        except json.JSONDecodeError as exc:
            return _error(f"parameters must be a JSON object: {exc}")
        if not isinstance(supplied, dict):
            return _error("parameters must be a JSON object, not a list or a string")

        try:
            argv = recipe.build_argv(supplied)
        except RecipeError as exc:
            return _error(f"{exc}\n\nCall describe_tool({recipe.name!r}) for the parameters.")

        try:
            result = await ctx.executor.run(
                args["agent"], argv,
                timeout_s=recipe.timeout_s,
                needs_raw_socket=recipe.needs_raw_socket,
                secrets=recipe.secret_values(supplied),
            )
        except ExecutionRefused as exc:
            return _refused(str(exc))
        except Exception as exc:  # noqa: BLE001 — surfaced verbatim
            return _error(f"execution failed: {type(exc).__name__}: {exc}")

        return _text(result.for_agent())

    @tool(
        "run_command",
        "Run an allowlisted binary with an explicit argument list, for cases no "
        "recipe covers. Pass args as a JSON array of strings. This is checked "
        "exactly like a recipe: no shell is involved, so nothing in args can "
        "chain a second command.",
        {"agent": str, "binary": str, "args": str, "needs_raw_socket": bool},
        annotations=TOUCHES_TARGET,
    )
    async def run_command(args: dict[str, Any]) -> dict[str, Any]:
        parsed, problem = _string_list(args.get("args") or "[]")
        if problem:
            return _error(problem)
        try:
            result = await ctx.executor.run_structured(
                args["agent"], args["binary"].strip(), parsed,
                needs_raw_socket=bool(args.get("needs_raw_socket")),
            )
        except ExecutionRefused as exc:
            return _refused(str(exc))
        except Exception as exc:  # noqa: BLE001
            return _error(f"execution failed: {type(exc).__name__}: {exc}")
        return _text(result.for_agent())

    @tool(
        "run_pipeline",
        "Pipe several commands together. Pass stages as a JSON array of string "
        "arrays. The first stage may be any allowlisted binary and is "
        "scope-checked; later stages must be filters that read standard input "
        "(grep, jq, sort, cut and similar). The pipe is built between "
        "containers, so there is still no shell.",
        {"agent": str, "stages": str},
        annotations=TOUCHES_TARGET,
    )
    async def run_pipeline(args: dict[str, Any]) -> dict[str, Any]:
        try:
            stages = json.loads(args.get("stages") or "[]")
        except json.JSONDecodeError as exc:
            return _error(f"stages must be a JSON array of string arrays: {exc}")
        if (not isinstance(stages, list) or not stages
                or not all(isinstance(s, list) and s and all(isinstance(x, str) for x in s)
                           for s in stages)):
            return _error(
                'stages must look like [["nmap","-sT","host"],["grep","open"]]'
            )

        try:
            result = await ctx.executor.run_pipeline(args["agent"], stages)
        except ExecutionRefused as exc:
            return _refused(str(exc))
        except Exception as exc:  # noqa: BLE001
            return _error(f"execution failed: {type(exc).__name__}: {exc}")
        return _text(result.for_agent())

    @tool(
        "run_shell",
        "Run a shell command or script that no structured form can express. "
        "This cannot be checked automatically, so a human has to approve each "
        "use and the default is to refuse. Say in `rationale` why a structured "
        "command will not do — that is what the operator reads when deciding. "
        "Prefer run_tool, run_command or run_pipeline: none of them wait on a "
        "person.",
        {"agent": str, "script": str, "rationale": str, "interpreter": str},
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, openWorldHint=True
        ),
    )
    async def run_shell(args: dict[str, Any]) -> dict[str, Any]:
        script = (args.get("script") or "").strip()
        if not script:
            return _error("script is empty")
        try:
            result = await ctx.executor.run_unchecked(
                args["agent"], script,
                interpreter=(args.get("interpreter") or "sh").strip(),
                rationale=(args.get("rationale") or "").strip(),
            )
        except ExecutionRefused as exc:
            return _refused(str(exc))
        except Exception as exc:  # noqa: BLE001
            return _error(f"execution failed: {type(exc).__name__}: {exc}")
        return _text(result.for_agent())

    return [list_tools, describe_tool, run_tool, run_command, run_pipeline, run_shell]


def build_toolbox_server(ctx: CampaignContext) -> Any:
    return create_sdk_mcp_server(
        name="toolbox", version="0.2.0", tools=build_toolbox_tools(ctx)
    )


# ===========================================================================
#  Knowledge: the fact graph, findings, coordination
# ===========================================================================
def build_knowledge_tools(ctx: CampaignContext) -> list[Any]:
    """The knowledge tools, as SdkMcpTool objects."""
    @tool(
        "record_fact",
        "Record something established about the engagement, as you establish it "
        "rather than at the end. The key is category/slug and the same key "
        "overwrites, so refining what you know updates one entry instead of "
        "scattering it. Categories: target, auth, infra, business, access, "
        "finding, chain, exploit, poc, detection, note. Set negative=true for a "
        "dead end — that is worth as much as a positive result, because it stops "
        "a teammate spending the budget on it again. Use links to join facts: "
        "'enables' is the edge attack paths are built from.",
        {
            "agent": str, "fact_key": str, "summary": str, "body": str,
            "confidence": str, "negative": bool, "links": str,
        },
        annotations=WRITES_STATE,
    )
    async def record_fact(args: dict[str, Any]) -> dict[str, Any]:
        links: list[tuple[str, str]] = []
        raw_links = (args.get("links") or "").strip()
        if raw_links:
            try:
                parsed = json.loads(raw_links)
                links = [(str(r), str(t)) for r, t in
                         (parsed.items() if isinstance(parsed, dict) else parsed)]
            except (json.JSONDecodeError, ValueError, TypeError):
                return _error(
                    'links must be JSON, e.g. [["enables","access/db-admin"]] '
                    'or {"enables": "access/db-admin"}'
                )

        try:
            created = ctx.kb.upsert_fact(
                args["fact_key"], args["summary"], args["agent"],
                body=args.get("body") or None,
                confidence=(args.get("confidence") or "tentative").strip(),
                negative=bool(args.get("negative")),
                links=links,
            )
        except FactError as exc:
            return _error(str(exc))

        ctx.emit("agent.fact", agent=args["agent"], fact_key=args["fact_key"],
                 summary=args["summary"], created=created,
                 negative=bool(args.get("negative")))
        return _text(
            f"{'recorded' if created else 'updated'} {args['fact_key']}"
            + (f" with {len(links)} link(s)" if links else "")
        )

    @tool(
        "get_fact",
        "Read one fact in full, including the body a listing leaves out. Call "
        "this rather than inferring detail from a summary.",
        {"agent": str, "fact_key": str},
        annotations=READ_ONLY,
    )
    async def get_fact(args: dict[str, Any]) -> dict[str, Any]:
        fact = ctx.kb.get_fact(args["fact_key"])
        if fact is None:
            return _error(f"no fact {args['fact_key']!r}")
        return _text(json.dumps(fact, indent=2, default=str))

    @tool(
        "list_facts",
        "The index of what the team has established: keys and summaries, "
        "without bodies. Read this first on every task — a teammate may already "
        "have found what you were about to look for, or already ruled it out.",
        {"agent": str, "category": str, "confidence": str, "include_negative": bool},
        annotations=READ_ONLY,
    )
    async def list_facts(args: dict[str, Any]) -> dict[str, Any]:
        rows = ctx.kb.list_facts(
            category=(args.get("category") or "").strip() or None,
            confidence=(args.get("confidence") or "").strip() or None,
            include_negative=args.get("include_negative", True),
        )
        if not rows:
            return _text("The fact graph is empty. You are first — record what you find.")
        return _text(json.dumps(rows, indent=2, default=str))

    @tool(
        "search_facts",
        "Search keys, summaries and bodies for a term.",
        {"agent": str, "query": str},
        annotations=READ_ONLY,
    )
    async def search_facts(args: dict[str, Any]) -> dict[str, Any]:
        rows = ctx.kb.search_facts(args["query"])
        return _text(json.dumps(rows, indent=2, default=str) if rows else "nothing matched")

    @tool(
        "link_facts",
        "Join two facts. Relations: enables (src makes dst reachable — this is "
        "what builds an attack path), evidences, contradicts, supersedes, "
        "part_of.",
        {"agent": str, "src_key": str, "dst_key": str, "relation": str, "note": str},
        annotations=WRITES_STATE,
    )
    async def link_facts(args: dict[str, Any]) -> dict[str, Any]:
        try:
            created = ctx.kb.link_facts(
                args["src_key"], args["dst_key"], args["relation"],
                note=args.get("note", ""), agent=args["agent"],
            )
        except FactError as exc:
            return _error(str(exc))
        return _text(
            f"{args['src_key']} --{args['relation']}--> {args['dst_key']}"
            + ("" if created else " (already linked)")
        )

    @tool(
        "retract_fact",
        "Mark a fact wrong. It stays in the record with your reasoning — that "
        "something was believed and then disproved is part of the engagement.",
        {"agent": str, "fact_key": str, "reason": str},
        annotations=WRITES_STATE,
    )
    async def retract_fact(args: dict[str, Any]) -> dict[str, Any]:
        if not ctx.kb.deprecate_fact(args["fact_key"], args["reason"], args["agent"]):
            return _error(f"no fact {args['fact_key']!r}")
        return _text(f"retracted {args['fact_key']}")

    @tool(
        "attack_paths",
        "The privilege paths the team has evidenced, assembled from the "
        "'enables' edges. Each path runs from an entry point to where it leads. "
        "The path is what a client needs to see — check it before adding a step, "
        "and extend an existing chain rather than starting a parallel one.",
        {"agent": str},
        annotations=READ_ONLY,
    )
    async def attack_paths(args: dict[str, Any]) -> dict[str, Any]:
        paths = ctx.kb.attack_paths()
        if not paths:
            return _text(
                "No path has been evidenced yet. A path appears once facts are "
                "joined with 'enables' edges."
            )
        rendered = [
            {
                "length": len(path),
                "steps": [
                    {"fact_key": f["fact_key"], "summary": f["summary"],
                     "confidence": f["confidence"]}
                    for f in path
                ],
            }
            for path in paths
        ]
        return _text(json.dumps(rendered, indent=2, default=str))

    # ------------------------------------------------------------------
    @tool(
        "record_finding",
        "Propose a deliverable finding. This is separate from a fact: a fact is "
        "what you know, a finding is what the client is told. It enters review "
        "as proposed and only reaches the report once the skeptic has tried to "
        "refute it and the arbiter has confirmed it. Supply a CVSS v3.1 vector, "
        "not a score — the score is computed from your vector.",
        {
            "agent": str, "title": str, "domain": str, "asset": str, "summary": str,
            "description": str, "impact": str, "remediation": str, "severity": str,
            "cvss_vector": str, "cwe": str, "owasp_wstg": str, "mitre_attack": str,
            "evidence": str, "fact_key": str,
        },
        annotations=WRITES_STATE,
    )
    async def record_finding(args: dict[str, Any]) -> dict[str, Any]:
        from ..report.cvss import score_vector

        vector = (args.get("cvss_vector") or "").strip() or None
        score, derived = score_vector(vector) if vector else (None, None)

        finding = Finding(
            title=args["title"], domain=args["domain"], asset=args["asset"],
            summary=args["summary"],
            description=args.get("description", ""), impact=args.get("impact", ""),
            remediation=args.get("remediation", ""),
            severity=(args.get("severity") or derived or "").lower() or None,
            cvss_vector=vector, cvss_score=score,
            cwe=(args.get("cwe") or "").strip() or None,
            owasp_wstg=(args.get("owasp_wstg") or "").strip() or None,
            mitre_attack=(args.get("mitre_attack") or "").strip() or None,
            discovered_by=args["agent"],
        )
        evidence = (args.get("evidence") or "").strip()
        if evidence:
            finding.evidence.append(("output", "as submitted", evidence))

        finding_id = ctx.kb.add_finding(finding)

        # Tie it back to the fact that holds the reproduction context.
        fact_key = (args.get("fact_key") or "").strip()
        if fact_key and ctx.kb.get_fact(fact_key) is not None:
            ctx.kb.upsert_fact(
                fact_key, ctx.kb.get_fact(fact_key)["summary"], args["agent"],
                related_finding_id=finding_id,
            )

        ctx.emit("agent.finding", agent=args["agent"], finding_id=finding_id,
                 title=finding.title, domain=finding.domain, asset=finding.asset,
                 severity=finding.severity or "unrated", cvss_score=score)
        return _text(
            f"{finding_id} recorded as proposed"
            + (f" (CVSS {score} {derived})" if score else "")
            + ". It will not appear in the report until the review round confirms it."
        )

    @tool(
        "add_evidence",
        "Attach reproducible evidence to a finding: the command, the HTTP "
        "exchange, or the relevant output.",
        {"agent": str, "finding_id": str, "kind": str, "label": str, "content": str},
        annotations=WRITES_STATE,
    )
    async def add_evidence(args: dict[str, Any]) -> dict[str, Any]:
        if ctx.kb.finding(args["finding_id"]) is None:
            return _error(f"no finding {args['finding_id']}")
        ctx.kb.add_evidence(args["finding_id"], args.get("kind") or "output",
                            args["content"], label=args.get("label", ""))
        return _text(f"evidence attached to {args['finding_id']}")

    @tool(
        "record_asset",
        "Record a discovered asset. Kinds: domain, host, url, service, "
        "cloud_resource, identity, repository.",
        {"agent": str, "kind": str, "value": str, "attributes": str},
        annotations=WRITES_STATE,
    )
    async def record_asset(args: dict[str, Any]) -> dict[str, Any]:
        try:
            attributes = json.loads(args.get("attributes") or "{}")
        except json.JSONDecodeError:
            attributes = {"note": args.get("attributes", "")}
        is_new = ctx.kb.add_asset(args["kind"], args["value"], args["agent"], attributes)
        if is_new:
            ctx.emit("agent.asset", agent=args["agent"], kind=args["kind"],
                     value=args["value"])
        return _text(
            f"recorded {args['kind']} {args['value']}" if is_new
            else f"{args['value']} was already known — another agent found it first"
        )

    @tool(
        "query_knowledge",
        "Campaign state. what: assets, services, findings, summary.",
        {"agent": str, "what": str, "filter": str},
        annotations=READ_ONLY,
    )
    async def query_knowledge(args: dict[str, Any]) -> dict[str, Any]:
        what = (args.get("what") or "summary").lower()
        selector = (args.get("filter") or "").strip() or None
        try:
            if what == "assets":
                payload: Any = ctx.kb.assets(selector)
            elif what == "services":
                payload = ctx.kb.services()
            elif what == "findings":
                payload = ctx.kb.findings(selector)
            else:
                payload = ctx.kb.summary()
        except Exception as exc:  # noqa: BLE001
            return _error(f"query failed: {exc}")
        return _text(json.dumps(payload, indent=2, default=str))

    @tool(
        "claim_task",
        "Claim a unit of work before starting it. If it comes back already "
        "claimed, another agent is on it — pick something else.",
        {"agent": str, "task_key": str},
        annotations=WRITES_STATE,
    )
    async def claim_task(args: dict[str, Any]) -> dict[str, Any]:
        granted = ctx.kb.try_claim(args["task_key"], args["agent"])
        return _text(
            f"claimed {args['task_key']}" if granted
            else f"{args['task_key']} is already claimed — do not duplicate it"
        )

    @tool(
        "halt_campaign",
        "Stop the entire campaign immediately. Use this if you observe a "
        "condition the contract says to halt on: a service degrading, an asset "
        "that may belong to a third party, or exposed personal data. Stopping is "
        "always the right call when you are unsure.",
        {"agent": str, "reason": str},
        annotations=WRITES_STATE,
    )
    async def halt_campaign(args: dict[str, Any]) -> dict[str, Any]:
        reason = f"halted by {args['agent']}: {args['reason']}"
        ctx.killswitch.engage(reason)
        ctx.kb.add_note(args["agent"], "halt", args["reason"])
        ctx.emit("campaign.halted", agent=args["agent"], reason=args["reason"])
        return _text(
            f"campaign halted. {reason}\n"
            f"Findings recorded so far remain valid and will be reported."
        )

    return [record_fact, get_fact, list_facts, search_facts, link_facts,
            retract_fact, attack_paths, record_finding, add_evidence,
            record_asset, query_knowledge, claim_task, halt_campaign]


def build_knowledge_server(ctx: CampaignContext) -> Any:
    return create_sdk_mcp_server(
        name="knowledge", version="0.2.0", tools=build_knowledge_tools(ctx)
    )


def handlers(tools: list[Any]) -> dict[str, Any]:
    """Name to handler, for calling a tool directly."""
    return {t.name: t.handler for t in tools}


def _string_list(raw: str) -> tuple[list[str], str | None]:
    raw = raw.strip() or "[]"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [], f"args must be a JSON array of strings: {exc}"
    if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
        return [], 'args must be a JSON array of strings, e.g. ["-sT","-p","80"]'
    return parsed, None


# Tool names as the agent harness addresses them: mcp__<server>__<tool>
TOOLBOX_TOOLS = [
    "mcp__toolbox__list_tools",
    "mcp__toolbox__describe_tool",
    "mcp__toolbox__run_tool",
    "mcp__toolbox__run_command",
    "mcp__toolbox__run_pipeline",
    "mcp__toolbox__run_shell",
]

KNOWLEDGE_TOOLS = [
    "mcp__knowledge__record_fact",
    "mcp__knowledge__get_fact",
    "mcp__knowledge__list_facts",
    "mcp__knowledge__search_facts",
    "mcp__knowledge__link_facts",
    "mcp__knowledge__retract_fact",
    "mcp__knowledge__attack_paths",
    "mcp__knowledge__record_finding",
    "mcp__knowledge__add_evidence",
    "mcp__knowledge__record_asset",
    "mcp__knowledge__query_knowledge",
    "mcp__knowledge__claim_task",
    "mcp__knowledge__halt_campaign",
]

# Reviewers and arbiters reason over the record; they never touch a target.
ANALYSIS_TOOLS = [
    "mcp__knowledge__get_fact",
    "mcp__knowledge__list_facts",
    "mcp__knowledge__search_facts",
    "mcp__knowledge__attack_paths",
    "mcp__knowledge__query_knowledge",
    "mcp__knowledge__add_evidence",
    "mcp__knowledge__retract_fact",
]
