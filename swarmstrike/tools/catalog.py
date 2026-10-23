"""The tools the swarm is given.

Agents do not get a shell. They get these typed tools, each of which builds its
own argument vector from validated parameters and hands it to ToolExecutor,
which checks it against the engagement contract before anything runs. Because
the argv is built as a list and executed without a shell, there is no string
for an agent to inject into.

`run_binary` is the escape hatch that keeps the swarm able to assess anything,
but it is allowlisted by binary and still passes through the same guard.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

from ..engagement import Engagement
from ..killswitch import KillSwitch
from ..knowledge import Finding, KnowledgeBase
from .executor import ExecutionRefused, ToolExecutor

# Binaries `run_binary` may invoke. Anything outside this list is refused
# before the scope guard is even consulted.
ALLOWED_BINARIES = {
    # discovery
    "nmap", "masscan", "dnsx", "subfinder", "amass", "httpx", "whatweb", "wafw00f",
    # web
    "nuclei", "ffuf", "feroxbuster", "katana", "gobuster", "nikto", "sqlmap", "curl",
    # tls
    "sslscan", "testssl.sh", "openssl",
    # network services
    "netexec", "smbclient", "enum4linux-ng", "snmpwalk", "ldapsearch", "rpcclient",
    # cloud / config
    "prowler", "trivy", "scoutsuite", "checkov",
    # inspection
    "dig", "host", "whois", "jq", "grep", "cat", "head", "tail", "wc", "sort", "uniq",
}


def _text(payload: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload}]}


def _error(payload: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": payload}], "is_error": True}


@dataclass
class CampaignContext:
    """What the tools act on. One per campaign."""

    engagement: Engagement
    executor: ToolExecutor
    kb: KnowledgeBase
    killswitch: KillSwitch
    on_event: Callable[[str, dict[str, Any]], None] | None = None

    def emit(self, kind: str, **payload: Any) -> None:
        if self.on_event is not None:
            self.on_event(kind, payload)


def build_toolbox_server(ctx: CampaignContext) -> Any:
    """Assessment tooling, every call gated by the engagement contract."""

    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)
    active = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)

    async def _dispatch(
        agent: str, argv: list[str], *, timeout_s: int = 900, raw_socket: bool = False
    ) -> dict[str, Any]:
        try:
            result = await ctx.executor.run(
                agent, argv, timeout_s=timeout_s, needs_raw_socket=raw_socket
            )
        except ExecutionRefused as exc:
            # A refusal is information, not a crash: the agent should record the
            # finding as theoretical and move on rather than retry.
            return _error(
                f"REFUSED by the engagement contract: {exc}\n"
                f"Do not retry this command. Either narrow it to an in-scope target, "
                f"or record the finding as theoretical with the reason it could not be proven."
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the agent verbatim
            return _error(f"execution failed: {type(exc).__name__}: {exc}")
        return _text(result.for_agent())

    # ------------------------------------------------------------------
    @tool(
        "port_scan",
        "Scan TCP/UDP ports on an in-scope host. Use mode='connect' unless you need "
        "a half-open scan. Returns open ports with service and version detection.",
        {
            "agent": str,
            "target": str,
            "ports": str,
            "mode": str,
            "service_detection": bool,
        },
        annotations=active,
    )
    async def port_scan(args: dict[str, Any]) -> dict[str, Any]:
        mode = (args.get("mode") or "connect").lower()
        flag = {"connect": "-sT", "syn": "-sS", "udp": "-sU"}.get(mode)
        if flag is None:
            return _error(f"mode must be connect, syn or udp — got {mode!r}")

        argv = ["nmap", flag, "-Pn", "--open"]
        if args.get("service_detection", True):
            argv += ["-sV", "--version-intensity", "5"]
        ports = (args.get("ports") or "").strip()
        argv += ["-p", ports] if ports else ["--top-ports", "1000"]
        argv.append(args["target"])

        return await _dispatch(
            args["agent"], argv, timeout_s=1800, raw_socket=mode in {"syn", "udp"}
        )

    @tool(
        "http_probe",
        "Fingerprint HTTP(S) services on in-scope hosts: status, title, technology, "
        "TLS details and redirect chain. Cheap; run it before deeper web testing.",
        {"agent": str, "targets": str},
        annotations=read_only,
    )
    async def http_probe(args: dict[str, Any]) -> dict[str, Any]:
        targets = [t for t in str(args["targets"]).split(",") if t.strip()]
        if not targets:
            return _error("targets must be a comma-separated list of hosts or URLs")
        argv = ["httpx", "-silent", "-title", "-status-code", "-tech-detect",
                "-tls-grab", "-follow-redirects", "-json", "-u", ",".join(targets)]
        return await _dispatch(args["agent"], argv, timeout_s=600)

    @tool(
        "vuln_scan",
        "Run templated vulnerability checks against an in-scope target. Set severity "
        "to limit noise (e.g. 'medium,high,critical'). Findings still need confirming.",
        {"agent": str, "target": str, "severity": str, "tags": str},
        annotations=active,
    )
    async def vuln_scan(args: dict[str, Any]) -> dict[str, Any]:
        argv = ["nuclei", "-silent", "-jsonl", "-no-interactsh", "-u", args["target"]]
        severity = (args.get("severity") or "medium,high,critical").strip()
        if severity:
            argv += ["-severity", severity]
        tags = (args.get("tags") or "").strip()
        if tags:
            argv += ["-tags", tags]
        return await _dispatch(args["agent"], argv, timeout_s=2400)

    @tool(
        "content_discovery",
        "Enumerate paths on an in-scope web target. Respects the contract's excluded "
        "URL paths. Use a focused wordlist; this is the noisiest tool available.",
        {"agent": str, "url": str, "wordlist": str, "extensions": str},
        annotations=active,
    )
    async def content_discovery(args: dict[str, Any]) -> dict[str, Any]:
        url = args["url"].rstrip("/")
        wordlist = args.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        argv = ["ffuf", "-s", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,201,204,301,302,307,401,403"]
        extensions = (args.get("extensions") or "").strip()
        if extensions:
            argv += ["-e", extensions]
        return await _dispatch(args["agent"], argv, timeout_s=1800)

    @tool(
        "dns_enum",
        "Enumerate subdomains and DNS records for an in-scope domain. Passive sources "
        "only, so it is safe to run early and widely.",
        {"agent": str, "domain": str},
        annotations=read_only,
    )
    async def dns_enum(args: dict[str, Any]) -> dict[str, Any]:
        argv = ["subfinder", "-silent", "-all", "-d", args["domain"]]
        return await _dispatch(args["agent"], argv, timeout_s=900)

    @tool(
        "tls_audit",
        "Audit the TLS configuration of an in-scope host: protocol versions, cipher "
        "suites, certificate validity and known weaknesses.",
        {"agent": str, "target": str},
        annotations=read_only,
    )
    async def tls_audit(args: dict[str, Any]) -> dict[str, Any]:
        argv = ["sslscan", "--no-colour", args["target"]]
        return await _dispatch(args["agent"], argv, timeout_s=600)

    @tool(
        "http_request",
        "Send one crafted HTTP request to an in-scope target and return the full "
        "response. This is how you prove a web finding: the request and response "
        "become the evidence a client can reproduce.",
        {"agent": str, "url": str, "method": str, "headers": str, "body": str},
        annotations=active,
    )
    async def http_request(args: dict[str, Any]) -> dict[str, Any]:
        argv = ["curl", "-sS", "-i", "--max-time", "30", "-X",
                (args.get("method") or "GET").upper()]
        raw_headers = (args.get("headers") or "").strip()
        if raw_headers:
            for line in raw_headers.splitlines():
                if line.strip():
                    argv += ["-H", line.strip()]
        body = args.get("body") or ""
        if body:
            argv += ["--data-raw", body]
        argv.append(args["url"])
        return await _dispatch(args["agent"], argv, timeout_s=60)

    @tool(
        "run_binary",
        "Run an allowlisted assessment binary with explicit arguments, for cases the "
        "typed tools do not cover. Pass args as a JSON array of strings. The command "
        "is still checked against the engagement contract before it runs.",
        {"agent": str, "binary": str, "args": str, "needs_raw_socket": bool},
        annotations=active,
    )
    async def run_binary(args: dict[str, Any]) -> dict[str, Any]:
        binary = args["binary"].strip()
        if binary not in ALLOWED_BINARIES:
            return _error(
                f"{binary!r} is not an allowlisted binary. Available: "
                f"{', '.join(sorted(ALLOWED_BINARIES))}"
            )
        raw = args.get("args") or "[]"
        try:
            parsed = json.loads(raw) if raw.strip().startswith("[") else shlex.split(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            return _error(f"could not read args: {exc}. Pass a JSON array of strings.")
        if not all(isinstance(item, str) for item in parsed):
            return _error("every element of args must be a string")

        return await _dispatch(
            args["agent"],
            [binary, *parsed],
            timeout_s=1800,
            raw_socket=bool(args.get("needs_raw_socket")),
        )

    return create_sdk_mcp_server(
        name="toolbox",
        version="0.1.0",
        tools=[port_scan, http_probe, vuln_scan, content_discovery, dns_enum,
               tls_audit, http_request, run_binary],
    )


def build_knowledge_server(ctx: CampaignContext) -> Any:
    """Shared campaign state: what we found, what we claimed, what we concluded."""

    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    writes = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)

    @tool(
        "record_asset",
        "Record a discovered asset so the rest of the team can see it. Kinds: domain, "
        "host, url, service, cloud_resource, identity, repository.",
        {"agent": str, "kind": str, "value": str, "attributes": str},
        annotations=writes,
    )
    async def record_asset(args: dict[str, Any]) -> dict[str, Any]:
        try:
            attributes = json.loads(args.get("attributes") or "{}")
        except json.JSONDecodeError:
            attributes = {"note": args.get("attributes", "")}
        is_new = ctx.kb.add_asset(args["kind"], args["value"], args["agent"], attributes)
        if is_new:
            ctx.emit(
                "agent.asset",
                agent=args["agent"], kind=args["kind"], value=args["value"],
            )
        return _text(
            f"recorded {args['kind']} {args['value']}"
            if is_new
            else f"{args['value']} was already known — another agent found it first"
        )

    @tool(
        "record_finding",
        "Propose a finding. It enters review as 'proposed' and only reaches the report "
        "once the skeptic has tried to refute it and the arbiter has confirmed it. "
        "Include evidence a client could reproduce, and a concrete remediation.",
        {
            "agent": str,
            "title": str,
            "domain": str,
            "asset": str,
            "summary": str,
            "description": str,
            "impact": str,
            "remediation": str,
            "severity": str,
            "cvss_vector": str,
            "cwe": str,
            "owasp_wstg": str,
            "mitre_attack": str,
            "evidence": str,
        },
        annotations=writes,
    )
    async def record_finding(args: dict[str, Any]) -> dict[str, Any]:
        from ..report.cvss import score_vector

        vector = (args.get("cvss_vector") or "").strip() or None
        score, derived_severity = score_vector(vector) if vector else (None, None)

        finding = Finding(
            title=args["title"],
            domain=args["domain"],
            asset=args["asset"],
            summary=args["summary"],
            description=args.get("description", ""),
            impact=args.get("impact", ""),
            remediation=args.get("remediation", ""),
            severity=(args.get("severity") or derived_severity or "").lower() or None,
            cvss_vector=vector,
            cvss_score=score,
            cwe=(args.get("cwe") or "").strip() or None,
            owasp_wstg=(args.get("owasp_wstg") or "").strip() or None,
            mitre_attack=(args.get("mitre_attack") or "").strip() or None,
            discovered_by=args["agent"],
        )
        evidence = (args.get("evidence") or "").strip()
        if evidence:
            finding.evidence.append(("output", "as submitted", evidence))

        finding_id = ctx.kb.add_finding(finding)
        ctx.emit(
            "agent.finding",
            agent=args["agent"],
            finding_id=finding_id,
            title=finding.title,
            domain=finding.domain,
            asset=finding.asset,
            severity=finding.severity or "unrated",
            cvss_score=score,
        )
        return _text(
            f"{finding_id} recorded as proposed"
            + (f" (CVSS {score} {derived_severity})" if score else "")
            + ". It will not appear in the report until the review round confirms it."
        )

    @tool(
        "add_evidence",
        "Attach reproducible evidence to an existing finding: the command run, the "
        "HTTP exchange, or the relevant output.",
        {"agent": str, "finding_id": str, "kind": str, "label": str, "content": str},
        annotations=writes,
    )
    async def add_evidence(args: dict[str, Any]) -> dict[str, Any]:
        if ctx.kb.finding(args["finding_id"]) is None:
            return _error(f"no finding {args['finding_id']}")
        ctx.kb.add_evidence(
            args["finding_id"], args.get("kind") or "output",
            args["content"], label=args.get("label", ""),
        )
        return _text(f"evidence attached to {args['finding_id']}")

    @tool(
        "query_knowledge",
        "Read shared campaign state before starting work, so you do not repeat what a "
        "teammate already did. what: assets, services, findings, notes, summary.",
        {"agent": str, "what": str, "filter": str},
        annotations=read_only,
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
            elif what == "notes":
                payload = ctx.kb.notes(selector)
            else:
                payload = ctx.kb.summary()
        except Exception as exc:  # noqa: BLE001
            return _error(f"query failed: {exc}")
        return _text(json.dumps(payload, indent=2, default=str))

    @tool(
        "claim_task",
        "Claim a unit of work before starting it. If this returns 'already claimed', "
        "another agent is on it — pick something else.",
        {"agent": str, "task_key": str},
        annotations=writes,
    )
    async def claim_task(args: dict[str, Any]) -> dict[str, Any]:
        granted = ctx.kb.try_claim(args["task_key"], args["agent"])
        return _text(
            f"claimed {args['task_key']}"
            if granted
            else f"{args['task_key']} is already claimed by another agent — do not duplicate it"
        )

    @tool(
        "leave_note",
        "Leave a note for the rest of the team: a lead worth following, a dead end "
        "worth not repeating, or context another specialist needs.",
        {"agent": str, "topic": str, "content": str},
        annotations=writes,
    )
    async def leave_note(args: dict[str, Any]) -> dict[str, Any]:
        ctx.kb.add_note(args["agent"], args["topic"], args["content"])
        return _text(f"noted under {args['topic']!r}")

    @tool(
        "halt_campaign",
        "Stop the entire campaign immediately. Use this if you observe a condition the "
        "contract says to halt on: a service degrading, an asset that looks like it "
        "belongs to a third party, or exposed personal data. Stopping is always the "
        "right call when you are unsure.",
        {"agent": str, "reason": str},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False),
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

    return create_sdk_mcp_server(
        name="knowledge",
        version="0.1.0",
        tools=[record_asset, record_finding, add_evidence, query_knowledge,
               claim_task, leave_note, halt_campaign],
    )


# Tool names as the agent harness addresses them: mcp__<server>__<tool>
TOOLBOX_TOOLS = [
    "mcp__toolbox__port_scan",
    "mcp__toolbox__http_probe",
    "mcp__toolbox__vuln_scan",
    "mcp__toolbox__content_discovery",
    "mcp__toolbox__dns_enum",
    "mcp__toolbox__tls_audit",
    "mcp__toolbox__http_request",
    "mcp__toolbox__run_binary",
]

KNOWLEDGE_TOOLS = [
    "mcp__knowledge__record_asset",
    "mcp__knowledge__record_finding",
    "mcp__knowledge__add_evidence",
    "mcp__knowledge__query_knowledge",
    "mcp__knowledge__claim_task",
    "mcp__knowledge__leave_note",
    "mcp__knowledge__halt_campaign",
]

# Reviewers and arbiters read and argue; they do not touch targets.
ANALYSIS_TOOLS = [
    "mcp__knowledge__query_knowledge",
    "mcp__knowledge__add_evidence",
    "mcp__knowledge__leave_note",
]
