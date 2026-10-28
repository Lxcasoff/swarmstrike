"""State-space search over the fact graph.

An engagement does not have a fixed shape. What to do next depends on what is
already established: a host nobody has fingerprinted, a credential that opens
something, a dead end that rules a whole direction out. So rather than running
fixed phases, the lead is asked the same question each round — given the facts
on the board, what is the most useful thing to do now — and the campaign ends
when it says there is nothing left worth doing, or a ceiling is reached.

The approach follows CyberStrikeAI's `pentest-agent-os` framing (Apache-2.0;
see NOTICE), which models penetration testing as search rather than a
playbook. What is added here is that the loop runs in code: the round
structure, the duplicate-work check, the no-progress guard and the budget
check are not things the lead can forget to do, because the lead is not the
thing doing them.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from .audit import AuditLog
from .budget import BudgetExceeded, BudgetTracker
from .engagement import Engagement
from .killswitch import Halted, KillSwitch
from .knowledge import KnowledgeBase
from .models import Role, effort_for, model_for
from .tools.recipes import RecipeBook

PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["reading", "actions", "complete"],
    "properties": {
        "reading": {
            "type": "string",
            "description": "What the board says right now: what is established, what "
                           "the most promising unexplored direction is, and why. Reason "
                           "from the facts listed, not from what a penetration test "
                           "usually does next.",
        },
        "actions": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["agent", "task_key", "brief"],
                "properties": {
                    "agent": {"type": "string", "description": "Which specialist."},
                    "task_key": {
                        "type": "string",
                        "description": "Short stable identifier for this unit of work, "
                                       "e.g. web:admin-subdomain-authz. Used to stop the "
                                       "same work being assigned twice.",
                    },
                    "brief": {
                        "type": "string",
                        "description": "What this specialist should do, naming the assets "
                                       "and the question to answer. Not a generic "
                                       "instruction to go and test things.",
                    },
                    "expected": {
                        "type": "string",
                        "description": "What would count as a result, so a null result is "
                                       "recognisable as one.",
                    },
                },
            },
        },
        "complete": {"type": "boolean"},
        "completion_reason": {
            "type": "string",
            "description": "If complete, what was covered and what was not.",
        },
    },
}


@dataclass
class Action:
    agent: str
    task_key: str
    brief: str
    expected: str = ""


@dataclass
class Outcome:
    action: Action
    ran: bool
    detail: str
    new_facts: int = 0
    new_findings: int = 0

    @property
    def productive(self) -> bool:
        return self.new_facts > 0 or self.new_findings > 0


@dataclass
class Round:
    number: int
    reading: str
    actions: list[Action] = field(default_factory=list)
    outcomes: list[Outcome] = field(default_factory=list)
    complete: bool = False
    completion_reason: str = ""

    @property
    def productive(self) -> bool:
        return any(o.productive for o in self.outcomes)


EventSink = Callable[[str, dict[str, Any]], None]


class StateSpaceSearch:
    def __init__(
        self,
        *,
        engagement: Engagement,
        kb: KnowledgeBase,
        audit: AuditLog,
        budget: BudgetTracker,
        killswitch: KillSwitch,
        book: RecipeBook,
        mcp_servers: dict[str, Any],
        lead_prompt: str,
        specialist_prompts: dict[str, str],
        specialist_tools: dict[str, list[str]],
        lead_tools: list[str],
        on_event: EventSink | None = None,
        max_rounds: int = 12,
        max_parallel: int = 3,
        carries: Callable[[str], bool] | None = None,
    ) -> None:
        self.engagement = engagement
        self.kb = kb
        self.audit = audit
        self.budget = budget
        self.killswitch = killswitch
        self.book = book
        self.mcp_servers = mcp_servers
        self.lead_prompt = lead_prompt
        self.specialist_prompts = specialist_prompts
        self.specialist_tools = specialist_tools
        self.lead_tools = lead_tools
        # Defaults to "assume present", which is what --skip-preflight leaves
        # behind: unprobed is not the same as absent.
        self.carries = carries or (lambda _binary: True)
        self.max_rounds = max_rounds
        self.max_parallel = max_parallel
        self._sink = on_event or (lambda _event, _payload: None)

    def _emit(self, event: str, **payload: Any) -> None:
        # The sink takes a payload dict positionally, as everywhere else here.
        self._sink(event, payload)

    # ------------------------------------------------------------------
    #  What the lead sees
    # ------------------------------------------------------------------
    def digest(self, round_number: int) -> str:
        """The board, compactly.

        Facts come from the index — keys and summaries, never bodies — because
        a lead that re-reads the whole engagement every round spends the budget
        on recall rather than on testing. It fetches a body when it needs one.
        """
        facts = self.kb.list_facts()
        positives = [f for f in facts if not f["negative"]]
        dead_ends = [f for f in facts if f["negative"]]

        assets: dict[str, list[str]] = {}
        for asset in self.kb.assets():
            assets.setdefault(asset["kind"], []).append(asset["value"])

        findings = self.kb.findings()
        paths = self.kb.attack_paths()

        claimed = [
            dict(row) for row in self.kb.conn.execute(
                "SELECT task_key, agent, released_at FROM claim WHERE campaign_id = ?",
                (self.kb.campaign_id,),
            )
        ]

        # What the contract authorizes and what the toolbox image carries are
        # different questions, and the digest is the lead's only view of the
        # toolset. Listing a tool that cannot run gets it planned for and
        # assigned, and the specialist comes back with nothing.
        available = {
            name: sorted({
                r.name for r in self.book.available_to(self.engagement, [name])
                if self.carries(r.binary)
            })
            for name in self.specialist_prompts
        }

        def block(title: str, lines: list[str], empty: str) -> str:
            body = "\n".join(f"- {line}" for line in lines) if lines else f"_{empty}_"
            return f"## {title}\n\n{body}\n"

        parts = [
            f"# Round {round_number} of at most {self.max_rounds}",
            "",
            f"Budget: {self.budget.status()}",
            "",
            block(
                "Attack surface",
                [f"{kind}: {', '.join(values[:24])}"
                 + (f" (+{len(values) - 24} more)" if len(values) > 24 else "")
                 for kind, values in sorted(assets.items())],
                "nothing discovered yet — this is the first thing to fix",
            ),
            block(
                "Established facts",
                [f"`{f['fact_key']}` [{f['confidence']}] {f['summary']}" for f in positives],
                "the board is empty",
            ),
            block(
                "Dead ends — do not reassign these",
                [f"`{f['fact_key']}` {f['summary']}" for f in dead_ends],
                "none recorded",
            ),
            block(
                "Evidenced paths",
                [" -> ".join(step["fact_key"] for step in path) for path in paths],
                "no path has been chained yet",
            ),
            block(
                "Findings proposed",
                [f"{f['id']} [{f['status']}/{f.get('severity') or 'unrated'}] {f['title']}"
                 for f in findings],
                "none yet",
            ),
            block(
                "Work already assigned — assigning it again is refused",
                [f"`{c['task_key']}` to {c['agent']}"
                 + (" (finished)" if c["released_at"] else " (no result recorded)")
                 for c in claimed],
                "nothing assigned yet",
            ),
            block(
                "Specialists, and the tools this contract authorizes for each",
                [f"**{name}**: {', '.join(tools) if tools else 'no tools authorized'}"
                 for name, tools in sorted(available.items())],
                "no specialists available",
            ),
        ]
        return "\n".join(parts)

    # ------------------------------------------------------------------
    #  Deciding
    # ------------------------------------------------------------------
    async def plan(self, round_number: int, note: str = "") -> Round:
        digest = self.digest(round_number)
        prompt = (
            f"{digest}\n\n"
            f"{note}\n\n" if note else f"{digest}\n\n"
        ) + (
            "Decide what to do now. Assign work to the specialists whose tools and "
            "discipline fit it, give each a brief naming the specific assets and the "
            "question to answer, and give each a task_key so the same work is not "
            "assigned twice.\n\n"
            "Assign several actions at once where they do not overlap. Do not assign "
            "work that duplicates a dead end or something already assigned.\n\n"
            "Set complete when the surface has been covered to the depth this budget "
            "allows — not when every specialist has run once — and say what was "
            "covered and what was not."
        )

        options = ClaudeAgentOptions(
            system_prompt=self.lead_prompt,
            model=model_for(Role.ORCHESTRATOR),
            effort=effort_for(Role.ORCHESTRATOR),
            mcp_servers=self.mcp_servers,
            allowed_tools=self.lead_tools,
            output_format={"type": "json_schema", "schema": PLAN_SCHEMA},
            setting_sources=[],
            max_turns=14,
        )

        payload: dict[str, Any] | None = None
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                self.budget.record_result(f"lead:{message.session_id}", message)
                payload = _structured(message)

        if payload is None:
            # No plan means no basis for another round. Stopping is the honest
            # outcome; inventing a next action is not.
            return Round(
                number=round_number,
                reading="The lead returned no plan.",
                complete=True,
                completion_reason="the lead returned no usable plan, so the campaign stopped",
            )

        actions = [
            Action(
                agent=str(item.get("agent", "")).strip(),
                task_key=str(item.get("task_key", "")).strip(),
                brief=str(item.get("brief", "")).strip(),
                expected=str(item.get("expected", "")).strip(),
            )
            for item in payload.get("actions", [])
        ]
        return Round(
            number=round_number,
            reading=str(payload.get("reading", "")).strip(),
            actions=[a for a in actions if a.agent and a.brief],
            complete=bool(payload.get("complete")),
            completion_reason=str(payload.get("completion_reason", "")).strip(),
        )

    # ------------------------------------------------------------------
    #  Doing
    # ------------------------------------------------------------------
    async def dispatch(self, action: Action) -> Outcome:
        prompt_text = self.specialist_prompts.get(action.agent)
        if prompt_text is None:
            return Outcome(
                action, False,
                f"there is no specialist called {action.agent!r} on this engagement. "
                f"Available: {', '.join(sorted(self.specialist_prompts))}",
            )

        # The claim is what stops duplicate work, and it is enforced here rather
        # than asked for: the lead sees assigned keys in the digest, but a race
        # between two rounds would still slip through a prompt.
        key = action.task_key or f"{action.agent}:{abs(hash(action.brief)) % 10**8}"
        if not self.kb.try_claim(key, action.agent):
            return Outcome(action, False, f"{key} was already claimed — skipped")
        opened_at = datetime.now(tz=UTC).isoformat()

        before_facts = len(self.kb.list_facts(include_deprecated=True))
        before_findings = len(self.kb.findings())

        self._emit("action.dispatched", agent=action.agent, task_key=key,
                   brief=action.brief[:300])

        options = ClaudeAgentOptions(
            system_prompt=prompt_text,
            model=model_for(Role.SPECIALIST),
            effort=effort_for(Role.SPECIALIST),
            mcp_servers=self.mcp_servers,
            allowed_tools=self.specialist_tools.get(action.agent, []),
            max_budget_usd=max(0.5, self.budget.remaining_usd / 3),
            setting_sources=[],
            max_turns=40,
        )

        brief = (
            f"{action.brief}\n\n"
            + (f"What would count as a result: {action.expected}\n\n" if action.expected else "")
            + "Read the fact graph before you start — a teammate may already have "
            "found this or ruled it out. Record what you establish as you establish "
            "it, and record a dead end as a negative fact so nobody repeats it. If "
            "you find nothing, say so plainly: a null result recorded is worth more "
            "than a null result forgotten."
        )

        detail = ""
        try:
            async for message in query(prompt=brief, options=options):
                if isinstance(message, ResultMessage):
                    self.budget.record_result(f"{action.agent}:{message.session_id}", message)
                    detail = (message.result or "").strip()[:4000]
        except Halted:
            raise
        except Exception as exc:  # noqa: BLE001 — one specialist failing is not the campaign failing
            detail = f"{type(exc).__name__}: {exc}"

        after_facts = len(self.kb.list_facts(include_deprecated=True))
        after_findings = len(self.kb.findings())
        self.kb.release_claim(key, detail[:500])
        self.kb.release_agent_claims(action.agent, opened_at)

        outcome = Outcome(
            action, True, detail or "(the specialist returned no summary)",
            new_facts=after_facts - before_facts,
            new_findings=after_findings - before_findings,
        )
        self._emit("action.finished", agent=action.agent, task_key=key,
                   new_facts=outcome.new_facts, new_findings=outcome.new_findings)
        return outcome

    # ------------------------------------------------------------------
    #  The loop
    # ------------------------------------------------------------------
    async def run(self) -> list[Round]:
        rounds: list[Round] = []
        barren = 0
        note = ""

        for number in range(1, self.max_rounds + 1):
            self.killswitch.check()
            try:
                self.budget.check()
            except BudgetExceeded as exc:
                self._emit("search.stopped", reason=str(exc), round=number)
                break

            self._emit("round.start", round=number, of=self.max_rounds)
            current = await self.plan(number, note)
            note = ""
            rounds.append(current)

            self.audit.record(
                "search.plan", round=number, reading=current.reading[:2000],
                actions=[{"agent": a.agent, "task_key": a.task_key, "brief": a.brief[:500]}
                         for a in current.actions],
                complete=current.complete,
            )
            self._emit("lead", text=current.reading)

            if current.complete and not current.actions:
                self._emit("search.complete", round=number,
                           reason=current.completion_reason)
                break

            semaphore = asyncio.Semaphore(self.max_parallel)

            async def guarded(action: Action) -> Outcome:
                async with semaphore:
                    self.killswitch.check()
                    return await self.dispatch(action)

            results = await asyncio.gather(
                *(guarded(a) for a in current.actions), return_exceptions=True
            )
            for item in results:
                if isinstance(item, Halted):
                    raise item
                if isinstance(item, BaseException):
                    self._emit("action.failed", detail=f"{type(item).__name__}: {item}")
                    continue
                current.outcomes.append(item)

            self._emit("round.end", round=number,
                       actions=len(current.actions),
                       new_facts=sum(o.new_facts for o in current.outcomes),
                       new_findings=sum(o.new_findings for o in current.outcomes))

            if current.complete:
                self._emit("search.complete", round=number,
                           reason=current.completion_reason)
                break

            # A round that established nothing is the signal that the search has
            # converged — or that the lead is circling. One more round with that
            # said plainly, then stop, rather than spending the budget on a loop.
            if current.productive:
                barren = 0
            else:
                barren += 1
                if barren >= 2:
                    self._emit("search.converged", round=number,
                               reason="two consecutive rounds established nothing new")
                    break
                note = (
                    "The previous round established no new facts and no new findings. "
                    "Either there is a direction on the board nobody has taken, or the "
                    "surface is covered to the depth this budget allows. If it is the "
                    "latter, set complete rather than reassigning work."
                )

        return rounds


def _structured(message: ResultMessage) -> dict[str, Any] | None:
    payload = getattr(message, "structured_output", None)
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            pass

    text = getattr(message, "result", None)
    if isinstance(text, str) and text.strip():
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                parsed = json.loads(text[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
    return None
