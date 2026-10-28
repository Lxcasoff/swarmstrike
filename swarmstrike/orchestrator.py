"""Campaign orchestration.

Runs an engagement end to end: verify the contract, stand up the campaign
workspace, brief the swarm, let the specialists work the target, put every
finding through the challenge round, and write the deliverable.

The assessment phase is delegated — a lead agent decides who works on what,
because that judgement is the thing a model is genuinely better at than a
fixed script. Everything around it is not delegated: the contract check, the
budget ceiling, the challenge round and the report assembly all run in code,
so they happen whether or not a model remembers to ask for them.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from . import engagement as contract
from .agents.roster import CHALLENGE_NAMES, SPECIALIST_NAMES, build_agents
from .approval import ApprovalGate, AutoDenyGate
from .audit import AuditLog
from .budget import BudgetExceeded, BudgetTracker
from .debate.peer_review import DebateEngine, Outcome
from .engagement import Engagement
from .killswitch import Halted, KillSwitch
from .knowledge import KnowledgeBase
from .search import StateSpaceSearch
from .tools.catalog import (
    ANALYSIS_TOOLS,
    CampaignContext,
    build_knowledge_server,
    build_toolbox_server,
)
from .tools.executor import ContainerPolicy, ToolExecutor

ORCHESTRATOR_PROMPT = """
You lead this penetration testing engagement. You do not run tools against the
target yourself — you decide what gets tested next, and you delegate it.

You are asked the same question each round: **given the facts on the board,
what is the most useful thing to do now?** Answer it from the board, not from
what a penetration test usually does next. There is no fixed sequence here. If
recon has found nothing yet, mapping the surface is obviously first. If a
credential has turned up, what it opens matters more than finishing a scan. If
a direction is a dead end, it is recorded as one and reassigning it wastes the
engagement's budget.

**Reading the board.** You are given the attack surface, the established facts
with their confidence, the dead ends, the paths already chained, the findings
proposed, and the work already assigned. Facts come as a one-line summary each;
when a summary is not enough, fetch the fact rather than guessing from it.

**Assigning work.** Give each specialist a brief that names the specific assets
and the question to answer — "test the authorization model on admin.example.org
with the two accounts recon found" rather than "test the web application".
Say what would count as a result, so a null result is recognisable as one
instead of looking like a failure. Give each a task_key; assigning a key that
is already on the board is refused in code, so check the list.

Assign several actions at once where they do not overlap. Two specialists
working the same asset is waste you are responsible for preventing.

**Following leads.** The value of this loop is that a result changes the next
decision. A host that turned out to run an application needs the web
specialist. A finding in one place usually means the same mistake elsewhere —
have it checked. A credential is worth more than another scan.

**Stopping.** Set complete when the surface has been covered to the depth this
budget allows, not when every specialist has run once. Say what was covered
and what was not: an engagement that stopped with an area untested is a fact
the client needs, and the report will say so.

If a round establishes nothing new, that is information. Either there is a
direction nobody has taken, or you are done. Do not reassign work to look busy.

**What is not yours.** You do not rule on findings. Specialists propose them
and a separate challenge round confirms or rejects them after you are done.
Do not try to confirm, reject or re-score one, and do not tell a specialist to
drop one — if you think a finding is weak, say so in a note and let the review
handle it.
"""


def build_context(engagement: Engagement) -> str:
    """The briefing every agent on the engagement receives."""
    meta = engagement.engagement
    scope = engagement.scope
    roe = engagement.rules_of_engagement
    exclusions = engagement.exclusions

    def listing(values: list[str]) -> str:
        return ", ".join(values) if values else "none"

    domains = listing([
        f"{d.name}{' (and subdomains)' if d.include_subdomains else ''}" for d in scope.domains
    ])
    excluded_domains = listing([d.name for d in exclusions.domains])

    permitted = []
    if roe.exploitation.allowed:
        permitted.append(
            "Confirming a vulnerability with a proof-of-concept is authorized"
            + (", and you must stop at proof" if roe.exploitation.stop_at_proof else "")
        )
    else:
        permitted.append("Exploitation is NOT authorized — identify and evidence only")
    if roe.credential_testing.allowed:
        accounts = listing([a.username for a in roe.credential_testing.accounts])
        permitted.append(f"Authentication testing is authorized against these accounts only: {accounts}")
    else:
        permitted.append("Authentication testing is NOT authorized")

    return f"""# Engagement briefing

You are working an authorized penetration test under a signed contract.

| | |
|---|---|
| Client | {meta.client} |
| Mission | {meta.mission} |
| Engagement reference | {meta.id} |
| Authorized by | {meta.authorized_by.name}, {meta.authorized_by.role} |
| Authorization on file | {meta.authorized_by.authorization_ref} |
| Testing window | {engagement.window.start.isoformat()} to {engagement.window.end.isoformat()} |
| Contract fingerprint | {engagement.integrity.fingerprint or 'unsigned'} |

## In scope

- Domains: {domains}
- Addresses: {listing(scope.ips)}
- Ranges: {listing(scope.cidrs)}
- URLs: {listing(scope.urls)}

## Explicitly out of scope

- Domains: {excluded_domains}
- Addresses: {listing(exclusions.ips)}
- Ranges: {listing(exclusions.cidrs)}
- URL paths containing: {listing(exclusions.url_paths)}

Anything not listed as in scope is out of scope. This is enforced in code:
a command against an out-of-scope target is refused before it runs.

## Rules of engagement

- Intensity: {roe.intensity}, at most {roe.max_requests_per_second} requests per second
- {permitted[0]}
- {permitted[1]}
- Denial of service, destruction, data modification, persistence and social
  engineering are forbidden outright and refused in code.

## Halt immediately if you observe

{chr(10).join(f'- {condition}' for condition in engagement.contacts.halt_on) or '- any sign of service disruption'}

Use the `halt_campaign` tool. Stopping early is always the right call when you
are unsure.
"""


@dataclass
class CampaignConfig:
    engagement_path: Path
    workspace_root: Path = Path("campaigns")
    domains: list[str] | None = None
    max_review_rounds: int = 2
    # How many decide-and-dispatch rounds the search may run.
    max_search_rounds: int = 12
    max_parallel_agents: int = 3
    toolbox_image: str = "swarmstrike/toolbox:latest"
    resume: str | None = None
    skip_preflight: bool = False


@dataclass
class CampaignResult:
    campaign_id: str
    status: str
    outcomes: list[Outcome] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    spend: str = ""
    report_path: Path | None = None
    halted_reason: str = ""


EventSink = Callable[[str, dict[str, Any]], None]


class Campaign:
    def __init__(
        self,
        config: CampaignConfig,
        on_event: EventSink | None = None,
        approval: ApprovalGate | None = None,
    ) -> None:
        self.config = config
        self._emit = on_event or (lambda _kind, _payload: None)

        self.engagement = contract.load(config.engagement_path)
        # Autonomous execution requires a contract whose integrity can be proven.
        self.engagement.require_verified()

        self.campaign_id = config.resume or (
            f"{self.engagement.engagement.id}-"
            f"{datetime.now(tz=ZoneInfo('UTC')):%Y%m%d-%H%M}-{uuid.uuid4().hex[:6]}"
        )
        self.dir = config.workspace_root / self.campaign_id
        self.dir.mkdir(parents=True, exist_ok=True)

        self.audit = AuditLog(self.dir / "audit.jsonl")
        self.kb = KnowledgeBase(self.dir / "knowledge.sqlite")
        self.killswitch = KillSwitch(self.dir)
        self.budget = BudgetTracker(self.engagement.budget)

        from .scope import ScopeGuard
        from .tools.recipes import load_recipes

        self.book = load_recipes()
        if self.book.errors:
            # A malformed recipe is a configuration problem, not a campaign one:
            # report it and run with the rest rather than refusing to start.
            for name, detail in self.book.errors.items():
                self._emit("recipe.invalid", file=name, detail=detail)

        self.guard = ScopeGuard(self.engagement)
        self.executor = ToolExecutor(
            guard=self.guard,
            audit=self.audit,
            kb=self.kb,
            workspace=self.dir,
            killswitch=self.killswitch,
            policy=ContainerPolicy(
                image=config.toolbox_image,
                # Set when swarmstrike runs in a container; see preflight.
                host_workspace=(
                    Path(os.environ["SWARMSTRIKE_HOST_WORKSPACE"])
                    if os.environ.get("SWARMSTRIKE_HOST_WORKSPACE") else None
                ),
                local_workspace_root=config.workspace_root,
            ),
            max_concurrent=self.engagement.rules_of_engagement.max_concurrent_tools,
            min_interval_s=_interval_for(self.engagement.rules_of_engagement.intensity),
            on_event=self._emit,
            approval=approval or AutoDenyGate(),
            allowed_binaries=frozenset(
                self.book.binaries()
                | set(self.engagement.rules_of_engagement.arbitrary_execution.extra_binaries)
            ),
        )

        self.context = build_context(self.engagement)
        self._servers: dict[str, Any] = {}

    # ------------------------------------------------------------------
    def _setup(self) -> None:
        if self.config.resume:
            self.kb.resume_campaign(self.campaign_id)
            self.killswitch.release()
        else:
            self.kb.open_campaign(self.campaign_id, self.engagement)
            self.audit.open_campaign(self.engagement, self.campaign_id)

        ctx = CampaignContext(
            engagement=self.engagement,
            executor=self.executor,
            kb=self.kb,
            killswitch=self.killswitch,
            book=self.book,
            on_event=self._emit,
        )
        self._servers = {
            "toolbox": build_toolbox_server(ctx),
            "knowledge": build_knowledge_server(ctx),
        }

    def _agents(self) -> dict[str, Any]:
        return build_agents(
            context=self.context,
            domains=self.config.domains,
            engagement=self.engagement,
        )

    # ------------------------------------------------------------------
    async def run(self) -> CampaignResult:
        self._setup()
        self._emit("campaign.start", {
            "campaign_id": self.campaign_id,
            "client": self.engagement.engagement.client,
            "directory": str(self.dir),
        })

        if not self.config.skip_preflight:
            ready, detail = await self.executor.preflight()
            self._emit("preflight", {"ready": ready, "detail": detail})
            if not ready:
                self.kb.close_campaign("aborted")
                return CampaignResult(
                    self.campaign_id, "aborted", summary=self.kb.summary(),
                    halted_reason=detail,
                )

        window_ok = self.guard.check_window()
        if not window_ok.allowed:
            self._emit("window.closed", {"reason": window_ok.reason})
            self.kb.close_campaign("aborted")
            return CampaignResult(
                self.campaign_id, "aborted", summary=self.kb.summary(),
                halted_reason=window_ok.reason,
            )

        status = "completed"
        halted_reason = ""
        outcomes: list[Outcome] = []

        try:
            await self._assess()
            outcomes = await self._debate()
        except Halted as exc:
            status, halted_reason = "aborted", str(exc)
            self._emit("campaign.halted", {"reason": halted_reason})
            # A halted campaign still gets its findings reviewed and reported.
            try:
                outcomes = await self._debate()
            except (Halted, BudgetExceeded):
                pass
        except BudgetExceeded as exc:
            status, halted_reason = "budget_exhausted", str(exc)
            self._emit("budget.exhausted", {"reason": halted_reason})
            try:
                outcomes = await self._debate()
            except (Halted, BudgetExceeded):
                pass

        report_path = self._write_report()

        self.kb.close_campaign(status)
        self.audit.record(
            "campaign.close",
            status=status,
            reason=halted_reason,
            spend=self.budget.status(),
            summary=self.kb.summary(),
        )

        result = CampaignResult(
            campaign_id=self.campaign_id,
            status=status,
            outcomes=outcomes,
            summary=self.kb.summary(),
            spend=self.budget.status(),
            report_path=report_path,
            halted_reason=halted_reason,
        )
        self._emit("campaign.done", {
            "status": status,
            "spend": result.spend,
            "report": str(report_path) if report_path else "",
        })
        return result

    # ------------------------------------------------------------------
    async def _assess(self) -> None:
        """The search: decide from the board, dispatch, absorb, repeat.

        This replaces a single long delegated session with an explicit loop.
        The reason is the same one that applies everywhere else here — the
        round structure, the duplicate-work check, the no-progress guard and
        the budget check are not things a model can forget to do, because the
        model is not the thing doing them.
        """
        self._emit("phase", {"name": "assessment"})

        agents = self._agents()
        specialist_prompts = {
            name: definition.prompt
            for name, definition in agents.items()
            if name not in CHALLENGE_NAMES
        }
        specialist_tools = {
            name: list(definition.tools or [])
            for name, definition in agents.items()
            if name not in CHALLENGE_NAMES
        }

        search = StateSpaceSearch(
            engagement=self.engagement,
            kb=self.kb,
            audit=self.audit,
            budget=self.budget,
            killswitch=self.killswitch,
            book=self.book,
            mcp_servers=self._servers,
            lead_prompt=f"{self.context}\n\n{ORCHESTRATOR_PROMPT}",
            specialist_prompts=specialist_prompts,
            specialist_tools=specialist_tools,
            # The lead reads shared state and decides; it never touches a target.
            lead_tools=ANALYSIS_TOOLS,
            on_event=lambda event, payload: self._emit(event, payload),
            max_rounds=self.config.max_search_rounds,
            max_parallel=self.config.max_parallel_agents,
        )

        rounds = await search.run()
        self.audit.record(
            "search.finished",
            rounds=len(rounds),
            actions=sum(len(r.actions) for r in rounds),
            productive_rounds=sum(1 for r in rounds if r.productive),
        )
        self._emit("search.finished", {
            "rounds": len(rounds),
            "actions": sum(len(r.actions) for r in rounds),
        })

    async def _debate(self) -> list[Outcome]:
        """The challenge round. Runs in code so it cannot be skipped."""
        proposed = self.kb.findings("proposed")
        self._emit("phase", {"name": "review", "findings": len(proposed)})
        if not proposed:
            return []

        specialist_prompts = {
            name: definition.prompt
            for name, definition in self._agents().items()
            if name in SPECIALIST_NAMES
        }

        engine = DebateEngine(
            kb=self.kb,
            audit=self.audit,
            budget=self.budget,
            mcp_servers=self._servers,
            allowed_tools=ANALYSIS_TOOLS,
            context=self.context,
            specialist_prompts=specialist_prompts,
            on_event=self._emit,
        )

        outcomes: list[Outcome] = []
        for finding in proposed:
            try:
                self.budget.check()
            except BudgetExceeded:
                self._emit("review.stopped", {"reason": "budget ceiling reached mid-review"})
                break

            outcome = await engine.run_round(finding["id"], 1)
            if outcome.verdict == "needs_work" and self.config.max_review_rounds > 1:
                outcome = await engine.run_round(finding["id"], 2)
                if outcome.verdict == "needs_work":
                    self.kb.set_status(finding["id"], "theoretical", outcome.confidence)
                    outcome.verdict = "theoretical"

            outcomes.append(outcome)
            self._emit("ruling", {
                "finding_id": outcome.finding_id,
                "verdict": outcome.verdict,
                "severity": outcome.severity or "unrated",
                "confidence": outcome.confidence,
            })

        return outcomes

    def _write_report(self) -> Path | None:
        from .report.builder import ReportBuilder

        self._emit("phase", {"name": "report"})
        try:
            builder = ReportBuilder(
                engagement=self.engagement,
                kb=self.kb,
                audit=self.audit,
                campaign_id=self.campaign_id,
            )
            path = builder.write(self.dir / "report")
        except Exception as exc:  # noqa: BLE001 — a report failure must not lose the findings
            self._emit("report.failed", {"detail": f"{type(exc).__name__}: {exc}"})
            return None
        self._emit("report.written", {"path": str(path)})
        return path

    def close(self) -> None:
        self.kb.close()


def _interval_for(intensity: str) -> float:
    """Minimum delay between command launches, by declared intensity."""
    return {"quiet": 3.0, "normal": 0.5, "aggressive": 0.0}.get(intensity, 0.5)
