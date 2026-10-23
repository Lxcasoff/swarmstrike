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

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
)

from . import engagement as contract
from .agents.roster import SPECIALIST_NAMES, build_agents
from .audit import AuditLog
from .budget import BudgetExceeded, BudgetTracker
from .debate.peer_review import DebateEngine, Outcome
from .engagement import Engagement
from .killswitch import Halted, KillSwitch
from .knowledge import KnowledgeBase
from .models import Role, effort_for, model_for
from .tools.catalog import (
    ANALYSIS_TOOLS,
    KNOWLEDGE_TOOLS,
    TOOLBOX_TOOLS,
    CampaignContext,
    build_knowledge_server,
    build_toolbox_server,
)
from .tools.executor import ContainerPolicy, ToolExecutor

ORCHESTRATOR_PROMPT = """
You lead this penetration testing engagement. You do not run tools against the
target yourself — you decide what gets tested, by whom, and in what order, and
you delegate that work to the specialists available to you.

Run the engagement in waves, and let each wave inform the next:

1. **Map the surface.** Delegate to `recon` first and wait for it. Nothing else
   can be planned sensibly until you know what exists. When it reports back,
   read the knowledge base yourself to see what was found.

2. **Assess in parallel.** Assign the assets that were found to the
   specialists who fit them — web applications to `web`, APIs to `api`, hosts
   and services to `network`, TLS and cryptography to `crypto`, cloud assets
   to `cloud`, directory services to `ad`, accessible source or artefacts to
   `code`. Give each one a specific brief naming the assets it should work and
   what you want answered, not a generic instruction to go and test things.
   Delegate several at once where their work does not overlap.

3. **Follow the leads.** When a specialist reports something that opens a new
   line of enquiry, assign it. A host that recon found and network
   fingerprinted may need `web` next. A finding in one place often means the
   same mistake elsewhere — have it checked.

4. **Decide when it is done.** The engagement is finished when the surface has
   been covered to the depth the budget allows, not when every agent has run
   once. Say so explicitly when you judge it complete, and summarise what was
   covered and what was not.

Keep the budget in mind: it is finite and shared. Two specialists scanning the
same host is waste you are responsible for preventing — that is what the claim
mechanism in the knowledge base is for, and you should tell specialists which
assets are theirs so they do not collide.

You do not rule on findings. Specialists propose them; a separate challenge
round confirms or rejects them after you are done. Do not try to confirm,
reject or re-score a finding yourself, and do not tell a specialist to drop
one — if you think a finding is weak, say so in a note and let the review
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
    def __init__(self, config: CampaignConfig, on_event: EventSink | None = None) -> None:
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

        self.guard = ScopeGuard(self.engagement)
        self.executor = ToolExecutor(
            guard=self.guard,
            audit=self.audit,
            kb=self.kb,
            workspace=self.dir,
            killswitch=self.killswitch,
            policy=ContainerPolicy(image=config.toolbox_image),
            max_concurrent=self.engagement.rules_of_engagement.max_concurrent_tools,
            min_interval_s=_interval_for(self.engagement.rules_of_engagement.intensity),
            on_event=self._emit,
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
            on_event=self._emit,
        )
        self._servers = {
            "toolbox": build_toolbox_server(ctx),
            "knowledge": build_knowledge_server(ctx),
        }

    def _agents(self) -> dict[str, Any]:
        return build_agents(context=self.context, domains=self.config.domains)

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
        """The delegated phase: the lead agent works the target through the team."""
        self._emit("phase", {"name": "assessment"})

        agents = self._agents()
        options = ClaudeAgentOptions(
            system_prompt=f"{self.context}\n\n{ORCHESTRATOR_PROMPT}",
            model=model_for(Role.ORCHESTRATOR),
            effort=effort_for(Role.ORCHESTRATOR),
            agents=agents,
            mcp_servers=self._servers,
            # The lead reads shared state and delegates; it does not touch targets.
            allowed_tools=["Task", *KNOWLEDGE_TOOLS],
            max_budget_usd=self.budget.remaining_usd,
            setting_sources=[],
            max_turns=120,
        )

        roster = ", ".join(self.config.domains or SPECIALIST_NAMES)
        opening = (
            f"Begin the engagement. Your specialists are: {roster}.\n\n"
            f"Start by delegating to `recon` to map the authorized surface, then assign "
            f"the assets it finds to the specialists that fit them. Report what you have "
            f"covered when you judge the assessment complete."
        )

        async with ClaudeSDKClient(options=options) as client:
            await client.query(opening)
            async for message in client.receive_response():
                self.killswitch.check()

                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock) and block.text.strip():
                            self._emit("lead", {"text": block.text})

                elif isinstance(message, ResultMessage):
                    self.budget.record_result(f"lead:{message.session_id}", message)
                    self._emit("spend", {"status": self.budget.status()})
                    if message.is_error:
                        self._emit("lead.error", {
                            "subtype": message.subtype,
                            "detail": message.result or "",
                        })
                    self.budget.check()

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
