"""The challenge round.

Every proposed finding is examined by a specialist from a different domain,
then attacked by a skeptic whose job is to show it is a false positive, then
ruled on by an arbiter. Only findings the arbiter confirms reach the report
body.

The flow is driven in code rather than delegated, because a debate that only
happens when an orchestrating model remembers to start it is not a control.
Each role is a single constrained call that must return a structured verdict.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from ..agents.roster import ARBITER_PROMPT, SKEPTIC_PROMPT
from ..audit import AuditLog
from ..budget import BudgetTracker
from ..knowledge import KnowledgeBase
from ..models import Role, effort_for, model_for
from ..report.cvss import score_vector

SEVERITIES = ["none", "low", "medium", "high", "critical"]

STANCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["stance", "rationale"],
    "properties": {
        "stance": {
            "type": "string",
            "enum": ["support", "refute", "abstain"],
            "description": "support if the evidence holds, refute if it does not, "
                           "abstain if the evidence given cannot settle it",
        },
        "rationale": {
            "type": "string",
            "description": "Specific reasoning. Name the step in the evidence that does or "
                           "does not support the claim.",
        },
        "evidence_gap": {
            "type": "string",
            "description": "If abstaining, exactly what additional evidence would settle it. "
                           "Empty otherwise.",
        },
    },
}

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "confidence", "rationale", "severity", "cvss_vector"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "rejected", "theoretical", "needs_work"],
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "rationale": {"type": "string"},
        "severity": {"type": "string", "enum": SEVERITIES},
        "cvss_vector": {
            "type": "string",
            "description": "The corrected CVSS v3.1 vector, e.g. "
                           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "needs": {
            "type": "string",
            "description": "If the verdict is needs_work, the one piece of evidence required.",
        },
    },
}


@dataclass
class Outcome:
    finding_id: str
    verdict: str
    confidence: float
    rationale: str
    severity: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    stances: list[tuple[str, str]] = field(default_factory=list)  # (reviewer, stance)

    @property
    def reached_report(self) -> bool:
        return self.verdict in {"confirmed", "theoretical"}


# Which specialist peer-reviews a finding from which domain. A reviewer from a
# different discipline catches what someone inside the discipline assumes.
PEER_MAP: dict[str, str] = {
    "web": "api",
    "api": "web",
    "network": "crypto",
    "crypto": "network",
    "cloud": "network",
    "ad": "network",
    "recon": "network",
    "code": "web",
}
FALLBACK_PEER = "network"


class DebateEngine:
    def __init__(
        self,
        *,
        kb: KnowledgeBase,
        audit: AuditLog,
        budget: BudgetTracker,
        mcp_servers: dict[str, Any],
        allowed_tools: list[str],
        context: str = "",
        model_overrides: dict[str, str] | None = None,
        effort_overrides: dict[str, str] | None = None,
        specialist_prompts: dict[str, str] | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.kb = kb
        self.audit = audit
        self.budget = budget
        self.mcp_servers = mcp_servers
        self.allowed_tools = allowed_tools
        self.context = context
        self.model_overrides = model_overrides or {}
        self.effort_overrides = effort_overrides or {}
        self.specialist_prompts = specialist_prompts or {}
        self.on_event = on_event

    def _emit(self, kind: str, **payload: Any) -> None:
        if self.on_event is not None:
            self.on_event(kind, payload)

    # ------------------------------------------------------------------
    async def _ask(
        self,
        *,
        label: str,
        system_prompt: str,
        role: Role,
        prompt: str,
        schema: dict[str, Any],
    ) -> dict[str, Any] | None:
        """One constrained call that must come back with a structured verdict."""
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model_for(role, self.model_overrides),
            effort=effort_for(role, self.effort_overrides),
            mcp_servers=self.mcp_servers,
            allowed_tools=self.allowed_tools,
            output_format={"type": "json_schema", "schema": schema},
            setting_sources=[],
            max_turns=12,
        )

        self._emit("agent.review.start", agent=label)

        payload: dict[str, Any] | None = None
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                self.budget.record_result(f"{label}:{message.session_id}", message)
                payload = _read_structured(message)

        self._emit(
            "agent.review.end",
            agent=label,
            stance=(payload or {}).get("stance") or (payload or {}).get("verdict") or "no reply",
        )
        return payload

    # ------------------------------------------------------------------
    def _brief(self, finding: dict[str, Any]) -> str:
        evidence = self.kb.evidence_for(finding["id"])
        rendered = "\n\n".join(
            f"### Evidence {n}: {item['label'] or item['kind']}\n```\n{item['content'][:8000]}\n```"
            for n, item in enumerate(evidence, start=1)
        ) or "_No evidence was attached to this finding._"

        return f"""## Finding {finding['id']}: {finding['title']}

| | |
|---|---|
| Domain | {finding['domain']} |
| Affected asset | {finding['asset']} |
| Submitted by | {finding['discovered_by']} |
| Claimed severity | {finding['severity'] or 'unrated'} |
| Claimed CVSS vector | {finding['cvss_vector'] or 'none supplied'} |

**Summary.** {finding['summary']}

**Description.** {finding['description'] or '_none given_'}

**Claimed impact.** {finding['impact'] or '_none given_'}

**Proposed remediation.** {finding['remediation'] or '_none given_'}

## Evidence as submitted

{rendered}
"""

    async def run_round(self, finding_id: str, round_: int = 1) -> Outcome:
        finding = self.kb.finding(finding_id)
        if finding is None:
            raise ValueError(f"no finding {finding_id}")

        self.kb.set_status(finding_id, "under_review")
        brief = self._brief(finding)
        stances: list[tuple[str, str]] = []

        # -- 1. Peer review, by a specialist from a neighbouring domain -----
        peer_name = PEER_MAP.get(finding["domain"], FALLBACK_PEER)
        peer_prompt = self.specialist_prompts.get(peer_name)
        if peer_prompt:
            peer = await self._ask(
                label=f"peer:{peer_name}",
                system_prompt=peer_prompt,
                role=Role.SPECIALIST,
                schema=STANCE_SCHEMA,
                prompt=(
                    f"A colleague on the {finding['domain']} side submitted the finding below. "
                    f"Review it from your own discipline. You may read the campaign knowledge "
                    f"base, but do not run tools against the target.\n\n{brief}"
                ),
            )
            if peer:
                stance = peer.get("stance", "abstain")
                self.kb.add_review(
                    finding_id, f"peer:{peer_name}", stance,
                    peer.get("rationale", ""), round_,
                )
                stances.append((f"peer:{peer_name}", stance))

        # -- 2. The skeptic tries to take it apart --------------------------
        skeptic = await self._ask(
            label="skeptic",
            system_prompt=f"{self.context}\n\n{SKEPTIC_PROMPT}",
            role=Role.SKEPTIC,
            schema=STANCE_SCHEMA,
            prompt=(
                f"Try to establish that the finding below is a false positive, an "
                f"overstatement, or a duplicate. Read the evidence closely and decide "
                f"whether it supports the claim or merely accompanies it.\n\n{brief}"
            ),
        )
        if skeptic:
            stance = skeptic.get("stance", "abstain")
            rationale = skeptic.get("rationale", "")
            gap = skeptic.get("evidence_gap", "")
            self.kb.add_review(
                finding_id, "skeptic", stance,
                f"{rationale}\n\nEvidence that would settle it: {gap}" if gap else rationale,
                round_,
            )
            stances.append(("skeptic", stance))
        else:
            # Without a skeptic verdict the finding has not been challenged, and
            # an unchallenged finding must not be presented as confirmed.
            self.kb.add_review(
                finding_id, "skeptic", "abstain",
                "The skeptic returned no structured verdict; the finding was not challenged.",
                round_,
            )
            stances.append(("skeptic", "abstain"))

        # -- 3. The arbiter rules -------------------------------------------
        debate = "\n\n".join(
            f"**{r['reviewer']} — {r['stance']}**\n{r['rationale']}"
            for r in self.kb.reviews_for(finding_id)
            if r["round"] == round_
        ) or "_No reviews were returned._"

        ruling = await self._ask(
            label="arbiter",
            system_prompt=f"{self.context}\n\n{ARBITER_PROMPT}",
            role=Role.ARBITER,
            schema=VERDICT_SCHEMA,
            prompt=(
                f"Rule on this finding. Set the severity and CVSS vector you believe are "
                f"correct, not the ones that were claimed.\n\n{brief}\n\n"
                f"## Review round {round_}\n\n{debate}"
            ),
        )

        if ruling is None:
            # No ruling means no confirmation. Hold it as theoretical rather than
            # letting an unadjudicated finding through either way.
            outcome = Outcome(
                finding_id=finding_id,
                verdict="theoretical",
                confidence=0.0,
                rationale="The arbiter returned no verdict, so the finding was not confirmed.",
                stances=stances,
            )
        else:
            vector = (ruling.get("cvss_vector") or "").strip() or None
            score, derived = score_vector(vector)
            outcome = Outcome(
                finding_id=finding_id,
                verdict=ruling.get("verdict", "theoretical"),
                confidence=float(ruling.get("confidence", 0.0)),
                rationale=ruling.get("rationale", ""),
                severity=(ruling.get("severity") or derived or None),
                cvss_vector=vector,
                cvss_score=score,
                stances=stances,
            )

        self.kb.add_arbitration(
            finding_id, "arbiter", outcome.verdict, outcome.confidence,
            outcome.rationale, round_,
        )
        if outcome.cvss_vector:
            self.kb.update_finding(
                finding_id,
                cvss_vector=outcome.cvss_vector,
                cvss_score=outcome.cvss_score,
                severity=outcome.severity,
            )

        self.audit.record(
            "debate.ruling",
            finding_id=finding_id,
            round=round_,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            severity=outcome.severity,
            stances=dict(stances),
        )
        return outcome

    # ------------------------------------------------------------------
    async def review_all(self, max_rounds: int = 2) -> list[Outcome]:
        """Run the challenge round over every proposed finding."""
        outcomes: list[Outcome] = []

        for finding in self.kb.findings("proposed"):
            finding_id = finding["id"]
            outcome: Outcome | None = None

            for round_ in range(1, max_rounds + 1):
                self.budget.check()
                outcome = await self.run_round(finding_id, round_)
                if outcome.verdict != "needs_work":
                    break
                # needs_work gives the finding one more pass with the gap named;
                # if it is still unresolved on the last round, it stays theoretical.
                if round_ == max_rounds:
                    self.kb.add_arbitration(
                        finding_id, "arbiter", "theoretical", outcome.confidence,
                        "Still unresolved after the final review round: "
                        + outcome.rationale,
                        round_,
                    )
                    outcome.verdict = "theoretical"

            if outcome is not None:
                outcomes.append(outcome)

        return outcomes


def _read_structured(message: ResultMessage) -> dict[str, Any] | None:
    """Pull the structured verdict out of a result, tolerating a plain-text reply."""
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
