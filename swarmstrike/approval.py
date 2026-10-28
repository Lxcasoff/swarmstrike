"""Human approval for actions that cannot be statically checked.

Most of what the swarm does is validated before it runs: a recipe's parameters
are typed, its argument vector is built rather than written, and the scope
guard reads the targets out of it. A shell command defeats all of that — `;`,
`$(...)` and `|` mean one approved-looking string can run anything — so for
those cases the control is a person instead.

This module is that control. It is deliberately deny-by-default: an unattended
campaign reaches `AutoDenyGate`, which refuses and says why, rather than
granting itself permission because nobody was watching.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from zoneinfo import ZoneInfo


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class ApprovalRequest:
    """One action awaiting a human decision."""

    agent: str
    kind: str                 # shell | script | binary | pipeline
    summary: str              # one line, for the operator's list
    detail: str               # the exact command or script that would run
    rationale: str = ""       # why the agent says it needs this
    risk_notes: list[str] = field(default_factory=list)  # what static checks flagged
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(
        default_factory=lambda: datetime.now(tz=ZoneInfo("UTC")).isoformat()
    )

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "agent": self.agent,
            "kind": self.kind,
            "summary": self.summary,
            "detail": self.detail,
            "rationale": self.rationale,
            "risk_notes": self.risk_notes,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str = ""
    decided_by: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


class ApprovalGate(Protocol):
    """Where an unvalidatable action goes to be decided."""

    async def request(self, req: ApprovalRequest) -> Verdict: ...


class AutoDenyGate:
    """The default. Refuses, and explains how to get a real decision.

    This is what an unattended run gets. It matters that the default is this
    and not an allow: a campaign that approves its own shell commands because
    no operator was connected has no approval control at all, only the
    appearance of one.
    """

    async def request(self, req: ApprovalRequest) -> Verdict:
        return Verdict(
            Decision.DENY,
            "no operator is attached to this campaign, and swarmstrike does not "
            "approve its own shell access. Run with --tui or the dashboard open, "
            "or use a structured command, which needs no approval.",
            decided_by="auto-deny",
        )


class AlwaysAllowGate:
    """For tests and lab work only. Never use this against a client system."""

    def __init__(self, reason: str = "approval gate disabled") -> None:
        self.reason = reason

    async def request(self, req: ApprovalRequest) -> Verdict:
        return Verdict(Decision.ALLOW, self.reason, decided_by="always-allow")


class QueueApprovalGate:
    """Holds requests until an operator decides, with a timeout.

    Used by the dashboard and the live terminal view: `pending` is what the
    operator sees, `resolve` is what their click calls, and `request` is what
    the agent's tool call awaits.
    """

    def __init__(self, timeout_s: float = 300.0) -> None:
        self.timeout_s = timeout_s
        # The loop is stored with the future because the decision may arrive on
        # a different thread from the one the agent is waiting on. Completing a
        # future from another thread does not wake its loop, so the agent would
        # hang until the timeout — which looks exactly like an operator who
        # never answered.
        self._waiting: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Future[Verdict]]] = {}
        self._requests: dict[str, ApprovalRequest] = {}
        self._decided: list[tuple[ApprovalRequest, Verdict]] = []
        self.on_request: list[object] = []   # callables, notified on arrival

    # ------------------------------------------------------------------
    def pending(self) -> list[ApprovalRequest]:
        return [self._requests[k] for k in self._requests]

    def resolve(self, request_id: str, decision: Decision, reason: str = "",
                decided_by: str = "operator") -> bool:
        """Record a decision. False if it was already decided or has gone.

        Safe to call from any thread.
        """
        entry = self._waiting.pop(request_id, None)
        req = self._requests.pop(request_id, None)
        if entry is None:
            return False

        loop, future = entry
        if future.done():
            return False

        verdict = Verdict(decision, reason, decided_by)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is loop:
            future.set_result(verdict)
        else:
            try:
                loop.call_soon_threadsafe(future.set_result, verdict)
            except RuntimeError:
                # The waiting loop has closed; nothing is listening any more.
                return False

        if req is not None:
            self._decided.append((req, verdict))
        return True

    def history(self) -> list[tuple[ApprovalRequest, Verdict]]:
        return list(self._decided)

    # ------------------------------------------------------------------
    async def request(self, req: ApprovalRequest) -> Verdict:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Verdict] = loop.create_future()
        self._waiting[req.id] = (loop, future)
        self._requests[req.id] = req

        for notify in self.on_request:
            try:
                notify(req)  # type: ignore[operator]
            except Exception:  # noqa: BLE001 — a broken listener must not block the gate
                pass

        try:
            return await asyncio.wait_for(future, timeout=self.timeout_s)
        except asyncio.TimeoutError:
            self._waiting.pop(req.id, None)
            self._requests.pop(req.id, None)
            verdict = Verdict(
                Decision.DENY,
                f"no decision within {self.timeout_s:.0f}s, so it was refused. "
                f"An action nobody approved does not run.",
                decided_by="timeout",
            )
            self._decided.append((req, verdict))
            return verdict


class ConsoleApprovalGate:
    """Prompts on the terminal. For `swarmstrike run` without the live view."""

    def __init__(self, timeout_s: float = 300.0) -> None:
        self.timeout_s = timeout_s

    async def request(self, req: ApprovalRequest) -> Verdict:
        banner = [
            "",
            "┌─ approval required " + "─" * 50,
            f"│ agent   {req.agent}",
            f"│ kind    {req.kind}",
            f"│ why     {req.rationale or '(none given)'}",
            "│",
            "│ would run:",
        ]
        banner += [f"│   {line}" for line in req.detail.splitlines()[:30]]
        if req.risk_notes:
            banner.append("│")
            banner.append("│ static checks flagged:")
            banner += [f"│   - {note}" for note in req.risk_notes]
        banner += ["└" + "─" * 70, ""]
        print("\n".join(banner), flush=True)

        loop = asyncio.get_running_loop()
        try:
            answer = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: input("allow this? [y/N] ").strip().lower()),
                timeout=self.timeout_s,
            )
        except (asyncio.TimeoutError, EOFError, OSError):
            return Verdict(
                Decision.DENY,
                f"no answer within {self.timeout_s:.0f}s", decided_by="timeout",
            )

        if answer in {"y", "yes"}:
            return Verdict(Decision.ALLOW, "approved at the console", "operator")
        return Verdict(Decision.DENY, "refused at the console", "operator")
