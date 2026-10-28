"""The live view's approval screen.

Textual owns stdin, so the console gate cannot be used under `--tui`. Without
this screen the shell tier is simply unavailable in the live view, which is the
mode an operator is most likely to be watching from.
"""

from __future__ import annotations

import asyncio

import pytest

textual = pytest.importorskip("textual")

from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Input  # noqa: E402

from swarmstrike.approval import (  # noqa: E402
    ApprovalRequest,
    Decision,
    QueueApprovalGate,
)
from swarmstrike.tui.app import ApprovalScreen  # noqa: E402


def request() -> ApprovalRequest:
    return ApprovalRequest(
        agent="web",
        kind="shell",
        summary="web wants to run sh",
        detail="for p in 8080 8443; do curl -sS https://admin.example.org:$p/; done",
        rationale="three ports need the same probe, compared side by side",
        risk_notes=[
            "names in-scope target admin.example.org",
            "a shell command cannot be checked statically: this runs contained, "
            "approved and logged, not scope-enforced",
        ],
    )


class Host(App[None]):
    """Minimal host so the screen can be driven on its own."""

    def __init__(self, req: ApprovalRequest) -> None:
        super().__init__()
        self.req = req
        self.result: tuple[Decision, str] | None = None

    def compose(self) -> ComposeResult:
        return iter(())

    def open_screen(self) -> None:
        self.push_screen(ApprovalScreen(self.req, timeout_s=30), self._done)

    def _done(self, result: tuple[Decision, str] | None) -> None:
        self.result = result


async def drive(keys: list[str], typed: str | None = None):
    app = Host(request())
    async with app.run_test() as pilot:
        app.open_screen()
        await pilot.pause()

        if typed is not None:
            app.screen.query_one("#reason", Input).value = typed
            await pilot.pause()

        for key in keys:
            await pilot.press(key)
        await pilot.pause()
    return app.result


# ---------------------------------------------------------------------------
def test_the_screen_shows_the_command_and_what_was_not_checked() -> None:
    async def scenario():
        app = Host(request())
        async with app.run_test() as pilot:
            app.open_screen()
            await pilot.pause()

            def shown(selector: str) -> str:
                return str(app.screen.query_one(selector).render())

            assert "curl -sS https://admin.example.org" in shown("#script")
            assert "not scope-enforced" in shown("#notes")
            assert "audit chain" in shown("#guarantee")
            assert "three ports need the same probe" in shown("#why")

    asyncio.run(scenario())


def test_pressing_a_allows() -> None:
    decision, reason = asyncio.run(drive(["a"]))
    assert decision is Decision.ALLOW
    assert reason == "approved in the live view"


def test_pressing_d_denies() -> None:
    decision, _ = asyncio.run(drive(["d"]))
    assert decision is Decision.DENY


def test_escape_denies_rather_than_dismissing() -> None:
    # An approval screen that can be dismissed without an answer would leave
    # the agent blocked with nothing recorded.
    decision, _ = asyncio.run(drive(["escape"]))
    assert decision is Decision.DENY


def test_a_typed_reason_is_carried_into_the_verdict() -> None:
    decision, reason = asyncio.run(drive(["a"], typed="checked the hosts myself"))
    assert decision is Decision.ALLOW
    assert reason == "checked the hosts myself"


def test_the_screen_resolves_the_gate_so_the_agent_continues() -> None:
    """The whole point: the waiting agent is released by the operator's key."""

    async def scenario():
        gate = QueueApprovalGate(timeout_s=10)
        pending = request()
        waiting = asyncio.create_task(gate.request(pending))

        for _ in range(100):
            if gate.pending():
                break
            await asyncio.sleep(0.01)

        app = Host(pending)

        def decided(result):
            decision, reason = result
            gate.resolve(pending.id, decision, reason, decided_by="operator (live view)")

        async with app.run_test() as pilot:
            app.push_screen(ApprovalScreen(pending, timeout_s=10), decided)
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()

        verdict = await asyncio.wait_for(waiting, timeout=5)
        assert verdict.allowed
        assert verdict.decided_by == "operator (live view)"

    asyncio.run(scenario())
