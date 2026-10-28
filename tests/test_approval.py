"""The approval gate.

This is the control that makes the shell tier acceptable, so its semantics
matter more than its convenience: an action nobody decided on must not run,
and a decision must not be able to arrive twice.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from swarmstrike.approval import (
    ApprovalRequest,
    AutoDenyGate,
    ConsoleApprovalGate,
    Decision,
    QueueApprovalGate,
)


def req(agent: str = "web", detail: str = "id") -> ApprovalRequest:
    return ApprovalRequest(agent=agent, kind="shell", summary=f"{agent}: {detail}",
                           detail=detail, rationale="because")


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
#  Deny by default
# ---------------------------------------------------------------------------
def test_unattended_runs_are_refused_not_granted() -> None:
    verdict = run(AutoDenyGate().request(req()))
    assert not verdict.allowed
    assert verdict.decided_by == "auto-deny"
    # And it has to say how to proceed, or the agent just retries.
    assert "structured command" in verdict.reason


def test_request_ids_are_distinct() -> None:
    assert req().id != req().id


# ---------------------------------------------------------------------------
#  Queue semantics
# ---------------------------------------------------------------------------
def test_a_waiting_request_is_visible_then_resolved() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=5)
        pending = req("ad", "nxc smb 10.0.0.5")
        task = asyncio.create_task(gate.request(pending))

        await asyncio.sleep(0.05)
        assert [r.id for r in gate.pending()] == [pending.id]

        assert gate.resolve(pending.id, Decision.ALLOW, "looks fine")
        verdict = await task

        assert verdict.allowed
        assert verdict.reason == "looks fine"
        assert verdict.decided_by == "operator"
        assert gate.pending() == []

    run(scenario())


def test_a_denial_carries_its_reason() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=5)
        pending = req()
        task = asyncio.create_task(gate.request(pending))
        await asyncio.sleep(0.05)
        gate.resolve(pending.id, Decision.DENY, "use run_command instead")

        verdict = await task
        assert not verdict.allowed
        assert "run_command" in verdict.reason

    run(scenario())


def test_a_request_cannot_be_decided_twice() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=5)
        pending = req()
        task = asyncio.create_task(gate.request(pending))
        await asyncio.sleep(0.05)

        assert gate.resolve(pending.id, Decision.ALLOW)
        # A second decision must not land: the action already ran.
        assert not gate.resolve(pending.id, Decision.DENY)
        assert (await task).allowed

    run(scenario())


def test_resolving_something_unknown_is_rejected() -> None:
    gate = QueueApprovalGate()
    assert not gate.resolve("nonexistent", Decision.ALLOW)


def test_timing_out_refuses_rather_than_hanging() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=0.15)
        verdict = await gate.request(req())
        assert not verdict.allowed
        assert verdict.decided_by == "timeout"
        assert "does not run" in verdict.reason
        assert gate.pending() == []

    run(scenario())


def test_each_request_is_independent() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=5)
        first, second = req("web", "a"), req("ad", "b")
        t1 = asyncio.create_task(gate.request(first))
        t2 = asyncio.create_task(gate.request(second))
        await asyncio.sleep(0.05)
        assert len(gate.pending()) == 2

        # Deciding one must not release the other.
        gate.resolve(first.id, Decision.ALLOW)
        await asyncio.sleep(0.05)
        assert [r.id for r in gate.pending()] == [second.id]

        gate.resolve(second.id, Decision.DENY)
        assert (await t1).allowed
        assert not (await t2).allowed

    run(scenario())


def test_history_records_both_outcomes_and_timeouts() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=0.15)
        allowed, refused = req("web", "a"), req("ad", "b")

        t1 = asyncio.create_task(gate.request(allowed))
        await asyncio.sleep(0.02)
        gate.resolve(allowed.id, Decision.ALLOW, "ok")
        await t1

        await gate.request(refused)  # times out

        outcomes = {r.id: v for r, v in gate.history()}
        assert outcomes[allowed.id].allowed
        assert not outcomes[refused.id].allowed
        assert outcomes[refused.id].decided_by == "timeout"

    run(scenario())


def test_listeners_are_notified_and_a_broken_one_does_not_block() -> None:
    async def scenario() -> None:
        gate = QueueApprovalGate(timeout_s=5)
        seen: list[str] = []
        gate.on_request.append(lambda r: (_ for _ in ()).throw(RuntimeError("boom")))
        gate.on_request.append(lambda r: seen.append(r.id))

        pending = req()
        task = asyncio.create_task(gate.request(pending))
        await asyncio.sleep(0.05)

        # The first listener raised; the second still ran and the gate works.
        assert seen == [pending.id]
        gate.resolve(pending.id, Decision.ALLOW)
        assert (await task).allowed

    run(scenario())


def test_a_decision_from_another_thread_still_wakes_the_waiter() -> None:
    """The web endpoint may run on a different thread from the agent.

    Completing a future from another thread does not wake its loop, so without
    the thread-safe path the agent hangs until the timeout — which is
    indistinguishable from an operator who never answered.
    """
    import threading

    gate = QueueApprovalGate(timeout_s=10)
    pending = req()
    verdicts: list[object] = []
    loop = asyncio.new_event_loop()

    def wait_on_another_thread() -> None:
        asyncio.set_event_loop(loop)
        verdicts.append(loop.run_until_complete(gate.request(pending)))

    waiter = threading.Thread(target=wait_on_another_thread, daemon=True)
    waiter.start()
    for _ in range(100):
        if gate.pending():
            break
        time.sleep(0.01)

    # Decide from the main thread, which is not the loop the agent waits on.
    assert gate.resolve(pending.id, Decision.ALLOW, "from elsewhere")

    waiter.join(timeout=3)
    assert verdicts, "the waiting agent was never released"
    assert verdicts[0].allowed
    assert verdicts[0].reason == "from elsewhere"
    loop.close()


# ---------------------------------------------------------------------------
#  Console gate
# ---------------------------------------------------------------------------
def test_console_gate_refuses_without_a_terminal() -> None:
    # Under pytest stdin is not a terminal, which is the same situation as a
    # campaign running detached: it must refuse rather than block forever.
    verdict = run(ConsoleApprovalGate(timeout_s=1).request(req()))
    assert not verdict.allowed


@pytest.mark.parametrize(("answer", "allowed"),
                         [("y", True), ("yes", True), ("n", False), ("", False),
                          ("maybe", False)])
def test_console_gate_only_a_clear_yes_allows(monkeypatch, answer: str, allowed: bool) -> None:
    monkeypatch.setattr("builtins.input", lambda *_: answer)
    verdict = run(ConsoleApprovalGate(timeout_s=5).request(req()))
    assert verdict.allowed is allowed
