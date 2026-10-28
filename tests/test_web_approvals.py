"""The dashboard's approval endpoints.

The gate's semantics are covered in test_approval.py; this covers the HTTP
surface an operator's click actually goes through, including the case where
they click on something that is no longer waiting.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")

from swarmstrike.approval import ApprovalRequest, Decision, QueueApprovalGate  # noqa: E402
from swarmstrike.web.server import Session, create_app  # noqa: E402


def make_app(gate: QueueApprovalGate):
    """An app with one session injected, so no campaign has to be started."""
    app = create_app()
    dashboard = None
    for route in app.routes:
        closure = getattr(getattr(route, "endpoint", None), "__closure__", None) or ()
        for cell in closure:
            if type(cell.cell_contents).__name__ == "Dashboard":
                dashboard = cell.cell_contents
                break
        if dashboard:
            break
    assert dashboard is not None, "could not reach the Dashboard instance"

    session = Session(id="s1", campaign=SimpleNamespace(), gate=gate)
    dashboard.sessions["s1"] = session
    return app, session


def test_pending_requests_are_listed(tmp_path) -> None:
    gate = QueueApprovalGate(timeout_s=30)
    app, _ = make_app(gate)

    pending = ApprovalRequest(agent="web", kind="shell", summary="a loop",
                              detail="for i in 1 2; do echo $i; done",
                              rationale="three ports at once",
                              risk_notes=["not scope-enforced"])

    # Park a request on the gate from a background loop, as the executor does.
    loop = asyncio.new_event_loop()
    verdicts: list[object] = []

    def park() -> None:
        asyncio.set_event_loop(loop)
        verdicts.append(loop.run_until_complete(gate.request(pending)))

    thread = threading.Thread(target=park, daemon=True)
    thread.start()
    for _ in range(50):
        if gate.pending():
            break
        time.sleep(0.02)

    with fastapi_testclient.TestClient(app) as client:
        body = client.get("/api/campaigns/s1/approvals").json()
        assert [r["id"] for r in body["pending"]] == [pending.id]
        assert body["pending"][0]["rationale"] == "three ports at once"
        assert body["timeout_s"] == 30

        accepted = client.post(
            f"/api/campaigns/s1/approvals/{pending.id}",
            json={"decision": "allow", "reason": "checked the hosts"},
        )
        assert accepted.status_code == 200
        assert accepted.json()["decision"] == "allow"

    thread.join(timeout=3)
    assert verdicts and verdicts[0].allowed
    assert verdicts[0].reason == "checked the hosts"
    # The decision is attributed to the dashboard, not to a named person.
    assert verdicts[0].decided_by == "operator (dashboard)"
    loop.close()


def test_a_bad_decision_value_is_rejected() -> None:
    app, _ = make_app(QueueApprovalGate())
    with fastapi_testclient.TestClient(app) as client:
        res = client.post("/api/campaigns/s1/approvals/whatever",
                          json={"decision": "probably"})
        assert res.status_code == 400


def test_deciding_something_no_longer_waiting_conflicts() -> None:
    # The operator's browser may be showing a card that already timed out.
    app, _ = make_app(QueueApprovalGate())
    with fastapi_testclient.TestClient(app) as client:
        res = client.post("/api/campaigns/s1/approvals/gone", json={"decision": "allow"})
        assert res.status_code == 409
        assert "no longer waiting" in res.json()["detail"]


def test_an_unknown_session_is_not_found() -> None:
    app, _ = make_app(QueueApprovalGate())
    with fastapi_testclient.TestClient(app) as client:
        assert client.get("/api/campaigns/nope/approvals").status_code == 404


def test_approval_events_mark_the_agent_as_waiting() -> None:
    _, session = make_app(QueueApprovalGate())
    session.agents["web"] = {"agent": "web", "state": "working", "detail": "",
                             "tools": 0, "findings": 0, "assets": 0, "refusals": 0}

    session.record("approval.requested", {"agent": "web", "summary": "a loop"})
    assert session.agents["web"]["state"] == "waiting"

    session.record("approval.decided", {"agent": "web", "decision": "deny",
                                        "reason": "use run_command"})
    assert session.agents["web"]["state"] == "blocked"
    assert "use run_command" in session.agents["web"]["detail"]

    session.record("approval.decided", {"agent": "web", "decision": "allow", "reason": ""})
    assert session.agents["web"]["state"] == "working"
