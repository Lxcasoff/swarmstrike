"""The three execution tiers.

Everything here tests a refusal that happens before a container is started, so
no Docker daemon is needed. Those refusals are the whole point of the tiers:
the question is not whether a command runs but whether it is allowed to.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from swarmstrike.approval import (
    ApprovalRequest,
    AlwaysAllowGate,
    AutoDenyGate,
    Decision,
    Verdict,
)
from swarmstrike.audit import AuditLog
from swarmstrike.engagement import Engagement
from swarmstrike.killswitch import KillSwitch
from swarmstrike.knowledge import KnowledgeBase
from swarmstrike.scope import ScopeGuard
from swarmstrike.tools.executor import (
    FILTER_BINARIES,
    ContainerPolicy,
    ExecutionRefused,
    ToolExecutor,
)

BASE = {
    "engagement": {
        "id": "ENG-TEST", "client": "C", "mission": "M",
        "authorized_by": {"name": "n", "role": "r", "email": "e",
                          "authorization_ref": "a", "signed_on": "2026-01-01"},
    },
    "window": {"start": "2026-10-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org", "include_subdomains": True}]},
}


class RecordingGate:
    """Captures what it was asked to approve, then refuses."""

    def __init__(self) -> None:
        self.seen: list[ApprovalRequest] = []

    async def request(self, req: ApprovalRequest) -> Verdict:
        self.seen.append(req)
        return Verdict(Decision.DENY, "recorded and refused", "test")


def build(tmp_path: Path, gate=None, **arbitrary):
    doc = dict(BASE)
    if arbitrary:
        doc["rules_of_engagement"] = {"arbitrary_execution": arbitrary}
    engagement = Engagement.model_validate(doc)

    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.open_campaign("CAMP", engagement)
    executor = ToolExecutor(
        guard=ScopeGuard(engagement, resolve=False),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        kb=kb,
        workspace=tmp_path,
        killswitch=KillSwitch(tmp_path),
        policy=ContainerPolicy(image="swarmstrike/toolbox:test"),
        approval=gate or AutoDenyGate(),
        allowed_binaries=frozenset({"nmap", "curl", "httpx"}),
    )
    return executor, engagement


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
#  Tier 1 — structured commands
# ---------------------------------------------------------------------------
def test_structured_refuses_a_binary_outside_the_allowlist(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, structured_commands=True)
    with pytest.raises(ExecutionRefused, match="not an allowlisted binary"):
        run(executor.run_structured("web", "wget", ["https://www.example.org/"]))


def test_structured_refuses_when_the_contract_disables_the_tier(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, structured_commands=False)
    with pytest.raises(ExecutionRefused, match="not_authorized"):
        run(executor.run_structured("web", "nmap", ["www.example.org"]))


def test_structured_still_enforces_scope(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, structured_commands=True)
    with pytest.raises(ExecutionRefused, match="scope"):
        run(executor.run_structured("web", "nmap", ["-sT", "evil.test"]))


# ---------------------------------------------------------------------------
#  Tier 2 — pipelines
# ---------------------------------------------------------------------------
def test_pipeline_refused_unless_the_contract_enables_it(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, pipelines=False)
    with pytest.raises(ExecutionRefused, match="pipelines are not enabled"):
        run(executor.run_pipeline("net", [["nmap", "www.example.org"], ["grep", "open"]]))


def test_pipeline_first_stage_is_scope_checked(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, pipelines=True)
    with pytest.raises(ExecutionRefused, match="scope"):
        run(executor.run_pipeline("net", [["nmap", "evil.test"], ["grep", "open"]]))


@pytest.mark.parametrize("binary", ["sh", "bash", "awk", "sed", "python3", "perl", "xargs"])
def test_an_interpreter_cannot_be_a_later_pipeline_stage(tmp_path: Path, binary: str) -> None:
    # Allowing any of these would turn a pipeline into a shell by another route.
    executor, _ = build(tmp_path, pipelines=True)
    with pytest.raises(ExecutionRefused, match="not_a_filter"):
        run(executor.run_pipeline(
            "net", [["nmap", "www.example.org"], [binary, "-c", "id"]]
        ))


def test_filter_set_excludes_everything_that_can_execute() -> None:
    for binary in ("sh", "bash", "zsh", "awk", "sed", "perl", "python", "python3",
                   "ruby", "xargs", "env", "find", "nc", "curl"):
        assert binary not in FILTER_BINARIES, binary


def test_pipeline_rejects_empty_and_overlong(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, pipelines=True)
    with pytest.raises(ExecutionRefused, match="malformed"):
        run(executor.run_pipeline("net", []))
    with pytest.raises(ExecutionRefused, match="malformed"):
        run(executor.run_pipeline("net", [["nmap", "www.example.org"], []]))
    with pytest.raises(ExecutionRefused, match="at most 6"):
        run(executor.run_pipeline(
            "net", [["nmap", "www.example.org"]] + [["grep", "x"]] * 6
        ))


# ---------------------------------------------------------------------------
#  Tier 3 — shell and scripts
# ---------------------------------------------------------------------------
def test_shell_refused_unless_the_contract_enables_it(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, shell=False)
    with pytest.raises(ExecutionRefused, match="shell execution is not enabled"):
        run(executor.run_unchecked("web", "curl https://www.example.org/"))


def test_scripts_are_a_separate_switch_from_shell(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, shell=True, scripts=False)
    with pytest.raises(ExecutionRefused, match="scripts execution is not enabled"):
        run(executor.run_unchecked("web", "print(1)", interpreter="python3"))


def test_the_default_gate_refuses_so_an_unattended_run_gets_no_shell(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, shell=True)
    with pytest.raises(ExecutionRefused, match="not_approved"):
        run(executor.run_unchecked("web", "curl https://www.example.org/"))


def test_forbidden_commands_are_refused_before_anyone_is_asked(tmp_path: Path) -> None:
    gate = RecordingGate()
    executor, _ = build(tmp_path, shell=True, gate=gate)
    with pytest.raises(ExecutionRefused, match="forbid_destructive"):
        run(executor.run_unchecked("web", "rm -rf / && echo done"))
    assert gate.seen == [], "a destructive command must not even reach the operator"


def test_an_out_of_scope_host_in_the_text_is_refused_before_approval(tmp_path: Path) -> None:
    gate = RecordingGate()
    executor, _ = build(tmp_path, shell=True, gate=gate)
    with pytest.raises(ExecutionRefused, match="scope"):
        run(executor.run_unchecked("web", "curl https://evil.test/ -o /tmp/x"))
    assert gate.seen == []


def test_an_unknown_interpreter_is_refused(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, shell=True, scripts=True)
    with pytest.raises(ExecutionRefused, match="interpreter must be"):
        run(executor.run_unchecked("web", "id", interpreter="perl"))


def test_the_operator_is_told_what_could_not_be_checked(tmp_path: Path) -> None:
    gate = RecordingGate()
    executor, _ = build(tmp_path, shell=True, gate=gate)
    with pytest.raises(ExecutionRefused):
        run(executor.run_unchecked(
            "web", "for i in 1 2 3; do echo $i; done", rationale="loop over ports"
        ))

    assert len(gate.seen) == 1
    request = gate.seen[0]
    assert request.agent == "web"
    assert request.kind == "shell"
    assert request.rationale == "loop over ports"
    joined = " ".join(request.risk_notes)
    # The operator must be told the guarantee is different here, and that no
    # target was visible to check.
    assert "not scope-enforced" in joined
    assert "could not confirm" in joined


def test_an_in_scope_target_in_the_text_is_reported_to_the_operator(tmp_path: Path) -> None:
    gate = RecordingGate()
    executor, _ = build(tmp_path, shell=True, gate=gate)
    with pytest.raises(ExecutionRefused):
        run(executor.run_unchecked("web", "curl https://www.example.org/admin"))
    assert any("in-scope target" in note for note in gate.seen[0].risk_notes)


def test_the_approval_decision_is_written_to_the_audit_chain(tmp_path: Path) -> None:
    gate = RecordingGate()
    executor, _ = build(tmp_path, shell=True, gate=gate)
    with pytest.raises(ExecutionRefused):
        run(executor.run_unchecked("web", "echo probing www.example.org"))

    events = [entry.event for entry in executor.audit.entries()]
    assert "approval.requested" in events
    assert "approval.decided" in events

    intact, reason, _ = executor.audit.verify()
    assert intact, reason


def test_always_allow_gate_is_only_for_labs(tmp_path: Path) -> None:
    # It exists for tests and lab work; this confirms it reports itself clearly
    # so an approval recorded by it is never mistaken for a human decision.
    verdict = run(AlwaysAllowGate().request(
        ApprovalRequest(agent="a", kind="shell", summary="s", detail="id")
    ))
    assert verdict.allowed
    assert verdict.decided_by == "always-allow"


def test_auto_deny_explains_how_to_proceed(tmp_path: Path) -> None:
    verdict = run(AutoDenyGate().request(
        ApprovalRequest(agent="a", kind="shell", summary="s", detail="id")
    ))
    assert not verdict.allowed
    assert "structured command" in verdict.reason


# ---------------------------------------------------------------------------
#  Redaction reaches the record, not just the return value
# ---------------------------------------------------------------------------
def test_a_refused_command_is_logged_without_its_password(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, structured_commands=True)
    secret = "Sup3rSecret!"

    with pytest.raises(ExecutionRefused):
        run(executor.run(
            "ad",
            ["netexec", "-u", "pentest1", "-p", secret, "smb", "evil.test"],
            secrets=[secret],
        ))

    # The audit chain holds the attempt, and must not hold the credential.
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "evil.test" in raw, "the attempt itself must be recorded"
    assert secret not in raw
    assert "«redacted»" in raw

    rows = executor.kb.conn.execute(
        "SELECT argv FROM command_log WHERE campaign_id = 'CAMP'"
    ).fetchall()
    assert rows and secret not in rows[0]["argv"]


def test_the_audit_chain_still_verifies_after_redaction(tmp_path: Path) -> None:
    executor, _ = build(tmp_path, structured_commands=True)
    with pytest.raises(ExecutionRefused):
        run(executor.run("ad", ["netexec", "-p", "hunter2222", "smb", "evil.test"],
                         secrets=["hunter2222"]))
    intact, reason, count = executor.audit.verify()
    assert intact, reason
    assert count >= 1
