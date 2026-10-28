"""The audit chain, and what it does and does not attest to."""

from __future__ import annotations

import json

from swarmstrike.audit import AuditLog


def test_chain_verifies_and_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(3):
        log.record("tool.command", argv=["curl", f"http://host-{index}.test/"])

    intact, reason, count = log.verify()
    assert intact, reason
    assert count == 3

    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["data"]["argv"] = ["curl", "http://somewhere-else.test/"]
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")

    intact, reason, _ = AuditLog(path).verify()
    assert not intact
    assert reason == "entry 1 was modified after it was written"


def test_agent_name_is_recorded_as_a_claim_against_the_roster(tmp_path):
    """The `agent` on a tool call is a string the model fills in — subagent
    identity never reaches the tool server. The entry says whether the name is
    one the campaign actually dispatched, so a reader is not misled into
    treating the field as identity."""
    log = AuditLog(tmp_path / "audit.jsonl", known_agents=("web", "api", "lead"))

    dispatched = log.record("tool.command", agent="web", argv=["curl", "http://a.test/"])
    invented = log.record("tool.command", agent="frontend", argv=["curl", "http://b.test/"])

    assert dispatched.data["agent_on_roster"] is True
    assert invented.data["agent_on_roster"] is False
    assert log.verify()[0]


def test_entries_without_an_agent_are_left_alone(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", known_agents=("web",))
    entry = log.record("campaign.note", detail="no agent on this one")
    assert "agent_on_roster" not in entry.data
