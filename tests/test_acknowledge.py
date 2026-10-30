"""Operator rulings on halts.

An agent that halts is judging what it found, and the thing it found is still
there: clear HALT, resume, and the next agent reaches the same endpoint and
halts again. The live lab campaign did exactly that twice. These tests pin down
the way past it, and the marks it has to leave — an override of the strongest
guardrail in the tool that nobody can see afterwards would be worse than no
override at all.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from swarmstrike.acknowledge import (
    RULINGS_FILENAME,
    RulingError,
    covering,
    load,
    record,
)

HALT_REASON = (
    "Unauthenticated GET http://172.31.77.10:3000/rest/memories returns embedded "
    "User records for other accounts (emails, MD5 password hashes, roles)."
)


def test_a_ruling_lets_the_condition_through(tmp_path) -> None:
    record(
        tmp_path,
        pattern="/rest/memories",
        ruling="Stock Juice Shop seed data on a lab target the operator owns.",
        operator="Lucas Offredi",
    )
    found = covering(tmp_path, HALT_REASON)
    assert found is not None
    assert found.operator == "Lucas Offredi"


def test_a_ruling_does_not_cover_a_different_condition(tmp_path) -> None:
    record(
        tmp_path,
        pattern="/rest/memories",
        ruling="Seed data, acceptable.",
        operator="Lucas Offredi",
    )
    assert covering(tmp_path, "172.31.77.11 stopped responding after the last request") is None


def test_a_short_pattern_is_refused(tmp_path) -> None:
    """Matching is by substring, so "data" would overrule every halt that
    mentions exposed data — a blanket disabling of the guardrail dressed up as
    a ruling on one condition."""
    with pytest.raises(RulingError, match="at least"):
        record(tmp_path, pattern="data", ruling="fine", operator="Lucas Offredi")
    assert load(tmp_path) == []


def test_a_ruling_needs_a_decision_and_a_name(tmp_path) -> None:
    with pytest.raises(RulingError, match="your own words"):
        record(tmp_path, pattern="/rest/memories", ruling="   ", operator="Lucas")
    with pytest.raises(RulingError, match="name of the person"):
        record(tmp_path, pattern="/rest/memories", ruling="Acceptable.", operator=" ")


def test_matching_ignores_case(tmp_path) -> None:
    record(
        tmp_path,
        pattern="/REST/Memories",
        ruling="Seed data.",
        operator="Lucas Offredi",
    )
    assert covering(tmp_path, HALT_REASON) is not None


def test_re_ruling_the_same_condition_replaces_it(tmp_path) -> None:
    record(tmp_path, pattern="/rest/memories", ruling="First call.", operator="Lucas")
    record(tmp_path, pattern="/rest/memories", ruling="Second call.", operator="Lucas")

    rulings = load(tmp_path)
    assert len(rulings) == 1
    assert rulings[0].ruling == "Second call."


def test_rulings_accumulate_across_conditions(tmp_path) -> None:
    record(tmp_path, pattern="/rest/memories", ruling="Seed data.", operator="Lucas")
    record(tmp_path, pattern="/api/Feedbacks comment", ruling="Seed data.", operator="Lucas")
    assert len(load(tmp_path)) == 2


def test_no_rulings_file_means_nothing_is_overruled(tmp_path) -> None:
    assert load(tmp_path) == []
    assert covering(tmp_path, HALT_REASON) is None


def test_a_corrupt_rulings_file_overrules_nothing(tmp_path) -> None:
    """Fail closed: an unreadable file must not be read as blanket permission."""
    (tmp_path / RULINGS_FILENAME).write_text("{ not json")
    assert load(tmp_path) == []
    assert covering(tmp_path, HALT_REASON) is None


def test_entries_missing_fields_are_skipped_not_guessed(tmp_path) -> None:
    (tmp_path / RULINGS_FILENAME).write_text(
        json.dumps([
            {"pattern": "/rest/memories"},
            {"pattern": "/api/Feedbacks comment", "ruling": "Seed.", "operator": "Lucas"},
        ])
    )
    assert [r.pattern for r in load(tmp_path)] == ["/api/Feedbacks comment"]


# ---------------------------------------------------------------------------
#  The halt tool itself
# ---------------------------------------------------------------------------
def _context(tmp_path):
    """A campaign context just complete enough to call halt_campaign."""
    from swarmstrike.audit import AuditLog
    from swarmstrike.engagement import Engagement
    from swarmstrike.killswitch import KillSwitch
    from swarmstrike.knowledge import KnowledgeBase
    from swarmstrike.scope import ScopeGuard
    from swarmstrike.tools.catalog import CampaignContext
    from swarmstrike.tools.executor import ToolExecutor

    engagement = Engagement.model_validate({
        "engagement": {"id": "E", "client": "Acme", "mission": "M",
                       "authorized_by": {"name": "n", "role": "r", "email": "e",
                                         "authorization_ref": "a",
                                         "signed_on": "2026-01-01"}},
        "window": {"start": "2026-01-01T00:00:00+00:00",
                   "end": "2030-01-01T00:00:00+00:00"},
        "scope": {"domains": [{"name": "example.org"}]},
    })
    kb = KnowledgeBase(tmp_path / "knowledge.sqlite")
    kb.open_campaign("C", engagement)
    audit = AuditLog(tmp_path / "audit.jsonl")
    killswitch = KillSwitch(tmp_path)
    executor = ToolExecutor(
        guard=ScopeGuard(engagement, resolve=False),
        audit=audit,
        kb=kb,
        workspace=tmp_path,
        killswitch=killswitch,
    )
    return CampaignContext(
        engagement=engagement, executor=executor, kb=kb, killswitch=killswitch,
    ), audit, killswitch


def _halt_handler(ctx):
    from swarmstrike.tools.catalog import build_knowledge_tools, handlers

    return handlers(build_knowledge_tools(ctx))["halt_campaign"]


def test_halt_stops_the_campaign_when_nothing_was_ruled_on(tmp_path) -> None:
    ctx, _audit, killswitch = _context(tmp_path)
    asyncio.run(_halt_handler(ctx)({"agent": "api", "reason": HALT_REASON}))
    assert killswitch.engaged


def test_a_ruled_on_condition_does_not_stop_the_campaign(tmp_path) -> None:
    ctx, audit, killswitch = _context(tmp_path)
    record(
        tmp_path,
        pattern="/rest/memories",
        ruling="Stock Juice Shop seed data on a lab target the operator owns.",
        operator="Lucas Offredi",
    )

    result = asyncio.run(_halt_handler(ctx)({"agent": "api", "reason": HALT_REASON}))

    assert not killswitch.engaged
    text = str(result)
    # The agent is told what was decided, so it carries on rather than retrying.
    assert "NOT halted" in text
    assert "Lucas Offredi" in text
    assert "seed data" in text.casefold()

    # And the override is in the chain, not only in the agent's transcript.
    events = [entry.event for entry in audit.entries()]
    assert "halt.overruled" in events
    assert audit.verify()[0]


def test_a_different_condition_still_stops_a_campaign_with_rulings(tmp_path) -> None:
    """A ruling is an answer to one condition, not a licence to keep going."""
    ctx, _audit, killswitch = _context(tmp_path)
    record(tmp_path, pattern="/rest/memories", ruling="Seed data.", operator="Lucas")

    asyncio.run(_halt_handler(ctx)(
        {"agent": "recon", "reason": "172.31.77.11 stopped answering after the last scan"}
    ))
    assert killswitch.engaged
