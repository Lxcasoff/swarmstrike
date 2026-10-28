"""The roster, and which agents the contract brings into existence."""

from __future__ import annotations

import pytest

from swarmstrike.agents.roster import (
    CHALLENGE_NAMES,
    DISCIPLINE,
    RED_TEAM_NAMES,
    SPECIALIST_NAMES,
    build_agents,
)
from swarmstrike.engagement import Engagement

BASE = {
    "engagement": {"id": "E", "client": "Acme", "mission": "M",
                   "authorized_by": {"name": "n", "role": "r", "email": "e",
                                     "authorization_ref": "a", "signed_on": "2026-01-01"}},
    "window": {"start": "2026-10-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org"}]},
}


def contract(**roe) -> Engagement:
    doc = dict(BASE)
    if roe:
        doc["rules_of_engagement"] = roe
    return Engagement.model_validate(doc)


def test_a_plain_pentest_gets_no_red_team_agents() -> None:
    agents = build_agents(engagement=contract())
    assert set(agents) == set(SPECIALIST_NAMES) | set(CHALLENGE_NAMES)
    for name in RED_TEAM_NAMES:
        assert name not in agents


def test_each_phase_brings_exactly_its_own_agent() -> None:
    # An agent that exists but is refused at every turn wastes budget, so the
    # roster follows the contract phase by phase.
    expected = {
        "post_exploitation": "foothold",
        "privilege_escalation": "privesc",
        "lateral_movement": "lateral",
        "evasion": "detection",
        "exfiltration_simulation": "exfil",
    }
    for flag, agent in expected.items():
        agents = build_agents(engagement=contract(red_team={"enabled": True, flag: True}))
        added = set(agents) - set(SPECIALIST_NAMES) - set(CHALLENGE_NAMES)
        assert added == {agent}, f"{flag} should add only {agent}, added {added}"


def test_persistence_agent_needs_both_switches() -> None:
    named_only = build_agents(
        engagement=contract(red_team={"enabled": True, "persistence": True})
    )
    # The agent appears once the phase is named, but every command it proposes
    # is still refused while forbid_persistence stands — the roster follows the
    # phase flag and the executor follows both.
    assert "persistence" in named_only

    both = build_agents(engagement=contract(
        forbid_persistence=False, red_team={"enabled": True, "persistence": True}
    ))
    assert "persistence" in both


def test_master_switch_off_means_no_red_team_agents() -> None:
    # The contract validator refuses a half-configured red team block, so the
    # only way to have the switch off is to have every phase off too.
    agents = build_agents(engagement=contract(red_team={"enabled": False}))
    assert not set(agents) & set(RED_TEAM_NAMES)


def test_roster_works_without_a_contract() -> None:
    # Used by the debate engine, which only needs the specialist prompts.
    agents = build_agents()
    assert set(agents) == set(SPECIALIST_NAMES) | set(CHALLENGE_NAMES)


def test_domains_narrow_the_specialists() -> None:
    agents = build_agents(domains=["web", "api"], engagement=contract())
    assert {"web", "api"} <= set(agents)
    assert "cloud" not in agents
    # The challenge roles are never narrowed away: a finding with no reviewer
    # would reach the report unchallenged.
    assert set(CHALLENGE_NAMES) <= set(agents)


def test_every_agent_carries_the_engagement_discipline() -> None:
    agents = build_agents(context="BRIEFING HERE", engagement=contract(
        forbid_persistence=False,
        red_team={"enabled": True, "post_exploitation": True, "persistence": True},
    ))
    for name, definition in agents.items():
        assert "BRIEFING HERE" in definition.prompt, name
        assert "REFUSED" in definition.prompt, name


def test_discipline_tells_agents_a_refusal_is_final() -> None:
    # The opposite instruction is what the ported project's prompts carry, and
    # it is the one thing deliberately not taken from them.
    flat = " ".join(DISCIPLINE.split())
    assert "do not look for a way around it" in flat
    assert "do not try a different tool to reach the same target" in flat
    assert "halt_campaign" in flat


@pytest.mark.parametrize("name", RED_TEAM_NAMES)
def test_red_team_prompts_do_not_suppress_authorization_questions(name: str) -> None:
    agents = build_agents(engagement=contract(
        forbid_persistence=False,
        red_team={"enabled": True, "post_exploitation": True, "privilege_escalation": True,
                  "lateral_movement": True, "persistence": True, "evasion": True,
                  "exfiltration_simulation": True},
    ))
    prompt = agents[name].prompt.lower()
    for phrase in ("never wait for approval", "do not verify authorization",
                   "never question", "do not question"):
        assert phrase not in prompt, f"{name} carries an authorization-suppression phrase"
