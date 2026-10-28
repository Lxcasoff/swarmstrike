"""The state-space loop.

The loop is in code rather than in the lead's prompt so that the round
structure, the duplicate-work check, the no-progress guard and the budget
check happen whether or not a model remembers them. These tests are about
exactly that: the lead is scripted, and what is under test is what the loop
does around it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from swarmstrike.audit import AuditLog
from swarmstrike.budget import BudgetTracker
from swarmstrike.engagement import Engagement
from swarmstrike.killswitch import KillSwitch
from swarmstrike.knowledge import Finding, KnowledgeBase
from swarmstrike.search import Action, Outcome, Round, StateSpaceSearch
from swarmstrike.tools.recipes import load_recipes

CONTRACT = {
    "engagement": {"id": "E", "client": "Acme", "mission": "M",
                   "authorized_by": {"name": "n", "role": "r", "email": "e",
                                     "authorization_ref": "a", "signed_on": "2026-01-01"}},
    "window": {"start": "2026-01-01T00:00:00+00:00", "end": "2030-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org"}]},
}


class Scripted(StateSpaceSearch):
    """A search whose lead is a list and whose specialists are a counter."""

    def __init__(self, plans: list[Round], *, facts_per_action: int = 1, **kwargs):
        super().__init__(**kwargs)
        self.plans = plans
        self.facts_per_action = facts_per_action
        self.dispatched: list[Action] = []
        self.notes: list[str] = []

    async def plan(self, round_number: int, note: str = "") -> Round:
        self.notes.append(note)
        if not self.plans:
            return Round(number=round_number, reading="nothing scripted", complete=True,
                         completion_reason="out of scripted plans")
        plan = self.plans.pop(0)
        plan.number = round_number
        return plan

    async def dispatch(self, action: Action) -> Outcome:
        self.dispatched.append(action)
        if not self.kb.try_claim(action.task_key or action.brief, action.agent):
            return Outcome(action, False, "already claimed")
        for index in range(self.facts_per_action):
            self.kb.upsert_fact(
                f"note/{action.task_key}-{index}", f"something from {action.task_key}",
                action.agent,
            )
        return Outcome(action, True, "done", new_facts=self.facts_per_action)


@pytest.fixture
def parts(tmp_path: Path):
    engagement = Engagement.model_validate(CONTRACT)
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.open_campaign("C", engagement)
    return {
        "engagement": engagement,
        "kb": kb,
        "audit": AuditLog(tmp_path / "audit.jsonl"),
        "budget": BudgetTracker(engagement.budget),
        "killswitch": KillSwitch(tmp_path),
        "book": load_recipes(),
        "mcp_servers": {},
        "lead_prompt": "lead",
        "specialist_prompts": {"web": "web prompt", "network": "network prompt"},
        "specialist_tools": {"web": ["mcp__toolbox__run_tool"], "network": []},
        "lead_tools": [],
    }


def act(agent: str, key: str) -> Action:
    return Action(agent=agent, task_key=key, brief=f"work on {key}")


# ---------------------------------------------------------------------------
#  The digest
# ---------------------------------------------------------------------------
def test_the_digest_shows_the_board_without_fact_bodies(parts) -> None:
    kb = parts["kb"]
    kb.add_asset("domain", "example.org", "recon")
    kb.upsert_fact("finding/upload", "unrestricted upload at /avatar", "web",
                   body="A VERY LONG REPRODUCTION BODY " * 50, confidence="confirmed")
    kb.upsert_fact("note/no-sqli", "login is parameterised", "web", negative=True)
    kb.add_finding(Finding(title="Upload", domain="web", asset="/avatar",
                           summary="s", discovered_by="web"))
    kb.try_claim("web:already-done", "web")

    digest = StateSpaceSearch(**parts).digest(3)

    assert "Round 3 of at most" in digest
    assert "example.org" in digest
    assert "unrestricted upload at /avatar" in digest
    # The index is what keeps a long campaign cheap; bodies are fetched, not pushed.
    assert "A VERY LONG REPRODUCTION BODY" not in digest
    # Dead ends are called out so they are not reassigned.
    assert "Dead ends" in digest and "login is parameterised" in digest
    assert "web:already-done" in digest
    assert "F-001" in digest


def test_the_digest_lists_only_tools_this_contract_authorizes(parts) -> None:
    digest = StateSpaceSearch(**parts).digest(1)
    # Exploitation is not authorized on this contract, so sqlmap must not be
    # offered to the lead as something it can assign.
    assert "sqlmap" not in digest
    assert "nmap" in digest or "no tools authorized" in digest


def test_an_empty_board_says_so_rather_than_rendering_blanks(parts) -> None:
    digest = StateSpaceSearch(**parts).digest(1)
    assert "the board is empty" in digest
    assert "nothing discovered yet" in digest


# ---------------------------------------------------------------------------
#  Dispatch
# ---------------------------------------------------------------------------
def test_an_unknown_specialist_is_refused_with_the_available_ones(parts) -> None:
    search = StateSpaceSearch(**parts)
    outcome = asyncio.run(search.dispatch(act("nonexistent", "k")))
    assert not outcome.ran
    assert "no specialist called" in outcome.detail
    assert "web" in outcome.detail


def test_duplicate_work_is_refused_by_the_claim_not_by_the_prompt(parts) -> None:
    # The lead sees assigned keys in the digest, but a race between rounds
    # would still slip past a prompt.
    parts["kb"].try_claim("web:admin-authz", "web")
    search = StateSpaceSearch(**parts)
    outcome = asyncio.run(search.dispatch(act("web", "web:admin-authz")))
    assert not outcome.ran
    assert "already claimed" in outcome.detail


# ---------------------------------------------------------------------------
#  The loop
# ---------------------------------------------------------------------------
def test_it_stops_when_the_lead_says_complete(parts) -> None:
    plans = [
        Round(number=0, reading="map the surface", actions=[act("web", "a")]),
        Round(number=0, reading="covered", complete=True,
              completion_reason="surface covered to the budget's depth"),
    ]
    search = Scripted(plans, **parts)
    rounds = asyncio.run(search.run())

    assert len(rounds) == 2
    assert rounds[-1].complete
    assert [a.task_key for a in search.dispatched] == ["a"]


def test_actions_in_a_round_run_together(parts) -> None:
    plans = [Round(number=0, reading="three at once", actions=[
        act("web", "a"), act("network", "b"), act("web", "c"),
    ])]
    search = Scripted(plans, **parts)
    asyncio.run(search.run())
    assert [a.task_key for a in search.dispatched] == ["a", "b", "c"]


def test_two_barren_rounds_end_the_search(parts) -> None:
    # A round that establishes nothing is the signal that the search has
    # converged — or that the lead is circling. Either way, stop.
    plans = [
        Round(number=0, reading="try", actions=[act("web", f"k{n}")])
        for n in range(6)
    ]
    search = Scripted(plans, facts_per_action=0, **parts)
    rounds = asyncio.run(search.run())

    assert len(rounds) == 2, "it should stop after the second barren round"


def test_a_barren_round_is_named_to_the_lead_before_stopping(parts) -> None:
    plans = [Round(number=0, reading="try", actions=[act("web", f"k{n}")])
             for n in range(4)]
    search = Scripted(plans, facts_per_action=0, **parts)
    asyncio.run(search.run())

    # First round gets no note; the second is told the previous established nothing.
    assert search.notes[0] == ""
    assert "established no new facts" in search.notes[1]


def test_progress_resets_the_barren_counter(parts) -> None:
    plans = [
        Round(number=0, reading="r1", actions=[act("web", "a")]),
        Round(number=0, reading="r2", actions=[act("web", "b")]),
        Round(number=0, reading="r3", actions=[act("web", "c")]),
    ]
    search = Scripted(plans, facts_per_action=1, **parts)
    rounds = asyncio.run(search.run())

    # Every round established something, so the barren guard never fired and
    # all three were dispatched. The extra round is the scripted lead running
    # out of plans and saying so, which is the loop stopping correctly.
    assert [a.task_key for a in search.dispatched] == ["a", "b", "c"]
    assert all(r.productive for r in rounds[:3])
    assert rounds[-1].complete


def test_the_round_ceiling_is_enforced(parts) -> None:
    plans = [Round(number=0, reading=f"r{n}", actions=[act("web", f"k{n}")])
             for n in range(20)]
    parts_with_cap = {**parts, "max_rounds": 3}
    search = Scripted(plans, **parts_with_cap)
    assert len(asyncio.run(search.run())) == 3


def test_the_budget_ceiling_stops_it_before_a_round(parts) -> None:
    parts["budget"].budget.max_usd = 0.0
    plans = [Round(number=0, reading="r1", actions=[act("web", "a")])]
    search = Scripted(plans, **parts)

    rounds = asyncio.run(search.run())
    assert rounds == []
    assert search.dispatched == []


def test_the_kill_switch_stops_it_before_a_round(parts) -> None:
    parts["killswitch"].engage("operator")
    plans = [Round(number=0, reading="r1", actions=[act("web", "a")])]
    search = Scripted(plans, **parts)

    from swarmstrike.killswitch import Halted

    with pytest.raises(Halted):
        asyncio.run(search.run())
    assert search.dispatched == []


def test_the_plan_is_written_to_the_audit_chain(parts) -> None:
    plans = [Round(number=0, reading="the board says X", actions=[act("web", "a")],
                   complete=True, completion_reason="done")]
    search = Scripted(plans, **parts)
    asyncio.run(search.run())

    events = [e.event for e in parts["audit"].entries()]
    assert "search.plan" in events

    plan_entry = next(e for e in parts["audit"].entries() if e.event == "search.plan")
    assert plan_entry.data["reading"] == "the board says X"
    assert plan_entry.data["actions"][0]["task_key"] == "a"

    intact, reason, _ = parts["audit"].verify()
    assert intact, reason


def test_events_are_emitted_for_the_live_view(parts) -> None:
    seen: list[str] = []
    parts["on_event"] = lambda event, _payload: seen.append(event)
    plans = [Round(number=0, reading="r1", actions=[act("web", "a")], complete=True)]
    asyncio.run(Scripted(plans, **parts).run())

    for event in ("round.start", "lead", "round.end", "search.complete"):
        assert event in seen, event


def test_the_digest_withholds_tools_the_image_cannot_run(parts) -> None:
    """The lab run failed on exactly this: the digest offered recon nmap, which
    the toolbox image did not carry, so the lead planned a port scan that could
    not happen. What the contract authorizes and what the image carries are
    different questions."""
    full = StateSpaceSearch(**parts).digest(1)
    assert "nmap" in full

    thin = StateSpaceSearch(**parts, carries=lambda binary: binary != "nmap").digest(1)
    assert "nmap" not in thin


def test_an_unreleased_claim_is_not_reported_as_running(parts) -> None:
    """Rounds are sequential — every dispatch is awaited before the next digest
    — so a claim with no release is not work in flight. Calling it "running"
    told the lead not to assign anything, and the campaign converged early."""
    parts["kb"].try_claim("agent-staked-this-out", "web")
    digest = StateSpaceSearch(**parts).digest(2)
    assert "agent-staked-this-out" in digest
    assert "(running)" not in digest
    assert "no result recorded" in digest
