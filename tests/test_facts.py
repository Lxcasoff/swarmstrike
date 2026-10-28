"""The fact graph.

Derived from CyberStrikeAI's project blackboard; the tests here cover the three
properties that make it more than a notes table — keyed overwrite, the
index/body split, and paths reconstructed from evidenced edges.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from swarmstrike.engagement import Engagement
from swarmstrike.knowledge.db import FactError, KnowledgeBase, _now, parse_fact_key

CONTRACT = {
    "engagement": {"id": "E", "client": "C", "mission": "M",
                   "authorized_by": {"name": "n", "role": "r", "email": "e",
                                     "authorization_ref": "a", "signed_on": "2026-01-01"}},
    "window": {"start": "2026-10-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org"}]},
}


@pytest.fixture
def kb(tmp_path: Path) -> KnowledgeBase:
    base = KnowledgeBase(tmp_path / "kb.sqlite")
    base.open_campaign("CAMP", Engagement.model_validate(CONTRACT))
    return base


# ---------------------------------------------------------------------------
#  Keys
# ---------------------------------------------------------------------------
def test_key_is_category_and_slug() -> None:
    assert parse_fact_key("finding/sqli-login") == ("finding", "sqli-login")


def test_key_case_is_normalised_not_rejected() -> None:
    assert parse_fact_key("  Target/Primary-Domain ") == ("target", "primary-domain")


@pytest.mark.parametrize("bad", ["nocategory", "bogus/x", "finding/", "/x", "a//b"])
def test_malformed_keys_are_refused(bad: str) -> None:
    with pytest.raises(FactError):
        parse_fact_key(bad)


# ---------------------------------------------------------------------------
#  Keyed overwrite
# ---------------------------------------------------------------------------
def test_same_key_updates_rather_than_duplicating(kb: KnowledgeBase) -> None:
    assert kb.upsert_fact("target/primary-domain", "example.org is the main site", "recon")
    assert not kb.upsert_fact("target/primary-domain", "example.org, Apache 2.4", "network")

    assert len(kb.list_facts(category="target")) == 1
    assert kb.get_fact("target/primary-domain")["summary"] == "example.org, Apache 2.4"


def test_omitting_body_on_update_keeps_the_stored_body(kb: KnowledgeBase) -> None:
    kb.upsert_fact("finding/sqli", "injection at /search", "web",
                   body="full reproduction steps here")
    kb.upsert_fact("finding/sqli", "injection at /search, confirmed", "web",
                   confidence="confirmed")

    fact = kb.get_fact("finding/sqli")
    assert fact["body"] == "full reproduction steps here"
    assert fact["confidence"] == "confirmed"


def test_a_summary_is_required(kb: KnowledgeBase) -> None:
    with pytest.raises(FactError, match="stands on its own"):
        kb.upsert_fact("note/empty", "   ", "recon")


def test_confidence_is_constrained(kb: KnowledgeBase) -> None:
    with pytest.raises(FactError, match="confidence must be"):
        kb.upsert_fact("note/x", "s", "a", confidence="probably")


# ---------------------------------------------------------------------------
#  The index/body split
# ---------------------------------------------------------------------------
def test_listings_never_carry_bodies(kb: KnowledgeBase) -> None:
    # This is the whole point: a long campaign must not spend its context
    # re-reading everything it already knows.
    kb.upsert_fact("infra/waf", "Cloudflare in front of www", "recon",
                   body="x" * 10_000)
    row = kb.list_facts()[0]
    assert "body" not in row
    assert row["summary"] == "Cloudflare in front of www"
    assert len(kb.get_fact("infra/waf")["body"]) == 10_000


def test_negative_results_are_recorded_and_filterable(kb: KnowledgeBase) -> None:
    kb.upsert_fact("note/no-sqli-on-login", "login form is parameterised; no injection",
                   "web", negative=True, confidence="confirmed")
    kb.upsert_fact("finding/open-admin", "admin panel unauthenticated", "web")

    assert len(kb.list_facts()) == 2
    assert len(kb.list_facts(include_negative=False)) == 1


def test_deprecated_facts_are_hidden_but_kept(kb: KnowledgeBase) -> None:
    kb.upsert_fact("finding/maybe", "timing suggests injection", "web",
                   body="three samples")
    assert kb.deprecate_fact("finding/maybe", "jitter, not injection", "skeptic")

    assert kb.list_facts() == []
    assert len(kb.list_facts(include_deprecated=True)) == 1

    fact = kb.get_fact("finding/maybe")
    assert fact["confidence"] == "deprecated"
    # The reasoning that retracted it stays in the record.
    assert "jitter, not injection" in fact["body"]
    assert "three samples" in fact["body"]


def test_search_covers_key_summary_and_body(kb: KnowledgeBase) -> None:
    kb.upsert_fact("auth/jwt", "tokens are JWT", "api", body="alg is HS256")
    assert kb.search_facts("jwt")
    assert kb.search_facts("HS256")
    assert not kb.search_facts("kerberos")


# ---------------------------------------------------------------------------
#  Edges and paths
# ---------------------------------------------------------------------------
def test_relations_are_constrained_and_self_links_refused(kb: KnowledgeBase) -> None:
    kb.upsert_fact("access/web-foothold", "shell via upload", "web")
    kb.upsert_fact("access/db-creds", "db password in config", "code")

    with pytest.raises(FactError, match="relation must be"):
        kb.link_facts("access/web-foothold", "access/db-creds", "causes")
    with pytest.raises(FactError, match="cannot link to itself"):
        kb.link_facts("access/web-foothold", "access/web-foothold", "enables")

    assert kb.link_facts("access/web-foothold", "access/db-creds", "enables")
    assert not kb.link_facts("access/web-foothold", "access/db-creds", "enables")


def test_links_are_visible_from_both_ends(kb: KnowledgeBase) -> None:
    kb.upsert_fact("finding/upload", "unrestricted upload", "web")
    kb.upsert_fact("access/shell", "code execution", "web")
    kb.link_facts("finding/upload", "access/shell", "enables", note="webshell")

    assert kb.get_fact("finding/upload")["links"]["out"][0]["dst_key"] == "access/shell"
    assert kb.get_fact("access/shell")["links"]["in"][0]["src_key"] == "finding/upload"


def test_attack_path_is_reconstructed_from_enables_edges(kb: KnowledgeBase) -> None:
    chain = [
        ("finding/upload", "unrestricted file upload on /avatar"),
        ("access/webshell", "code execution as www-data"),
        ("auth/db-creds", "database credentials in config.php"),
        ("access/db-admin", "full read on the customer database"),
    ]
    for key, summary in chain:
        kb.upsert_fact(key, summary, "web", confidence="confirmed")
    for (src, _), (dst, _) in zip(chain, chain[1:]):
        kb.link_facts(src, dst, "enables")

    # A side branch that is evidence, not a step, must not become a path.
    kb.upsert_fact("poc/upload-request", "the POST that proves it", "web")
    kb.link_facts("poc/upload-request", "finding/upload", "evidences")

    paths = kb.attack_paths()
    assert len(paths) == 1
    assert [f["fact_key"] for f in paths[0]] == [k for k, _ in chain]


def test_a_retracted_step_breaks_the_path(kb: KnowledgeBase) -> None:
    for key in ("finding/a", "access/b", "access/c"):
        kb.upsert_fact(key, f"step {key}", "web", confidence="confirmed")
    kb.link_facts("finding/a", "access/b", "enables")
    kb.link_facts("access/b", "access/c", "enables")
    assert len(kb.attack_paths()[0]) == 3

    kb.deprecate_fact("access/b", "false positive", "skeptic")
    # With the middle step retracted there is no evidenced chain left.
    assert kb.attack_paths() == []


def test_cycles_do_not_hang_the_walk(kb: KnowledgeBase) -> None:
    for key in ("access/a", "access/b", "access/c"):
        kb.upsert_fact(key, key, "net", confidence="confirmed")
    kb.link_facts("access/a", "access/b", "enables")
    kb.link_facts("access/b", "access/c", "enables")
    kb.link_facts("access/c", "access/a", "enables")

    # Every node has an incoming edge, so there is no entry point to start from.
    assert kb.attack_paths() == []


def test_longest_path_comes_first(kb: KnowledgeBase) -> None:
    for key in ("finding/x", "access/x1", "finding/y", "access/y1", "access/y2"):
        kb.upsert_fact(key, key, "web", confidence="confirmed")
    kb.link_facts("finding/x", "access/x1", "enables")
    kb.link_facts("finding/y", "access/y1", "enables")
    kb.link_facts("access/y1", "access/y2", "enables")

    paths = kb.attack_paths()
    assert [len(p) for p in paths] == [3, 2]


def test_links_can_be_supplied_with_the_fact(kb: KnowledgeBase) -> None:
    kb.upsert_fact("access/target", "domain admin", "ad", confidence="confirmed")
    kb.upsert_fact("finding/spn", "kerberoastable service account", "ad",
                   confidence="confirmed", links=[("enables", "access/target")])
    assert [f["fact_key"] for f in kb.attack_paths()[0]] == ["finding/spn", "access/target"]


def test_claims_an_agent_opened_during_a_dispatch_close_with_it(kb) -> None:
    """An agent can stake out work inside its own task with claim_task, and
    nothing else releases those: the orchestrator only knows the key it
    dispatched under. Left open they read as work still in flight, and the
    lead — told not to reassign running work — stops assigning anything."""
    kb.try_claim("web:from-an-earlier-round", "web")
    kb.release_claim("web:from-an-earlier-round", "done")

    opened_at = _now()
    kb.try_claim("web:dispatched", "web")
    kb.try_claim("web-self-staked-subtask", "web")
    kb.try_claim("api:a-different-agents-work", "api")

    kb.release_claim("web:dispatched", "summary")
    closed = kb.release_agent_claims("web", opened_at)

    assert closed == 1
    rows = {
        row["task_key"]: row["released_at"]
        for row in kb.conn.execute("SELECT task_key, released_at FROM claim")
    }
    assert rows["web-self-staked-subtask"] is not None
    # Another agent's open claim is not this dispatch's to close.
    assert rows["api:a-different-agents-work"] is None
