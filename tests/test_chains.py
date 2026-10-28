"""Attack paths as they appear in the report."""

from __future__ import annotations

import pytest

from swarmstrike.report.chains import FALLBACK, STEP_KIND, describe_path, prepare, step_kind


def fact(key: str, category: str, summary: str, *, confidence: str = "confirmed",
         finding: str | None = None) -> dict:
    return {"fact_key": key, "category": category, "summary": summary,
            "confidence": confidence, "related_finding_id": finding}


CHAIN = [
    fact("finding/upload", "finding", "unrestricted upload at /avatar", finding="F-001"),
    fact("access/webshell", "access", "code execution as www-data"),
    fact("auth/db-creds", "auth", "credentials in config.php", finding="F-002"),
    fact("access/customer-db", "access", "full read on the customer database"),
]
FINDINGS = [
    {"id": "F-001", "title": "Unrestricted file upload", "severity": "critical"},
    {"id": "F-002", "title": "Credentials in the web root", "severity": "high"},
]


# ---------------------------------------------------------------------------
#  Step kinds
# ---------------------------------------------------------------------------
def test_every_fact_category_has_an_icon_and_a_label() -> None:
    for category, (icon, label) in STEP_KIND.items():
        assert icon.strip(), category
        assert label.strip(), category


def test_an_unknown_category_still_gets_a_label() -> None:
    # A new category added to the database must not render a blank step.
    icon, label = step_kind("something-new")
    assert (icon, label) == FALLBACK
    assert label == "Step"
    assert step_kind(None) == FALLBACK


def test_no_step_relies_on_its_icon_alone() -> None:
    """The design rule: the glyph speeds up reading, it never carries meaning.

    A client's PDF viewer that cannot render an emoji must not lose the sense
    of the step, so every step is required to have a written label.
    """
    for step in prepare([CHAIN], FINDINGS)[0]["steps"]:
        assert step["label"], step["fact_key"]
        assert step["label"] != step["icon"]


# ---------------------------------------------------------------------------
#  Preparation
# ---------------------------------------------------------------------------
def test_steps_are_numbered_and_the_last_is_marked() -> None:
    steps = prepare([CHAIN], FINDINGS)[0]["steps"]
    assert [s["position"] for s in steps] == [1, 2, 3, 4]
    assert [s["last"] for s in steps] == [False, False, False, True]


def test_a_step_that_is_also_a_finding_cross_references_it() -> None:
    # So a reader can turn to the reproduction steps rather than taking the
    # chain on trust.
    steps = prepare([CHAIN], FINDINGS)[0]["steps"]
    assert steps[0]["finding_id"] == "F-001"
    assert steps[0]["severity"] == "critical"
    assert steps[1]["finding_id"] is None
    assert steps[2]["finding_id"] == "F-002"


def test_an_unknown_finding_reference_is_dropped_not_rendered() -> None:
    orphan = [fact("finding/x", "finding", "something", finding="F-999")]
    step = prepare([orphan], FINDINGS)[0]["steps"][0]
    assert step["finding_id"] is None


def test_a_fully_confirmed_chain_is_marked_as_such() -> None:
    chain = prepare([CHAIN], FINDINGS)[0]
    assert chain["fully_confirmed"]
    assert chain["unverified_steps"] == []


def test_one_unverified_step_makes_the_whole_path_unproven() -> None:
    # A chain is only as strong as its weakest link, and the report has to say
    # so rather than presenting a hypothesis as a demonstration.
    weakened = [*CHAIN[:3], fact("access/customer-db", "access", "full read",
                                 confidence="tentative")]
    chain = prepare([weakened], FINDINGS)[0]
    assert not chain["fully_confirmed"]
    assert chain["unverified_steps"] == ["access/customer-db"]


def test_longest_path_comes_first() -> None:
    short = [fact("finding/ssrf", "finding", "ssrf"),
             fact("access/metadata", "access", "metadata reachable")]
    chains = prepare([short, CHAIN], FINDINGS)
    assert [c["length"] for c in chains] == [4, 2]
    # Numbering follows the input so it stays stable across renders.
    assert chains[0]["number"] == 2


def test_describe_names_both_ends() -> None:
    assert describe_path(CHAIN) == "from weakness to access gained"
    assert describe_path([]) == ""


def test_no_paths_prepares_to_nothing() -> None:
    assert prepare([], FINDINGS) == []


# ---------------------------------------------------------------------------
#  In the rendered report
# ---------------------------------------------------------------------------
@pytest.fixture
def rendered(tmp_path):
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo

    from swarmstrike.audit import AuditLog
    from swarmstrike.engagement import Engagement
    from swarmstrike.knowledge import Finding, KnowledgeBase
    from swarmstrike.report.builder import ReportBuilder
    from swarmstrike.report.html import render_html

    now = datetime.now(tz=ZoneInfo("UTC"))
    engagement = Engagement.model_validate({
        "engagement": {"id": "E", "client": "Acme", "mission": "M",
                       "authorized_by": {"name": "n", "role": "r", "email": "e",
                                         "authorization_ref": "a", "signed_on": "2026-01-01"}},
        "window": {"start": (now - timedelta(days=1)).isoformat(),
                   "end": (now + timedelta(days=1)).isoformat()},
        "scope": {"domains": [{"name": "example.org"}]},
    })

    def build(with_chain: bool):
        kb = KnowledgeBase(tmp_path / f"kb{with_chain}.sqlite")
        kb.open_campaign("C", engagement)
        audit = AuditLog(tmp_path / f"a{with_chain}.jsonl")

        fid = kb.add_finding(Finding(title="Unrestricted upload", domain="web",
                                     asset="/avatar", summary="accepts .php",
                                     discovered_by="web", severity="critical"))
        kb.add_arbitration(fid, "arbiter", "confirmed", 0.9, "confirmed")

        if with_chain:
            kb.upsert_fact("finding/upload", "unrestricted upload at /avatar", "web",
                           confidence="confirmed", related_finding_id=fid)
            kb.upsert_fact("access/webshell", "code execution as www-data", "web",
                           confidence="confirmed")
            kb.link_facts("finding/upload", "access/webshell", "enables")

        builder = ReportBuilder(engagement=engagement, kb=kb, audit=audit, campaign_id="C")
        markdown = builder.render()
        html = render_html(engagement=engagement, kb=kb, audit=audit, campaign_id="C")
        return markdown, html, builder.context()

    return build


def test_the_report_has_an_attack_paths_section(rendered) -> None:
    markdown, html, context = rendered(True)

    assert "# 5. Attack paths" in markdown
    assert "<h2>5. Attack paths</h2>" in html
    assert len(context["chains"]) == 1

    for text in (markdown, html):
        assert "finding/upload" in text
        assert "access/webshell" in text
        # The label travels with the icon in both formats.
        assert "Access gained" in text


def test_the_section_is_honest_when_no_path_was_found(rendered) -> None:
    markdown, html, context = rendered(False)

    assert context["chains"] == []
    for text in (markdown, html):
        assert "No multi-step path was evidenced" in text
        # And says what that does and does not mean.
        assert "not an assurance that none" in text


def test_the_summary_mentions_a_proven_chain(rendered) -> None:
    _, _, context = rendered(True)
    summary = context["executive_summary"]
    assert "do not stand alone" in summary
    assert "two-step path" in summary
    assert "breaking any single one of them" in summary


def test_the_summary_says_nothing_about_chains_when_there_are_none(rendered) -> None:
    _, _, context = rendered(False)
    assert "stand alone" not in context["executive_summary"]
