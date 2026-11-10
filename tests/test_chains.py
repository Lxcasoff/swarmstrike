"""Attack paths as they appear in the report."""

from __future__ import annotations

import pytest

from swarmstrike.report.chains import FALLBACK, STEP_KIND, describe_path, prepare, step_kind
from swarmstrike.report.builder import _first_sentence


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


# ---------------------------------------------------------------------------
#  The one-line remediation in the priorities list
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("label", "text", "expected"),
    [
        (
            # The lab report cut priority 1 here, which is the line an
            # executive reads first.
            "an abbreviation mid-sentence",
            "In the memories route handler, query with an explicit attributes "
            "whitelist on the User include (e.g. id, email). Then redeploy.",
            "In the memories route handler, query with an explicit attributes "
            "whitelist on the User include (e.g. id, email).",
        ),
        (
            "several sentences",
            "Set Options -Indexes in the vhost. Deny access to *.dist files.",
            "Set Options -Indexes in the vhost.",
        ),
        (
            "one long sentence is kept whole rather than cut",
            "Restrict /metrics to the monitoring network (reverse-proxy allowlist "
            "or basic auth/mTLS) and do not route it through the public listener.",
            "Restrict /metrics to the monitoring network (reverse-proxy allowlist "
            "or basic auth/mTLS) and do not route it through the public listener.",
        ),
        ("no trailing period", "Rotate the exposed key", "Rotate the exposed key."),
        ("an abbreviation first", "Use e.g. a bound query. That is all.", "Use e.g. a bound query."),
        ("nothing at all", "   ", ""),
    ],
)
def test_the_priority_line_breaks_at_a_real_sentence_end(label, text, expected) -> None:
    assert _first_sentence(text) == expected, label


# ---------------------------------------------------------------------------
#  The map as an Excalidraw scene
# ---------------------------------------------------------------------------
def _graph():
    return {
        "nodes": [
            {"id": "asset:a", "type": "asset", "label": "admin.example.pf",
             "detail": "domain"},
            {"id": "fact:auth", "type": "fact", "label": "auth/creds",
             "detail": "admin password recovered", "category": "auth"},
            {"id": "fact:dead", "type": "fact", "label": "note/no-sqli",
             "detail": "parameterised", "category": "note", "negative": True},
            {"id": "finding:F-001", "type": "finding", "label": "F-001",
             "detail": "Unrestricted upload", "severity": "high"},
        ],
        "edges": [
            {"from": "asset:a", "to": "finding:F-001", "kind": "on"},
            {"from": "fact:auth", "to": "finding:F-001", "kind": "enables"},
        ],
    }


def test_the_scene_is_a_file_excalidraw_will_open() -> None:
    from swarmstrike.report.excalidraw import scene

    result = scene(_graph(), title="Commune de Faa'a")
    assert result["type"] == "excalidraw"
    assert result["version"] == 2
    assert result["files"] == {}
    assert "viewBackgroundColor" in result["appState"]

    required = {"id", "x", "y", "width", "height", "angle", "strokeColor",
                "backgroundColor", "seed", "version", "versionNonce", "isDeleted"}
    for element in result["elements"]:
        assert required <= set(element), f"{element['type']} is missing fields"


def test_every_node_becomes_a_box_with_its_text_inside() -> None:
    from swarmstrike.report.excalidraw import scene

    elements = scene(_graph())["elements"]
    boxes = [e for e in elements if e["type"] == "rectangle"]
    assert len(boxes) == 4

    for box in boxes:
        bound = {b["type"] for b in box["boundElements"] or []}
        assert "text" in bound, "a box with no label is a box nobody can read"
    texts = {e["containerId"] for e in elements
             if e["type"] == "text" and e.get("containerId")}
    assert texts == {b["id"] for b in boxes}


def test_an_arrow_is_bound_at_both_ends_so_it_follows_what_it_joins() -> None:
    """An unbound arrow stays where it was drawn when the operator moves a box,
    which is the whole reason for handing them an editable scene."""
    from swarmstrike.report.excalidraw import scene

    arrows = [e for e in scene(_graph())["elements"] if e["type"] == "arrow"]
    assert len(arrows) == 2
    for arrow in arrows:
        assert arrow["startBinding"] and arrow["endBinding"]
        assert arrow["endArrowhead"] == "arrow"


def test_colour_and_outline_carry_what_a_node_amounted_to() -> None:
    from swarmstrike.report.excalidraw import ASSET_COLOUR, scene

    by_text = {}
    for element in scene(_graph())["elements"]:
        if element["type"] == "text" and element.get("containerId"):
            by_text[element["text"].split("\n")[0]] = element["containerId"]
    boxes = {e["id"]: e for e in scene(_graph())["elements"] if e["type"] == "rectangle"}

    # Rebuilt, so look them up by position instead: the first box is the asset.
    elements = scene(_graph())["elements"]
    rects = [e for e in elements if e["type"] == "rectangle"]
    assert rects[0]["strokeColor"] == ASSET_COLOUR[0]
    # The dead end is the one drawn dashed, whatever its colour.
    assert any(r["strokeStyle"] == "dashed" for r in rects)
    assert sum(1 for r in rects if r["strokeStyle"] == "dashed") == 1


def test_an_empty_campaign_still_produces_a_valid_scene() -> None:
    from swarmstrike.report.excalidraw import scene

    result = scene({"nodes": [], "edges": []})
    assert result["type"] == "excalidraw"
    assert all(e["type"] == "text" for e in result["elements"])   # column labels
