"""Findings the budget never let anyone review.

A campaign ran out of budget after proposing five findings, two of them high.
The review loop stopped before the first, the report read only confirmed and
unproven findings, and it concluded "no exploitable weaknesses", overall risk
Informational, status completed. Every part of that was wrong.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from swarmstrike.audit import AuditLog
from swarmstrike.engagement import Engagement
from swarmstrike.knowledge import Finding, KnowledgeBase
from swarmstrike.report.builder import ReportBuilder


@pytest.fixture
def engagement() -> Engagement:
    now = datetime.now(tz=ZoneInfo("UTC"))
    return Engagement.model_validate({
        "engagement": {"id": "E", "client": "Acme", "mission": "M",
                       "authorized_by": {"name": "n", "role": "r", "email": "e",
                                         "authorization_ref": "a", "signed_on": "2026-01-01"}},
        "window": {"start": (now - timedelta(days=1)).isoformat(),
                   "end": (now + timedelta(days=1)).isoformat()},
        "scope": {"domains": [{"name": "example.org"}]},
    })


def _kb(tmp_path, engagement, *, confirmed: bool) -> KnowledgeBase:
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.open_campaign("C", engagement)
    if confirmed:
        fid = kb.add_finding(Finding(title="Unrestricted upload", domain="web",
                                     asset="/avatar", summary="accepts .php",
                                     discovered_by="web", severity="critical"))
        kb.add_arbitration(fid, "arbiter", "confirmed", 0.9, "confirmed")
    kb.add_finding(Finding(title="Directory listing on /ftp", domain="web",
                           asset="/ftp", summary="lists a KeePass database",
                           discovered_by="web", severity="high"))
    return kb


def _report(tmp_path, engagement, *, confirmed: bool) -> tuple[str, dict]:
    kb = _kb(tmp_path, engagement, confirmed=confirmed)
    builder = ReportBuilder(engagement=engagement, kb=kb,
                            audit=AuditLog(tmp_path / "a.jsonl"), campaign_id="C")
    return builder.render(), builder.context()


def test_an_unreviewed_finding_is_listed_not_dropped(tmp_path, engagement) -> None:
    markdown, context = _report(tmp_path, engagement, confirmed=False)
    assert context["counts"]["unreviewed"] == 1
    assert "## Proposed but not reviewed" in markdown
    assert "Directory listing on /ftp" in markdown
    assert "Proposed, not reviewed" in markdown


def test_nothing_reviewed_is_not_a_clean_result(tmp_path, engagement) -> None:
    markdown, context = _report(tmp_path, engagement, confirmed=False)
    assert context["risk_level"] == "Undetermined"
    assert "confirmed no exploitable weaknesses" not in markdown
    assert "should not be read as a clean result" in markdown
    assert "No unproven weaknesses were recorded." not in markdown


def test_the_limits_say_the_budget_stopped_the_review(tmp_path, engagement) -> None:
    _, context = _report(tmp_path, engagement, confirmed=False)
    assert "budget ran out before 1 proposed" in context["limits"]


def test_confirmed_findings_still_set_the_risk(tmp_path, engagement) -> None:
    markdown, context = _report(tmp_path, engagement, confirmed=True)
    assert context["risk_level"] == "Critical"
    assert context["counts"]["total"] == 1
    assert "1 proposed finding(s) were not reviewed" in markdown


def test_a_finished_review_leaves_nothing_unreviewed(tmp_path, engagement) -> None:
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.open_campaign("C", engagement)
    markdown = ReportBuilder(engagement=engagement, kb=kb,
                             audit=AuditLog(tmp_path / "a.jsonl"), campaign_id="C").render()
    assert "Proposed but not reviewed" not in markdown
    assert "No unproven weaknesses were recorded." in markdown


def test_a_review_cut_short_is_not_reported_completed(tmp_path, engagement) -> None:
    from swarmstrike.orchestrator import Campaign

    kb = _kb(tmp_path, engagement, confirmed=False)
    campaign = Campaign.__new__(Campaign)
    campaign._sink = lambda event, payload: None
    campaign._setup = lambda: None
    campaign.campaign_id = "C"
    campaign.dir = tmp_path
    campaign.engagement = engagement
    campaign.config = SimpleNamespace(skip_preflight=True)
    campaign.guard = SimpleNamespace(check_window=lambda: SimpleNamespace(allowed=True))
    campaign.kb = kb
    campaign.audit = AuditLog(tmp_path / "a.jsonl")
    campaign.budget = SimpleNamespace(status=lambda: "$4.01/$4.00")
    campaign._write_report = lambda: None

    async def nothing():
        return []

    campaign._assess = nothing
    campaign._debate = nothing  # stopped before the first finding

    result = asyncio.run(campaign.run())
    assert result.status == "budget_exhausted"
    assert "1 finding(s) were not reviewed" in result.halted_reason
