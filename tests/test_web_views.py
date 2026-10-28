"""The dashboard's view endpoints, against a real campaign.

A stub would not exercise the parts that matter: whether the tool inventory
reflects this contract, whether the audit record verifies, whether the roster
matches the phases the contract authorizes.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")

from swarmstrike import engagement as contract  # noqa: E402
from swarmstrike.orchestrator import Campaign, CampaignConfig  # noqa: E402
from swarmstrike.web.server import Session, create_app  # noqa: E402

CONTRACT = """
schema_version: 1
engagement:
  id: ENG-VIEW
  client: Acme
  mission: External assessment
  reference: Q-1
  authorized_by:
    name: Jane Doe
    role: CISO
    email: ciso@example.org
    authorization_ref: letter 1
    signed_on: '2026-01-01'
window:
  start: '2026-01-01T00:00:00+00:00'
  end: '2030-01-01T00:00:00+00:00'
  timezone: UTC
scope:
  domains:
    - name: example.org
      include_subdomains: true
  cidrs: ['203.0.113.0/28']
exclusions:
  ips: ['203.0.113.1']
  url_paths: ['/payment/']
rules_of_engagement:
  exploitation:
    allowed: true
    stop_at_proof: true
  red_team:
    enabled: true
    lateral_movement: true
integrity:
  fingerprint: null
  signature: null
  signed_at: null
"""


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SWARMSTRIKE_SCOPE_KEY", "0" * 32)
    path = tmp_path / "engagement.yaml"
    path.write_text(CONTRACT, encoding="utf-8")
    contract.sign_file(path)

    campaign = Campaign(
        CampaignConfig(engagement_path=path, workspace_root=tmp_path / "campaigns",
                       skip_preflight=True)
    )
    campaign.kb.open_campaign(campaign.campaign_id, campaign.engagement)
    campaign.audit.open_campaign(campaign.engagement, campaign.campaign_id)

    app = create_app()
    dashboard = None
    for route in app.routes:
        for cell in getattr(getattr(route, "endpoint", None), "__closure__", None) or ():
            if type(cell.cell_contents).__name__ == "Dashboard":
                dashboard = cell.cell_contents
                break
        if dashboard:
            break
    dashboard.sessions["s1"] = Session(id="s1", campaign=campaign)

    with fastapi_testclient.TestClient(app) as c:
        yield c, campaign
    campaign.close()


# ---------------------------------------------------------------------------
def test_tool_inventory_reflects_this_contract(client) -> None:
    c, _ = client
    body = c.get("/api/campaigns/s1/tools").json()

    assert body["total"] >= 50
    assert 0 < body["authorized"] < body["total"], "some tools must be withheld"
    assert not body["invalid"], f"malformed recipes: {body['invalid']}"

    by_name = {r["name"]: r for r in body["tools"]}

    # Exploitation is authorized, so the intrusive tier is open.
    assert by_name["sqlmap"]["authorized"]
    # Lateral movement is the only red team phase named.
    assert by_name["netexec-exec"]["authorized"]
    # Privilege escalation is not, and the reason says which flag.
    assert not by_name["certipy-find"]["authorized"]
    assert "privilege_escalation" in by_name["certipy-find"]["reason"]
    # Authentication testing was never authorized.
    assert not by_name["netexec-auth"]["authorized"]
    assert "credential_testing" in by_name["netexec-auth"]["reason"]


def test_a_withheld_tool_says_why(client) -> None:
    c, _ = client
    body = c.get("/api/campaigns/s1/tools").json()
    for row in body["tools"]:
        if not row["authorized"]:
            assert row["reason"], f"{row['name']} is withheld with no reason given"


def test_sensitive_parameters_are_flagged_to_the_interface(client) -> None:
    c, _ = client
    body = c.get("/api/campaigns/s1/tools").json()
    netexec = next(r for r in body["tools"] if r["name"] == "netexec-auth")
    sensitive = [p["name"] for p in netexec["parameters"] if p["sensitive"]]
    assert sensitive == ["password"]


def test_roster_matches_the_authorized_phases(client) -> None:
    c, _ = client
    rows = {a["agent"]: a for a in c.get("/api/campaigns/s1/agents").json()["agents"]}

    assert "lateral" in rows, "the authorized phase should have its agent"
    assert "persistence" not in rows
    assert "privesc" not in rows

    # The challenge roles reason over the record and must not reach a target.
    assert rows["skeptic"]["touches_targets"] is False
    assert rows["arbiter"]["touches_targets"] is False
    assert rows["web"]["touches_targets"] is True
    assert rows["lead"]["touches_targets"] is False


def test_contract_view_reports_verification_and_phases(client) -> None:
    c, _ = client
    body = c.get("/api/campaigns/s1/contract").json()

    assert body["verified"] is True
    assert body["window_open"] is True
    assert body["engagement"]["client"] == "Acme"
    assert body["integrity"]["fingerprint"]

    roe = body["rules_of_engagement"]
    assert roe["red_team"]["lateral_movement"] is True
    assert roe["red_team"]["persistence"] is False
    assert roe["forbid_destructive"] is True
    assert body["exclusions"]["url_paths"] == ["/payment/"]


def test_facts_and_paths_come_from_the_graph(client) -> None:
    c, campaign = client
    kb = campaign.kb
    kb.upsert_fact("finding/upload", "unrestricted upload at /avatar", "web",
                   body="POST …", confidence="confirmed")
    kb.upsert_fact("access/webshell", "code execution as www-data", "web",
                   confidence="confirmed")
    kb.link_facts("finding/upload", "access/webshell", "enables")
    kb.upsert_fact("note/no-sqli", "login is parameterised", "web", negative=True)

    index = c.get("/api/campaigns/s1/facts").json()
    assert index["total"] == 3
    # A listing must not carry bodies: that is what keeps a long campaign cheap.
    assert all("body" not in row for row in index["facts"])

    without_negatives = c.get("/api/campaigns/s1/facts?include_negative=false").json()
    assert without_negatives["total"] == 2

    detail = c.get("/api/campaigns/s1/fact", params={"key": "finding/upload"}).json()
    assert detail["body"] == "POST …"
    assert detail["links"]["out"][0]["dst_key"] == "access/webshell"

    assert c.get("/api/campaigns/s1/fact", params={"key": "nope/x"}).status_code == 404

    paths = c.get("/api/campaigns/s1/attack-paths").json()
    assert len(paths["paths"]) == 1
    assert [s["fact_key"] for s in paths["paths"][0]["steps"]] == [
        "finding/upload", "access/webshell"
    ]


def test_audit_view_carries_its_verification(client) -> None:
    c, _ = client
    body = c.get("/api/campaigns/s1/audit").json()

    assert body["verified"] is True
    assert "chain intact" in body["verification"]
    assert body["entries_total"] >= 1
    assert body["entries"][0]["event"] == "campaign.open"
    assert "campaign.open" in body["by_event"]

    filtered = c.get("/api/campaigns/s1/audit", params={"event": "nothing"}).json()
    assert filtered["matching"] == 0
    # Filtering the view must not change what the chain says about itself.
    assert filtered["verified"] is True
