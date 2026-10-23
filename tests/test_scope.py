"""Scope enforcement.

These tests are the ones that matter most in this project: every case here is
a command that must not reach a target the client did not authorize.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from swarmstrike.engagement import Engagement
from swarmstrike.scope import ScopeGuard


def build_engagement(**overrides) -> Engagement:
    now = datetime.now(tz=ZoneInfo("UTC"))
    doc = {
        "engagement": {
            "id": "ENG-TEST",
            "client": "Example Organisation",
            "mission": "External assessment",
            "authorized_by": {
                "name": "Jane Doe",
                "role": "CISO",
                "email": "ciso@example.org",
                "authorization_ref": "letter 1",
                "signed_on": "2026-01-01",
            },
        },
        "window": {
            "start": (now - timedelta(days=1)).isoformat(),
            "end": (now + timedelta(days=1)).isoformat(),
            "timezone": "UTC",
        },
        "scope": {
            "domains": [{"name": "example.org", "include_subdomains": True}],
            "cidrs": ["203.0.113.0/28"],
        },
        "exclusions": {
            "domains": [{"name": "webmail.example.org", "include_subdomains": False}],
            "ips": ["203.0.113.1"],
            "url_paths": ["/payment/"],
        },
    }
    doc.update(overrides)
    return Engagement.model_validate(doc)


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard(build_engagement(), resolve=False)


# ---------------------------------------------------------------------------
#  Hosts
# ---------------------------------------------------------------------------
def test_in_scope_domain_and_subdomain_allowed(guard: ScopeGuard) -> None:
    assert guard.check_host("example.org").allowed
    assert guard.check_host("www.example.org").allowed
    assert guard.check_host("deep.nested.example.org").allowed


def test_lookalike_domain_refused(guard: ScopeGuard) -> None:
    # The classic scope mistake: a suffix match that is a different registrant.
    decision = guard.check_host("notexample.org")
    assert not decision.allowed
    assert decision.rule == "scope.miss"


def test_exclusion_beats_scope(guard: ScopeGuard) -> None:
    decision = guard.check_host("webmail.example.org")
    assert not decision.allowed
    assert decision.rule == "exclusions"


def test_excluded_ip_inside_in_scope_range_refused(guard: ScopeGuard) -> None:
    assert guard.check_host("203.0.113.10").allowed
    decision = guard.check_host("203.0.113.1")
    assert not decision.allowed
    assert decision.rule == "exclusions"


def test_address_outside_range_refused(guard: ScopeGuard) -> None:
    assert not guard.check_host("203.0.113.200").allowed
    assert not guard.check_host("8.8.8.8").allowed


# ---------------------------------------------------------------------------
#  Addresses that are never in scope
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",        # the toolbox container itself
        "169.254.169.254",  # cloud metadata endpoint
        "::1",
        "0.0.0.0",
    ],
)
def test_loopback_and_link_local_never_in_scope(address: str) -> None:
    # Even when the contract lists them, these are refused.
    engagement = build_engagement(
        scope={
            "domains": [],
            "cidrs": ["127.0.0.0/8", "169.254.0.0/16", "::1/128", "0.0.0.0/8"],
        }
    )
    decision = ScopeGuard(engagement, resolve=False).check_host(address)
    assert not decision.allowed
    assert decision.rule == "hard_deny"


def test_private_range_refused_unless_contract_names_it() -> None:
    external = ScopeGuard(build_engagement(), resolve=False)
    decision = external.check_host("192.168.1.10")
    assert not decision.allowed
    assert decision.rule == "private_not_authorized"

    internal = ScopeGuard(
        build_engagement(scope={"domains": [], "cidrs": ["192.168.1.0/24"]}), resolve=False
    )
    assert internal.check_host("192.168.1.10").allowed


# ---------------------------------------------------------------------------
#  URLs
# ---------------------------------------------------------------------------
def test_excluded_path_refused(guard: ScopeGuard) -> None:
    assert guard.check_url("https://www.example.org/public").allowed
    decision = guard.check_url("https://www.example.org/payment/checkout")
    assert not decision.allowed
    assert decision.rule == "exclusions.path"


# ---------------------------------------------------------------------------
#  Commands
# ---------------------------------------------------------------------------
def test_command_against_in_scope_target_allowed(guard: ScopeGuard) -> None:
    assert guard.check_command(["nmap", "-sT", "-p", "80,443", "www.example.org"]).allowed


def test_command_with_one_out_of_scope_target_refused(guard: ScopeGuard) -> None:
    # A single stray target poisons the whole command.
    decision = guard.check_command(["nmap", "-sT", "www.example.org", "evil.test"])
    assert not decision.allowed


def test_command_without_a_readable_target_refused(guard: ScopeGuard) -> None:
    decision = guard.check_command(["nmap", "-sT", "--top-ports", "100"])
    assert not decision.allowed
    assert decision.rule == "unverifiable"


def test_output_filenames_are_not_mistaken_for_hosts(guard: ScopeGuard) -> None:
    decision = guard.check_command(
        ["nmap", "-sT", "-oN", "results.txt", "-w", "wordlist.txt", "www.example.org"]
    )
    assert decision.allowed, decision.reason


def test_target_inside_a_flag_value_is_checked(guard: ScopeGuard) -> None:
    assert guard.check_command(["ffuf", "--url=https://www.example.org/FUZZ"]).allowed
    assert not guard.check_command(["ffuf", "--url=https://evil.test/FUZZ"]).allowed


@pytest.mark.parametrize(
    ("argv", "rule"),
    [
        (["rm", "-rf", "/", "www.example.org"], "forbid_destructive"),
        (["nmap", "--script", "dos", "www.example.org"], "forbid_denial_of_service"),
        (["hping3", "--flood", "www.example.org"], "forbid_denial_of_service"),
        (["sqlmap", "-u", "https://www.example.org/", "--os-shell"], "forbid_data_modification"),
        (["crontab", "-e", "www.example.org"], "forbid_persistence"),
        (["setoolkit", "www.example.org"], "forbid_social_engineering"),
        (["hydra", "-l", "admin", "www.example.org"], "credential_testing"),
    ],
)
def test_forbidden_command_shapes_refused(guard: ScopeGuard, argv: list[str], rule: str) -> None:
    decision = guard.check_command(argv)
    assert not decision.allowed
    assert decision.rule == rule


def test_forbidden_check_runs_before_scope(guard: ScopeGuard) -> None:
    # An in-scope target does not license a destructive command.
    decision = guard.check_command(["mkfs", "www.example.org"])
    assert not decision.allowed
    assert decision.rule == "forbid_destructive"


def test_credential_testing_allowed_when_contract_permits() -> None:
    engagement = build_engagement()
    engagement.rules_of_engagement.credential_testing.allowed = True
    guard = ScopeGuard(engagement, resolve=False)
    assert guard.check_command(["hydra", "-l", "pentest1", "www.example.org"]).allowed


# ---------------------------------------------------------------------------
#  Window
# ---------------------------------------------------------------------------
def test_command_refused_outside_engagement_window() -> None:
    past = datetime.now(tz=ZoneInfo("UTC")) - timedelta(days=10)
    engagement = build_engagement(
        window={
            "start": (past - timedelta(days=1)).isoformat(),
            "end": past.isoformat(),
            "timezone": "UTC",
        }
    )
    decision = ScopeGuard(engagement, resolve=False).check_command(
        ["nmap", "-sT", "www.example.org"]
    )
    assert not decision.allowed
    assert decision.rule == "window"
