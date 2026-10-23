"""CVSS v3.1 base score, checked against vectors scored by hand from the spec."""

from __future__ import annotations

import pytest

from swarmstrike.report.cvss import (
    InvalidVector,
    base_score,
    normalise_vector,
    score_vector,
    severity_band,
    severity_rank,
)

# (vector, expected base score, expected qualitative rating)
REFERENCE = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5, "low"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    # No impact on any of confidentiality, integrity or availability scores 0.
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0, "none"),
]


@pytest.mark.parametrize(("vector", "expected", "band"), REFERENCE)
def test_base_score_matches_specification(vector: str, expected: float, band: str) -> None:
    score = base_score(vector)
    assert score == pytest.approx(expected)
    assert severity_band(score) == band


def test_version_prefix_is_optional() -> None:
    bare = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert base_score(bare) == base_score(f"CVSS:3.1/{bare}")


def test_roundup_rounds_away_from_zero_at_one_decimal() -> None:
    # 8.0 here only survives the specification's Roundup; ordinary rounding of
    # the same intermediate value lands a tenth low.
    assert base_score("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 8.0


def test_scope_change_reweights_privileges_required() -> None:
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
    assert changed > unchanged


def test_normalise_reorders_metrics_canonically() -> None:
    assert (
        normalise_vector("C:H/A:H/I:H/AV:N/AC:L/PR:N/UI:N/S:U")
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "not-a-vector",
        "CVSS:3.1/AV:N/AC:L",                               # missing metrics
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # unknown value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:H",     # v2 spelling of Low
    ],
)
def test_malformed_vectors_are_rejected(vector: str) -> None:
    with pytest.raises((InvalidVector, ValueError)):
        base_score(vector)


def test_score_vector_tolerates_bad_input() -> None:
    # Agents submit these, so a malformed vector must not abort a campaign.
    assert score_vector(None) == (None, None)
    assert score_vector("garbage") == (None, None)
    assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (9.8, "critical")


def test_severity_rank_orders_report_sections() -> None:
    ordered = sorted(["low", "critical", None, "medium", "high"], key=severity_rank)
    assert ordered == ["critical", "high", "medium", "low", None]
