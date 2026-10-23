"""CVSS v3.1 base score.

Agents supply a vector string; the score is computed here rather than asked
for, because a model asked to produce a number alongside a vector will
sometimes produce a number that does not follow from it. The arithmetic is the
specification's, including its Roundup function, which is not ordinary rounding.
"""

from __future__ import annotations

import math
import re

PREFIX = "CVSS:3.1/"

METRIC_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    # Impact metrics are High / Low / None in v3.1 — "Medium" is a v2 spelling.
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}

# Privileges Required is weighted differently when Scope changes.
PR_WEIGHTS = {
    "unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
    "changed": {"N": 0.85, "L": 0.68, "H": 0.50},
}

REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

VECTOR_RE = re.compile(r"^(CVSS:3\.[01]/)?([A-Z]+:[A-Z]+)(/[A-Z]+:[A-Z]+)*$")


class InvalidVector(ValueError):
    """The vector string is not a well-formed CVSS v3.1 base vector."""


def _roundup(value: float) -> float:
    """The specification's Roundup: round up to one decimal place.

    Done on scaled integers because the float form of the same operation gives
    9.0 for inputs that should score 8.9.
    """
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    raw = vector.strip()
    if not VECTOR_RE.match(raw):
        raise InvalidVector(f"{vector!r} is not a CVSS v3.1 vector")

    body = raw[len(PREFIX):] if raw.startswith(PREFIX) else raw
    body = body.removeprefix("CVSS:3.0/")

    metrics: dict[str, str] = {}
    for part in body.split("/"):
        if not part:
            continue
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()

    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise InvalidVector(f"vector is missing required metrics: {', '.join(missing)}")
    return metrics


def base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    try:
        av = METRIC_WEIGHTS["AV"][metrics["AV"]]
        ac = METRIC_WEIGHTS["AC"][metrics["AC"]]
        ui = METRIC_WEIGHTS["UI"][metrics["UI"]]
        pr = PR_WEIGHTS["changed" if scope_changed else "unchanged"][metrics["PR"]]
        conf = METRIC_WEIGHTS["C"][metrics["C"]]
        integ = METRIC_WEIGHTS["I"][metrics["I"]]
        avail = METRIC_WEIGHTS["A"][metrics["A"]]
    except KeyError as exc:
        raise InvalidVector(f"unknown metric value: {exc}") from exc

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08

    return _roundup(min(combined, 10.0))


def severity_band(score: float) -> str:
    """CVSS v3.1 qualitative rating."""
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_vector(vector: str | None) -> tuple[float | None, str | None]:
    """Score a vector, tolerating a malformed one. Returns (score, severity)."""
    if not vector:
        return None, None
    try:
        score = base_score(vector)
    except InvalidVector:
        return None, None
    return score, severity_band(score)


def normalise_vector(vector: str) -> str:
    """Canonical form, with the version prefix and metrics in specification order."""
    metrics = parse_vector(vector)
    ordered = "/".join(f"{key}:{metrics[key]}" for key in REQUIRED)
    return PREFIX + ordered


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unrated": 5}


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get((severity or "unrated").lower(), 5)

def subscores(vector: str | None) -> tuple[float, float] | None:
    """Return (exploitability, impact) from a vector, or None if unusable.

    These are the two halves the base score is built from, and plotting a
    finding against both says something the single score hides: whether it is
    severe because it is trivially reachable, or because the consequence is
    grave. Both come from the vector, so nothing here is estimated.
    """
    if not vector:
        return None
    try:
        metrics = parse_vector(vector)
    except InvalidVector:
        return None

    scope_changed = metrics["S"] == "C"
    try:
        av = METRIC_WEIGHTS["AV"][metrics["AV"]]
        ac = METRIC_WEIGHTS["AC"][metrics["AC"]]
        ui = METRIC_WEIGHTS["UI"][metrics["UI"]]
        pr = PR_WEIGHTS["changed" if scope_changed else "unchanged"][metrics["PR"]]
        conf = METRIC_WEIGHTS["C"][metrics["C"]]
        integ = METRIC_WEIGHTS["I"][metrics["I"]]
        avail = METRIC_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None

    exploitability = 8.22 * av * ac * pr * ui
    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    return round(exploitability, 2), round(max(impact, 0.0), 2)

