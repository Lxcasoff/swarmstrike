"""Which model runs which role, and what that costs.

Reasoning quality matters most where a mistake propagates: the orchestrator
that decides what to test, and the arbiter that decides whether a finding is
real. Specialists run one domain each on a mid-tier model, and the high-volume
mechanical work — parsing a 40,000-line scanner dump into structured findings —
runs on the cheapest model that can do it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# Model identifiers, current as of the Claude 5 family.
OPUS = "claude-opus-5-5"
SONNET = "claude-sonnet-5-5"
HAIKU = "claude-haiku-5-5"


class Role(StrEnum):
    ORCHESTRATOR = "orchestrator"   # plans the campaign, assigns work
    SPECIALIST = "specialist"       # one domain of expertise
    SKEPTIC = "skeptic"             # argues every finding is a false positive
    ARBITER = "arbiter"             # rules on contested findings
    PARSER = "parser"               # tool output -> structured records
    REPORTER = "reporter"           # assembles the deliverable


DEFAULT_ROUTING: dict[Role, str] = {
    Role.ORCHESTRATOR: OPUS,
    Role.ARBITER: OPUS,
    Role.REPORTER: OPUS,
    Role.SPECIALIST: SONNET,
    Role.SKEPTIC: SONNET,
    Role.PARSER: HAIKU,
}

# Effort per role. The arbiter and orchestrator think hard; parsing does not
# benefit from it and the volume makes it expensive.
DEFAULT_EFFORT: dict[Role, str] = {
    Role.ORCHESTRATOR: "high",
    Role.ARBITER: "high",
    Role.REPORTER: "high",
    Role.SPECIALIST: "medium",
    Role.SKEPTIC: "high",
    Role.PARSER: "low",
}


@dataclass(frozen=True)
class Price:
    """USD per million tokens."""
    input: float
    output: float
    cache_read: float


# Fallback price table. The agent harness reports its own cost estimate per
# run, which BudgetTracker prefers; this is only used when that is missing.
# Prices move — treat a surprising number here as stale before trusting it.
PRICING: dict[str, Price] = {
    OPUS: Price(input=4.00, output=20.00, cache_read=0.20),
    SONNET: Price(input=2.00, output=10.00, cache_read=0.20),
    HAIKU: Price(input=0.10, output=0.50, cache_read=0.01),
}


def model_for(role: Role, overrides: dict[str, str] | None = None) -> str:
    if overrides and role.value in overrides:
        return overrides[role.value]
    return DEFAULT_ROUTING[role]


def effort_for(role: Role, overrides: dict[str, str] | None = None) -> str:
    if overrides and role.value in overrides:
        return overrides[role.value]
    return DEFAULT_EFFORT[role]


def estimate_usd(
    model: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read_tokens: int = 0,
) -> float:
    """Cost estimate from the fallback table. Returns 0.0 for unknown models."""
    price = PRICING.get(model)
    if price is None:
        # An unrecognised model is more likely a new release than an error;
        # the caller still has the harness's own cost figure.
        return 0.0
    return (
        input_tokens * price.input
        + output_tokens * price.output
        + cache_read_tokens * price.cache_read
    ) / 1_000_000
