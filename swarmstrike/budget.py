"""Spend ceiling for a campaign.

A swarm that argues with itself can burn tokens indefinitely, so the contract's
budget is enforced rather than advertised. The orchestrator checks this before
dispatching each unit of work and stops the campaign when a ceiling is reached,
leaving whatever was found already intact and reportable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .engagement import Budget
from .models import estimate_usd


class BudgetExceeded(Exception):
    """A campaign ceiling was reached. Not an error — a designed stop."""


@dataclass
class Spend:
    usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_creation_tokens
        )


@dataclass
class BudgetTracker:
    budget: Budget
    started_at: float = field(default_factory=time.monotonic)

    # The harness reports cumulative usage per session, so the latest figure
    # for a session replaces the previous one rather than adding to it.
    _by_session: dict[str, Spend] = field(default_factory=dict)
    _by_model: dict[str, Spend] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def record_result(self, session_id: str, result: Any) -> Spend:
        """Absorb a ResultMessage from the agent harness.

        `model_usage` covers subagents and internal calls, so it is preferred
        over the top-level `usage`, which only counts the outer loop.
        """
        spend = Spend()
        model_usage: dict[str, Any] = getattr(result, "model_usage", None) or {}

        if model_usage:
            per_model: dict[str, Spend] = {}
            for model, usage in model_usage.items():
                entry = Spend(
                    usd=float(_get(usage, "costUSD", 0.0)),
                    input_tokens=int(_get(usage, "inputTokens", 0)),
                    output_tokens=int(_get(usage, "outputTokens", 0)),
                    cache_read_tokens=int(_get(usage, "cacheReadInputTokens", 0)),
                    cache_creation_tokens=int(_get(usage, "cacheCreationInputTokens", 0)),
                )
                if not entry.usd:
                    entry.usd = estimate_usd(
                        model,
                        input_tokens=entry.input_tokens,
                        output_tokens=entry.output_tokens,
                        cache_read_tokens=entry.cache_read_tokens,
                    )
                per_model[model] = entry
                spend = _add(spend, entry)
            self._by_model = _merge_models(self._by_model, self._by_session.get(session_id),
                                           per_model, session_id)
        else:
            usage = getattr(result, "usage", None) or {}
            spend = Spend(
                input_tokens=int(_get(usage, "input_tokens", 0)),
                output_tokens=int(_get(usage, "output_tokens", 0)),
                cache_read_tokens=int(_get(usage, "cache_read_input_tokens", 0)),
                cache_creation_tokens=int(_get(usage, "cache_creation_input_tokens", 0)),
            )

        reported = getattr(result, "total_cost_usd", None)
        if reported is not None:
            spend.usd = float(reported)

        self._by_session[session_id] = spend
        return spend

    # ------------------------------------------------------------------
    @property
    def spend(self) -> Spend:
        total = Spend()
        for entry in self._by_session.values():
            total = _add(total, entry)
        return total

    @property
    def elapsed_minutes(self) -> float:
        return (time.monotonic() - self.started_at) / 60.0

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.budget.max_usd - self.spend.usd)

    def status(self) -> str:
        s = self.spend
        return (
            f"${s.usd:.2f}/${self.budget.max_usd:.2f} · "
            f"{s.total_tokens:,}/{self.budget.max_tokens:,} tokens · "
            f"{self.elapsed_minutes:.0f}/{self.budget.max_wall_clock_minutes} min"
        )

    def check(self) -> None:
        """Raise if a ceiling has been reached. Called before dispatching work."""
        s = self.spend
        if s.usd >= self.budget.max_usd:
            raise BudgetExceeded(
                f"cost ceiling reached: ${s.usd:.2f} of ${self.budget.max_usd:.2f}"
            )
        if s.total_tokens >= self.budget.max_tokens:
            raise BudgetExceeded(
                f"token ceiling reached: {s.total_tokens:,} of {self.budget.max_tokens:,}"
            )
        if self.elapsed_minutes >= self.budget.max_wall_clock_minutes:
            raise BudgetExceeded(
                f"time ceiling reached: {self.elapsed_minutes:.0f} of "
                f"{self.budget.max_wall_clock_minutes} minutes"
            )

    def would_exceed(self, projected_usd: float) -> bool:
        return (self.spend.usd + projected_usd) >= self.budget.max_usd

    def by_model(self) -> dict[str, Spend]:
        return dict(self._by_model)


def _get(source: Any, key: str, default: Any) -> Any:
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _add(left: Spend, right: Spend) -> Spend:
    return Spend(
        usd=left.usd + right.usd,
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        cache_read_tokens=left.cache_read_tokens + right.cache_read_tokens,
        cache_creation_tokens=left.cache_creation_tokens + right.cache_creation_tokens,
    )


def _merge_models(
    accumulated: dict[str, Spend],
    _previous_session_total: Spend | None,
    per_model: dict[str, Spend],
    _session_id: str,
) -> dict[str, Spend]:
    """Per-model totals are indicative only — session figures are authoritative."""
    merged = dict(accumulated)
    for model, entry in per_model.items():
        merged[model] = entry
    return merged
