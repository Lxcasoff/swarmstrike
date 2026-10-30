"""Operator rulings on halts, so a resumed campaign can get past one.

An agent that sees something alarming halts the campaign, which is right. But
the halt is a judgment about what it just found, and the thing it found does
not go away: clear the HALT file, resume, and the next agent reaches the same
endpoint and halts again on the same reason. "Resume" is then impossible by
construction, and the campaign can never produce a report.

What was missing is a record of the operator's answer. A ruling says: this
specific condition was raised, a person looked at it, and here is what they
decided. The halt tool consults them and declines a halt whose reason a ruling
already covers, telling the agent what was decided so it carries on instead of
stopping.

This deliberately weakens the strongest guardrail in the tool, so it is built
to leave marks. A ruling exists only because someone ran a command to create
it; creating one and relying on one both go into the audit chain; and the
report discloses every halt that was overruled, with the operator's own words.
An override that nobody can see afterwards would be worse than no override.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

RULINGS_FILENAME = "ACKNOWLEDGED.json"


@dataclass(frozen=True)
class Ruling:
    """One condition an operator has looked at and ruled on."""

    pattern: str
    ruling: str
    operator: str
    recorded_at: str

    def covers(self, reason: str) -> bool:
        """Whether this ruling answers a halt raised for `reason`.

        Substring, case-insensitive. A pattern has to be specific enough to
        name the condition — see `record`, which refuses a short one.
        """
        return self.pattern.casefold() in reason.casefold()

    def to_dict(self) -> dict[str, str]:
        return {
            "pattern": self.pattern,
            "ruling": self.ruling,
            "operator": self.operator,
            "recorded_at": self.recorded_at,
        }


class RulingError(ValueError):
    """A ruling that would not do what the operator thinks it does."""


MIN_PATTERN_LENGTH = 12


def record(campaign_dir: str | Path, *, pattern: str, ruling: str, operator: str) -> Ruling:
    """Store an operator's ruling on a halt condition.

    The pattern has a length floor because matching is substring matching: a
    pattern of "data" would silently cover every halt mentioning exposed data,
    which is not a ruling on one condition but a blanket disabling of the
    guardrail. Refusing it here is cheaper than discovering it in a campaign.
    """
    pattern = pattern.strip()
    ruling = ruling.strip()
    operator = operator.strip()

    if len(pattern) < MIN_PATTERN_LENGTH:
        raise RulingError(
            f"the pattern must be at least {MIN_PATTERN_LENGTH} characters and name the "
            f"specific condition — matching is by substring, so a short pattern "
            f"overrules halts you have not seen. Quote the endpoint or the phrase "
            f"from the halt reason."
        )
    if not ruling:
        raise RulingError(
            "a ruling needs the decision in your own words: it goes in the report "
            "as the reason this halt was overruled."
        )
    if not operator:
        raise RulingError("a ruling needs the name of the person making it.")

    entry = Ruling(
        pattern=pattern,
        ruling=ruling,
        operator=operator,
        recorded_at=datetime.now(tz=UTC).isoformat(),
    )

    path = Path(campaign_dir) / RULINGS_FILENAME
    existing = [r.to_dict() for r in load(campaign_dir) if r.pattern != entry.pattern]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(existing + [entry.to_dict()], indent=2) + "\n", encoding="utf-8"
    )
    return entry


def load(campaign_dir: str | Path) -> list[Ruling]:
    """Every ruling recorded for a campaign. Unreadable means none."""
    path = Path(campaign_dir) / RULINGS_FILENAME
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []

    rulings = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            rulings.append(
                Ruling(
                    pattern=str(item["pattern"]),
                    ruling=str(item["ruling"]),
                    operator=str(item["operator"]),
                    recorded_at=str(item.get("recorded_at", "")),
                )
            )
        except KeyError:
            continue
    return rulings


def covering(campaign_dir: str | Path, reason: str) -> Ruling | None:
    """The ruling that answers a halt raised for `reason`, if there is one."""
    for entry in load(campaign_dir):
        if entry.covers(reason):
            return entry
    return None
