"""Stopping a campaign that is already running.

Autonomous means nobody is watching every command, so there has to be one
action that stops everything immediately. The switch lives in a file as well
as in memory: an operator who is not at the controlling terminal can halt the
swarm with `touch <campaign>/HALT`, and every agent notices before its next
command.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

HALT_FILENAME = "HALT"


class Halted(Exception):
    """The campaign was stopped. Work already done stays valid and reportable."""


class KillSwitch:
    def __init__(self, campaign_dir: str | Path) -> None:
        self.path = Path(campaign_dir) / HALT_FILENAME
        self._reason: str | None = None

    # ------------------------------------------------------------------
    def engage(self, reason: str) -> None:
        """Stop the campaign. Safe to call more than once."""
        if self._reason is None:
            self._reason = reason
            self.path.parent.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(tz=ZoneInfo("UTC")).isoformat()
            self.path.write_text(f"{stamp}\n{reason}\n", encoding="utf-8")

    def release(self) -> None:
        """Clear the switch. Only for starting a fresh campaign in the same directory."""
        self._reason = None
        self.path.unlink(missing_ok=True)

    @property
    def engaged(self) -> bool:
        if self._reason is not None:
            return True
        if self.path.exists():
            # Tripped from outside this process — adopt it and its reason.
            content = self.path.read_text(encoding="utf-8").strip().splitlines()
            self._reason = content[-1] if content else "halted externally"
            return True
        return False

    @property
    def reason(self) -> str:
        return self._reason or ""

    def check(self) -> None:
        """Called before every dispatched command."""
        if self.engaged:
            raise Halted(self._reason or "campaign halted")
