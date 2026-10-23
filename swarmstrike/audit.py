"""Tamper-evident audit log.

A client who authorizes an autonomous test is entitled to an exact account of
what ran against their systems. Every entry is chained to the one before it by
hash, so a record cannot be altered or removed after the fact without the chain
failing to verify.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

from .engagement import Engagement

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(tz=ZoneInfo("UTC")).isoformat()


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Entry:
    seq: int
    ts: str
    event: str
    data: dict[str, Any]
    prev: str
    hash: str

    @classmethod
    def build(cls, seq: int, event: str, data: dict[str, Any], prev: str) -> Entry:
        body = {"seq": seq, "ts": _now(), "event": event, "data": data, "prev": prev}
        return cls(**body, hash=_digest(body))

    def to_json(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "event": self.event,
                "data": self.data,
                "prev": self.prev,
                "hash": self.hash,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def recompute(self) -> str:
        return _digest(
            {"seq": self.seq, "ts": self.ts, "event": self.event,
             "data": self.data, "prev": self.prev}
        )


class AuditLog:
    """Append-only JSONL log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._tail_state()

    def _tail_state(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        for last in self._iter_raw():
            pass
        if last is None:
            return 0, GENESIS
        return last["seq"] + 1, last["hash"]

    def _iter_raw(self) -> Iterator[dict[str, Any]]:
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    # ------------------------------------------------------------------
    def record(self, event: str, **data: Any) -> Entry:
        entry = Entry.build(self._seq, event, data, self._head)
        # Append and flush to disk before returning: a crash must not be able
        # to lose the record of a command that already ran.
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._seq += 1
        self._head = entry.hash
        return entry

    def open_campaign(self, engagement: Engagement, campaign_id: str) -> Entry:
        """First entry: who authorized this, and exactly which contract applies."""
        meta = engagement.engagement
        return self.record(
            "campaign.open",
            campaign_id=campaign_id,
            engagement_id=meta.id,
            client=meta.client,
            mission=meta.mission,
            authorized_by=meta.authorized_by.model_dump(),
            contract_fingerprint=engagement.integrity.fingerprint,
            window_start=engagement.window.start.isoformat(),
            window_end=engagement.window.end.isoformat(),
        )

    def command(
        self,
        *,
        agent: str,
        argv: list[str],
        decision: str,
        reason: str,
        rule: str = "",
        exit_code: int | None = None,
        duration_ms: int | None = None,
        stdout_sha256: str | None = None,
    ) -> Entry:
        return self.record(
            "tool.command",
            agent=agent,
            argv=argv,
            decision=decision,
            reason=reason,
            rule=rule,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_sha256=stdout_sha256,
        )

    def refusal(self, *, agent: str, argv: list[str], reason: str, rule: str) -> Entry:
        return self.record("tool.refused", agent=agent, argv=argv, reason=reason, rule=rule)

    # ------------------------------------------------------------------
    def verify(self) -> tuple[bool, str, int]:
        """Walk the chain. Returns (intact, reason, entries_checked)."""
        if not self.path.exists():
            return True, "no audit log yet", 0

        prev = GENESIS
        count = 0
        for raw in self._iter_raw():
            entry = Entry(**raw)
            if entry.seq != count:
                return False, f"entry {count} has sequence {entry.seq} — an entry was removed", count
            if entry.prev != prev:
                return False, f"entry {entry.seq} does not chain to its predecessor", count
            if entry.recompute() != entry.hash:
                return False, f"entry {entry.seq} was modified after it was written", count
            prev = entry.hash
            count += 1

        return True, f"chain intact across {count} entries (head {prev[:16]}…)", count

    def entries(self) -> list[Entry]:
        if not self.path.exists():
            return []
        return [Entry(**raw) for raw in self._iter_raw()]
