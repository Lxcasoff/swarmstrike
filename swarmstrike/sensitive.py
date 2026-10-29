"""Recognising credential material a target handed back.

`redact` in the executor covers the other direction: secrets swarmstrike
*sends*, which it knows about because a recipe marked the parameter sensitive.
Nothing knew about what a target *returns*. A read-only GET against a broken
authorization check can answer with a user table, and that lands in the
campaign's output directory as the evidence of record — then in whatever
archive the evidence is handed over in.

The output is not altered. Proving that an endpoint exposes credentials means
keeping what it returned, and an assessment that shreds its own proof has
nothing to show. What this does is make sure nobody is holding that material
without knowing it: the file is listed in a manifest, the audit chain records
it, and the report says which files carry what and how to handle them.

Detection is by pattern, so it is a floor and not a guarantee: a credential in
a shape not listed here passes unnoticed. The report says so rather than
implying the list is complete.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Each entry is a kind of material and the shape that finds it. The shapes are
# deliberately narrow: a bare 32-hex string is as likely to be a request id as
# an MD5 hash, so the hash patterns only fire next to a credential-ish key.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
    ),
    (
        "password hash",
        re.compile(
            r"\"(?:password|passwordHash|pass_hash|pwd|hash)\"\s*:\s*\""
            r"(?:\$2[aby]\$|\$argon2|\$6\$|\$5\$|[0-9a-f]{32,128})",
            re.IGNORECASE,
        ),
    ),
    (
        "password hash",
        # Shadow-file and SQL-dump shapes, where there is no JSON key to anchor on.
        re.compile(r"(?m)^[\w.@-]+:(?:\$2[aby]\$|\$argon2|\$6\$|\$5\$)[./A-Za-z0-9$]{20,}"),
    ),
    (
        "cleartext password",
        # Anything but a hash in a password field. Without the lookahead this
        # also fires on every hashed password, and the report then says a
        # hashed store was exposed in cleartext, which is a different finding.
        re.compile(
            r"\"(?:password|passwd|pwd|secret|client_secret)\"\s*:\s*\""
            r"(?!\s*\")(?![0-9a-f]{32,128}\")(?!\$2[aby]\$)(?!\$argon2)(?!\$[56]\$)"
            r"[^\"]{3,}\"",
            re.IGNORECASE,
        ),
    ),
    (
        "session token or JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "API key",
        re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}"
            r"|github_pat_[A-Za-z0-9_]{22,}|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,})"
        ),
    ),
    (
        "API key",
        re.compile(
            r"\"(?:api_?key|access_?token|refresh_?token|authorization)\"\s*:\s*\"[^\"]{12,}\"",
            re.IGNORECASE,
        ),
    ),
)

MANIFEST_NAME = "SENSITIVE.json"


@dataclass(frozen=True)
class Marking:
    """What a file turned out to be holding."""

    path: str
    kinds: tuple[str, ...]

    def describe(self) -> str:
        return f"{self.path}: {', '.join(self.kinds)}"


def classify(text: str) -> tuple[str, ...]:
    """Kinds of credential material present, in a stable order, deduplicated."""
    found: list[str] = []
    for kind, pattern in _PATTERNS:
        if kind not in found and pattern.search(text):
            found.append(kind)
    return tuple(found)


def mark(output_dir: Path, filename: str, text: str) -> Marking | None:
    """Record that a file holds credential material. Returns None if it does not.

    The manifest is rewritten whole each time rather than appended to, so a
    resumed campaign does not accumulate duplicate entries for the same file.
    """
    kinds = classify(text)
    if not kinds:
        return None

    import json

    manifest = output_dir / MANIFEST_NAME
    entries: dict[str, list[str]] = {}
    if manifest.exists():
        try:
            entries = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            entries = {}
    entries[filename] = list(kinds)
    manifest.write_text(
        json.dumps(dict(sorted(entries.items())), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return Marking(filename, kinds)


def read_manifest(output_dir: Path) -> list[Marking]:
    """Every marked file in a campaign's output directory."""
    import json

    manifest = output_dir / MANIFEST_NAME
    if not manifest.exists():
        return []
    try:
        entries = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [
        Marking(name, tuple(kinds))
        for name, kinds in sorted(entries.items())
        if isinstance(kinds, list)
    ]
