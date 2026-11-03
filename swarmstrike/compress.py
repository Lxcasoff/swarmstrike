"""Shrinking what an agent reads, never what the record keeps.

A scanner's output is mostly noise around a little signal: a curl over sixty
URLs returns sixty HTML bodies and sixty lines that actually say what was
found. The agent was given the first 60,000 characters of that and the rest
was dropped — a cut by position, which for a scanner throws away the end,
where the findings usually are.

This replaces the cut with a compressor that knows the shapes our recipes
produce. It is deliberately boring: it drops structure it recognises as noise,
deduplicates, and keeps head and tail of whatever is left. There is no model
in the path and no guessing at meaning.

Two rules hold everywhere in here:

* **It never touches the record.** The full output is already on disk and
  hashed into the audit chain before this runs. This shapes the copy that goes
  into an agent's context, and nothing else.
* **It never drops silently.** Every result says what was removed, how much,
  and where to read the original. An agent that needs the part that went can
  go and fetch it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Fields that carry a full request or response. They are the bulk of a nuclei
# or httpx record and say nothing the matched line does not.
VERBOSE_KEYS = frozenset({
    "request", "response", "curl-command", "curl_command", "raw", "body",
    "stored_response_path", "interactsh_request", "interactsh_response",
    "template-encoded", "chain", "headers", "response_headers", "har",
})

# Fields worth keeping first when a record has to be shortened.
SALIENT_KEYS = (
    "template-id", "templateID", "template", "type", "severity", "info",
    "name", "host", "url", "matched-at", "matched_at", "input", "status",
    "status_code", "status-code", "title", "webserver", "tech", "technologies",
    "location", "content_length", "content-length", "words", "lines",
    "extracted-results", "extracted_results", "matcher-name", "port", "scheme",
)

_HTML = re.compile(r"<\s*(?:!doctype|html|head|body|div|span|script|style)\b", re.I)
_TAG = re.compile(r"<[^>]{0,4000}>")
_WS = re.compile(r"[ \t]+")
# Binary bodies land in the output as replacement characters and control
# codes; they carry nothing and wreck a line's readability.
_PRINTABLE = re.compile(r"[^\x20-\x7e\u00a0-\uffff]|\ufffd")


@dataclass
class Compressed:
    """What an agent gets, and an account of what it did not."""

    text: str
    original_chars: int
    strategy: str
    notes: list[str] = field(default_factory=list)

    @property
    def kept_chars(self) -> int:
        return len(self.text)

    @property
    def saved_fraction(self) -> float:
        if not self.original_chars:
            return 0.0
        return 1 - self.kept_chars / self.original_chars

    def render(self, output_path: str | None = None) -> str:
        """The text, followed by an honest account of what was removed."""
        if self.kept_chars >= self.original_chars and not self.notes:
            return self.text
        lines = [
            f"--- {self.original_chars:,} characters reduced to {self.kept_chars:,} "
            f"({min(self.saved_fraction, 0.999):.1%} less) by the "
            f"{self.strategy} compressor ---"
        ]
        lines += [f"--- {note} ---" for note in self.notes]
        if output_path:
            lines.append(f"--- the full output is on disk at {output_path} ---")
        return self.text + "\n" + "\n".join(lines)


def compress(text: str, *, limit: int) -> Compressed:
    """Shrink tool output towards `limit` characters, by its shape."""
    original = len(text)
    if original <= limit:
        return Compressed(text, original, "none")

    for detect, apply in (
        (_looks_like_jsonl, _compress_jsonl),
        (_looks_like_http, _compress_http),
    ):
        if detect(text):
            result = apply(text, limit)
            if result is not None:
                return result
    return _compress_text(text, limit)


# ---------------------------------------------------------------------------
#  JSON lines: nuclei, httpx, and anything else that emits one object a line
# ---------------------------------------------------------------------------
def _looks_like_jsonl(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()][:40]
    if len(lines) < 2:
        return False
    parsed = sum(1 for ln in lines if ln.lstrip().startswith("{") and _is_json(ln))
    return parsed >= max(2, len(lines) // 2)


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
    except (ValueError, TypeError):
        return False
    return True


def _compress_jsonl(text: str, limit: int) -> Compressed | None:
    records, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if isinstance(obj, dict):
            records.append(obj)
    if not records:
        return None

    notes = []
    dropped_keys: set[str] = set()
    thinned = []
    for obj in records:
        flat = _flatten(obj)
        kept = {}
        for key, value in flat.items():
            leaf = key.rsplit(".", 1)[-1]
            if leaf in VERBOSE_KEYS or key in VERBOSE_KEYS:
                dropped_keys.add(leaf)
                continue
            kept[key] = value
        thinned.append(kept)

    lines = [_one_line(record) for record in thinned]
    lines, duplicates = _dedupe(lines)

    if dropped_keys:
        notes.append(
            f"dropped the full request and response bodies from each record "
            f"({', '.join(sorted(dropped_keys))})"
        )
    if duplicates:
        notes.append(f"{duplicates} identical record(s) collapsed")
    if skipped:
        notes.append(f"{skipped} line(s) were not JSON and were kept out")

    body, elided = _fit(lines, limit)
    if elided:
        notes.append(f"{elided} record(s) elided from the middle; "
                     f"the first and last are shown")
    return Compressed("\n".join(body), len(text), "json-lines", notes)


def _flatten(obj: dict, prefix: str = "") -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in obj.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{path}."))
        else:
            out[path] = value
    return out


def _one_line(record: dict[str, object]) -> str:
    ordered = sorted(
        record.items(),
        key=lambda kv: (
            next((i for i, s in enumerate(SALIENT_KEYS)
                  if kv[0] == s or kv[0].endswith("." + s)), len(SALIENT_KEYS)),
            kv[0],
        ),
    )
    parts = []
    for key, value in ordered:
        if value is None or value == "" or value == [] or value == {}:
            continue
        rendered = ",".join(map(str, value)) if isinstance(value, list) else str(value)
        if len(rendered) > 220:
            rendered = rendered[:220] + "…"
        parts.append(f"{key.rsplit('.', 1)[-1]}={rendered}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
#  HTTP: curl -i, and curl -w loops whose bodies drown the metric lines
# ---------------------------------------------------------------------------
_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.M)
# The shape `curl -w` writes: one URL and a status code on a short line. The
# order depends on the format string whoever wrote the command chose, so the
# two are looked for independently rather than in a fixed sequence — a first
# version expected the URL first and missed half the files in the lab.
_URL_IN_LINE = re.compile(r"https?://\S+")
_CODE_AFTER = re.compile(r"^\s+([1-5]\d{2})(?:\s|$)")
_CODE_BEFORE = re.compile(r"(?:^|\s)([1-5]\d{2})\s+[^\s]*\s*$")


def _metrics_in(line: str) -> list[str]:
    """The `curl -w` results on a line, with any response body stripped off.

    curl writes the format string after the body it just printed, so a result
    arrives glued to the end of two kilobytes of HTML. Filtering lines by
    length threw away ninety of the hundred and fourteen results in the lab's
    largest file: the result has to be cut out of the line, not matched
    against it.
    """
    out = []
    for match in _URL_IN_LINE.finditer(line):
        start, end = match.span()
        # Fields written after the URL — status, content type, size.
        after = line[end:end + 120].split("\n")[0]
        # Or before it, when the format string puts the status first.
        before = line[max(0, start - 60):start]
        # The code has to follow the URL immediately, or sit immediately
        # before it. Looking anywhere in a window matched URLs quoted inside
        # JSON bodies, because some number nearby looked like a status — the
        # agent was shown documentation links as if they were scan results.
        if _CODE_AFTER.match(after):
            piece = (match.group(0) + after).strip()
        elif _CODE_BEFORE.search(before):
            piece = (_CODE_BEFORE.search(before).group(1) + " " + match.group(0)).strip()
        else:
            continue
        piece = _PRINTABLE.sub("", piece)
        if piece:
            out.append(piece[:220])
    return out


def _looks_like_http(text: str) -> bool:
    if _STATUS.search(text[:4000]):
        return True
    # A curl loop writes its result lines between the response bodies, so the
    # first line is the command and the shape has to be looked for throughout.
    # Checking only the opening lines missed every such file in the lab.
    return sum(len(_metrics_in(ln)) for ln in text.splitlines()[:4000]) >= 3


def _compress_http(text: str, limit: int) -> Compressed | None:
    lines = text.splitlines()
    metrics = [m for ln in lines for m in _metrics_in(ln)]

    # A curl loop over many URLs: the metric lines are the result, the bodies
    # are noise. This is the 4 MB case from the lab.
    if len(metrics) >= 3:
        notes = [
            f"kept the {len(metrics)} result line(s) and dropped the response "
            f"bodies between them"
        ]
        kept, duplicates = _dedupe(metrics)
        if duplicates:
            notes.append(f"{duplicates} identical result(s) collapsed")
        # The command echo is worth keeping as context; any other first line
        # is part of the output and has already been extracted if it mattered.
        # Prepending it raw put a binary body back into a cleaned result.
        preamble = [_PRINTABLE.sub("", lines[0])] if lines and lines[0].startswith("$ ") else []
        body, elided = _fit(preamble + kept, limit)
        if elided:
            notes.append(f"{elided} result line(s) elided from the middle")
        return Compressed("\n".join(body), len(text), "http-metrics", notes)

    # A single response: the status line and headers are the finding; the body
    # is evidence that is already on disk.
    blank = next((i for i, ln in enumerate(lines) if not ln.strip()), None)
    if blank is None or not _STATUS.search(text[:4000]):
        return None

    head = lines[:blank + 1]
    rest = "\n".join(lines[blank + 1:])
    notes = []
    if _HTML.search(rest[:2000]):
        rest = _strip_html(rest)
        notes.append("the HTML body was reduced to its visible text")

    room = max(limit - len("\n".join(head)) - 200, 600)
    if len(rest) > room:
        half = room // 2
        notes.append(
            f"the body was {len(rest):,} characters; its first and last "
            f"{half:,} are shown"
        )
        rest = rest[:half] + "\n\n[… middle of the body omitted …]\n\n" + rest[-half:]
    return Compressed("\n".join(head) + "\n" + rest, len(text), "http-response", notes)


def _strip_html(markup: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    text = _TAG.sub(" ", text)
    text = _WS.sub(" ", text)
    return "\n".join(ln.strip() for ln in text.splitlines() if ln.strip())


# ---------------------------------------------------------------------------
#  Anything else
# ---------------------------------------------------------------------------
def _compress_text(text: str, limit: int) -> Compressed:
    lines = text.splitlines()
    kept, duplicates = _dedupe(lines)
    notes = []
    if duplicates:
        notes.append(f"{duplicates} repeated line(s) collapsed")
    body, elided = _fit(kept, limit)
    if elided:
        notes.append(f"{elided} line(s) elided from the middle; the first and "
                     f"last are shown")
    return Compressed("\n".join(body), len(text), "text", notes)


def _dedupe(lines: list[str]) -> tuple[list[str], int]:
    """Collapse runs and repeats, counting what went."""
    seen: dict[str, int] = {}
    out, dropped = [], 0
    for line in lines:
        key = line.strip()
        if not key:
            if out and not out[-1].strip():
                dropped += 1
                continue
            out.append(line)
            continue
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            dropped += 1
            continue
        out.append(line)
    return out, dropped


def _fit(lines: list[str], limit: int) -> tuple[list[str], int]:
    """Head and tail of a list of lines, within a character budget."""
    total = sum(len(ln) + 1 for ln in lines)
    if total <= limit:
        return lines, 0

    head: list[str] = []
    tail: list[str] = []
    budget = limit - 120          # room for the elision marker
    low, high = 0, len(lines) - 1
    used = 0
    while low <= high:
        if used + len(lines[low]) + 1 > budget * 0.6 and head:
            break
        head.append(lines[low]); used += len(lines[low]) + 1; low += 1
        if used + len(lines[high]) + 1 > budget:
            break
        tail.append(lines[high]); used += len(lines[high]) + 1; high -= 1

    elided = max(high - low + 1, 0)
    marker = [f"[… {elided} line(s) omitted …]"] if elided else []
    return head + marker + list(reversed(tail)), elided
