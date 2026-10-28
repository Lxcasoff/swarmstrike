"""Attack paths, prepared for the report.

A path is the finding a client acts on most directly: not that four separate
weaknesses exist, but that one leads to the next and the last one reaches their
data. The graph already holds the steps and the edges that join them; this
turns them into something a reader follows in one pass.

Each step carries a small icon for what kind of step it is, and always the
written label beside it. The icon speeds up reading a four-step chain; it never
carries the meaning alone, because a glyph that fails to render in a client's
PDF viewer must not take the sense of the step with it.
"""

from __future__ import annotations

from typing import Any

# Icon and label per fact category. The label is what the reader relies on.
STEP_KIND: dict[str, tuple[str, str]] = {
    "finding":   ("\U0001FAB2", "Weakness"),          # 🪲
    "exploit":   ("\U0001F4A5", "Exploitation"),       # 💥
    "access":    ("\U0001F513", "Access gained"),      # 🔓
    "auth":      ("\U0001F511", "Credentials"),        # 🔑
    "target":    ("\U0001F3AF", "Asset"),              # 🎯
    "infra":     ("\U0001F5A7", "Infrastructure"),     # 🖧
    "business":  ("\U0001F4BC", "Business process"),   # 💼
    "chain":     ("⛓",     "Chained step"),       # ⛓
    "poc":       ("\U0001F4CE", "Proof"),              # 📎
    "detection": ("\U0001F4E1", "Detection"),          # 📡
    "note":      ("\U0001F4DD", "Observation"),        # 📝
}

FALLBACK = ("•", "Step")


def step_kind(category: str | None) -> tuple[str, str]:
    return STEP_KIND.get((category or "").lower(), FALLBACK)


def describe_path(steps: list[dict[str, Any]]) -> str:
    """One line naming where the path starts and where it ends."""
    if not steps:
        return ""
    first, last = steps[0], steps[-1]
    _, start_label = step_kind(first.get("category"))
    _, end_label = step_kind(last.get("category"))
    return f"from {start_label.lower()} to {end_label.lower()}"


def prepare(paths: list[list[dict[str, Any]]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Decorate the graph's paths for the report.

    `findings` is used only to cross-reference: where a step was also raised as
    a deliverable finding, the reader gets the finding's identifier so they can
    turn to its reproduction steps rather than taking the chain on trust.
    """
    by_id = {f["id"]: f for f in findings}

    prepared: list[dict[str, Any]] = []
    for index, steps in enumerate(paths, start=1):
        rendered = []
        for position, fact in enumerate(steps, start=1):
            icon, label = step_kind(fact.get("category"))
            finding = by_id.get(fact.get("related_finding_id") or "")
            rendered.append({
                "position": position,
                "icon": icon,
                "label": label,
                "fact_key": fact.get("fact_key", ""),
                "summary": fact.get("summary", ""),
                "confidence": fact.get("confidence", "tentative"),
                "finding_id": finding["id"] if finding else None,
                "finding_title": finding["title"] if finding else None,
                "severity": finding.get("severity") if finding else None,
                "last": position == len(steps),
            })

        # A chain is only as strong as its weakest step: one unverified link
        # and the whole path is a hypothesis, which the report has to say.
        unverified = [s for s in rendered if s["confidence"] != "confirmed"]
        prepared.append({
            "number": index,
            "length": len(rendered),
            "steps": rendered,
            "describe": describe_path(steps),
            "fully_confirmed": not unverified,
            "unverified_steps": [s["fact_key"] for s in unverified],
            "findings": [s["finding_id"] for s in rendered if s["finding_id"]],
        })

    # Longest first: the deepest chain is what the client needs to see.
    prepared.sort(key=lambda p: (-p["length"], p["number"]))
    return prepared
