"""Styled HTML report.

The same record the Markdown report is built from, laid out for reading on
screen and for printing. Chart geometry is computed here and emitted as inline
SVG, so the report renders with no scripts, no fonts and no network — which
matters for a document that will be read on a client's machine and archived.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..audit import AuditLog
from ..engagement import Engagement
from ..knowledge import KnowledgeBase
from .builder import TEMPLATES, ReportBuilder
from .cvss import subscores

# Severity rows are labelled, so the bars are one series in one hue rather than
# five hues the labels already name. Documented sequential blue, step 450/400;
# both steps pass the lightness band, chroma floor and 3:1 contrast on their
# own surface.
BAR_LIGHT = "#2a78d6"
BAR_DARK = "#3987e5"

SEVERITY_ROWS = ("critical", "high", "medium", "low", "none")
SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "none": "Informational",
}

# Status roles, used only on a finding's own badge — one at a time, beside its
# name — never as adjacent marks for the eye to compare.
STATUS_COLOUR = {
    "critical": "#d03b3b",   # status/critical
    "high": "#ec835a",       # status/serious
    "medium": "#fab219",     # status/warning
    "low": "#2a78d6",
    "none": "#898781",
    "unrated": "#898781",
}

BAR_GEOMETRY = {"label_w": 104, "row_h": 32, "bar_h": 10, "track_w": 300, "value_w": 54}
PLOT = {"w": 430, "h": 280, "pad_l": 54, "pad_b": 44, "pad_t": 16, "pad_r": 18}


@dataclass
class Charts:
    bars: list[dict[str, Any]]
    bars_height: int
    bars_width: int
    matrix: list[dict[str, Any]]
    matrix_ticks: dict[str, list[dict[str, Any]]]
    has_matrix: bool


def _severity_bars(counts: dict[str, int]) -> tuple[list[dict[str, Any]], int, int]:
    rows = [(key, counts.get(key, 0)) for key in SEVERITY_ROWS]
    peak = max((n for _, n in rows), default=0)

    geometry = BAR_GEOMETRY
    bars: list[dict[str, Any]] = []
    for index, (key, count) in enumerate(rows):
        # Width is proportional to count; a zero count draws no mark at all
        # rather than a stub that reads as "a little".
        width = (count / peak) * geometry["track_w"] if peak and count else 0
        bars.append({
            "key": key,
            "label": SEVERITY_LABEL[key],
            "count": count,
            # 2px of surface between adjacent bars comes from the row pitch.
            "y": geometry["pad_t"] if False else index * geometry["row_h"],
            "bar_y": index * geometry["row_h"] + (geometry["row_h"] - geometry["bar_h"]) / 2,
            "width": round(width, 1),
            "label_x": geometry["label_w"] - 10,
            "value_x": geometry["label_w"] + max(width, 0) + 9,
        })

    height = len(rows) * geometry["row_h"]
    width = geometry["label_w"] + geometry["track_w"] + geometry["value_w"]
    return bars, height, width


def _risk_matrix(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list]]:
    """Plot each finding by the two halves its CVSS score is built from.

    The x axis is exploitability and the y axis is impact, both taken straight
    from the vector. This is deliberately not a likelihood/impact matrix: the
    engagement produced no likelihood data, and inventing that axis in a client
    report would be presenting a guess as a measurement.
    """
    # CVSS v3.1 bounds: exploitability tops out at 3.89, impact at 6.05.
    x_max, y_max = 3.9, 6.1
    plot_w = PLOT["w"] - PLOT["pad_l"] - PLOT["pad_r"]
    plot_h = PLOT["h"] - PLOT["pad_t"] - PLOT["pad_b"]

    points: list[dict[str, Any]] = []
    for finding in findings:
        pair = subscores(finding.get("cvss_vector"))
        if pair is None:
            continue
        exploitability, impact = pair
        points.append({
            "id": finding["id"],
            "title": finding["title"],
            "severity": finding.get("severity") or "unrated",
            "colour": STATUS_COLOUR.get(finding.get("severity") or "unrated", "#898781"),
            "exploitability": exploitability,
            "impact": impact,
            "cx": round(PLOT["pad_l"] + (exploitability / x_max) * plot_w, 1),
            "cy": round(PLOT["pad_t"] + plot_h - (impact / y_max) * plot_h, 1),
        })

    ticks = {
        "x": [
            {"value": value,
             "x": round(PLOT["pad_l"] + (value / x_max) * plot_w, 1)}
            for value in (0, 1, 2, 3)
        ],
        "y": [
            {"value": value,
             "y": round(PLOT["pad_t"] + plot_h - (value / y_max) * plot_h, 1)}
            for value in (0, 2, 4, 6)
        ],
    }
    return points, ticks


def build_charts(context: dict[str, Any]) -> Charts:
    bars, bars_height, bars_width = _severity_bars(context["counts"])
    matrix, ticks = _risk_matrix(context["findings"])
    return Charts(
        bars=bars,
        bars_height=bars_height,
        bars_width=bars_width,
        matrix=matrix,
        matrix_ticks=ticks,
        has_matrix=bool(matrix),
    )


def render_html(
    *,
    engagement: Engagement,
    kb: KnowledgeBase,
    audit: AuditLog,
    campaign_id: str,
    executive_summary: str | None = None,
) -> str:
    builder = ReportBuilder(
        engagement=engagement, kb=kb, audit=audit,
        campaign_id=campaign_id, executive_summary=executive_summary,
    )
    context = builder.context()
    context["charts"] = build_charts(context)
    context["bar_light"] = BAR_LIGHT
    context["bar_dark"] = BAR_DARK
    context["status_colour"] = STATUS_COLOUR
    context["plot"] = PLOT
    context["bar_geometry"] = BAR_GEOMETRY

    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=True,
    )
    return env.get_template("report.html.j2").render(**context)


def write_html(destination: str | Path, **kwargs: Any) -> Path:
    path = Path(destination)
    if path.suffix != ".html":
        path = path.with_suffix(".html")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(**kwargs), encoding="utf-8")
    return path


def write_pdf(destination: str | Path, **kwargs: Any) -> Path:
    """Render to PDF. Needs the `pdf` extra; falls back with a clear message."""
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "PDF output needs WeasyPrint: pip install 'swarmstrike[pdf]'. "
            "Alternatively, open the HTML report and print it to PDF — the "
            "stylesheet has print rules."
        ) from exc

    path = Path(destination)
    if path.suffix != ".pdf":
        path = path.with_suffix(".pdf")
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=render_html(**kwargs)).write_pdf(str(path))
    return path
