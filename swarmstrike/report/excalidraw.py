"""The campaign map as an Excalidraw scene.

The console draws the map so it can be watched while the work happens. This
writes the same board as a `.excalidraw` file, which is a different job: a
consultant opens it in Excalidraw, moves things where they want them, adds the
boxes and arrows the tool had no way to know about, and exports a picture for
the report.

Generating the format rather than embedding the editor is deliberate. The
console loads nothing from a CDN and carries no framework, and the thing worth
having from Excalidraw is the editing — which happens in Excalidraw. A scene
file costs us no dependency and gives the operator the whole tool.

Format: https://docs.excalidraw.com/docs/codebase/json-schema (MIT).
"""

from __future__ import annotations

import json
import random
from typing import Any

# What a node amounted to, in the palette the console uses, so a board exported
# from one looks like the board in the other.
CATEGORY_COLOURS = {
    "auth":      ("#dc3545", "#ffe3e5"),     # credentials in hand
    "access":    ("#fd7e14", "#ffeddb"),     # access gained
    "exploit":   ("#b26a00", "#fff4d6"),     # weakness proven
    "poc":       ("#b26a00", "#fff4d6"),
    "chain":     ("#7c3aed", "#ede9fe"),     # steps joined up
    "business":  ("#0d9488", "#d8f3f0"),     # business impact
    "detection": ("#64748b", "#e9edf2"),     # noticed by defences
    "target":    ("#0066ff", "#e0ecff"),     # surface mapped
    "infra":     ("#0066ff", "#e0ecff"),
}
SEVERITY_COLOURS = {
    "critical": ("#a01828", "#ffd9de"),
    "high":     ("#dc3545", "#ffe3e5"),
    "medium":   ("#b26a00", "#fff4d6"),
    "low":      ("#0066ff", "#e0ecff"),
}
ASSET_COLOUR = ("#475568", "#eef1f5")
DEAD_END_COLOUR = ("#8a94a6", "transparent")

COLUMNS = ("asset", "fact", "finding")
NODE_W, NODE_H, GAP_Y, GAP_X, MARGIN = 230, 70, 28, 150, 60


def _rand() -> int:
    return random.randint(0, 2**31 - 1)


def _base(**over: Any) -> dict[str, Any]:
    element = {
        "id": "", "x": 0, "y": 0, "width": 0, "height": 0, "angle": 0,
        "strokeColor": "#1e1e1e", "backgroundColor": "transparent",
        "fillStyle": "solid", "strokeWidth": 2, "strokeStyle": "solid",
        "roughness": 1, "opacity": 100, "groupIds": [], "frameId": None,
        "roundness": {"type": 3}, "seed": _rand(), "version": 1,
        "versionNonce": _rand(), "isDeleted": False, "boundElements": None,
        "updated": 1, "link": None, "locked": False,
    }
    element.update(over)
    return element


def _colours(node: dict[str, Any]) -> tuple[str, str]:
    if node.get("negative"):
        return DEAD_END_COLOUR
    if node["type"] == "asset":
        return ASSET_COLOUR
    if node["type"] == "finding":
        return SEVERITY_COLOURS.get(node.get("severity", ""), ("#b26a00", "#fff4d6"))
    return CATEGORY_COLOURS.get(node.get("category", ""), ("#0066ff", "#e0ecff"))


def scene(graph: dict[str, Any], *, title: str = "") -> dict[str, Any]:
    """An Excalidraw scene for a campaign map, ready to open and rearrange."""
    nodes = graph.get("nodes") or []
    elements: list[dict[str, Any]] = []
    placed: dict[str, dict[str, Any]] = {}
    rows = dict.fromkeys(COLUMNS, 0)

    if title:
        elements.append(_base(
            id="title", type="text", x=MARGIN, y=MARGIN - 54,
            width=len(title) * 11, height=34, text=title, fontSize=28,
            fontFamily=1, textAlign="left", verticalAlign="top",
            strokeColor="#1e1e1e", originalText=title, autoResize=True,
            lineHeight=1.25,
        ))

    for index, column in enumerate(COLUMNS):
        label = {"asset": "FOUND", "fact": "ESTABLISHED", "finding": "CONFIRMED"}[column]
        elements.append(_base(
            id=f"col-{column}", type="text",
            x=MARGIN + index * (NODE_W + GAP_X), y=MARGIN - 12,
            width=140, height=20, text=label, fontSize=14, fontFamily=3,
            textAlign="left", verticalAlign="top", strokeColor="#8a94a6",
            originalText=label, autoResize=True, lineHeight=1.25,
        ))

    for node in nodes:
        if node["type"] not in rows:
            continue
        column = COLUMNS.index(node["type"])
        x = MARGIN + column * (NODE_W + GAP_X)
        y = MARGIN + 24 + rows[node["type"]] * (NODE_H + GAP_Y)
        rows[node["type"]] += 1

        stroke, fill = _colours(node)
        box_id = f"box-{len(elements)}"
        text_id = f"txt-{len(elements)}"
        label = str(node.get("label", ""))
        detail = str(node.get("detail", ""))[:60]
        text = f"{label}\n{detail}" if detail else label

        elements.append(_base(
            id=box_id, type="rectangle", x=x, y=y, width=NODE_W, height=NODE_H,
            strokeColor=stroke, backgroundColor=fill,
            strokeStyle="dashed" if node.get("negative") else "solid",
            boundElements=[{"id": text_id, "type": "text"}],
        ))
        elements.append(_base(
            id=text_id, type="text", x=x + 8, y=y + 10,
            width=NODE_W - 16, height=NODE_H - 20, text=text,
            fontSize=14, fontFamily=3, textAlign="center", verticalAlign="middle",
            strokeColor="#1e1e1e", containerId=box_id, originalText=text,
            autoResize=False, lineHeight=1.25,
        ))
        placed[node["id"]] = {"box": box_id, "x": x, "y": y}

    for edge in graph.get("edges") or []:
        source, target = placed.get(edge["from"]), placed.get(edge["to"])
        if not source or not target:
            continue
        x1, y1 = source["x"] + NODE_W, source["y"] + NODE_H / 2
        x2, y2 = target["x"], target["y"] + NODE_H / 2
        enables = edge.get("kind") == "enables"
        arrow_id = f"arrow-{len(elements)}"
        elements.append(_base(
            id=arrow_id, type="arrow", x=x1, y=y1,
            width=x2 - x1, height=y2 - y1,
            points=[[0, 0], [x2 - x1, y2 - y1]],
            strokeColor="#dc3545" if enables else "#8a94a6",
            strokeWidth=3 if enables else 1.5,
            roundness={"type": 2}, endArrowhead="arrow", startArrowhead=None,
            startBinding={"elementId": source["box"], "focus": 0, "gap": 6},
            endBinding={"elementId": target["box"], "focus": 0, "gap": 6},
            elbowed=False,
        ))
        for end in (source, target):
            for element in elements:
                if element["id"] == end["box"]:
                    bound = list(element.get("boundElements") or [])
                    bound.append({"id": arrow_id, "type": "arrow"})
                    element["boundElements"] = bound

    return {
        "type": "excalidraw",
        "version": 2,
        "source": "https://github.com/Lxcasoff/swarmstrike",
        "elements": elements,
        "appState": {"viewBackgroundColor": "#ffffff", "gridModeEnabled": False},
        "files": {},
    }


def dumps(graph: dict[str, Any], *, title: str = "") -> str:
    return json.dumps(scene(graph, title=title), indent=2)
