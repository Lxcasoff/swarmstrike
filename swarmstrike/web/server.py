"""Web dashboard backend.

Serves the live view: start a campaign, watch the team work, read the debate
behind each finding, trip the kill switch, open the report.

Binds to localhost by default. A campaign's record contains unremediated
vulnerabilities in a client's systems, so exposing this beyond the machine it
runs on needs a deliberate decision and an authentication layer in front.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import engagement as contract
from ..approval import Decision, QueueApprovalGate
from ..agents.roster import AGENT_FACES, SPECIALIST_NAMES, face
from ..engagement import ContractError
from ..orchestrator import Campaign, CampaignConfig

STATIC = Path(__file__).parent / "static"
HISTORY_LIMIT = 4_000


def _now() -> str:
    return datetime.now(tz=ZoneInfo("UTC")).isoformat()


class StartRequest(BaseModel):
    engagement_path: str = Field(..., description="Path to a signed engagement contract.")
    domains: list[str] | None = Field(None, description="Limit the roster to these specialists.")
    workspace: str = "campaigns"
    image: str = "swarmstrike/toolbox:latest"
    review_rounds: int = Field(2, ge=1, le=4)
    skip_preflight: bool = False


@dataclass
class Session:
    """One campaign and everyone watching it."""

    id: str
    campaign: Campaign
    history: list[dict[str, Any]] = field(default_factory=list)
    subscribers: set[WebSocket] = field(default_factory=set)
    task: asyncio.Task[Any] | None = None
    status: str = "starting"
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=asyncio.Queue)

    # Where this campaign's shell and script requests wait for a decision.
    # One per session: a decision made in one campaign must not release an
    # action waiting in another.
    gate: QueueApprovalGate = field(default_factory=QueueApprovalGate)

    # ------------------------------------------------------------------
    def record(self, kind: str, payload: dict[str, Any]) -> None:
        """Called from the campaign's event callback. Must not block."""
        event = {"seq": len(self.history), "at": _now(), "kind": kind, "data": payload}
        self.history.append(event)
        if len(self.history) > HISTORY_LIMIT:
            del self.history[: len(self.history) - HISTORY_LIMIT]
        self._track(kind, payload)
        with contextlib.suppress(asyncio.QueueFull):
            self.queue.put_nowait(event)

    def _track(self, kind: str, payload: dict[str, Any]) -> None:
        """Maintain per-agent state so a late subscriber sees the current picture."""
        name = payload.get("agent")
        if kind == "lead":
            name = "lead"
        if not name:
            if kind == "campaign.done":
                self.status = payload.get("status", "done")
                for state in self.agents.values():
                    state["state"] = "idle"
                    state["detail"] = ""
            return

        state = self.agents.setdefault(
            name,
            {"agent": name, **face(name), "state": "idle", "detail": "",
             "tools": 0, "findings": 0, "assets": 0, "refusals": 0},
        )

        if kind == "agent.tool.start":
            state["state"] = "working"
            state["detail"] = f"{payload.get('tool', '')} → {', '.join(payload.get('targets') or []) or '—'}"
            state["tools"] += 1
        elif kind == "agent.tool.end":
            state["state"] = "idle"
            state["detail"] = f"{payload.get('tool', '')} finished in {payload.get('duration_ms', 0)}ms"
        elif kind == "agent.refused":
            state["state"] = "blocked"
            state["detail"] = f"refused: {payload.get('rule', '')}"
            state["refusals"] += 1
        elif kind == "agent.asset":
            state["assets"] += 1
            state["detail"] = f"found {payload.get('kind', '')} {payload.get('value', '')}"
        elif kind == "agent.finding":
            state["findings"] += 1
            state["state"] = "found"
            state["detail"] = f"{payload.get('finding_id', '')} {payload.get('title', '')}"[:120]
        elif kind == "approval.requested":
            # An agent in this state is stopped, waiting on a person.
            state["state"] = "waiting"
            state["detail"] = f"waiting for approval: {payload.get('summary', '')}"[:140]
        elif kind == "approval.decided":
            allowed = payload.get("decision") == "allow"
            state["state"] = "working" if allowed else "blocked"
            state["detail"] = (
                f"approval {payload.get('decision', '')}"
                + (f" — {payload.get('reason', '')}" if payload.get("reason") else "")
            )[:140]
        elif kind == "agent.review.start":
            state["state"] = "thinking"
            state["detail"] = "reviewing a finding"
        elif kind == "agent.review.end":
            state["state"] = "idle"
            state["detail"] = f"ruled: {payload.get('stance', '')}"
        elif kind == "lead":
            state["state"] = "thinking"
            state["detail"] = (payload.get("text") or "").strip()[:160]

    def snapshot(self) -> dict[str, Any]:
        campaign = self.campaign
        try:
            summary = campaign.kb.summary()
        except Exception:  # noqa: BLE001 — the database may not be open yet
            summary = {}
        return {
            "id": self.id,
            "campaign_id": campaign.campaign_id,
            "client": campaign.engagement.engagement.client,
            "mission": campaign.engagement.engagement.mission,
            "status": self.status,
            "halted": campaign.killswitch.engaged,
            "halt_reason": campaign.killswitch.reason,
            "spend": campaign.budget.status(),
            "budget": {
                "usd": round(campaign.budget.spend.usd, 4),
                "max_usd": campaign.engagement.budget.max_usd,
                "tokens": campaign.budget.spend.total_tokens,
                "max_tokens": campaign.engagement.budget.max_tokens,
                "minutes": round(campaign.budget.elapsed_minutes, 1),
                "max_minutes": campaign.engagement.budget.max_wall_clock_minutes,
            },
            "summary": summary,
            "agents": list(self.agents.values()),
            "directory": str(campaign.dir),
            "approvals": [r.as_dict() for r in self.gate.pending()],
            "approval_timeout_s": self.gate.timeout_s,
            "shell_enabled": (
                campaign.engagement.rules_of_engagement.arbitrary_execution.shell
                or campaign.engagement.rules_of_engagement.arbitrary_execution.scripts
            ),
        }


class Dashboard:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}

    def get(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, f"no campaign session {session_id}")
        return session

    async def start(self, request: StartRequest) -> Session:
        unknown = sorted(set(request.domains or []) - set(SPECIALIST_NAMES))
        if unknown:
            raise HTTPException(400, f"unknown specialist(s): {', '.join(unknown)}")

        config = CampaignConfig(
            engagement_path=Path(request.engagement_path),
            workspace_root=Path(request.workspace),
            domains=request.domains or None,
            max_review_rounds=request.review_rounds,
            toolbox_image=request.image,
            skip_preflight=request.skip_preflight,
        )

        session_id = uuid.uuid4().hex[:12]
        gate = QueueApprovalGate()
        try:
            campaign = Campaign(
                config,
                on_event=lambda kind, payload: session.record(kind, payload),
                approval=gate,
            )
        except ContractError as exc:
            raise HTTPException(
                400,
                f"{exc} — autonomous mode will not run against a contract whose integrity "
                f"cannot be proven. Sign it first.",
            ) from exc
        except (FileNotFoundError, OSError) as exc:
            raise HTTPException(400, str(exc)) from exc

        session = Session(id=session_id, campaign=campaign, gate=gate)
        self.sessions[session_id] = session

        # The contract sets how long an operator has before an unapproved
        # action is refused.
        gate.timeout_s = float(
            campaign.engagement.rules_of_engagement.arbitrary_execution.approval_timeout_s
        )

        # Seed the roster so the UI can draw every agent before any of them move.
        for name in ("lead", *(request.domains or SPECIALIST_NAMES), "skeptic", "arbiter", "reporter"):
            session.agents[name] = {
                "agent": name, **face(name), "state": "idle", "detail": "",
                "tools": 0, "findings": 0, "assets": 0, "refusals": 0,
            }

        session.status = "running"
        session.task = asyncio.create_task(self._drive(session))
        asyncio.create_task(self._broadcast(session))
        return session

    async def _drive(self, session: Session) -> None:
        try:
            await session.campaign.run()
        except Exception as exc:  # noqa: BLE001 — surfaced to the dashboard
            session.record("campaign.failed", {"detail": f"{type(exc).__name__}: {exc}"})
            session.status = "failed"
        finally:
            if session.status == "running":
                session.status = "completed"
            session.campaign.close()
            session.record("session.closed", {"status": session.status})

    async def _broadcast(self, session: Session) -> None:
        while True:
            event = await session.queue.get()
            message = json.dumps(event, default=str)
            for socket in list(session.subscribers):
                try:
                    await socket.send_text(message)
                except Exception:  # noqa: BLE001 — a dropped viewer is not an error
                    session.subscribers.discard(socket)
            if event["kind"] == "session.closed":
                break

    async def halt(self, session_id: str, reason: str) -> dict[str, Any]:
        session = self.get(session_id)
        session.campaign.killswitch.engage(f"halted from the dashboard: {reason}")
        session.record("campaign.halted", {"reason": reason, "agent": "operator"})
        return {"halted": True, "reason": reason}


def create_app() -> FastAPI:
    app = FastAPI(title="swarmstrike", docs_url="/api/docs", openapi_url="/api/openapi.json")
    dashboard = Dashboard()

    # ------------------------------------------------------------------
    @app.get("/api/roster")
    async def roster() -> dict[str, Any]:
        return {
            "specialists": list(SPECIALIST_NAMES),
            "faces": AGENT_FACES,
        }

    @app.post("/api/engagement/verify")
    async def verify_contract(body: dict[str, str]) -> dict[str, Any]:
        """Check a contract before offering to run it."""
        path = Path(body.get("engagement_path", ""))
        try:
            engagement = contract.load(path)
        except ContractError as exc:
            return {"ok": False, "reason": str(exc)}

        ok, reason = engagement.verify()
        window_open, window_reason = engagement.window.status()
        meta = engagement.engagement
        return {
            "ok": ok,
            "reason": reason,
            "window_open": window_open,
            "window_reason": window_reason,
            "client": meta.client,
            "mission": meta.mission,
            "authorized_by": f"{meta.authorized_by.name}, {meta.authorized_by.role}",
            "authorization_ref": meta.authorized_by.authorization_ref,
            "budget_usd": engagement.budget.max_usd,
            "scope": {
                "domains": [d.name for d in engagement.scope.domains],
                "cidrs": engagement.scope.cidrs,
                "ips": engagement.scope.ips,
                "urls": engagement.scope.urls,
            },
        }

    @app.post("/api/campaigns")
    async def start_campaign(request: StartRequest) -> dict[str, Any]:
        session = await dashboard.start(request)
        return session.snapshot()

    @app.get("/api/campaigns")
    async def list_campaigns() -> list[dict[str, Any]]:
        return [session.snapshot() for session in dashboard.sessions.values()]

    @app.get("/api/campaigns/{session_id}")
    async def get_campaign(session_id: str) -> dict[str, Any]:
        return dashboard.get(session_id).snapshot()

    @app.post("/api/campaigns/{session_id}/halt")
    async def halt_campaign(session_id: str, body: dict[str, str] | None = None) -> dict[str, Any]:
        return await dashboard.halt(session_id, (body or {}).get("reason", "operator request"))

    @app.get("/api/campaigns/{session_id}/findings")
    async def findings(session_id: str, status: str | None = None) -> list[dict[str, Any]]:
        session = dashboard.get(session_id)
        return session.campaign.kb.findings(status)

    @app.get("/api/campaigns/{session_id}/findings/{finding_id}")
    async def finding_detail(session_id: str, finding_id: str) -> dict[str, Any]:
        session = dashboard.get(session_id)
        kb = session.campaign.kb
        record = kb.finding(finding_id)
        if record is None:
            raise HTTPException(404, f"no finding {finding_id}")
        return {
            "finding": record,
            "evidence": kb.evidence_for(finding_id),
            "reviews": kb.reviews_for(finding_id),
            "arbitrations": kb.arbitrations_for(finding_id),
        }

    @app.get("/api/campaigns/{session_id}/events")
    async def events(session_id: str, since: int = 0) -> list[dict[str, Any]]:
        return dashboard.get(session_id).history[since:]


    @app.get("/api/campaigns/{session_id}/approvals")
    async def list_approvals(session_id: str) -> dict[str, Any]:
        """What is waiting on a human, and what was already decided."""
        session = dashboard.get(session_id)
        return {
            "pending": [r.as_dict() for r in session.gate.pending()],
            "timeout_s": session.gate.timeout_s,
            "decided": [
                {**request.as_dict(), "decision": verdict.decision.value,
                 "reason": verdict.reason, "decided_by": verdict.decided_by}
                for request, verdict in session.gate.history()
            ],
        }

    @app.post("/api/campaigns/{session_id}/approvals/{request_id}")
    async def decide_approval(
        session_id: str, request_id: str, body: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Allow or deny one waiting action.

        The dashboard has no identity of its own, so the decision is recorded
        as having been made at the dashboard rather than by a named person. On
        a shared host, put authentication in front of this.
        """
        session = dashboard.get(session_id)
        payload = body or {}
        raw = (payload.get("decision") or "").strip().lower()
        if raw not in {"allow", "deny"}:
            raise HTTPException(400, "decision must be 'allow' or 'deny'")

        resolved = session.gate.resolve(
            request_id,
            Decision.ALLOW if raw == "allow" else Decision.DENY,
            reason=(payload.get("reason") or "").strip(),
            decided_by="operator (dashboard)",
        )
        if not resolved:
            # Either it was already decided or it timed out and was refused.
            raise HTTPException(
                409,
                "that request is no longer waiting — it was already decided, or it "
                "timed out and was refused.",
            )

        session.record("approval.resolved", {
            "request_id": request_id, "decision": raw,
            "reason": payload.get("reason", ""),
        })
        return {"request_id": request_id, "decision": raw}

    @app.get("/api/campaigns/{session_id}/report")
    async def report(session_id: str) -> HTMLResponse:
        from ..report.html import render_html

        session = dashboard.get(session_id)
        return HTMLResponse(render_html(
            engagement=session.campaign.engagement,
            kb=session.campaign.kb,
            audit=session.campaign.audit,
            campaign_id=session.campaign.campaign_id,
        ))

    @app.websocket("/api/campaigns/{session_id}/stream")
    async def stream(socket: WebSocket, session_id: str) -> None:
        await socket.accept()
        session = dashboard.sessions.get(session_id)
        if session is None:
            await socket.send_text(json.dumps({"kind": "error", "data": {"detail": "no such session"}}))
            await socket.close()
            return

        session.subscribers.add(socket)
        try:
            # Replay so a viewer arriving mid-campaign sees the whole picture.
            await socket.send_text(json.dumps(
                {"kind": "snapshot", "data": session.snapshot()}, default=str
            ))
            for event in session.history:
                await socket.send_text(json.dumps(event, default=str))

            while True:
                # The client sends keepalives; we only need to notice it leaving.
                await socket.receive_text()
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            pass
        finally:
            session.subscribers.discard(socket)

    # ------------------------------------------------------------------
    @app.get("/")
    async def index() -> FileResponse:
        page = STATIC / "index.html"
        if not page.is_file():
            return JSONResponse({"detail": "dashboard assets are missing"}, status_code=500)
        return FileResponse(page)

    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

    return app


def serve(host: str = "127.0.0.1", port: int = 8787, reload: bool = False) -> None:
    import uvicorn

    uvicorn.run(
        "swarmstrike.web.server:create_app",
        host=host, port=port, reload=reload, factory=True, log_level="info",
    )
