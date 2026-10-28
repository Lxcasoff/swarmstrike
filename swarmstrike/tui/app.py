"""Live campaign view.

A running campaign is a dozen agents working in parallel, and a scrolling log
makes it hard to see what is actually happening. This shows the lead's
reasoning on one side, rulings as they land on the other, and the budget
burning down in the header — plus a key that stops everything.
"""

from __future__ import annotations

import asyncio
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static

from ..approval import ApprovalRequest, Decision, QueueApprovalGate
from ..engagement import ContractError
from ..orchestrator import Campaign, CampaignConfig, CampaignResult

AGENT_STATE_STYLE = {
    "working": "cyan", "thinking": "magenta", "waiting": "bold yellow",
    "blocked": "red", "found": "bold yellow", "idle": "dim",
}

VERDICT_STYLE = {
    "confirmed": "bold red",
    "rejected": "dim",
    "theoretical": "yellow",
    "needs_work": "cyan",
}


class StatusBar(Static):
    """Phase and spend, refreshed as the campaign runs."""

    def __init__(self) -> None:
        super().__init__("starting…", id="status")
        self.phase = "starting"
        self.spend = ""
        self.note = ""

    def refresh_text(self) -> None:
        parts = [f"[bold]{self.phase}[/]"]
        if self.spend:
            parts.append(self.spend)
        if self.note:
            parts.append(f"[yellow]{self.note}[/]")
        self.update("   ·   ".join(parts))


class ApprovalScreen(ModalScreen[tuple[Decision, str]]):
    """Asks the operator about one action that could not be checked.

    It takes over the screen rather than waiting in a corner, because the
    agent that asked is stopped until this is answered. Dismissing without
    deciding is not offered: the campaign has to go one way or the other, and
    the gate refuses on its own timeout anyway.
    """

    CSS = """
    ApprovalScreen { align: center middle; }
    #box {
        width: 90%; max-width: 110; height: auto; max-height: 90%;
        border: round $warning; background: $surface; padding: 1 2;
    }
    #who { color: $warning; text-style: bold; }
    #why { color: $text-muted; margin: 1 0 0 0; }
    #script {
        border: round $panel; background: $boost; padding: 1;
        margin: 1 0; max-height: 14;
    }
    #notes { color: $text-muted; margin: 0 0 1 0; }
    #guarantee { color: $text-muted; margin: 0 0 1 0; }
    #actions { height: auto; align: left middle; }
    #actions Button { margin: 0 1 0 0; }
    #reason { margin: 0 0 1 0; }
    """

    BINDINGS = [
        Binding("a", "allow", "Allow", show=True),
        Binding("d", "deny", "Deny", show=True),
        Binding("escape", "deny", "Deny", show=False),
    ]

    def __init__(self, request: ApprovalRequest, timeout_s: float) -> None:
        super().__init__()
        self.request = request
        self.timeout_s = timeout_s

    def compose(self) -> ComposeResult:
        request = self.request
        with VerticalScroll(id="box"):
            yield Label(
                f"{request.agent} is waiting for approval  ·  {request.kind}",
                id="who",
            )
            yield Label(
                f"Why it says it needs this: {request.rationale}" if request.rationale
                else "No rationale was given. An agent that cannot say why a "
                     "structured command will not do is usually reaching for a "
                     "shell out of habit.",
                id="why",
            )
            yield Static(request.detail, id="script")
            if request.risk_notes:
                yield Label(
                    "\n".join(f"  · {note}" for note in request.risk_notes),
                    id="notes",
                )
            yield Label(
                "Approving runs this in the campaign container with the "
                "engagement's network and limits, and records it in the audit "
                "chain. It is not scope-enforced: a shell command can reach a "
                "target this check could not see.",
                id="guarantee",
            )
            yield Input(placeholder="reason (recorded in the audit log)", id="reason")
            with Horizontal(id="actions"):
                yield Button("Allow  (a)", variant="success", id="allow")
                yield Button("Deny  (d)", variant="error", id="deny")

    def on_mount(self) -> None:
        self.set_timer(self.timeout_s, self._expire)

    def _reason(self) -> str:
        try:
            return self.query_one("#reason", Input).value.strip()
        except Exception:  # noqa: BLE001 — the screen may already be closing
            return ""

    def _expire(self) -> None:
        # The gate times out on its own; closing here keeps the view honest
        # rather than leaving a decision prompt for something already refused.
        if self.is_running:
            self.dismiss((Decision.DENY, "no decision before the contract's timeout"))

    def action_allow(self) -> None:
        self.dismiss((Decision.ALLOW, self._reason() or "approved in the live view"))

    def action_deny(self) -> None:
        self.dismiss((Decision.DENY, self._reason() or "refused in the live view"))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "allow":
            self.action_allow()
        else:
            self.action_deny()


class SwarmstrikeApp(App[int]):
    CSS = """
    Screen { layout: vertical; }
    #status { padding: 0 1; height: 1; background: $panel; }
    #panes { height: 1fr; }
    #activity { width: 3fr; border: round $primary; padding: 0 1; }
    #rulings { width: 2fr; border: round $secondary; }
    """

    BINDINGS = [
        Binding("k", "halt", "Halt campaign", show=True),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(self, config: CampaignConfig) -> None:
        super().__init__()
        self.config = config
        self.campaign: Campaign | None = None
        self.result: CampaignResult | None = None
        self.events: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        self._finished = asyncio.Event()

        # Textual owns stdin, so the console gate cannot be used here. This one
        # is answered by the modal below, which is what makes the shell tier
        # usable from the live view at all.
        self.gate = QueueApprovalGate()
        self.gate.on_request.append(self._approval_arrived)

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar()
        with Horizontal(id="panes"):
            yield RichLog(id="activity", markup=True, wrap=True, highlight=False)
            with Vertical(id="rulings"):
                yield DataTable(id="verdicts", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#verdicts", DataTable)
        table.add_columns("Finding", "Verdict", "Severity", "Conf.")
        self.query_one(StatusBar).refresh_text()
        self.drain_events()
        self.drive_campaign()

    # ------------------------------------------------------------------
    @work(exclusive=True)
    async def drive_campaign(self) -> None:
        log = self.query_one("#activity", RichLog)
        status = self.query_one(StatusBar)

        try:
            self.campaign = Campaign(
                self.config,
                on_event=lambda kind, payload: self.events.put_nowait((kind, payload)),
                approval=self.gate,
            )
        except ContractError as exc:
            status.note = "contract rejected"
            status.refresh_text()
            log.write(f"[bold red]✗ {exc}[/]")
            log.write(
                "\n[dim]Autonomous mode will not run against a contract whose integrity "
                "cannot be proven. Sign it first:[/]\n"
                f"  swarmstrike engagement sign {self.config.engagement_path}"
            )
            self._finished.set()
            return
        except Exception as exc:  # noqa: BLE001
            log.write(f"[bold red]✗ {type(exc).__name__}: {exc}[/]")
            self._finished.set()
            return

        self.sub_title = f"{self.campaign.engagement.engagement.client} · {self.campaign.campaign_id}"
        self.gate.timeout_s = float(
            self.campaign.engagement.rules_of_engagement
            .arbitrary_execution.approval_timeout_s
        )

        try:
            self.result = await self.campaign.run()
        except Exception as exc:  # noqa: BLE001
            log.write(f"[bold red]✗ campaign failed: {type(exc).__name__}: {exc}[/]")
        finally:
            self.campaign.close()
            self._finished.set()

    @work(exclusive=False)
    async def drain_events(self) -> None:
        log = self.query_one("#activity", RichLog)
        table = self.query_one("#verdicts", DataTable)
        status = self.query_one(StatusBar)

        while True:
            try:
                kind, payload = await asyncio.wait_for(self.events.get(), timeout=0.4)
            except asyncio.TimeoutError:
                if self._finished.is_set() and self.events.empty():
                    break
                continue

            if kind == "campaign.start":
                log.write(f"[cyan]campaign {payload['campaign_id']}[/]")
                log.write(f"[dim]{payload['directory']}[/]\n")
            elif kind == "preflight":
                marker = "[green]✓[/]" if payload["ready"] else "[red]✗[/]"
                log.write(f"{marker} {payload['detail']}")
            elif kind == "phase":
                status.phase = payload["name"]
                status.refresh_text()
                log.write(f"\n[bold reverse] {payload['name']} [/]\n")
            elif kind == "lead":
                log.write(payload["text"].strip() + "\n")
            elif kind == "lead.error":
                log.write(f"[yellow]⚠ lead: {payload['subtype']}[/] {payload['detail'][:200]}")
            elif kind == "round.start":
                status.phase = f"assessment · round {payload['round']}/{payload['of']}"
                status.refresh_text()
            elif kind == "round.end":
                log.write(
                    f"[dim]round {payload['round']}: {payload['actions']} action(s), "
                    f"{payload['new_facts']} new fact(s), "
                    f"{payload['new_findings']} new finding(s)[/]"
                )
            elif kind == "action.dispatched":
                log.write(
                    f"[cyan]\u2192 {payload['agent']}[/] [dim]{payload['task_key']}[/]  "
                    f"{payload['brief'][:160]}"
                )
            elif kind == "action.finished":
                log.write(
                    f"[dim]\u2190 {payload['agent']} done: {payload['new_facts']} fact(s), "
                    f"{payload['new_findings']} finding(s)[/]"
                )
            elif kind in {"search.complete", "search.converged", "search.stopped"}:
                status.note = payload.get("reason", "")
                status.refresh_text()
                log.write(f"[bold]{kind}[/] [dim]{payload.get('reason', '')}[/]")
            elif kind == "approval.requested":
                log.write(
                    f"[bold yellow]\u270b {payload.get('agent', '')} is waiting for "
                    f"approval[/] [dim]{payload.get('summary', '')}[/]"
                )
            elif kind == "approval.decided":
                marker = ("[green]allowed[/]" if payload.get("decision") == "allow"
                          else "[red]refused[/]")
                log.write(f"  approval {marker} [dim]{payload.get('reason', '')}[/]")
            elif kind == "recipe.invalid":
                log.write(
                    f"[yellow]\u26a0 recipe {payload['file']} could not be loaded:[/] "
                    f"{payload['detail'][:140]}"
                )
            elif kind == "spend":
                status.spend = payload["status"]
                status.refresh_text()
            elif kind == "ruling":
                style = VERDICT_STYLE.get(payload["verdict"], "white")
                table.add_row(
                    payload["finding_id"],
                    f"[{style}]{payload['verdict']}[/]",
                    payload["severity"],
                    f"{payload['confidence']:.0%}",
                )
            elif kind in {"campaign.halted", "budget.exhausted", "window.closed", "review.stopped"}:
                status.note = payload.get("reason", kind)
                status.refresh_text()
                log.write(f"[bold yellow]⚠ {kind}: {payload.get('reason', '')}[/]")
            elif kind == "report.written":
                log.write(f"\n[bold green]✓ report written to {payload['path']}[/]")
            elif kind == "report.failed":
                log.write(f"[red]✗ report assembly failed: {payload['detail']}[/]")
            elif kind == "campaign.done":
                status.phase = f"done ({payload['status']})"
                status.refresh_text()
                log.write(
                    f"\n[bold]finished:[/] {payload['status']}   "
                    f"[dim]{payload['spend']}[/]\n"
                    "[dim]press q to exit[/]"
                )

    # ------------------------------------------------------------------
    def _approval_arrived(self, request: ApprovalRequest) -> None:
        """Called by the gate when an agent blocks. Hands off to the UI thread."""
        self.call_from_thread(self._ask_operator, request)

    def _ask_operator(self, request: ApprovalRequest) -> None:
        def decided(result: tuple[Decision, str] | None) -> None:
            decision, reason = result or (
                Decision.DENY, "the approval screen closed without a decision"
            )
            self.gate.resolve(request.id, decision, reason, decided_by="operator (live view)")

        self.push_screen(ApprovalScreen(request, self.gate.timeout_s), decided)

    # ------------------------------------------------------------------
    def action_halt(self) -> None:
        """Stop the campaign. Findings already recorded stay valid."""
        log = self.query_one("#activity", RichLog)
        if self.campaign is None:
            log.write("[yellow]nothing running to halt[/]")
            return
        self.campaign.killswitch.engage("halted from the live view")
        status = self.query_one(StatusBar)
        status.note = "halting — agents stop before their next command"
        status.refresh_text()
        log.write(
            "[bold yellow]⚠ halt requested.[/] Agents stop before their next command. "
            "Findings already recorded will still be reviewed and reported."
        )

    def action_quit_app(self) -> None:
        if self.campaign is not None and not self._finished.is_set():
            self.campaign.killswitch.engage("live view closed")
        self.exit(0 if self.result and self.result.status == "completed" else 2)


def run_with_tui(config: CampaignConfig) -> int:
    return SwarmstrikeApp(config).run() or 0
