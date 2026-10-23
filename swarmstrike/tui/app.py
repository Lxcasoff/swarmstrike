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
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from ..engagement import ContractError
from ..orchestrator import Campaign, CampaignConfig, CampaignResult

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
