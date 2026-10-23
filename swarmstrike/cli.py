"""Command line interface."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import engagement as contract
from .audit import AuditLog
from .engagement import SCOPE_KEY_ENV, ContractError
from .knowledge import KnowledgeBase

# The agent harness is only needed to run a campaign. Importing it lazily keeps
# the contract and audit commands usable without it — which matters, because
# signing and reviewing a contract is work you do before installing anything.
SPECIALIST_NAMES = (
    "recon", "network", "web", "api", "cloud", "ad", "code", "crypto",
)

app = typer.Typer(
    name="swarmstrike",
    help="Multi-agent orchestration for authorized penetration tests.",
    no_args_is_help=True,
    add_completion=False,
)
engagement_app = typer.Typer(help="Create, sign and verify engagement contracts.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect and verify the campaign audit record.", no_args_is_help=True)
app.add_typer(engagement_app, name="engagement")
app.add_typer(audit_app, name="audit")

console = Console()
err = Console(stderr=True)

EXAMPLE = Path(__file__).resolve().parent.parent / "engagement.example.yaml"


def _fail(message: str, code: int = 1) -> None:
    err.print(f"[bold red]✗[/] {message}")
    raise typer.Exit(code)


# ---------------------------------------------------------------------------
#  engagement
# ---------------------------------------------------------------------------
@engagement_app.command("init")
def engagement_init(
    path: Path = typer.Argument(Path("engagement.yaml"), help="Where to write the contract."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a starter engagement contract to fill in."""
    if path.exists() and not force:
        _fail(f"{path} already exists. Pass --force to overwrite it.")
    if not EXAMPLE.is_file():
        _fail(f"the packaged example contract is missing from {EXAMPLE}")

    shutil.copyfile(EXAMPLE, path)
    console.print(f"[bold green]✓[/] wrote {path}")
    console.print(
        "\nFill in the client, the written authorization, the testing window and the "
        "scope, then sign it:\n"
        f"  [cyan]export {SCOPE_KEY_ENV}=$(openssl rand -hex 32)[/]\n"
        f"  [cyan]swarmstrike engagement sign {path}[/]\n\n"
        "Keep that key outside the repository. It is what makes the contract tamper-evident."
    )


@engagement_app.command("sign")
def engagement_sign(
    path: Path = typer.Argument(..., help="Contract to sign in place."),
) -> None:
    """Sign a contract so a campaign can run against it."""
    try:
        signed = contract.sign_file(path)
    except ContractError as exc:
        _fail(str(exc))

    console.print(f"[bold green]✓[/] signed {path}")
    console.print(f"  fingerprint [dim]{signed.integrity.fingerprint}[/]")
    console.print(f"  signed at   [dim]{signed.integrity.signed_at}[/]")


@engagement_app.command("verify")
def engagement_verify(
    path: Path = typer.Argument(..., help="Contract to verify."),
) -> None:
    """Check a contract has not been modified since it was signed."""
    try:
        engagement = contract.load(path)
    except ContractError as exc:
        _fail(str(exc))

    ok, reason = engagement.verify()
    if not ok:
        _fail(reason)
    console.print(f"[bold green]✓[/] {reason}")

    meta = engagement.engagement
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("Client", meta.client)
    table.add_row("Mission", meta.mission)
    table.add_row("Authorized by", f"{meta.authorized_by.name}, {meta.authorized_by.role}")
    table.add_row("Authorization", meta.authorized_by.authorization_ref)
    table.add_row("Window", f"{engagement.window.start} → {engagement.window.end}")
    table.add_row("Budget", f"${engagement.budget.max_usd:.2f}")
    console.print(table)

    open_, window_reason = engagement.window.status()
    marker = "[green]open[/]" if open_ else "[yellow]closed[/]"
    console.print(f"\nTesting window is {marker} — {window_reason}")


@engagement_app.command("check")
def engagement_check(
    path: Path = typer.Argument(..., help="Contract to check against."),
    targets: list[str] = typer.Argument(..., help="Hosts, URLs or addresses to test."),
) -> None:
    """Ask the scope guard how it would rule on specific targets.

    Run this before a campaign to confirm the contract says what you think.
    """
    from .scope import ScopeGuard

    try:
        engagement = contract.load(path)
    except ContractError as exc:
        _fail(str(exc))

    guard = ScopeGuard(engagement)
    table = Table("Target", "Decision", "Rule", "Reason", box=None, padding=(0, 2))
    refused = 0

    for target in targets:
        decision = guard.check_url(target) if "://" in target else guard.check_host(target)
        refused += not decision.allowed
        table.add_row(
            target,
            "[green]allow[/]" if decision.allowed else "[red]refuse[/]",
            decision.rule,
            decision.reason,
        )

    console.print(table)
    console.print(f"\n{len(targets) - refused} allowed, {refused} refused")


# ---------------------------------------------------------------------------
#  run
# ---------------------------------------------------------------------------
@app.command("run")
def run(
    engagement_path: Path = typer.Argument(..., help="Signed engagement contract."),
    domains: list[str] = typer.Option(
        None, "--domain", "-d",
        help=f"Limit the roster to these specialists. Available: {', '.join(SPECIALIST_NAMES)}",
    ),
    workspace: Path = typer.Option(Path("campaigns"), "--workspace", help="Where campaigns are written."),
    image: str = typer.Option("swarmstrike/toolbox:latest", "--image", help="Toolbox container image."),
    resume: str = typer.Option(None, "--resume", help="Resume an existing campaign by id."),
    rounds: int = typer.Option(2, "--review-rounds", min=1, max=4, help="Maximum review rounds per finding."),
    tui: bool = typer.Option(False, "--tui", help="Live view instead of streaming log."),
    skip_preflight: bool = typer.Option(
        False, "--skip-preflight", help="Skip the Docker and toolbox image check."
    ),
) -> None:
    """Run a campaign against a signed engagement contract."""
    unknown = sorted(set(domains or []) - set(SPECIALIST_NAMES))
    if unknown:
        _fail(f"unknown specialist(s): {', '.join(unknown)}. Available: {', '.join(SPECIALIST_NAMES)}")

    try:
        from .orchestrator import Campaign, CampaignConfig
    except ImportError as exc:
        _fail(
            f"the agent harness is not available: {exc}\n"
            f"Install it with: pip install claude-agent-sdk"
        )

    config = CampaignConfig(
        engagement_path=engagement_path,
        workspace_root=workspace,
        domains=list(domains) if domains else None,
        max_review_rounds=rounds,
        toolbox_image=image,
        resume=resume,
        skip_preflight=skip_preflight,
    )

    if tui:
        from .tui.app import run_with_tui

        raise typer.Exit(run_with_tui(config))

    try:
        campaign = Campaign(config, on_event=_print_event)
    except ContractError as exc:
        _fail(
            f"{exc}\n\n"
            f"Autonomous mode will not run against a contract whose integrity cannot be "
            f"proven. Sign it with: swarmstrike engagement sign {engagement_path}"
        )

    try:
        result = asyncio.run(campaign.run())
    except KeyboardInterrupt:
        campaign.killswitch.engage("interrupted at the console")
        err.print("\n[yellow]⚠[/] halted. The campaign record and findings are intact.")
        raise typer.Exit(130) from None
    finally:
        campaign.close()

    _print_result(result)
    raise typer.Exit(0 if result.status == "completed" else 2)


def _print_event(kind: str, payload: dict) -> None:
    if kind == "campaign.start":
        console.print(Panel(
            f"[bold]{payload['client']}[/]\ncampaign [cyan]{payload['campaign_id']}[/]\n"
            f"[dim]{payload['directory']}[/]",
            title="swarmstrike", border_style="cyan",
        ))
    elif kind == "preflight":
        marker = "[green]✓[/]" if payload["ready"] else "[red]✗[/]"
        console.print(f"{marker} {payload['detail']}")
    elif kind == "phase":
        console.rule(f"[bold]{payload['name']}[/]")
    elif kind == "lead":
        console.print(payload["text"].strip())
    elif kind == "lead.error":
        err.print(f"[yellow]⚠ lead agent: {payload['subtype']}[/] {payload['detail'][:300]}")
    elif kind == "ruling":
        colour = {
            "confirmed": "red", "rejected": "dim", "theoretical": "yellow",
        }.get(payload["verdict"], "white")
        console.print(
            f"  [{colour}]{payload['verdict']:<12}[/] {payload['finding_id']} "
            f"[dim]{payload['severity']} · confidence {payload['confidence']:.0%}[/]"
        )
    elif kind == "spend":
        console.print(f"[dim]  spend {payload['status']}[/]")
    elif kind in {"campaign.halted", "budget.exhausted", "window.closed", "review.stopped"}:
        err.print(f"[yellow]⚠ {kind}:[/] {payload.get('reason', '')}")
    elif kind == "report.written":
        console.print(f"[bold green]✓[/] report written to {payload['path']}")
    elif kind == "report.failed":
        err.print(f"[red]✗ report assembly failed:[/] {payload['detail']}")


def _print_result(result) -> None:
    counts = result.summary.get("confirmed_by_severity", {})
    table = Table("Severity", "Confirmed", box=None, padding=(0, 2))
    for severity in ("critical", "high", "medium", "low"):
        if counts.get(severity):
            table.add_row(severity, str(counts[severity]))

    console.rule("[bold]result[/]")
    console.print(f"status   {result.status}")
    console.print(f"spend    {result.spend}")
    console.print(f"assets   {result.summary.get('assets', 0)}")
    console.print(f"commands {result.summary.get('commands', 0)}")
    if counts:
        console.print(table)
    else:
        console.print("[dim]no confirmed findings[/]")
    if result.halted_reason:
        console.print(f"[yellow]note[/]    {result.halted_reason}")
    if result.report_path:
        console.print(f"report   {result.report_path}")


# ---------------------------------------------------------------------------
#  audit
# ---------------------------------------------------------------------------
@audit_app.command("verify")
def audit_verify(
    campaign_dir: Path = typer.Argument(..., help="Campaign directory, or an audit.jsonl file."),
) -> None:
    """Verify the audit chain has not been altered."""
    path = campaign_dir / "audit.jsonl" if campaign_dir.is_dir() else campaign_dir
    if not path.is_file():
        _fail(f"no audit log at {path}")

    intact, reason, count = AuditLog(path).verify()
    if not intact:
        _fail(f"audit chain FAILED after {count} entries: {reason}")
    console.print(f"[bold green]✓[/] {reason}")


@audit_app.command("show")
def audit_show(
    campaign_dir: Path = typer.Argument(..., help="Campaign directory, or an audit.jsonl file."),
    event: str = typer.Option(None, "--event", help="Only this event type, e.g. tool.refused."),
    limit: int = typer.Option(40, "--limit", help="How many entries to show."),
) -> None:
    """Print the audit record."""
    path = campaign_dir / "audit.jsonl" if campaign_dir.is_dir() else campaign_dir
    if not path.is_file():
        _fail(f"no audit log at {path}")

    entries = [e for e in AuditLog(path).entries() if event is None or e.event == event]
    for entry in entries[-limit:]:
        console.print(f"[dim]{entry.seq:>4} {entry.ts}[/] [cyan]{entry.event}[/]")
        console.print(f"     {json.dumps(entry.data, default=str)[:400]}")


# ---------------------------------------------------------------------------
#  report
# ---------------------------------------------------------------------------
@app.command("report")
def report(
    campaign_dir: Path = typer.Argument(..., help="Campaign directory."),
    engagement_path: Path = typer.Option(None, "--engagement", help="Contract, if not alongside."),
    output: Path = typer.Option(None, "--output", "-o", help="Where to write the report."),
    narrate: bool = typer.Option(
        False, "--narrate", help="Have the reporter agent write the executive summary in prose."
    ),
) -> None:
    """Rebuild the report from a campaign's record."""
    from .report.builder import ReportBuilder

    kb_path = campaign_dir / "knowledge.sqlite"
    if not kb_path.is_file():
        _fail(f"no campaign database at {kb_path}")

    path = engagement_path or next(campaign_dir.glob("engagement*.y*ml"), None)
    if path is None:
        _fail("could not find the engagement contract. Pass --engagement.")

    try:
        engagement = contract.load(path)
    except ContractError as exc:
        _fail(str(exc))

    kb = KnowledgeBase(kb_path)
    campaign_id = kb.conn.execute("SELECT id FROM campaign LIMIT 1").fetchone()
    if campaign_id is None:
        _fail(f"no campaign recorded in {kb_path}")
    kb.resume_campaign(campaign_id["id"])

    builder = ReportBuilder(
        engagement=engagement, kb=kb, audit=AuditLog(campaign_dir / "audit.jsonl"),
        campaign_id=campaign_id["id"],
    )

    if narrate:
        from .orchestrator import build_context

        console.print("[dim]writing the executive summary…[/]")
        asyncio.run(builder.narrate(context_brief=build_context(engagement)))

    destination = builder.write(output or campaign_dir / "report")
    kb.close()
    console.print(f"[bold green]✓[/] {destination}")


# ---------------------------------------------------------------------------
#  toolbox
# ---------------------------------------------------------------------------
@app.command("toolbox")
def toolbox(
    image: str = typer.Option("swarmstrike/toolbox:latest", "--image"),
    dockerfile: Path = typer.Option(Path("docker/Dockerfile.toolbox"), "--file"),
) -> None:
    """Print the command that builds the toolbox container image."""
    if not dockerfile.is_file():
        _fail(f"no Dockerfile at {dockerfile}")
    console.print("Build the toolbox image with:\n")
    console.print(f"  [cyan]docker build -t {image} -f {dockerfile} .[/]\n")
    console.print(
        "[dim]The image carries the assessment tooling. Agents never execute on the "
        "host — every command runs inside a disposable container built from it.[/]"
    )


def main() -> int:
    try:
        app()
    except typer.Exit as exc:
        return exc.exit_code
    return 0


if __name__ == "__main__":
    sys.exit(main())
