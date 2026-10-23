"""Command execution.

Every command an agent proposes arrives here, and nothing reaches a target by
any other path. The executor validates the command against the engagement
contract, refuses it or runs it inside a disposable container, records what
happened in the audit log, and hands back a bounded view of the output.

Agents never execute on the host. That is the point of this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..audit import AuditLog
from ..killswitch import KillSwitch
from ..knowledge import KnowledgeBase
from ..scope import Decision, ScopeGuard

# A scanner can emit tens of megabytes. The full output is kept on disk; the
# agent is handed this much, which is plenty to reason over and cheap to read.
AGENT_OUTPUT_LIMIT = 60_000
DEFAULT_TIMEOUT_S = 900


class ExecutionRefused(Exception):
    """The command was not run. The reason is the contract, not a failure."""


@dataclass
class ToolResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    output_path: Path | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def for_agent(self) -> str:
        """Rendered for an agent to read."""
        header = f"$ {shlex.join(self.argv)}\nexit={self.exit_code} in {self.duration_ms}ms"
        body = self.stdout or "(no output on stdout)"
        parts = [header, body]
        if self.stderr.strip():
            parts.append(f"--- stderr ---\n{self.stderr}")
        if self.truncated:
            parts.append(
                f"--- output truncated at {AGENT_OUTPUT_LIMIT} characters; "
                f"full output at {self.output_path} ---"
            )
        return "\n\n".join(parts)


@dataclass
class ContainerPolicy:
    """How the toolbox container is constrained."""

    image: str = "swarmstrike/toolbox:latest"
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 512
    # Raw sockets are needed for SYN scanning and some protocol probes. Tools
    # that do not need them run without, which is most of them.
    raw_socket_capabilities: tuple[str, ...] = ("NET_RAW", "NET_ADMIN")

    def docker_argv(self, workspace: Path, *, needs_raw_socket: bool) -> list[str]:
        argv = [
            "docker", "run", "--rm", "--interactive=false",
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            # The toolbox is disposable: its root filesystem is read-only and
            # the only writable places are a scratch tmpfs and the campaign
            # workspace, so a tool cannot modify the image or the host.
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            "--volume", f"{workspace}:/work:rw",
            "--workdir", "/work",
        ]
        if needs_raw_socket:
            for capability in self.raw_socket_capabilities:
                argv += ["--cap-add", capability]
        argv.append(self.image)
        return argv


@dataclass
class ToolExecutor:
    guard: ScopeGuard
    audit: AuditLog
    kb: KnowledgeBase
    workspace: Path
    killswitch: KillSwitch
    policy: ContainerPolicy = field(default_factory=ContainerPolicy)
    max_concurrent: int = 4
    min_interval_s: float = 0.0

    _semaphore: asyncio.Semaphore = field(init=False)
    _last_launch: float = field(default=0.0, init=False)
    _launch_lock: asyncio.Lock = field(init=False)
    _sequence: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._launch_lock = asyncio.Lock()
        self.output_dir = self.workspace / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def authorize(self, argv: list[str]) -> Decision:
        """Pure check, no side effects. Useful for dry runs and for the TUI."""
        return self.guard.check_command(argv)

    async def run(
        self,
        agent: str,
        argv: list[str],
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        needs_raw_socket: bool = False,
    ) -> ToolResult:
        """Validate, run and record a command. Raises ExecutionRefused if denied."""
        self.killswitch.check()

        decision = self.guard.check_command(argv)
        if not decision.allowed:
            self.audit.refusal(agent=agent, argv=argv, reason=decision.reason, rule=decision.rule)
            self.kb.log_command(
                agent=agent, argv=argv, decision="refused",
                reason=f"[{decision.rule}] {decision.reason}",
            )
            raise ExecutionRefused(f"[{decision.rule}] {decision.reason}")

        async with self._semaphore:
            self.killswitch.check()
            await self._pace()
            return await self._execute(agent, argv, timeout_s, needs_raw_socket, decision)

    # ------------------------------------------------------------------
    async def _pace(self) -> None:
        if self.min_interval_s <= 0:
            return
        async with self._launch_lock:
            wait = self.min_interval_s - (time.monotonic() - self._last_launch)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_launch = time.monotonic()

    async def _execute(
        self,
        agent: str,
        argv: list[str],
        timeout_s: int,
        needs_raw_socket: bool,
        decision: Decision,
    ) -> ToolResult:
        self._sequence += 1
        full = self.policy.docker_argv(self.workspace, needs_raw_socket=needs_raw_socket) + argv

        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *full,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            raw_out, raw_err = await asyncio.wait_for(process.communicate(), timeout=timeout_s)
            exit_code = process.returncode or 0
        except asyncio.TimeoutError:
            process.kill()
            raw_out, raw_err = await process.communicate()
            exit_code = 124
            raw_err = (raw_err or b"") + f"\n[swarmstrike] killed after {timeout_s}s\n".encode()

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = (raw_out or b"").decode("utf-8", errors="replace")
        stderr = (raw_err or b"").decode("utf-8", errors="replace")

        # Keep the full output on disk as the evidence of record, and give the
        # agent a bounded slice of it.
        tool_name = Path(argv[0]).name
        output_path = self.output_dir / f"{self._sequence:04d}-{agent}-{tool_name}.txt"
        output_path.write_text(
            f"$ {shlex.join(argv)}\nexit={exit_code}\n\n{stdout}\n--- stderr ---\n{stderr}",
            encoding="utf-8",
        )

        truncated = len(stdout) > AGENT_OUTPUT_LIMIT
        visible = stdout[:AGENT_OUTPUT_LIMIT] if truncated else stdout

        self.audit.command(
            agent=agent,
            argv=argv,
            decision="allowed",
            reason=decision.reason,
            rule=decision.rule,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_sha256=hashlib.sha256((raw_out or b"")).hexdigest(),
        )
        self.kb.log_command(
            agent=agent, argv=argv, decision="allowed", reason=decision.reason,
            exit_code=exit_code, duration_ms=duration_ms, output_path=str(output_path),
        )

        return ToolResult(
            argv=argv,
            exit_code=exit_code,
            stdout=visible,
            stderr=stderr[:AGENT_OUTPUT_LIMIT],
            duration_ms=duration_ms,
            output_path=output_path,
            truncated=truncated,
        )

    # ------------------------------------------------------------------
    async def preflight(self) -> tuple[bool, str]:
        """Check Docker is reachable and the toolbox image is present."""
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "image", "inspect", self.policy.image,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, err = await process.communicate()
        except FileNotFoundError:
            return False, "docker is not installed or not on PATH"

        if process.returncode != 0:
            detail = err.decode(errors="replace").strip().splitlines()
            reason = detail[0] if detail else "unknown error"
            return False, (
                f"toolbox image {self.policy.image} is not available ({reason}). "
                f"Build it with: docker build -t {self.policy.image} -f docker/Dockerfile.toolbox ."
            )
        return True, f"toolbox image {self.policy.image} ready"

    def manifest(self) -> str:
        """What ran this campaign, as JSON. Goes into the report appendix."""
        return json.dumps(
            {
                "image": self.policy.image,
                "commands_dispatched": self._sequence,
                "workspace": str(self.workspace),
            },
            indent=2,
        )
