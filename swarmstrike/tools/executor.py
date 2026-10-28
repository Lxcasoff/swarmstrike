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
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..approval import ApprovalGate, ApprovalRequest, AutoDenyGate
from ..audit import AuditLog
from ..killswitch import KillSwitch
from ..knowledge import KnowledgeBase
from ..scope import Decision, ScopeGuard

# A scanner can emit tens of megabytes. The full output is kept on disk; the
# agent is handed this much, which is plenty to reason over and cheap to read.
AGENT_OUTPUT_LIMIT = 60_000
DEFAULT_TIMEOUT_S = 900

REDACTED = "«redacted»"


def redact(value: str, secrets: Sequence[str]) -> str:
    """Replace credential values wherever they appear.

    Applied to the command before it is written anywhere — the audit chain, the
    campaign database, the evidence file on disk — and to the output, because a
    tool may echo the credential it was given straight back. A report built from
    a campaign record should not hand the client's password back to them.
    """
    for secret in secrets:
        if secret:
            value = value.replace(secret, REDACTED)
    return value


def redact_argv(argv: Sequence[str], secrets: Sequence[str]) -> list[str]:
    return [redact(part, secrets) for part in argv]

# Binaries permitted as a pipeline stage after the first. They read stdin,
# write stdout and reach no network, so they need no target to scope-check.
# Deliberately excludes awk, sed, perl, xargs and every interpreter: those can
# execute a command, which would make a pipeline a shell by another route.
FILTER_BINARIES = frozenset({
    "grep", "jq", "sort", "uniq", "head", "tail", "wc", "cut", "tr", "nl",
    "rev", "cat", "column", "tee",
})


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

    # Several assessment tools write a config file on first run. The root
    # filesystem is read-only, so HOME and the XDG directories point at the
    # scratch tmpfs; without this nuclei, httpx and subfinder fail outright.
    writable_home: str = "/tmp"

    # Docker network to attach. Needed to reach a target on a user-defined
    # network — a lab, or a jump host that sits on one.
    network: str | None = None

    # Where campaigns live *as the Docker daemon sees them*, when that differs
    # from where this process sees them.
    #
    # Toolbox containers are siblings, not children: the daemon resolves their
    # bind mounts against the host filesystem, not against this process's. When
    # swarmstrike runs in a container that mounts its campaigns directory at
    # the same absolute path it has on the host — which is what the shipped
    # compose file does — the two agree and neither of these is needed. They
    # exist for the case where the paths differ.
    host_workspace: Path | None = None
    local_workspace_root: Path | None = None

    def mount_source(self, workspace: Path) -> str:
        """The bind-mount source the daemon will resolve.

        Translation is anchored on the workspace root rather than the working
        directory: a campaign directory sits under that root, and anchoring
        anywhere else produces a doubled path.
        """
        if self.host_workspace is None:
            return str(workspace)

        root = self.local_workspace_root
        if root is not None:
            try:
                relative = workspace.resolve().relative_to(root.resolve())
            except (ValueError, OSError):
                relative = None
            if relative is not None and relative != Path("."):
                return str(self.host_workspace / relative)

        return str(self.host_workspace)

    def docker_argv(
        self, workspace: Path, *, needs_raw_socket: bool, stdin: bool = False
    ) -> list[str]:
        argv = [
            "docker", "run", "--rm",
            "--interactive" if stdin else "--interactive=false",
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
            "--volume", f"{self.mount_source(workspace)}:/work:rw",
            "--workdir", "/work",
            "--env", f"HOME={self.writable_home}",
            "--env", f"XDG_CONFIG_HOME={self.writable_home}/.config",
            "--env", f"XDG_CACHE_HOME={self.writable_home}/.cache",
        ]
        if self.network:
            argv += ["--network", self.network]
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
    # Per-agent activity, for the live view. The executor is the only place
    # that knows which agent is doing what to whom, and when it stops.
    on_event: Callable[[str, dict[str, Any]], None] | None = None

    # Where a command that cannot be statically checked goes to be decided.
    # Deny-by-default: an unattended campaign does not approve its own shell.
    approval: ApprovalGate = field(default_factory=AutoDenyGate)

    # Binaries the agents may invoke. Populated from the recipe book plus the
    # contract's extra_binaries.
    allowed_binaries: frozenset[str] = frozenset()

    _semaphore: asyncio.Semaphore = field(init=False)
    _last_launch: float = field(default=0.0, init=False)
    _launch_lock: asyncio.Lock = field(init=False)
    _sequence: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._launch_lock = asyncio.Lock()
        self.output_dir = self.workspace / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _emit(self, event: str, **payload: Any) -> None:
        # Named `event` rather than `kind` so a payload may carry its own
        # `kind` field without colliding with the positional argument.
        if self.on_event is not None:
            self.on_event(event, payload)

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
        secrets: Sequence[str] = (),
    ) -> ToolResult:
        """Validate, run and record a command. Raises ExecutionRefused if denied.

        `secrets` are values from this invocation that must not be written
        down — a recipe supplies them from its sensitive parameters.
        """
        self.killswitch.check()

        decision = self.guard.check_command(argv)
        if not decision.allowed:
            safe = redact_argv(argv, secrets)
            self.audit.refusal(agent=agent, argv=safe, reason=decision.reason,
                               rule=decision.rule)
            self.kb.log_command(
                agent=agent, argv=safe, decision="refused",
                reason=f"[{decision.rule}] {decision.reason}",
            )
            self._emit(
                "agent.refused",
                agent=agent,
                tool=Path(argv[0]).name,
                rule=decision.rule,
                reason=decision.reason,
            )
            raise ExecutionRefused(f"[{decision.rule}] {decision.reason}")

        async with self._semaphore:
            self.killswitch.check()
            await self._pace()
            return await self._execute(agent, argv, timeout_s, needs_raw_socket,
                                       decision, secrets)

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
        secrets: Sequence[str] = (),
    ) -> ToolResult:
        self._sequence += 1
        full = self.policy.docker_argv(self.workspace, needs_raw_socket=needs_raw_socket) + argv
        tool_name = Path(argv[0]).name
        targets = self.guard.extract_targets(argv)
        safe_argv = redact_argv(argv, secrets)

        self._emit(
            "agent.tool.start",
            agent=agent,
            tool=tool_name,
            targets=targets,
            sequence=self._sequence,
            command=shlex.join(safe_argv)[:300],
        )

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
        stdout = redact((raw_out or b"").decode("utf-8", errors="replace"), secrets)
        stderr = redact((raw_err or b"").decode("utf-8", errors="replace"), secrets)

        # Keep the full output on disk as the evidence of record, and give the
        # agent a bounded slice of it.
        output_path = self.output_dir / f"{self._sequence:04d}-{agent}-{tool_name}.txt"
        output_path.write_text(
            f"$ {shlex.join(safe_argv)}\nexit={exit_code}\n\n{stdout}"
            f"\n--- stderr ---\n{stderr}",
            encoding="utf-8",
        )

        truncated = len(stdout) > AGENT_OUTPUT_LIMIT
        visible = stdout[:AGENT_OUTPUT_LIMIT] if truncated else stdout

        self.audit.command(
            agent=agent,
            argv=safe_argv,
            decision="allowed",
            reason=decision.reason,
            rule=decision.rule,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_sha256=hashlib.sha256((raw_out or b"")).hexdigest(),
        )
        self.kb.log_command(
            agent=agent, argv=safe_argv, decision="allowed", reason=decision.reason,
            exit_code=exit_code, duration_ms=duration_ms, output_path=str(output_path),
        )

        self._emit(
            "agent.tool.end",
            agent=agent,
            tool=tool_name,
            targets=targets,
            sequence=self._sequence,
            exit_code=exit_code,
            duration_ms=duration_ms,
            output_bytes=len(raw_out or b""),
        )

        return ToolResult(
            argv=safe_argv,
            exit_code=exit_code,
            stdout=visible,
            stderr=stderr[:AGENT_OUTPUT_LIMIT],
            duration_ms=duration_ms,
            output_path=output_path,
            truncated=truncated,
        )


    # ------------------------------------------------------------------
    #  Tier 1 — a structured command outside the recipe set
    # ------------------------------------------------------------------
    async def run_structured(
        self,
        agent: str,
        binary: str,
        args: list[str],
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        needs_raw_socket: bool = False,
    ) -> ToolResult:
        """A binary plus an argument vector. Checked exactly like a recipe.

        No shell is involved, so nothing in `args` can chain a second command,
        redirect, or substitute. The scope guard reads the targets out of the
        vector as usual.
        """
        tiers = self.guard.engagement.rules_of_engagement.arbitrary_execution
        if not tiers.structured_commands:
            raise ExecutionRefused(
                "[not_authorized] the contract does not permit commands outside the "
                "recipe set (rules_of_engagement.arbitrary_execution."
                "structured_commands is false)"
            )

        if self.allowed_binaries and binary not in self.allowed_binaries:
            reason = (
                f"{binary!r} is not an allowlisted binary. Either use a recipe, or "
                f"have the engagement contract list it in "
                f"rules_of_engagement.arbitrary_execution.extra_binaries."
            )
            self.audit.refusal(agent=agent, argv=[binary, *args], reason=reason,
                               rule="binary_not_allowlisted")
            self.kb.log_command(agent=agent, argv=[binary, *args], decision="refused",
                                reason=reason)
            self._emit("agent.refused", agent=agent, tool=binary,
                       rule="binary_not_allowlisted", reason=reason)
            raise ExecutionRefused(f"[binary_not_allowlisted] {reason}")

        return await self.run(agent, [binary, *args], timeout_s=timeout_s,
                              needs_raw_socket=needs_raw_socket)

    # ------------------------------------------------------------------
    #  Tier 2 — several structured commands piped together
    # ------------------------------------------------------------------
    async def run_pipeline(
        self,
        agent: str,
        stages: list[list[str]],
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        needs_raw_socket: bool = False,
    ) -> ToolResult:
        """Pipe structured commands without a shell.

        The pipe is built between containers rather than by a shell: the first
        stage runs and its output is handed to the next as standard input. The
        first stage is scope-checked in full; later stages must come from
        FILTER_BINARIES, which read standard input and reach no network, so
        there is no target to place in scope — they are still checked against
        the categorical refusals.
        """
        self.killswitch.check()

        tiers = self.guard.engagement.rules_of_engagement.arbitrary_execution
        if not tiers.pipelines:
            raise ExecutionRefused(
                "[not_authorized] pipelines are not enabled for this engagement "
                "(rules_of_engagement.arbitrary_execution.pipelines is false). "
                "Run the stages as separate commands instead."
            )

        if not stages or not all(stages):
            raise ExecutionRefused("[malformed] an empty pipeline stage was given")
        if len(stages) > 6:
            raise ExecutionRefused("[malformed] a pipeline may have at most 6 stages")

        head, *rest = stages

        if self.allowed_binaries and head[0] not in self.allowed_binaries:
            raise ExecutionRefused(
                f"[binary_not_allowlisted] {head[0]!r} is not allowlisted"
            )

        decision = self.guard.check_command(head)
        if not decision.allowed:
            self.audit.refusal(agent=agent, argv=head, reason=decision.reason,
                               rule=decision.rule)
            self.kb.log_command(agent=agent, argv=head, decision="refused",
                                reason=f"[{decision.rule}] {decision.reason}")
            self._emit("agent.refused", agent=agent, tool=Path(head[0]).name,
                       rule=decision.rule, reason=decision.reason)
            raise ExecutionRefused(f"[{decision.rule}] {decision.reason}")

        for stage in rest:
            if stage[0] not in FILTER_BINARIES:
                raise ExecutionRefused(
                    f"[not_a_filter] {stage[0]!r} cannot be a later pipeline stage. "
                    f"After the first stage only filters that read standard input "
                    f"are permitted: {', '.join(sorted(FILTER_BINARIES))}. An "
                    f"interpreter or awk would make this a shell by another route."
                )
            verdict = self.guard.check_forbidden(stage)
            if not verdict.allowed:
                raise ExecutionRefused(f"[{verdict.rule}] {verdict.reason}")

        async with self._semaphore:
            self.killswitch.check()
            await self._pace()
            return await self._execute_piped(agent, stages, timeout_s, needs_raw_socket,
                                             decision)

    async def _execute_piped(
        self,
        agent: str,
        stages: list[list[str]],
        timeout_s: int,
        needs_raw_socket: bool,
        decision: Decision,
    ) -> ToolResult:
        self._sequence += 1
        rendered = " | ".join(shlex.join(s) for s in stages)
        self._emit("agent.tool.start", agent=agent, tool=Path(stages[0][0]).name,
                   targets=self.guard.extract_targets(stages[0]),
                   sequence=self._sequence, command=rendered[:300])

        started = time.monotonic()
        payload = b""
        exit_code = 0
        stderr_parts: list[str] = []

        for index, stage in enumerate(stages):
            first = index == 0
            full = self.policy.docker_argv(
                self.workspace,
                needs_raw_socket=needs_raw_socket and first,
                stdin=not first,
            ) + stage

            process = await asyncio.create_subprocess_exec(
                *full,
                stdin=asyncio.subprocess.PIPE if not first else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(
                    process.communicate(input=None if first else payload),
                    timeout=timeout_s,
                )
                exit_code = process.returncode or 0
            except asyncio.TimeoutError:
                process.kill()
                out, err = await process.communicate()
                exit_code = 124
                err = (err or b"") + f"\n[swarmstrike] stage {index} killed after {timeout_s}s\n".encode()

            if err:
                stderr_parts.append(
                    f"--- stage {index} ({Path(stage[0]).name}) ---\n"
                    + err.decode("utf-8", errors="replace")
                )
            payload = out or b""
            if exit_code != 0 and index < len(stages) - 1:
                # A failed stage produces nothing useful downstream; stop rather
                # than feeding an empty pipe through the remaining filters.
                break

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = payload.decode("utf-8", errors="replace")
        stderr = "\n".join(stderr_parts)

        output_path = self.output_dir / f"{self._sequence:04d}-{agent}-pipeline.txt"
        output_path.write_text(
            f"$ {rendered}\nexit={exit_code}\n\n{stdout}\n--- stderr ---\n{stderr}",
            encoding="utf-8",
        )

        truncated = len(stdout) > AGENT_OUTPUT_LIMIT
        self.audit.command(agent=agent, argv=[rendered], decision="allowed",
                           reason=decision.reason, rule="pipeline",
                           exit_code=exit_code, duration_ms=duration_ms,
                           stdout_sha256=hashlib.sha256(payload).hexdigest())
        self.kb.log_command(agent=agent, argv=[rendered], decision="allowed",
                            reason=decision.reason, exit_code=exit_code,
                            duration_ms=duration_ms, output_path=str(output_path))
        self._emit("agent.tool.end", agent=agent, tool=Path(stages[0][0]).name,
                   targets=self.guard.extract_targets(stages[0]), sequence=self._sequence,
                   exit_code=exit_code, duration_ms=duration_ms, output_bytes=len(payload))

        return ToolResult(
            argv=[rendered], exit_code=exit_code,
            stdout=stdout[:AGENT_OUTPUT_LIMIT] if truncated else stdout,
            stderr=stderr[:AGENT_OUTPUT_LIMIT], duration_ms=duration_ms,
            output_path=output_path, truncated=truncated,
        )

    # ------------------------------------------------------------------
    #  Tier 3 — a shell command or script, which cannot be checked statically
    # ------------------------------------------------------------------
    async def run_unchecked(
        self,
        agent: str,
        script: str,
        *,
        interpreter: str = "sh",
        rationale: str = "",
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> ToolResult:
        """Run a shell command or script, after a human approves it.

        What still holds here: the categorical refusals, any out-of-scope host
        that appears literally in the text, the container, and the audit
        record. What does not hold is completeness — `$(...)`, a variable or an
        encoded string can name a target this cannot see. So the control is a
        person, and the default gate refuses.
        """
        self.killswitch.check()

        if interpreter not in {"sh", "bash", "python3"}:
            raise ExecutionRefused(
                f"[malformed] interpreter must be sh, bash or python3, got {interpreter!r}"
            )

        # The contract decides whether this tier exists at all; the approval
        # gate decides each use of it. Both have to agree.
        tiers = self.guard.engagement.rules_of_engagement.arbitrary_execution
        wanted = "scripts" if interpreter == "python3" else "shell"
        if not getattr(tiers, wanted):
            raise ExecutionRefused(
                f"[not_authorized] {wanted} execution is not enabled for this "
                f"engagement (rules_of_engagement.arbitrary_execution.{wanted} is "
                f"false). Use a structured command or a pipeline instead — neither "
                f"needs approval."
            )

        window = self.guard.check_window()
        if not window.allowed:
            raise ExecutionRefused(f"[{window.rule}] {window.reason}")

        # Checks that do still apply, run before anyone is asked to approve.
        forbidden = self.guard.check_forbidden([script])
        if not forbidden.allowed:
            self.audit.refusal(agent=agent, argv=[interpreter, "-c", script],
                               reason=forbidden.reason, rule=forbidden.rule)
            raise ExecutionRefused(f"[{forbidden.rule}] {forbidden.reason}")

        notes: list[str] = []
        literals = self.guard.extract_targets([interpreter, *script.split()])
        for literal in literals:
            verdict = (
                self.guard.check_url(literal) if "://" in literal
                else self.guard.check_host(literal)
            )
            if not verdict.allowed:
                self.audit.refusal(agent=agent, argv=[interpreter, "-c", script],
                                   reason=verdict.reason, rule=verdict.rule)
                raise ExecutionRefused(f"[{verdict.rule}] {verdict.reason}")
            notes.append(f"names in-scope target {literal}")

        if not literals:
            notes.append(
                "no target appears literally in the text, so the scope guard could "
                "not confirm what this reaches"
            )
        notes.append(
            "a shell command cannot be checked statically: this runs contained, "
            "approved and logged, not scope-enforced"
        )

        request = ApprovalRequest(
            agent=agent,
            kind="script" if interpreter == "python3" else "shell",
            summary=f"{agent} wants to run {interpreter}: {script.splitlines()[0][:90]}",
            detail=script,
            rationale=rationale,
            risk_notes=notes,
        )
        self.audit.record("approval.requested", request_id=request.id, agent=agent,
                          kind=request.kind, detail=script[:2000], rationale=rationale,
                          risk_notes=notes)
        self._emit("approval.requested", **request.as_dict())

        verdict = await self.approval.request(request)
        self.audit.record("approval.decided", request_id=request.id,
                          decision=verdict.decision.value, reason=verdict.reason,
                          decided_by=verdict.decided_by)
        self._emit("approval.decided", request_id=request.id,
                   decision=verdict.decision.value, reason=verdict.reason,
                   decided_by=verdict.decided_by, agent=agent)

        if not verdict.allowed:
            self.kb.log_command(agent=agent, argv=[interpreter, "-c", script],
                                decision="refused", reason=verdict.reason)
            raise ExecutionRefused(
                f"[not_approved] {verdict.reason} "
                f"Use a structured command or a pipeline, which need no approval."
            )

        async with self._semaphore:
            self.killswitch.check()
            await self._pace()
            return await self._execute(
                agent, [interpreter, "-c", script], timeout_s, False,
                Decision(True, f"approved by {verdict.decided_by}: {verdict.reason}",
                         "approved"),
            )

    # ------------------------------------------------------------------
    @staticmethod
    def running_in_container() -> bool:
        """Whether this process is itself inside a container."""
        if Path("/.dockerenv").exists():
            return True
        try:
            cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8")
        except OSError:
            return False
        return any(marker in cgroup for marker in ("docker", "containerd", "kubepods"))

    async def verify_mount(self) -> tuple[bool, str]:
        """Prove the workspace mount lands where this process is writing.

        Toolbox containers are siblings, so the daemon resolves their bind
        mounts against the host filesystem. When those paths disagree with this
        process's, every tool mounts an empty directory, runs normally and
        writes into nothing — the campaign looks healthy until someone opens a
        report with no evidence in it.

        Guessing at that from an environment variable was the earlier approach
        and it was wrong twice over: the arithmetic had an off-by-one-directory
        bug, and a heuristic cannot answer the question anyway. So this writes
        a token into the workspace and has a container read it back.
        """
        token = uuid.uuid4().hex
        sentinel = self.workspace / ".swarmstrike-mount-check"
        try:
            sentinel.write_text(token, encoding="utf-8")
        except OSError as exc:
            return False, f"the campaign workspace is not writable: {exc}"

        try:
            argv = self.policy.docker_argv(self.workspace, needs_raw_socket=False) + [
                "cat", "/work/.swarmstrike-mount-check",
            ]
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
            )
            try:
                out, err = await asyncio.wait_for(process.communicate(), timeout=60)
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return False, "the mount check timed out starting a toolbox container"
        finally:
            sentinel.unlink(missing_ok=True)

        if out.decode(errors="replace").strip() == token:
            return True, "workspace mount verified"

        detail = err.decode(errors="replace").strip().splitlines()
        return False, (
            f"a toolbox container could not read the campaign workspace "
            f"({detail[-1] if detail else 'no output'}). It mounted "
            f"{self.policy.mount_source(self.workspace)}, which is not where this "
            f"process is writing. Tools would run and write into nothing. If "
            f"swarmstrike is containerised, mount the campaigns directory at the "
            f"same absolute path it has on the host, or set "
            f"SWARMSTRIKE_HOST_WORKSPACE to the host path for it."
        )

    async def preflight(self) -> tuple[bool, str]:
        """Check Docker is reachable, the toolbox is present and mounts land."""

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

        mounted, detail = await self.verify_mount()
        if not mounted:
            return False, detail

        return True, f"toolbox image {self.policy.image} ready, {detail}"

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
