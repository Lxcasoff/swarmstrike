"""Running swarmstrike itself in a container.

The case that matters here is the silent one. Toolbox containers are started
as siblings, so the Docker daemon resolves their bind mounts against the host
filesystem. If swarmstrike is containerised and does not know where its
workspace lives on the host, every tool mounts an empty directory, runs
normally and writes into nothing — and the campaign looks fine until someone
opens a report with no evidence in it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from swarmstrike.audit import AuditLog
from swarmstrike.engagement import Engagement
from swarmstrike.killswitch import KillSwitch
from swarmstrike.knowledge import KnowledgeBase
from swarmstrike.scope import ScopeGuard
from swarmstrike.tools.executor import ContainerPolicy, ToolExecutor

CONTRACT = {
    "engagement": {"id": "E", "client": "C", "mission": "M",
                   "authorized_by": {"name": "n", "role": "r", "email": "e",
                                     "authorization_ref": "a", "signed_on": "2026-01-01"}},
    "window": {"start": "2026-01-01T00:00:00+00:00", "end": "2030-01-01T00:00:00+00:00"},
    "scope": {"domains": [{"name": "example.org"}]},
}


def mount_of(argv: list[str]) -> str:
    return argv[argv.index("--volume") + 1]


# ---------------------------------------------------------------------------
#  Mount translation
# ---------------------------------------------------------------------------
def test_without_a_mapping_the_local_path_is_used(tmp_path: Path) -> None:
    policy = ContainerPolicy()
    argv = policy.docker_argv(tmp_path, needs_raw_socket=False)
    assert mount_of(argv) == f"{tmp_path}:/work:rw"


def test_a_relative_workspace_still_mounts(monkeypatch, tmp_path: Path) -> None:
    """The daemon rejects a relative bind-mount source.

    A relative --workspace is the normal thing to pass on the command line, and
    this failed with nothing but docker's usage message until the mount check
    caught it on a real campaign.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "campaigns" / "C1").mkdir(parents=True)

    source = ContainerPolicy().mount_source(Path("campaigns/C1"))
    assert Path(source).is_absolute()
    assert source == str((tmp_path / "campaigns" / "C1").resolve())


def test_a_translated_mapping_is_absolute_too(tmp_path: Path) -> None:
    root = tmp_path / "campaigns"
    (root / "C1").mkdir(parents=True)
    policy = ContainerPolicy(host_workspace=Path("/data/sw"), local_workspace_root=root)
    assert Path(policy.mount_source(root / "C1")).is_absolute()


def test_a_host_mapping_is_anchored_on_the_workspace_root(tmp_path: Path) -> None:
    # Anchoring on the working directory instead produced a doubled path
    # (/data/sw/campaigns/campaigns/ENG-1), so the root is passed explicitly.
    root = tmp_path / "campaigns"
    workspace = root / "ENG-2026-014"
    workspace.mkdir(parents=True)

    policy = ContainerPolicy(host_workspace=Path("/data/sw"), local_workspace_root=root)
    assert policy.mount_source(workspace) == "/data/sw/ENG-2026-014"


def test_the_root_itself_maps_to_the_host_root(tmp_path: Path) -> None:
    root = tmp_path / "campaigns"
    root.mkdir()
    policy = ContainerPolicy(host_workspace=Path("/data/sw"), local_workspace_root=root)
    assert policy.mount_source(root) == "/data/sw"


def test_without_a_declared_root_the_mapping_does_not_guess(tmp_path: Path) -> None:
    # Better to mount the declared root than to invent a relative position.
    policy = ContainerPolicy(host_workspace=Path("/data/sw"))
    assert policy.mount_source(tmp_path / "campaigns" / "ENG-1") == "/data/sw"


def test_a_workspace_outside_the_working_directory_falls_back(tmp_path: Path) -> None:
    policy = ContainerPolicy(host_workspace=Path("/srv/swarmstrike"))
    # Nothing sensible can be derived, so it maps to the declared root rather
    # than inventing a path.
    assert policy.mount_source(Path("/somewhere/else")) == "/srv/swarmstrike"


def test_the_mapping_reaches_the_docker_invocation(tmp_path: Path) -> None:
    root = tmp_path / "campaigns"
    workspace = root / "C1"
    workspace.mkdir(parents=True)

    argv = ContainerPolicy(
        host_workspace=Path("/srv/sw"), local_workspace_root=root
    ).docker_argv(workspace, needs_raw_socket=False)
    assert mount_of(argv) == "/srv/sw/C1:/work:rw"


# ---------------------------------------------------------------------------
#  Preflight proves the mount rather than guessing at it
# ---------------------------------------------------------------------------
def build_executor(tmp_path: Path, **policy_kwargs) -> ToolExecutor:
    engagement = Engagement.model_validate(CONTRACT)
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.open_campaign("C", engagement)
    return ToolExecutor(
        guard=ScopeGuard(engagement, resolve=False),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        kb=kb,
        workspace=tmp_path,
        killswitch=KillSwitch(tmp_path),
        policy=ContainerPolicy(**policy_kwargs),
    )


def test_an_unwritable_workspace_is_reported(tmp_path: Path) -> None:
    executor = build_executor(tmp_path)
    executor.workspace = tmp_path / "does" / "not" / "exist"
    ok, detail = asyncio.run(executor.verify_mount())
    assert not ok
    assert "not writable" in detail


def test_the_sentinel_is_always_removed(tmp_path: Path) -> None:
    # It is written into the campaign workspace, which becomes the evidence
    # record, so it must not survive the check either way.
    executor = build_executor(tmp_path, image="swarmstrike/definitely-absent:latest")
    asyncio.run(executor.verify_mount())
    assert not list(tmp_path.glob(".swarmstrike-mount-check"))


def test_a_failed_mount_says_what_it_mounted_and_what_would_happen(tmp_path: Path) -> None:
    executor = build_executor(tmp_path, image="swarmstrike/definitely-absent:latest")
    ok, detail = asyncio.run(executor.verify_mount())
    assert not ok
    # The operator needs the path it tried, not just that it failed.
    assert str(tmp_path) in detail or "SWARMSTRIKE_HOST_WORKSPACE" in detail
    assert "write into nothing" in detail


def test_container_detection_reads_the_usual_markers(monkeypatch) -> None:
    import swarmstrike.tools.executor as module

    monkeypatch.setattr(module.Path, "exists", lambda self: str(self) == "/.dockerenv")
    assert ToolExecutor.running_in_container()


# ---------------------------------------------------------------------------
#  The image ships what the product needs
# ---------------------------------------------------------------------------
REPO = Path(__file__).resolve().parent.parent


def test_server_image_pins_its_runtimes() -> None:
    # A report states what produced it; "whatever was latest on build day" is
    # not a statement.
    dockerfile = (REPO / "docker" / "Dockerfile").read_text()
    assert "ARG NODE_VERSION=" in dockerfile
    assert "ARG DOCKER_CLI_VERSION=" in dockerfile
    assert "slim-bookworm" in dockerfile


def test_server_image_carries_no_assessment_tooling() -> None:
    # Agents never execute in the server container. If nmap turned up in this
    # image, that separation would have quietly stopped being true.
    dockerfile = (REPO / "docker" / "Dockerfile").read_text()
    for tool in ("nmap", "nuclei", "sqlmap", "ffuf", "netexec", "seclists"):
        assert tool not in dockerfile, f"{tool} belongs in the toolbox image"


def test_server_image_runs_unprivileged() -> None:
    dockerfile = (REPO / "docker" / "Dockerfile").read_text()
    assert "USER operator" in dockerfile
    assert dockerfile.index("USER operator") < dockerfile.index("CMD [")


def test_compose_publishes_only_to_loopback() -> None:
    # The dashboard can start a penetration test and approve shell commands,
    # and has no authentication of its own.
    compose = (REPO / "docker" / "docker-compose.yml").read_text()
    assert '"127.0.0.1:8787:8787"' in compose
    assert "no-new-privileges:true" in compose


def test_compose_mounts_campaigns_at_the_same_path_on_both_sides() -> None:
    """The arrangement that needs no translation.

    Sibling containers have their bind mounts resolved by the daemon against
    the host, so mounting the campaigns directory at its own host path makes
    the two agree and removes the translation entirely. The variable is
    documented for the case where someone changes this, and deliberately left
    unset here.
    """
    compose = (REPO / "docker" / "docker-compose.yml").read_text()
    assert "- ${PWD}/campaigns:${PWD}/campaigns:rw" in compose
    assert "SWARMSTRIKE_HOST_WORKSPACE is deliberately NOT set" in compose
    # Set, it would override the agreement above with a translation nobody asked for.
    assert "SWARMSTRIKE_HOST_WORKSPACE: " not in compose


def test_compose_mounts_the_contract_read_only() -> None:
    # A running campaign has no business modifying what authorizes it.
    compose = (REPO / "docker" / "docker-compose.yml").read_text()
    assert "engagement.yaml:ro" in compose


def test_dockerignore_keeps_campaign_output_out_of_the_image() -> None:
    ignored = (REPO / ".dockerignore").read_text().splitlines()
    for entry in ("campaigns/", ".env", "engagement.yaml", "*.sqlite"):
        assert entry in ignored, f"{entry} would be baked into the image"
