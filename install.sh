#!/usr/bin/env bash
# swarmstrike setup.
#
# Brings a fresh checkout to the point where one command starts a campaign:
# dependencies installed, toolbox image built, signing key generated, contract
# scaffolded.
#
#   ./install.sh
#
# It stops short of signing the contract, and that is deliberate. The contract
# is the written authorization this tool answers to — who asked for the test,
# against which targets, within which window. A script cannot know any of that,
# and a script that signed one anyway would be forging the authorization the
# rest of the design exists to enforce. You fill it in, you sign it.
#
# Re-running is safe: it keeps a key, a contract and an image that already
# exist rather than replacing them.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
RED=$'\033[31m'; CYAN=$'\033[36m'; OFF=$'\033[0m'

step() { printf '\n%s▸ %s%s\n' "$BOLD" "$1" "$OFF"; }

# A build that prints nothing for four minutes looks like a hang, and someone
# interrupting it is a reasonable response to what they are shown.
spinner() {
    local pid=$1 message=$2 frames='|/-\' i=0 start elapsed
    start=$(date +%s)
    if [ ! -t 1 ]; then wait "$pid"; return $?; fi
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(( $(date +%s) - start ))
        printf '\r%s  %s %s  %dm%02ds%s\033[K' "$DIM" \
            "${frames:i++%4:1}" "$message" $((elapsed / 60)) $((elapsed % 60)) "$OFF"
        sleep 0.4
    done
    printf '\r\033[K'
    wait "$pid"
}

run_build() {   # run_build <log> <message> <docker build args...>
    local log=$1 message=$2; shift 2
    docker build "$@" > "$log" 2>&1 &
    spinner $! "$message"
}
ok()   { printf '%s  ✓%s %s\n' "$GREEN" "$OFF" "$1"; }
warn() { printf '%s  ⚠%s %s\n' "$YELLOW" "$OFF" "$1"; }
die()  { printf '\n%s  ✗%s %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

cd "$(dirname "$0")"

TOOLBOX_IMAGE="${SWARMSTRIKE_TOOLBOX_IMAGE:-swarmstrike/toolbox:latest}"
TOOLBOX_OK=yes
CONTRACT="${SWARMSTRIKE_CONTRACT:-engagement.yaml}"

# --- 1. Prerequisites ------------------------------------------------------
step "Checking prerequisites"

command -v python3 >/dev/null || die "python3 is not installed."
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
[ "$PY_OK" = 1 ] || die "Python 3.11 or newer is required (found $(python3 -V 2>&1))."
ok "$(python3 -V 2>&1)"

command -v docker >/dev/null || die "docker is not installed. Agents never execute on
  the host: every command runs inside a throwaway container, so the daemon is
  not optional."
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable.
  Start Docker, or point DOCKER_HOST at a daemon, and run this again."
ok "docker daemon reachable"

command -v node >/dev/null 2>&1 \
    && ok "node $(node -v)" \
    || warn "node was not found. The agent harness drives the Claude Code CLI,
    which is a Node program. Install Node 20+ or use the server container
    (docker/docker-compose.yml), which carries its own."

# --- 2. The package --------------------------------------------------------
step "Installing swarmstrike"

if python3 -c 'import swarmstrike' 2>/dev/null; then
    ok "already importable"
else
    pip install -q -e '.[web]' || die "pip install failed. In a managed Python
  (Debian, Homebrew) make a virtualenv first:
      python3 -m venv .venv && source .venv/bin/activate"
    ok "installed with the dashboard extras"
fi

command -v claude >/dev/null 2>&1 \
    && ok "claude CLI present" \
    || warn "the claude CLI was not found. Install it with
    'npm install -g @anthropic-ai/claude-code', or use the server container."

# --- 3. The toolbox image --------------------------------------------------
step "Building the toolbox image"

LOG_DIR="${TMPDIR:-/tmp}/swarmstrike-setup.$$"
mkdir -p "$LOG_DIR"

# Show what actually failed. An earlier version printed a guess at the cause
# and threw the output away, which sent someone looking at their network when
# the build had broken on something else entirely.
tail_log() {
    printf '%s  ── last lines of %s ──%s\n' "$DIM" "$1" "$OFF"
    # Enough lines to carry the tool's own error message, not just docker's
    # summary of which step failed. apt in particular says why several lines
    # above the line docker quotes back.
    tail -n 40 "$1" | sed 's/^/    /'
    printf '%s  ── full log: %s ──%s\n' "$DIM" "$1" "$OFF"
}

# A build the operator interrupted is not a build that failed, and saying so
# sends them debugging something that was working.
was_cancelled() {
    grep -qE 'context canceled|CANCELED' "$1"
}

# Which Dockerfile an image was built from, recorded in the image itself.
# Comparing the image's creation time against the Dockerfile's mtime does not
# work: a cache hit hands back an image whose Created predates the edit, so
# every run looked stale and rebuilt. The content hash is exact.
dockerfile_sha() { sha256sum "$1" 2>/dev/null | cut -c1-16; }

image_is_current() {   # image_is_current <image> <dockerfile>
    local stamped want
    docker image inspect "$1" >/dev/null 2>&1 || return 1
    [ -f "$2" ] || return 0
    want=$(dockerfile_sha "$2")
    stamped=$(docker image inspect \
        -f '{{index .Config.Labels "swarmstrike.dockerfile"}}' "$1" 2>/dev/null)
    # An image built before this label existed carries none. Rebuilding every
    # such image once is the price of knowing afterwards.
    [ -n "$stamped" ] && [ "$stamped" = "$want" ]
}

if image_is_current "$TOOLBOX_IMAGE" docker/Dockerfile.toolbox; then
    ok "$TOOLBOX_IMAGE already built from this Dockerfile"
elif image_is_current swarmstrike/toolbox:minimal docker/Dockerfile.toolbox-minimal; then
    TOOLBOX_IMAGE=swarmstrike/toolbox:minimal
    ok "swarmstrike/toolbox:minimal already built from this Dockerfile"
else
    if run_build "$LOG_DIR/toolbox.log" \
            "building $TOOLBOX_IMAGE — it installs a lot of tooling" \
            -t "$TOOLBOX_IMAGE" -f docker/Dockerfile.toolbox \
            --label "swarmstrike.dockerfile=$(dockerfile_sha docker/Dockerfile.toolbox)" .; then
        ok "$TOOLBOX_IMAGE built"
    else
        warn "the full toolbox did not build. Falling back to the minimal image:
    curl, nuclei, httpx and ffuf, which covers web and API work and nothing
    else. The reason the full one failed is below — it is worth reading, since
    the minimal image is a smaller toolset, not a fix."
        tail_log "$LOG_DIR/toolbox.log"
        printf '\n%s  building swarmstrike/toolbox:minimal%s\n' "$DIM" "$OFF"
        if run_build "$LOG_DIR/toolbox-minimal.log" \
                "building swarmstrike/toolbox:minimal — fetching three archives from GitHub" \
                -t swarmstrike/toolbox:minimal \
                -f docker/Dockerfile.toolbox-minimal \
                --label "swarmstrike.dockerfile=$(dockerfile_sha docker/Dockerfile.toolbox-minimal)" \
                docker/; then
            TOOLBOX_IMAGE=swarmstrike/toolbox:minimal
            ok "swarmstrike/toolbox:minimal built"
        elif was_cancelled "$LOG_DIR/toolbox-minimal.log"; then
            TOOLBOX_OK=no
            warn "the minimal toolbox build was interrupted before it finished.
    Nothing is wrong with it — the downloads take a few minutes. Run this
    script again and let it finish."
        else
            TOOLBOX_OK=no
            tail_log "$LOG_DIR/toolbox-minimal.log"
            warn "neither toolbox image would build. Setup continues — an image
    is needed to run a campaign, not to set one up — but you will need one
    before the first run.

    If the failure above is a TLS error (curl 60, or a message about trust
    anchors) you are behind an intercepting proxy. Export its certificate,
    copy it into docker/ since that is the build context, and pass it in:
        cp /path/to/ca-bundle.crt docker/
        docker build -t swarmstrike/toolbox:minimal \\
            --build-arg CA_BUNDLE=ca-bundle.crt \\
            -f docker/Dockerfile.toolbox-minimal docker/"
        fi
    fi
fi

# --- 4. Environment --------------------------------------------------------
step "Setting up .env"

[ -f .env ] || { cp .env.example .env; ok "created .env from the example"; }

# The signing key. Generated here because a key is the one secret a script can
# safely create: it authorizes nothing by itself, it only detects tampering.
if grep -qE '^SWARMSTRIKE_SCOPE_KEY=.+' .env; then
    ok "signing key already set"
else
    KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')
    python3 - "$KEY" <<'PY'
import pathlib, sys
key = sys.argv[1]
path = pathlib.Path(".env")
lines = path.read_text().splitlines()
for index, line in enumerate(lines):
    if line.startswith("SWARMSTRIKE_SCOPE_KEY="):
        lines[index] = f"SWARMSTRIKE_SCOPE_KEY={key}"
        break
else:
    lines.append(f"SWARMSTRIKE_SCOPE_KEY={key}")
path.write_text("\n".join(lines) + "\n")
PY
    chmod 600 .env
    ok "signing key generated into .env (mode 600)"
fi

grep -qE '^ANTHROPIC_API_KEY=sk-ant-\.\.\.$|^ANTHROPIC_API_KEY=$' .env \
    && warn "ANTHROPIC_API_KEY is still a placeholder in .env. Set it before running." \
    || ok "ANTHROPIC_API_KEY is set"

if ! grep -qE "^SWARMSTRIKE_TOOLBOX_IMAGE=${TOOLBOX_IMAGE//\//\\/}$" .env; then
    python3 - "$TOOLBOX_IMAGE" <<'PY'
import pathlib, sys
image = sys.argv[1]
path = pathlib.Path(".env")
lines = path.read_text().splitlines()
for index, line in enumerate(lines):
    if line.startswith("SWARMSTRIKE_TOOLBOX_IMAGE="):
        lines[index] = f"SWARMSTRIKE_TOOLBOX_IMAGE={image}"
        break
else:
    lines.append(f"SWARMSTRIKE_TOOLBOX_IMAGE={image}")
path.write_text("\n".join(lines) + "\n")
PY
    ok "toolbox image recorded as $TOOLBOX_IMAGE"
fi

# --- 5. The contract -------------------------------------------------------
step "Scaffolding the engagement contract"

if [ -f "$CONTRACT" ]; then
    ok "$CONTRACT already exists — left untouched"
else
    python3 -m swarmstrike.cli engagement init "$CONTRACT" >/dev/null
    ok "$CONTRACT written, with every field to fill in"
fi

SIGNED=no
set +e
( set -a; . ./.env; set +a; python3 -m swarmstrike.cli engagement verify "$CONTRACT" ) >/dev/null 2>&1 \
    && SIGNED=yes
set -e

# --- Done ------------------------------------------------------------------
printf '\n%s%s  Setup complete.%s\n' "$BOLD" "$GREEN" "$OFF"

if [ "$TOOLBOX_OK" = no ]; then
    printf '\n%s  ⚠%s %s\n' "$YELLOW" "$OFF" "No toolbox image was built. Every command an agent
    proposes runs inside one, so a campaign cannot start without it. Build one
    with the commands above, then check what it carries:
        swarmstrike probe --image <image>"
fi

if [ "$SIGNED" = yes ]; then
    cat <<EOF

  Your contract is signed and verifies. Start a campaign:

    ${CYAN}source .env${OFF}
    ${CYAN}swarmstrike run ${CONTRACT} --tui${OFF}        ${DIM}# terminal${OFF}
    ${CYAN}swarmstrike serve${OFF}                    ${DIM}# http://127.0.0.1:8787${OFF}

EOF
    exit 0
fi

cat <<EOF

  Three steps remain, and they are yours rather than the script's.

  ${BOLD}1. Fill in the contract${OFF}  ${CYAN}\$EDITOR ${CONTRACT}${OFF}

     This is the authority the whole tool answers to: who authorized the test
     in writing, which targets are in scope, what is forbidden, what it may
     spend. Scope is enforced at execution time, so a target missing here is a
     target the swarm will refuse to touch.

  ${BOLD}2. Sign it${OFF}              ${CYAN}source .env${OFF}
                          ${CYAN}swarmstrike engagement sign ${CONTRACT}${OFF}

     Any edit after signing is detected and refuses the campaign.

  ${BOLD}3. Check it says what you think${OFF}
     ${CYAN}swarmstrike engagement check ${CONTRACT} app.client.example 10.0.0.5${OFF}

     Each target comes back allowed or refused, with the rule that decided it.
     Do this before every engagement, not once.

  Then:

    ${CYAN}swarmstrike run ${CONTRACT} --tui${OFF}        ${DIM}# terminal${OFF}
    ${CYAN}swarmstrike serve${OFF}                    ${DIM}# http://127.0.0.1:8787${OFF}

  To see the interface before any of this, with no backend and no target:
  ${CYAN}swarmstrike serve${OFF} then open ${CYAN}http://127.0.0.1:8787/?demo${OFF}

EOF
