#!/usr/bin/env bash
# swarmstrike — one command, from a fresh checkout to a running console.
#
#   ./run.sh                   set up what is missing, then open the console
#   ./run.sh --tui             set up what is missing, then run a campaign
#   ./run.sh --setup-only      set up and stop
#   ./run.sh --key sk-ant-...  record an API key and carry on
#   ./run.sh --rebuild         rebuild the toolbox image even if it is current
#   ./run.sh --port 9000       serve somewhere other than 8787
#
# Setup is idempotent: a key, a contract and an image that already exist are
# left alone, so this is also the command to run after a git pull.
#
# It stops short of signing the contract, and that is deliberate. The contract
# is the written authorization this tool answers to — who asked for the test,
# against which targets, within which window. A script cannot know any of that,
# and one that signed a contract anyway would be forging the authorization the
# rest of the design exists to enforce. You fill it in, you sign it.
set -euo pipefail
cd "$(dirname "$0")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
RED=$'\033[31m'; CYAN=$'\033[36m'; OFF=$'\033[0m'

step() { printf '\n%s▸ %s%s\n' "$BOLD" "$1" "$OFF"; }
ok()   { printf '%s  ✓%s %s\n' "$GREEN" "$OFF" "$1"; }
warn() { printf '%s  ⚠%s %s\n' "$YELLOW" "$OFF" "$1"; }
die()  { printf '\n%s  ✗%s %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

# --- options ---------------------------------------------------------------
MODE=serve
HOST=127.0.0.1
PORT=8787
REBUILD=no
API_KEY=""
CONTRACT="${SWARMSTRIKE_CONTRACT:-engagement.yaml}"
PASSTHROUGH=()

while [ $# -gt 0 ]; do
    case "$1" in
        --tui)        MODE=tui; shift ;;
        --setup-only|--no-start) MODE=setup; shift ;;
        --rebuild)    REBUILD=yes; shift ;;
        --key)        API_KEY=$2; shift 2 ;;
        --host)       HOST=$2; shift 2 ;;
        --port)       PORT=$2; shift 2 ;;
        --contract)   CONTRACT=$2; shift 2 ;;
        -h|--help)    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            PASSTHROUGH+=("$1"); shift ;;
    esac
done

# .env is where DOCKER_HOST, the API key and the signing key live, so it has
# to be loaded before anything checks them. Empty assignments are skipped: the
# example file ships DOCKER_HOST= blank, and sourcing that wholesale unset a
# daemon the operator had configured in their own shell.
load_env() {
    [ -f .env ] || return 0
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue ;; esac
        key=${line%%=*}
        value=${line#*=}
        case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac
        [ -n "$value" ] || continue
        export "$key=$value"
    done < .env
}
load_env

TOOLBOX_IMAGE="${SWARMSTRIKE_TOOLBOX_IMAGE:-swarmstrike/toolbox:latest}"
TOOLBOX_OK=yes

# Rewrite one KEY=value line in .env, adding it if it is not there.
set_env() {   # set_env <key> <value>
    python3 - "$1" "$2" <<'PY'
import pathlib, sys
key, value = sys.argv[1], sys.argv[2]
path = pathlib.Path(".env")
lines = path.read_text().splitlines()
for index, line in enumerate(lines):
    if line.startswith(f"{key}="):
        lines[index] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
path.write_text("\n".join(lines) + "\n")
PY
}

# --- 1. prerequisites ------------------------------------------------------
step "Checking prerequisites"

command -v python3 >/dev/null || die "python3 is not installed."
[ "$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')" = 1 ] \
    || die "Python 3.11 or newer is required (found $(python3 -V 2>&1))."
ok "$(python3 -V 2>&1)"

command -v docker >/dev/null || die "docker is not installed. Agents never execute
  on the host: every command runs inside a throwaway container, so the daemon
  is not optional."
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable.
  Start Docker, or point DOCKER_HOST at a daemon, and run this again."
ok "docker daemon reachable"

command -v node >/dev/null 2>&1 \
    && ok "node $(node -v)" \
    || warn "node was not found. The agent harness drives the Claude Code CLI,
    which is a Node program. Install Node 20+ or use the server container
    (docker/docker-compose.yml), which carries its own."

# --- 2. the package --------------------------------------------------------
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

# --- 3. the toolbox image --------------------------------------------------
step "Building the toolbox image"

LOG_DIR="${TMPDIR:-/tmp}/swarmstrike-setup.$$"
mkdir -p "$LOG_DIR"

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

# Show what actually failed. An earlier version printed a guess at the cause
# and threw the output away, which sent someone looking at their network when
# the build had broken on something else entirely.
tail_log() {
    printf '%s  ── last lines of %s ──%s\n' "$DIM" "$1" "$OFF"
    # Enough lines to carry the tool's own error, not just docker's summary of
    # which step failed: apt says why several lines above the line docker
    # quotes back.
    tail -n 40 "$1" | sed 's/^/    /'
    printf '%s  ── full log: %s ──%s\n' "$DIM" "$1" "$OFF"
}

# A build the operator interrupted is not a build that failed, and saying so
# sends them debugging something that was working.
was_cancelled() { grep -qE 'context canceled|CANCELED' "$1"; }

# Which Dockerfile an image was built from, recorded in the image itself.
# Comparing creation time against the Dockerfile's mtime does not work: a cache
# hit hands back an image whose Created predates the edit, so every run looked
# stale. The content hash is exact.
dockerfile_sha() { sha256sum "$1" 2>/dev/null | cut -c1-16; }

image_is_current() {   # image_is_current <image> <dockerfile>
    local stamped want
    [ "$REBUILD" = yes ] && return 1
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
elif run_build "$LOG_DIR/toolbox.log" \
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
        warn "neither toolbox image would build. Setup continues — an image is
    needed to run a campaign, not to set one up — but you will need one before
    the first run.

    If the failure above is a TLS error (curl 60, or a message about trust
    anchors) you are behind an intercepting proxy. Export its certificate,
    copy it into docker/ since that is the build context, and pass it in:
        cp /path/to/ca-bundle.crt docker/
        docker build -t swarmstrike/toolbox:minimal \\
            --build-arg CA_BUNDLE=ca-bundle.crt \\
            -f docker/Dockerfile.toolbox-minimal docker/"
    fi
fi

# --- 4. environment --------------------------------------------------------
step "Setting up .env"

[ -f .env ] || { cp .env.example .env; chmod 600 .env; ok "created .env from the example"; }

# The signing key. Generated here because a key is the one secret a script can
# safely create: it authorizes nothing by itself, it only detects tampering.
if grep -qE '^SWARMSTRIKE_SCOPE_KEY=.+' .env; then
    ok "signing key already set"
else
    set_env SWARMSTRIKE_SCOPE_KEY \
        "$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
    chmod 600 .env
    ok "signing key generated into .env (mode 600)"
fi

key_missing() { grep -qE '^ANTHROPIC_API_KEY=(sk-ant-\.\.\.)?$' .env; }

if [ -n "$API_KEY" ]; then
    set_env ANTHROPIC_API_KEY "$API_KEY"
    chmod 600 .env
    ok "API key recorded in .env"
elif key_missing && [ -t 0 ] && [ "$MODE" != setup ]; then
    # Asking beats printing instructions for a file the operator then has to
    # find. Nothing is echoed, and it goes to the same mode-600 file.
    printf '%s  Paste your Anthropic API key, or press Enter to skip: %s' "$DIM" "$OFF"
    read -r -s PASTED; printf '\n'
    if [ -n "$PASTED" ]; then
        set_env ANTHROPIC_API_KEY "$PASTED"
        chmod 600 .env
        ok "API key recorded in .env"
    fi
fi

key_missing \
    && warn "ANTHROPIC_API_KEY is still a placeholder in .env. The console opens
    and the demonstration runs without it; a campaign does not." \
    || ok "ANTHROPIC_API_KEY is set"

grep -qE "^SWARMSTRIKE_TOOLBOX_IMAGE=${TOOLBOX_IMAGE//\//\\/}$" .env \
    || { set_env SWARMSTRIKE_TOOLBOX_IMAGE "$TOOLBOX_IMAGE"
         ok "toolbox image recorded as $TOOLBOX_IMAGE"; }

# --- 5. the contract -------------------------------------------------------
step "Scaffolding the engagement contract"

if [ -f "$CONTRACT" ]; then
    ok "$CONTRACT already exists — left untouched"
else
    python3 -m swarmstrike.cli engagement init "$CONTRACT" >/dev/null
    ok "$CONTRACT written, with every field to fill in"
fi

load_env

SIGNED=no
if swarmstrike engagement verify "$CONTRACT" >/dev/null 2>&1; then SIGNED=yes; fi

# --- done ------------------------------------------------------------------
printf '\n%s%s  Setup complete.%s\n' "$BOLD" "$GREEN" "$OFF"

[ "$TOOLBOX_OK" = no ] && warn "No toolbox image was built. Every command an agent
    proposes runs inside one, so a campaign cannot start without it. Build one
    with the commands above, then check what it carries:
        swarmstrike probe --image <image>"

if [ "$SIGNED" = no ]; then
    cat <<EOF

  ${BOLD}Before a campaign, three steps that are yours rather than the script's${OFF}

  ${BOLD}1.${OFF} ${CYAN}\$EDITOR ${CONTRACT}${OFF}
     Who authorized this test in writing, which targets are in scope, what is
     forbidden, what it may spend. Scope is enforced at execution time, so a
     target missing here is a target the swarm will refuse to touch.

  ${BOLD}2.${OFF} ${CYAN}swarmstrike engagement sign ${CONTRACT}${OFF}
     Any edit after signing is detected and refuses the campaign.

  ${BOLD}3.${OFF} ${CYAN}swarmstrike engagement check ${CONTRACT} app.client.example 10.0.0.5${OFF}
     Each target comes back allowed or refused, with the rule that decided it.
     Do this before every engagement, not once.
EOF
fi

[ "$MODE" = setup ] && { printf '\n'; exit 0; }

if [ "$MODE" = tui ]; then
    key_missing && die "ANTHROPIC_API_KEY is not set in .env. The agents cannot
  run without it. Put it in .env, or pass it: ./run.sh --tui --key sk-ant-..."
    [ "$SIGNED" = yes ] || die "$CONTRACT is unsigned, or was edited after signing.
  A campaign will not start on a contract whose integrity cannot be proven.
  Do the three steps above, then run this again."
    printf '\n%s▸ Starting a campaign against %s%s\n\n' "$BOLD" "$CONTRACT" "$OFF"
    exec swarmstrike run "$CONTRACT" --tui "${PASSTHROUGH[@]}"
fi

printf '\n%s▸ Console on %shttp://%s:%s%s\n' "$BOLD" "$CYAN" "$HOST" "$PORT" "$OFF"
printf '%s  The demonstration, with no backend and no target: %s/?demo%s\n' \
    "$DIM" "http://$HOST:$PORT" "$OFF"
printf '%s  No authentication, which is why it binds to %s. Ctrl-C to stop.%s\n\n' \
    "$DIM" "$HOST" "$OFF"
exec swarmstrike serve --host "$HOST" --port "$PORT" "${PASSTHROUGH[@]}"
