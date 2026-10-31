#!/usr/bin/env bash
# swarmstrike, from a fresh checkout to a running console in one command.
#
#   ./run.sh                 # set up if needed, then open the console
#   ./run.sh --tui           # set up if needed, then run a campaign in the terminal
#   ./run.sh --setup-only    # stop after setup
#   ./run.sh --port 9000     # serve somewhere else
#
# Setup is idempotent, so this is also the command to run after a git pull:
# it rebuilds a toolbox image whose Dockerfile has changed and leaves
# everything else alone.
set -euo pipefail
cd "$(dirname "$0")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RED=$'\033[31m'; OFF=$'\033[0m'
die() { printf '\n%s  ✗%s %s\n\n' "$RED" "$OFF" "$1" >&2; exit 1; }

MODE=serve
HOST=127.0.0.1
PORT=8787
CONTRACT="${SWARMSTRIKE_CONTRACT:-engagement.yaml}"
PASSTHROUGH=()

while [ $# -gt 0 ]; do
    case "$1" in
        --tui)        MODE=tui; shift ;;
        --setup-only) MODE=setup; shift ;;
        --host)       HOST=$2; shift 2 ;;
        --port)       PORT=$2; shift 2 ;;
        --contract)   CONTRACT=$2; shift 2 ;;
        -h|--help)    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            PASSTHROUGH+=("$1"); shift ;;
    esac
done

./install.sh

[ "$MODE" = setup ] && exit 0

# The signing key lives in .env, and nothing below works without it.
[ -f .env ] || die "no .env — setup should have created one. Run ./install.sh."
set -a; . ./.env; set +a

have_api_key() {
    [ -n "${ANTHROPIC_API_KEY:-}" ] && [ "${ANTHROPIC_API_KEY}" != "sk-ant-..." ]
}

# A campaign needs a signed contract. The console does not — you can open it,
# look at the demonstration and verify a contract from the launch panel — so
# only the terminal path insists.
if [ "$MODE" = tui ]; then
    have_api_key || die "ANTHROPIC_API_KEY is not set in .env. The agents cannot
  run without it."
    [ -f "$CONTRACT" ] || die "no contract at $CONTRACT. Write one with
  'swarmstrike engagement init $CONTRACT', fill it in, and sign it."
    swarmstrike engagement verify "$CONTRACT" >/dev/null 2>&1 || die \
"$CONTRACT is unsigned or was edited after signing. A campaign will not start
  on a contract whose integrity cannot be proven:
      swarmstrike engagement sign $CONTRACT"
    printf '\n%s▸ Starting a campaign against %s%s\n\n' "$BOLD" "$CONTRACT" "$OFF"
    exec swarmstrike run "$CONTRACT" --tui "${PASSTHROUGH[@]}"
fi

# Serving needs no key. The console opens, the demonstration runs with no
# backend and no target, and a contract can be verified from the launch panel.
# Only starting a campaign needs one, and the console says so when you try.
have_api_key || printf '%s  ⚠  ANTHROPIC_API_KEY is still a placeholder in .env.\n     The console opens and the demonstration runs; starting a campaign\n     will not.%s\n' "$DIM" "$OFF"

printf '\n%s▸ Console on %shttp://%s:%s%s\n' "$BOLD" "$CYAN" "$HOST" "$PORT" "$OFF"
printf '%s  The demonstration, with no backend and no target, is at %s/?demo%s\n' \
    "$DIM" "http://$HOST:$PORT" "$OFF"
printf '%s  It has no authentication, which is why it binds to %s. Ctrl-C to stop.%s\n\n' \
    "$DIM" "$HOST" "$OFF"
exec swarmstrike serve --host "$HOST" --port "$PORT" "${PASSTHROUGH[@]}"
