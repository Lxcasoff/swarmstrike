# swarmstrike server image.
#
# This is the whole product in one image: the CLI, the orchestrator and the web
# dashboard. It is the answer to "I want one command to run this" without
# rewriting the project in a language that compiles to a single binary — see
# README for why that trade was taken.
#
#   docker build -t swarmstrike/server:latest -f docker/Dockerfile .
#   docker compose -f docker/docker-compose.yml up
#
# It does NOT carry the assessment tooling. Agents never execute in this
# container: every command they propose runs in a throwaway toolbox container
# started from swarmstrike/toolbox, which is built separately. That separation
# is the point — this process holds the API key and the signing key, and the
# processes that touch a client's systems hold neither.
FROM mirror.gcr.io/library/python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/node/bin:${PATH}"

# Pin everything: an assessment report states what produced it, and "whatever
# was latest on build day" is not a statement.
ARG NODE_VERSION=22.11.0
ARG DOCKER_CLI_VERSION=27.3.1
ARG TARGETARCH=amd64

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git tini; \
    rm -rf /var/lib/apt/lists/*

# --- Node, for the agent harness ------------------------------------------
# The Claude Agent SDK drives the `claude` CLI, which is a Node program. This
# is why the image carries two runtimes; it is also why rewriting the project
# in Go would not have produced a single static binary either.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) NODE_ARCH=x64 ;; \
        arm64) NODE_ARCH=arm64 ;; \
        *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.tar.xz \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.xz; \
    npm install -g @anthropic-ai/claude-code; \
    npm cache clean --force

# --- Docker client --------------------------------------------------------
# The client only. The orchestrator talks to a daemon it is given; it never
# runs one. See the security note in docker-compose.yml about what granting
# that access means.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) DOCKER_ARCH=x86_64 ;; \
        arm64) DOCKER_ARCH=aarch64 ;; \
        *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/docker.tgz \
        "https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_CLI_VERSION}.tgz"; \
    tar -xzf /tmp/docker.tgz -C /tmp docker/docker; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker.tgz /tmp/docker

# --- swarmstrike ----------------------------------------------------------
WORKDIR /opt/swarmstrike

# Dependencies first, so editing the source does not re-resolve them.
COPY pyproject.toml README.md ./
COPY swarmstrike ./swarmstrike
RUN pip install --no-cache-dir '.[web]'

# --- Unprivileged user ----------------------------------------------------
# The campaign workspace is written as this user, so the host directory behind
# it has to be writable by uid 1000. docker-compose.yml notes this.
RUN useradd --create-home --uid 1000 --shell /bin/bash operator \
    && mkdir -p /srv/swarmstrike/campaigns \
    && chown -R operator:operator /srv/swarmstrike

USER operator
WORKDIR /srv/swarmstrike

EXPOSE 8787

# The dashboard binds to every interface here because the container's network
# is the isolation boundary — publish the port only where you mean to, and put
# authentication in front of it if that is anywhere but your own machine.
ENV SWARMSTRIKE_WORKSPACE=/srv/swarmstrike/campaigns

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/roster', timeout=4).status == 200 else 1)"

# tini reaps the toolbox client processes the executor spawns; without an init
# a long campaign accumulates zombies until it hits the pid limit.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["swarmstrike", "serve", "--host", "0.0.0.0", "--port", "8787"]
