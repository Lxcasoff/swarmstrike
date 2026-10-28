# Lab

A pair of deliberately vulnerable applications on an isolated Docker network,
and a signed engagement contract that authorizes testing them. It exists so a
change to the orchestrator can be exercised end to end against something that
answers, instead of only against unit tests.

Everything here stays on the host. The network has no route out, the targets
are published images built for this purpose, and no third party is involved.

## Standing it up

```sh
docker network create --subnet 172.31.77.0/24 swarmlab

docker run -d --name juice --network swarmlab --ip 172.31.77.10 \
    bkimminich/juice-shop:latest          # OWASP Juice Shop, :3000

docker run -d --name dvwa --network swarmlab --ip 172.31.77.11 \
    vulnerables/web-dvwa:latest           # DVWA, :80
```

Give Juice Shop a few seconds to start, then check both answer:

```sh
curl -so /dev/null -w '%{http_code}\n' http://172.31.77.10:3000/   # 200
curl -so /dev/null -w '%{http_code}\n' http://172.31.77.11/        # 302
```

## The toolbox

`docker/Dockerfile.toolbox` is the full toolset and needs network access to a
package mirror to build. Where that is unavailable, the minimal variant carries
curl, nuclei, httpx and ffuf from published release archives, which is enough
for a web and API campaign:

```sh
docker build -t swarmstrike/toolbox:minimal -f docker/Dockerfile.toolbox-minimal .
swarmstrike probe --image swarmstrike/toolbox:minimal
```

`probe` reports which recipes the image can actually run (5 of 68 binaries,
for the minimal image). Recipes whose binary
is absent are withheld from the agents rather than failing at execution time —
an agent that is told nmap exists will keep reaching for it.

## Signing the contract

`engagement.yaml` is signed, and the signature in it is keyed to whoever signed
it. Re-sign it with your own key before running anything:

```sh
export SWARMSTRIKE_SCOPE_KEY="$(openssl rand -hex 32)"
swarmstrike engagement sign lab/engagement.yaml
swarmstrike engagement verify lab/engagement.yaml
```

The scope names `172.31.77.0/24` explicitly. Private ranges are refused unless
the contract names them, so that line is what makes the lab reachable at all —
the same mechanism that authorizes an internal engagement.

## Running a campaign

```sh
swarmstrike run \
    --engagement lab/engagement.yaml \
    --workspace lab/campaigns \
    --image swarmstrike/toolbox:minimal \
    --network swarmlab \
    -d recon -d web -d api \
    --search-rounds 3 --review-rounds 1
```

`--network swarmlab` puts each toolbox container on the lab network; without it
the targets are unreachable and every command returns a connection error.
Preflight catches the other half of that problem by writing a token into the
workspace and having a toolbox container read it back, so a campaign cannot run
with a bind mount that silently did not land.

Output lands in `lab/campaigns/<campaign-id>/`: the knowledge base, the audit
chain, raw tool output and the report. That directory is gitignored.
