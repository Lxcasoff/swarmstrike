# swarmstrike

A team of specialised AI agents that work an authorized penetration test the
way a human team would: each one covering a domain it knows, all of them
sharing what they find, and every finding challenged by a colleague before it
reaches the client.

The output is a report, not a scanner dump. Nothing reaches it that has not
been reviewed by a second specialist, attacked by a reviewer whose job is to
prove it is a false positive, and adjudicated.

> **This tool runs against systems you are authorized to test, and it enforces
> that in code.** It will not start without a signed engagement contract, and
> it refuses commands outside that contract's scope at execution time. If you
> do not have written authorization for the targets, this is not the tool for
> you.

---

## How the safety model works

This is the part that matters, because the agents run autonomously.

**The engagement contract is the authority.** `engagement.yaml` declares the
client, the written authorization, the testing window, the in-scope and
excluded targets, the rules of engagement and the spend ceilings. It is
HMAC-signed with a key kept outside the repository. A campaign will not start
on an unsigned contract, and any edit after signing is detected:

```console
$ swarmstrike engagement verify engagement.yaml
✗ contract content does not match its fingerprint — it was edited after signing
```

**Scope is enforced, not trusted.** Every command an agent proposes is parsed
and checked before it runs. The guard fails closed — a command whose targets it
cannot positively place inside the contract is refused rather than allowed
through:

```console
$ swarmstrike engagement check engagement.yaml www.example.org 8.8.8.8 169.254.169.254
www.example.org   allow    scope.domain   matches in-scope domain example.org
8.8.8.8           refuse   scope.miss     not in any in-scope range
169.254.169.254   refuse   hard_deny      loopback/link-local, never in scope
```

Loopback and link-local addresses are refused regardless of what the contract
says, which keeps the swarm off its own toolbox and off the cloud metadata
endpoint. Private ranges count as in scope only when the contract names them,
so an external engagement cannot wander into an internal network by accident.

**Some things are refused outright.** Destruction, denial of service, data
modification, persistence and social engineering are matched before scope is
even consulted, because an in-scope target does not license them. Authentication
testing is off unless the contract authorizes it against named test accounts.

**Agents never execute on the host.** Every command runs in a disposable
container with a read-only root filesystem, all capabilities dropped, and bind
mounts limited to the campaign workspace.

**No shell is exposed.** Agents get typed tools that build their own argument
vectors from validated parameters. There is no string for an agent to inject
into.

**Everything is recorded.** Commands are logged before they run, in an
append-only record where each entry is hash-chained to the one before it. The
chain can be verified afterwards, which is what lets a client audit what was
actually done:

```console
$ swarmstrike audit verify campaigns/ENG-2026-014-20261023-1412-a7f3c1
✓ chain intact across 1,284 entries (head 5e8671140d671e67…)
```

**There is a stop button.** `halt_campaign` is a tool the agents themselves
have, and they are told to use it when they see a service degrading, an asset
that may belong to a third party, or exposed personal data. An operator can
trip the same switch from the live view, or from any shell with
`touch <campaign-dir>/HALT`.

**Spend is capped.** The contract sets cost, token and wall-clock ceilings. The
campaign stops when one is reached, and the findings gathered up to that point
are still reviewed and reported.

---

## Quickstart

```bash
./run.sh
```

One script does the lot: checks your prerequisites, installs the package with
the dashboard, builds the toolbox image the agents' commands run inside,
generates a signing key into `.env`, asks for your Anthropic API key if it is
not set, scaffolds a contract, and opens the console. Re-running it is safe —
a key, a contract and an image that already exist are left alone — so it is
also the command to run after a `git pull`.

```bash
./run.sh --tui            # run a campaign in the terminal instead
./run.sh --setup-only     # set up and stop
./run.sh --key sk-ant-... # record an API key without being asked
./run.sh --rebuild        # rebuild the toolbox image even if it is current
```

It stops short of signing the contract, and that is deliberate. The contract is
the written authorization this tool answers to — who asked for the test,
against which targets, within which window. A script cannot know any of that,
and one that signed a contract anyway would be forging the authorization the
rest of the design exists to enforce. The last three steps are yours:

```bash
$EDITOR engagement.yaml                 # who authorized this, and against what
swarmstrike engagement sign engagement.yaml

# Confirm the contract says what you think it says, before every engagement.
swarmstrike engagement check engagement.yaml app.client.example 10.0.0.5

# Then run it.
./run.sh                                # console, http://127.0.0.1:8787
./run.sh --tui                          # or in the terminal
```

See the interface without touching anything: `swarmstrike serve`, then open
`http://127.0.0.1:8787/?demo`, which replays a scripted campaign through the
same renderers with no backend and no target. A hosted copy of that
demonstration is linked from the repository description.

<details>
<summary>Doing it by hand instead</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[web]'
npm install -g @anthropic-ai/claude-code      # the harness drives this CLI

docker build -t swarmstrike/toolbox:latest -f docker/Dockerfile.toolbox .

cp .env.example .env
# Fill in ANTHROPIC_API_KEY, and SWARMSTRIKE_SCOPE_KEY=$(openssl rand -hex 32).

swarmstrike engagement init engagement.yaml
```

Where there is no egress to a package mirror, the full toolbox cannot build.
`docker/Dockerfile.toolbox-minimal` carries curl, nuclei, httpx and ffuf from
published release archives, which covers web and API work and nothing else.
`swarmstrike probe --image <image>` reports which recipes an image can actually
run; the ones it cannot are withheld from the agents rather than left to fail
mid-campaign.

</details>

---

## The dashboard

`swarmstrike serve` gives you the campaign as it happens: each agent as an
animated avatar whose state comes from real events — working while a tool runs,
thinking while it reasons over a finding, a burst when it proposes one, a shake
when the contract refuses a command. Findings appear as they are proposed and
change as the arbiter rules on them; clicking one opens the debate behind it.
The kill switch is in the header.

It binds to localhost. A campaign record describes unremediated vulnerabilities
in a client's systems and the dashboard has no authentication of its own, so
putting it anywhere else needs a deliberate decision and something in front of it.

---

## Running it as a container

One command, which is the property a single static binary would have bought —
without rewriting the project in a language that produces one. The reasoning is
in [Why Python](#why-python) below.

```bash
cp .env.example .env            # ANTHROPIC_API_KEY and SWARMSTRIKE_SCOPE_KEY
mkdir -p campaigns              # writable by uid 1000
$EDITOR engagement.yaml         # then sign it

docker build -t swarmstrike/toolbox:latest -f docker/Dockerfile.toolbox .
docker compose -f docker/docker-compose.yml up
```

Then open http://127.0.0.1:8787.

Two images, and the split is the point. `swarmstrike/server` holds the
orchestrator, the dashboard, the API key and the signing key, and carries no
assessment tooling at all. `swarmstrike/toolbox` holds the tooling and is
started fresh per command, holding neither key. A test fails if an assessment
binary turns up in the server image, because that separation is easy to erode
by accident.

**Before running it anywhere but your own machine.** The compose file mounts the
Docker socket, because the orchestrator starts a toolbox container per command.
Access to that socket is equivalent to root on the host, so the container around
swarmstrike is not a security boundary against swarmstrike. Run it on a machine
you are willing to treat as dedicated to the engagement. The dashboard has no
authentication and the port is published to loopback for that reason — it can
start a penetration test and approve shell commands. Where you have the option,
point `DOCKER_HOST` at a remote daemon and drop the socket mount entirely.

### The mount that fails silently

Toolbox containers are siblings of the server, not children, so the daemon
resolves their bind mounts against the host filesystem rather than against the
server's. If those paths disagree, every tool mounts an empty directory, runs
normally, writes into nothing and reports success — and the campaign looks
healthy until someone opens a report with no evidence in it.

The compose file avoids it by mounting the campaigns directory at the same
absolute path on both sides, so there is nothing to translate. If you change
that, set `SWARMSTRIKE_HOST_WORKSPACE` to the host path for the directory.

Either way, preflight proves it rather than trusting it: it writes a token into
the workspace, has a toolbox container read it back, and refuses to start the
campaign if the token does not come back.

---

## Why Python

CyberStrikeAI, the project this borrows from, is written in Go and ships as one
static binary. That is a real advantage for a tool you drop on a jump host, and
it is worth saying why this is not.

Their `multiagent` package is 17,000 lines: the agent loop, context management,
subagents, and their orchestration modes. The Claude Agent SDK provides that,
and it is Python and TypeScript. Writing this in Go would mean paying those
17,000 lines back.

It would not even produce the single binary, because the Agent SDK drives the
`claude` CLI, which is a Node program — so the runtime is Python plus Node
either way, and a Go rewrite would either embed that same Node CLI for no gain
or reimplement the harness against the Messages API directly.

The deployment property Go was bought for is real, so it is solved above with a
container instead. The other usual argument, concurrency, does not apply: this
process starts subprocesses and containers, which is I/O, and asyncio is
entirely adequate for that.

## The team

| Agent | Covers |
|---|---|
| `recon` | Attack surface: domains, hosts, services, public footprint, forgotten assets |
| `network` | Exposed services, version identification, known vulnerabilities, segmentation |
| `web` | OWASP Top 10, authentication, authorization, business logic |
| `api` | REST and GraphQL, object-level authorization, token handling, rate limiting |
| `cloud` | IAM, storage exposure, network policy, key management |
| `ad` | Active Directory: Kerberos, delegation, ACLs, privilege paths |
| `code` | Secrets, dependencies, supply chain, implementation review |
| `crypto` | TLS configuration, certificates, cryptographic implementation |

Plus three roles that never touch a target:

| Agent | Role |
|---|---|
| `skeptic` | Argues every finding is a false positive, an overstatement or a duplicate |
| `arbiter` | Rules on contested findings and sets the severity the client sees |
| `reporter` | Writes the deliverable from the confirmed record |

A lead agent decides what gets tested next, because that is genuinely a
judgement call. Everything around the decision — the contract check, the budget
ceiling, the challenge round, the report assembly — runs in code, so it happens
whether or not a model remembers to ask for it.

### The campaign is a search, not a playbook

An engagement does not have a fixed shape. What to do next depends on what is
already established: a host nobody has fingerprinted, a credential that opens
something, a dead end that rules a whole direction out. So the lead is asked
the same question each round — given the facts on the board, what is the most
useful thing to do now — and the campaign ends when it says there is nothing
left worth doing, or a ceiling is reached.

```
          ┌──────────────────────────────────────┐
          │  the board: facts, dead ends, paths  │
          └───────────────┬──────────────────────┘
                          │  what is most useful now?
                   ┌──────▼───────┐
                   │     lead     │
                   └──────┬───────┘
          ┌───────────────┼───────────────┐
      ┌───▼────┐     ┌────▼───┐      ┌────▼───┐   assigned in parallel,
      │ recon  │     │  web   │      │   ad   │   claimed so no two
      └───┬────┘     └────┬───┘      └────┬───┘   agents duplicate work
          └───────────────┼───────────────┘
                          │  facts, findings, dead ends
                          └──────────────► back to the board
```

The approach follows CyberStrikeAI's `pentest-agent-os` framing, which models
penetration testing as search rather than a sequence of phases. What is added
here is that the loop runs in code: the round structure, the duplicate-work
check, the budget check and the stopping condition are not things the lead can
forget to do, because the lead is not the thing doing them.

Two stopping conditions beyond the obvious ones. Assigning a unit of work that
is already claimed is refused by the database rather than by the prompt, since
the lead sees the assigned list but a race between rounds would still slip
past it. And two consecutive rounds that establish nothing new end the search —
that is either convergence or a lead going in circles, and both mean stop.

Limit the roster when you only need part of it:

```bash
swarmstrike run engagement.yaml -d recon -d web -d api
```

---

## How a finding becomes a finding

1. A specialist records it as **proposed**, with evidence and a CVSS v3.1
   vector. The score is computed from the vector, never taken on the model's
   word.
2. A specialist **from a different discipline** reviews it. A reviewer outside
   the discipline catches what someone inside it assumes.
3. The **skeptic** tries to establish it is a false positive: does the evidence
   show what is claimed, is it reachable the way the vector says, is the vector
   honest, is it a duplicate, is it actually a vulnerability?
4. The **arbiter** rules: `confirmed`, `rejected`, `theoretical` (plausible but
   not proven within the rules of engagement), or `needs_work` — which sends it
   back for one more pass with the missing evidence named.

Only `confirmed` findings reach the report body. `theoretical` ones get their
own section, labelled honestly as unproven. `rejected` ones stay in the record
with the reasoning that rejected them.

Rejection is the system working. A report that overstates findings costs the
client their trust in the parts that are right.

---

## What the report contains

Markdown with YAML front matter, so `pandoc` converts it to PDF or DOCX
directly. Structured the way an assessment report should be:

- Executive summary and overall risk, written for readers who stop there
- Scope, exclusions and the rules of engagement, as agreed
- Methodology: PTES phases, OWASP WSTG alignment, CVSS v3.1 scoring
- How findings were validated, and how many were rejected
- Confirmed findings, each with severity, CVSS vector, CWE, OWASP WSTG and
  MITRE ATT&CK references, reproduction steps and specific remediation
- Unproven weaknesses, separately and honestly labelled
- Coverage: what was found and what was examined
- A prioritised remediation roadmap
- The engagement record: audit chain verification, commands issued, and the
  refusals that show the scope boundary held
- The limits of the assessment, stated plainly

Markdown is the default; `--format html` adds a styled, printable version with
two charts, and `--format pdf` needs the `pdf` extra. Rebuild any of them from
the campaign record at any time, and optionally have the reporter agent write
the summary in prose:

```bash
swarmstrike report campaigns/ENG-2026-014-… --format all --narrate
```

The HTML report needs no scripts, fonts or network, and prints to A4. Its
evidence sections are autoescaped — a reflected-XSS finding whose payload ran
in the client's browser when they opened the report would be a vulnerability
delivered by the deliverable.

The second chart plots each finding by CVSS exploitability against impact,
both taken from its vector. It is deliberately not a likelihood-and-impact
matrix: the engagement produces no likelihood data, and that axis would be a
guess presented as a measurement.

---

## Model routing

Reasoning quality matters most where a mistake propagates, so the roles are
not all on the same model.

| Role | Model | Why |
|---|---|---|
| Lead, arbiter, reporter | Opus | Decisions that shape everything downstream |
| Specialists, skeptic | Sonnet | Domain work and adversarial review at volume |
| Output parsing | Haiku | Turning a 40,000-line scanner dump into records |

Override per role in the campaign configuration. The budget tracker reads the
harness's own cost estimate per run and stops the campaign at the contract's
ceiling.

---

## Status

Version 1.0: exercised end to end, and honest about where the line still is.

**Tested.** 276 tests, covering the contract and its signing, scope
enforcement, the audit chain, the approval gate, the three execution tiers,
the fact graph, the state-space loop, CVSS scoring, and the report's escaping
of target-controlled evidence. Every command shape that must never reach a
target has a test that proves it does not.

**Exercised against live targets.** Two full campaigns against a lab of
deliberately vulnerable applications (OWASP Juice Shop and DVWA on an isolated
network — see `lab/`). 155 commands, nine confirmed findings including an
unauthenticated SQL injection and a user-record disclosure, a hash chain
verified across 186 entries, inside a $4 budget. That is also where eight
defects came from that no unit test was going to find: a digest that offered
the lead tools the image did not carry, agent self-claims that never closed and
stalled the search two rounds early, a comma-separated target list that read as
no target at all, credential material written to the evidence directory
unflagged, a halt that made resuming impossible by construction, and a fact
link to a non-existent key that silently dropped the only attack-path step.
Each is fixed, each has a test.

**Not yet exercised.**

- *A real client engagement.* The lab is a lab. Prompts in particular will want
  iteration against findings a client actually cares about.
- *The attack-path section.* It has never produced a chain from real data. On
  the lab engagement that is arguably correct — exploitation stopped at proof
  and authentication testing was unauthorized, so the findings are independent
  pre-auth disclosures with nothing to chain — but the section remains unproven.
- *The red-team phases.* Persistence, exfiltration and evasion are implemented
  and gated behind contract flags that the lab contract left off.
- *Active Directory and cloud.* The specialists and their recipes exist; no
  target has been available to run them against.

```bash
pytest
```

Before you run this against anything real: read `swarmstrike/scope.py`, run
`swarmstrike engagement check` against your contract until you are satisfied it
refuses what it should, and start with a narrow roster on a small scope.
