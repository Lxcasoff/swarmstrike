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
pip install -e .

# Build the toolbox image the agents' commands run inside.
docker build -t swarmstrike/toolbox:latest -f docker/Dockerfile.toolbox .

# A signing key, kept outside the repository.
export SWARMSTRIKE_SCOPE_KEY=$(openssl rand -hex 32)
export ANTHROPIC_API_KEY=sk-ant-...

# Write a contract, fill it in, and sign it.
swarmstrike engagement init engagement.yaml
$EDITOR engagement.yaml
swarmstrike engagement sign engagement.yaml

# Confirm the contract says what you think it says.
swarmstrike engagement check engagement.yaml app.client.example 10.0.0.5

# Run it — in the terminal…
swarmstrike run engagement.yaml --tui

# …or in the browser.
pip install -e '.[web]'
swarmstrike serve          # http://127.0.0.1:8787
```

See the interface without touching anything: open
`http://127.0.0.1:8787/?demo=1`, which replays a scripted campaign through the
same renderers with no backend and no target.

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

A lead agent plans the engagement and delegates to the specialists, because
deciding what to test next given what was just found is genuinely a judgement
call. Everything around that decision — the contract check, the budget ceiling,
the challenge round, the report assembly — runs in code, so it happens whether
or not a model remembers to ask for it.

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

Early, and honest about where the line is.

**Tested.** The contract and its signing, scope enforcement, the audit chain,
the budget ceiling and CVSS scoring — 48 tests, including every command shape
that must never reach a target, and the report's escaping of
target-controlled evidence.

**Implemented but not yet exercised against a live engagement.** The agent
roster, the lead's delegation, the challenge round, and the toolbox image.
These need a first real campaign to tune, and the prompts in particular will
want iteration against findings a client actually cares about.

```bash
pytest
```

Before you run this against anything real: read `swarmstrike/scope.py`, run
`swarmstrike engagement check` against your contract until you are satisfied it
refuses what it should, and start with a narrow roster on a small scope.
