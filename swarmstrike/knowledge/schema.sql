-- swarmstrike campaign knowledge base.
--
-- One database per campaign. Every agent reads and writes here, which is what
-- lets a web specialist notice that the network specialist already fingerprinted
-- a host, and what stops two agents scanning the same target twice.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS campaign (
    id                   TEXT PRIMARY KEY,
    engagement_id        TEXT NOT NULL,
    client               TEXT NOT NULL,
    mission              TEXT NOT NULL,
    contract_fingerprint TEXT NOT NULL,
    started_at           TEXT NOT NULL,
    ended_at             TEXT,
    status               TEXT NOT NULL DEFAULT 'running'
                         CHECK (status IN ('running','completed','aborted','budget_exhausted'))
);

-- ---------------------------------------------------------------------------
--  Attack surface
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id   TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN
                  ('domain','host','url','service','cloud_resource','identity','repository')),
    value         TEXT NOT NULL,
    discovered_by TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    attributes    TEXT NOT NULL DEFAULT '{}',   -- JSON
    UNIQUE (campaign_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_asset_campaign ON asset(campaign_id, kind);

CREATE TABLE IF NOT EXISTS service (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id  INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    protocol  TEXT NOT NULL DEFAULT 'tcp',
    name      TEXT,
    product   TEXT,
    version   TEXT,
    banner    TEXT,
    UNIQUE (asset_id, port, protocol)
);

-- ---------------------------------------------------------------------------
--  Findings and the debate around them
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS finding (
    id            TEXT PRIMARY KEY,
    campaign_id   TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    domain        TEXT NOT NULL,          -- web | network | cloud | ad | ...
    asset         TEXT NOT NULL,          -- what it affects, as presented to the client

    -- A finding is 'proposed' until the review round has run. Only 'confirmed'
    -- findings reach the report body; 'rejected' ones are kept for the audit
    -- trail, and 'theoretical' means plausible but not provable within the ROE.
    status        TEXT NOT NULL DEFAULT 'proposed'
                  CHECK (status IN ('proposed','under_review','confirmed','rejected','theoretical')),
    confidence    REAL NOT NULL DEFAULT 0.0 CHECK (confidence BETWEEN 0.0 AND 1.0),

    severity      TEXT CHECK (severity IN ('none','low','medium','high','critical')),
    cvss_vector   TEXT,
    cvss_score    REAL,

    summary       TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    impact        TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    effort        TEXT,                   -- remediation effort: low | medium | high

    cwe           TEXT,
    owasp_wstg    TEXT,                   -- e.g. WSTG-ATHN-01
    mitre_attack  TEXT,                   -- e.g. T1190

    discovered_by TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_campaign ON finding(campaign_id, status);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('command','http','output','file','screenshot')),
    label       TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

-- Peer review: a specialist from another domain examines the finding.
CREATE TABLE IF NOT EXISTS review (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    reviewer   TEXT NOT NULL,
    round      INTEGER NOT NULL DEFAULT 1,
    stance     TEXT NOT NULL CHECK (stance IN ('support','refute','abstain')),
    rationale  TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_finding ON review(finding_id);

-- The arbiter's ruling. One per finding per round.
CREATE TABLE IF NOT EXISTS arbitration (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    arbiter     TEXT NOT NULL,
    round       INTEGER NOT NULL DEFAULT 1,
    verdict     TEXT NOT NULL CHECK (verdict IN ('confirmed','rejected','theoretical','needs_work')),
    confidence  REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    rationale   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (finding_id, round)
);

-- ---------------------------------------------------------------------------
--  Coordination
-- ---------------------------------------------------------------------------
-- An agent claims a unit of work before starting it. The UNIQUE constraint is
-- the whole mechanism: a second agent's insert fails and it moves on.
CREATE TABLE IF NOT EXISTS claim (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    task_key    TEXT NOT NULL,
    agent       TEXT NOT NULL,
    claimed_at  TEXT NOT NULL,
    released_at TEXT,
    result      TEXT,
    UNIQUE (campaign_id, task_key)
);

-- Free-form notes agents leave for each other.
CREATE TABLE IF NOT EXISTS note (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    agent       TEXT NOT NULL,
    topic       TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_note_topic ON note(campaign_id, topic);

-- Every command dispatched, mirroring the audit log for queryability.
CREATE TABLE IF NOT EXISTS command_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    agent       TEXT NOT NULL,
    argv        TEXT NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    exit_code   INTEGER,
    duration_ms INTEGER,
    output_path TEXT,
    created_at  TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
--  Fact graph
-- ---------------------------------------------------------------------------
--  Derived from CyberStrikeAI's project blackboard (Apache-2.0; see NOTICE).
--
--  A fact is one piece of established knowledge about the engagement, keyed so
--  that learning more about the same thing overwrites rather than accumulating
--  near-duplicates. Three things make this more than a notes table:
--
--  * `summary` is an index line and `body` is the full reproducible context.
--    Agents list summaries cheaply and fetch a body only when they need it,
--    which keeps a long campaign from spending its context on recall.
--  * `confidence` distinguishes a lead from an established fact, so an agent
--    can see that something is unverified rather than inferring it.
--  * edges make the facts a graph, which is what lets a privilege path be
--    reconstructed afterwards instead of being asserted.

CREATE TABLE IF NOT EXISTS fact (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,

    -- category/slug, e.g. target/primary-domain or finding/sqli-login
    fact_key    TEXT NOT NULL,
    category    TEXT NOT NULL CHECK (category IN
                ('target','auth','infra','business','access',
                 'finding','chain','exploit','poc','detection','note')),

    -- One line, and it has to stand alone: what, where, and how it was
    -- established. "SQL injection exists" is not a summary.
    summary     TEXT NOT NULL,
    -- Everything needed to reproduce it. Not returned by listings.
    body        TEXT NOT NULL DEFAULT '',

    confidence  TEXT NOT NULL DEFAULT 'tentative'
                CHECK (confidence IN ('confirmed','tentative','deprecated')),

    -- A fact that records something that did NOT work. Worth as much as a
    -- positive one: it stops another agent spending the budget again.
    negative    INTEGER NOT NULL DEFAULT 0,

    agent       TEXT NOT NULL,
    related_finding_id TEXT REFERENCES finding(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (campaign_id, fact_key)
);

CREATE INDEX IF NOT EXISTS idx_fact_campaign ON fact(campaign_id, category, confidence);

CREATE TABLE IF NOT EXISTS fact_edge (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaign(id) ON DELETE CASCADE,
    src_key     TEXT NOT NULL,
    dst_key     TEXT NOT NULL,

    -- enables:     src makes dst reachable — this is the attack-path edge
    -- evidences:   src is evidence for dst
    -- contradicts: src argues against dst
    -- supersedes:  src replaces dst
    -- part_of:     src is a component of dst
    relation    TEXT NOT NULL CHECK (relation IN
                ('enables','evidences','contradicts','supersedes','part_of')),
    note        TEXT NOT NULL DEFAULT '',
    agent       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE (campaign_id, src_key, dst_key, relation)
);

CREATE INDEX IF NOT EXISTS idx_edge_src ON fact_edge(campaign_id, src_key);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON fact_edge(campaign_id, dst_key);
