"""Campaign knowledge base.

Shared state for the swarm. Agents discover assets, propose findings, review
each other's work and claim tasks through this one object, which is what makes
a dozen agents behave like a team rather than a dozen independent scans.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from ..engagement import Engagement

SCHEMA = Path(__file__).with_name("schema.sql")

# ---------------------------------------------------------------------------
#  Fact graph
# ---------------------------------------------------------------------------
FACT_CATEGORIES = (
    "target", "auth", "infra", "business", "access",
    "finding", "chain", "exploit", "poc", "detection", "note",
)
FACT_KEY = re.compile(r"^([a-z][a-z0-9]*)/([a-z0-9][a-z0-9._-]{0,80})$")
RELATIONS = ("enables", "evidences", "contradicts", "supersedes", "part_of")
CONFIDENCES = ("confirmed", "tentative", "deprecated")


class FactError(ValueError):
    """A fact key, category, confidence or relation is not valid."""


def parse_fact_key(fact_key: str) -> tuple[str, str]:
    """Split and validate a `category/slug` key.

    Case and surrounding whitespace are normalised rather than rejected, so an
    agent writing `Target/Primary-Domain` gets the same fact as one writing
    `target/primary-domain` instead of an error.
    """
    match = FACT_KEY.match(fact_key.strip().lower())
    if match is None:
        raise FactError(
            f"{fact_key!r} is not a fact key. Keys are category/slug, e.g. "
            f"target/primary-domain or finding/sqli-login."
        )
    category, slug = match.groups()
    if category not in FACT_CATEGORIES:
        raise FactError(
            f"{category!r} is not a fact category. Use one of: "
            f"{', '.join(FACT_CATEGORIES)}"
        )
    return category, slug



def _now() -> str:
    return datetime.now(tz=ZoneInfo("UTC")).isoformat()


@dataclass
class Finding:
    """A candidate finding, before the debate has ruled on it."""

    title: str
    domain: str
    asset: str
    summary: str
    discovered_by: str

    description: str = ""
    impact: str = ""
    remediation: str = ""
    effort: str | None = None

    severity: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None

    cwe: str | None = None
    owasp_wstg: str | None = None
    mitre_attack: str | None = None

    id: str = ""
    status: str = "proposed"
    confidence: float = 0.0
    evidence: list[tuple[str, str, str]] = field(default_factory=list)  # (kind, label, content)


class KnowledgeBase:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because the campaign writes from the event
        # loop while the dashboard reads from whichever thread serves the
        # request. CPython's sqlite3 is built serialized, so sharing one
        # autocommit connection is safe; without this the reader raises and an
        # endpoint fails mid-campaign.
        self.conn = sqlite3.connect(
            self.path, isolation_level=None, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA.read_text(encoding="utf-8"))
        self._campaign_id: str | None = None

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> KnowledgeBase:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def campaign_id(self) -> str:
        if self._campaign_id is None:
            raise RuntimeError("no campaign opened on this knowledge base")
        return self._campaign_id

    # ------------------------------------------------------------------
    #  Campaign lifecycle
    # ------------------------------------------------------------------
    def open_campaign(self, campaign_id: str, engagement: Engagement) -> str:
        meta = engagement.engagement
        self.conn.execute(
            """INSERT OR IGNORE INTO campaign
               (id, engagement_id, client, mission, contract_fingerprint, started_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                campaign_id,
                meta.id,
                meta.client,
                meta.mission,
                engagement.integrity.fingerprint or "",
                _now(),
            ),
        )
        self._campaign_id = campaign_id
        return campaign_id

    def resume_campaign(self, campaign_id: str) -> None:
        row = self.conn.execute("SELECT id FROM campaign WHERE id = ?", (campaign_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"no campaign {campaign_id!r} in {self.path}")
        self._campaign_id = campaign_id

    def close_campaign(self, status: str = "completed") -> None:
        self.conn.execute(
            "UPDATE campaign SET status = ?, ended_at = ? WHERE id = ?",
            (status, _now(), self.campaign_id),
        )

    # ------------------------------------------------------------------
    #  Attack surface
    # ------------------------------------------------------------------
    def add_asset(
        self,
        kind: str,
        value: str,
        discovered_by: str,
        attributes: dict[str, Any] | None = None,
    ) -> bool:
        """Record an asset. Returns True if it was new to the campaign."""
        cursor = self.conn.execute(
            """INSERT OR IGNORE INTO asset
               (campaign_id, kind, value, discovered_by, discovered_at, attributes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (self.campaign_id, kind, value, discovered_by, _now(),
             json.dumps(attributes or {}, sort_keys=True)),
        )
        return cursor.rowcount > 0

    def assets(self, kind: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM asset WHERE campaign_id = ?"
        params: list[Any] = [self.campaign_id]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        sql += " ORDER BY discovered_at"
        return [dict(r) for r in self.conn.execute(sql, params)]

    def add_service(
        self,
        host: str,
        port: int,
        *,
        protocol: str = "tcp",
        name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
        discovered_by: str = "unknown",
    ) -> None:
        self.add_asset("host", host, discovered_by)
        row = self.conn.execute(
            "SELECT id FROM asset WHERE campaign_id = ? AND kind = 'host' AND value = ?",
            (self.campaign_id, host),
        ).fetchone()
        if row is None:
            return
        self.conn.execute(
            """INSERT INTO service (asset_id, port, protocol, name, product, version, banner)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
                   name    = COALESCE(excluded.name, service.name),
                   product = COALESCE(excluded.product, service.product),
                   version = COALESCE(excluded.version, service.version),
                   banner  = COALESCE(excluded.banner, service.banner)""",
            (row["id"], port, protocol, name, product, version, banner),
        )

    def services(self) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                """SELECT a.value AS host, s.port, s.protocol, s.name, s.product, s.version
                   FROM service s JOIN asset a ON a.id = s.asset_id
                   WHERE a.campaign_id = ?
                   ORDER BY a.value, s.port""",
                (self.campaign_id,),
            )
        ]

    # ------------------------------------------------------------------
    #  Findings
    # ------------------------------------------------------------------
    def _next_finding_id(self) -> str:
        count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM finding WHERE campaign_id = ?", (self.campaign_id,)
        ).fetchone()["n"]
        return f"F-{count + 1:03d}"

    def add_finding(self, finding: Finding) -> str:
        finding.id = finding.id or self._next_finding_id()
        now = _now()
        self.conn.execute(
            """INSERT INTO finding
               (id, campaign_id, title, domain, asset, status, confidence, severity,
                cvss_vector, cvss_score, summary, description, impact, remediation, effort,
                cwe, owasp_wstg, mitre_attack, discovered_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.id, self.campaign_id, finding.title, finding.domain, finding.asset,
                finding.status, finding.confidence, finding.severity,
                finding.cvss_vector, finding.cvss_score, finding.summary, finding.description,
                finding.impact, finding.remediation, finding.effort,
                finding.cwe, finding.owasp_wstg, finding.mitre_attack,
                finding.discovered_by, now, now,
            ),
        )
        for kind, label, content in finding.evidence:
            self.add_evidence(finding.id, kind, content, label=label)
        return finding.id

    def add_evidence(self, finding_id: str, kind: str, content: str, label: str = "") -> None:
        self.conn.execute(
            """INSERT INTO evidence (finding_id, kind, label, content, sha256, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (finding_id, kind, label, content,
             hashlib.sha256(content.encode()).hexdigest(), _now()),
        )

    def set_status(self, finding_id: str, status: str, confidence: float | None = None) -> None:
        if confidence is None:
            self.conn.execute(
                "UPDATE finding SET status = ?, updated_at = ? WHERE id = ?",
                (status, _now(), finding_id),
            )
        else:
            self.conn.execute(
                "UPDATE finding SET status = ?, confidence = ?, updated_at = ? WHERE id = ?",
                (status, confidence, _now(), finding_id),
            )

    def update_finding(self, finding_id: str, **fields: Any) -> None:
        allowed = {
            "title", "summary", "description", "impact", "remediation", "effort",
            "severity", "cvss_vector", "cvss_score", "cwe", "owasp_wstg", "mitre_attack",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        clause = ", ".join(f"{k} = ?" for k in updates)
        self.conn.execute(
            f"UPDATE finding SET {clause}, updated_at = ? WHERE id = ?",  # noqa: S608
            (*updates.values(), _now(), finding_id),
        )

    def findings(self, status: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM finding WHERE campaign_id = ?"
        params: list[Any] = [self.campaign_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY COALESCE(cvss_score, 0) DESC, id"
        return [dict(r) for r in self.conn.execute(sql, params)]

    def finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM finding WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def evidence_for(self, finding_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY id", (finding_id,)
            )
        ]

    # ------------------------------------------------------------------
    #  Debate
    # ------------------------------------------------------------------
    def add_review(
        self, finding_id: str, reviewer: str, stance: str, rationale: str, round_: int = 1
    ) -> None:
        self.conn.execute(
            """INSERT INTO review (finding_id, reviewer, round, stance, rationale, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (finding_id, reviewer, round_, stance, rationale, _now()),
        )

    def reviews_for(self, finding_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM review WHERE finding_id = ? ORDER BY round, id", (finding_id,)
            )
        ]

    def add_arbitration(
        self,
        finding_id: str,
        arbiter: str,
        verdict: str,
        confidence: float,
        rationale: str,
        round_: int = 1,
    ) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO arbitration
               (finding_id, arbiter, round, verdict, confidence, rationale, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, arbiter, round_, verdict, confidence, rationale, _now()),
        )
        if verdict != "needs_work":
            self.set_status(finding_id, verdict, confidence)

    def arbitrations_for(self, finding_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM arbitration WHERE finding_id = ? ORDER BY round", (finding_id,)
            )
        ]

    # ------------------------------------------------------------------
    #  Coordination
    # ------------------------------------------------------------------
    def try_claim(self, task_key: str, agent: str) -> bool:
        """Claim a unit of work. False means another agent already has it."""
        cursor = self.conn.execute(
            """INSERT OR IGNORE INTO claim (campaign_id, task_key, agent, claimed_at)
               VALUES (?, ?, ?, ?)""",
            (self.campaign_id, task_key, agent, _now()),
        )
        return cursor.rowcount > 0

    def release_claim(self, task_key: str, result: str = "") -> None:
        self.conn.execute(
            "UPDATE claim SET released_at = ?, result = ? WHERE campaign_id = ? AND task_key = ?",
            (_now(), result, self.campaign_id, task_key),
        )

    def add_note(self, agent: str, topic: str, content: str) -> None:
        self.conn.execute(
            "INSERT INTO note (campaign_id, agent, topic, content, created_at) VALUES (?,?,?,?,?)",
            (self.campaign_id, agent, topic, content, _now()),
        )

    def notes(self, topic: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM note WHERE campaign_id = ?"
        params: list[Any] = [self.campaign_id]
        if topic:
            sql += " AND topic = ?"
            params.append(topic)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def log_command(
        self,
        *,
        agent: str,
        argv: list[str],
        decision: str,
        reason: str = "",
        exit_code: int | None = None,
        duration_ms: int | None = None,
        output_path: str | None = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO command_log
               (campaign_id, agent, argv, decision, reason, exit_code, duration_ms,
                output_path, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (self.campaign_id, agent, json.dumps(argv), decision, reason,
             exit_code, duration_ms, output_path, _now()),
        )


    # ------------------------------------------------------------------
    #  Fact graph
    # ------------------------------------------------------------------
    def upsert_fact(
        self,
        fact_key: str,
        summary: str,
        agent: str,
        *,
        body: str | None = None,
        confidence: str = "tentative",
        negative: bool = False,
        related_finding_id: str | None = None,
        links: list[tuple[str, str]] | None = None,
    ) -> bool:
        """Write or update one fact. Returns True if it was new.

        The same key overwrites rather than accumulating near-duplicates, so an
        agent that learns more about something it already recorded updates the
        one entry instead of splitting the knowledge across several. Omitting
        `body` on an update keeps the body already stored, which lets an agent
        refine a summary without having to restate everything.
        """
        category, _ = parse_fact_key(fact_key)
        key = fact_key.strip().lower()

        if confidence not in CONFIDENCES:
            raise FactError(f"confidence must be one of {', '.join(CONFIDENCES)}")
        if not summary.strip():
            raise FactError("a fact needs a summary that stands on its own")

        now = _now()
        existing = self.conn.execute(
            "SELECT body FROM fact WHERE campaign_id = ? AND fact_key = ?",
            (self.campaign_id, key),
        ).fetchone()

        if existing is None:
            self.conn.execute(
                """INSERT INTO fact (campaign_id, fact_key, category, summary, body,
                                     confidence, negative, agent, related_finding_id,
                                     created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (self.campaign_id, key, category, summary.strip(), (body or "").strip(),
                 confidence, int(negative), agent, related_finding_id, now, now),
            )
            created = True
        else:
            self.conn.execute(
                """UPDATE fact SET summary = ?, body = ?, confidence = ?, negative = ?,
                                   agent = ?, related_finding_id = COALESCE(?, related_finding_id),
                                   updated_at = ?
                   WHERE campaign_id = ? AND fact_key = ?""",
                (summary.strip(), (body.strip() if body is not None else existing["body"]),
                 confidence, int(negative), agent, related_finding_id, now,
                 self.campaign_id, key),
            )
            created = False

        for relation, target in links or []:
            self.link_facts(key, target, relation, agent=agent)

        return created

    def get_fact(self, fact_key: str) -> dict[str, Any] | None:
        """One fact in full, body included."""
        row = self.conn.execute(
            "SELECT * FROM fact WHERE campaign_id = ? AND fact_key = ?",
            (self.campaign_id, fact_key.strip().lower()),
        ).fetchone()
        if row is None:
            return None
        fact = dict(row)
        fact["links"] = self.fact_links(fact["fact_key"])
        return fact

    def list_facts(
        self,
        category: str | None = None,
        confidence: str | None = None,
        *,
        include_deprecated: bool = False,
        include_negative: bool = True,
    ) -> list[dict[str, Any]]:
        """The index: keys and summaries, never bodies.

        This is what an agent reads to orient itself, so it has to stay cheap.
        An agent that needs the detail calls get_fact.
        """
        sql = ["SELECT fact_key, category, summary, confidence, negative, agent,",
               "updated_at FROM fact WHERE campaign_id = ?"]
        params: list[Any] = [self.campaign_id]
        if category:
            sql.append("AND category = ?")
            params.append(category)
        if confidence:
            sql.append("AND confidence = ?")
            params.append(confidence)
        elif not include_deprecated:
            sql.append("AND confidence != 'deprecated'")
        if not include_negative:
            sql.append("AND negative = 0")
        sql.append("ORDER BY category, fact_key")
        return [dict(r) for r in self.conn.execute(" ".join(sql), params)]

    def search_facts(self, query: str, limit: int = 40) -> list[dict[str, Any]]:
        like = f"%{query.strip().lower()}%"
        return [
            dict(r)
            for r in self.conn.execute(
                """SELECT fact_key, category, summary, confidence, negative
                   FROM fact
                   WHERE campaign_id = ?
                     AND (lower(fact_key) LIKE ? OR lower(summary) LIKE ?
                          OR lower(body) LIKE ?)
                   ORDER BY confidence = 'confirmed' DESC, fact_key
                   LIMIT ?""",
                (self.campaign_id, like, like, like, limit),
            )
        ]

    def deprecate_fact(self, fact_key: str, reason: str, agent: str) -> bool:
        """Mark a fact wrong without deleting it.

        A retracted fact stays in the record: that something was believed and
        then disproved is part of how the engagement went, and the reasoning
        belongs in the audit trail.
        """
        key = fact_key.strip().lower()
        cursor = self.conn.execute(
            """UPDATE fact
               SET confidence = 'deprecated',
                   body = body || char(10) || char(10) || '--- deprecated by '
                          || ? || ': ' || ?,
                   updated_at = ?
               WHERE campaign_id = ? AND fact_key = ?""",
            (agent, reason, _now(), self.campaign_id, key),
        )
        return cursor.rowcount > 0

    def link_facts(
        self, src_key: str, dst_key: str, relation: str, *, note: str = "", agent: str = ""
    ) -> bool:
        """Join two facts. `enables` is the edge attack paths are built from."""
        if relation not in RELATIONS:
            raise FactError(f"relation must be one of {', '.join(RELATIONS)}")
        src, dst = src_key.strip().lower(), dst_key.strip().lower()
        parse_fact_key(src)
        parse_fact_key(dst)
        if src == dst:
            raise FactError("a fact cannot link to itself")
        cursor = self.conn.execute(
            """INSERT OR IGNORE INTO fact_edge
               (campaign_id, src_key, dst_key, relation, note, agent, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (self.campaign_id, src, dst, relation, note, agent, _now()),
        )
        return cursor.rowcount > 0

    def fact_links(self, fact_key: str) -> dict[str, list[dict[str, str]]]:
        key = fact_key.strip().lower()
        out: dict[str, list[dict[str, str]]] = {"out": [], "in": []}
        for row in self.conn.execute(
            """SELECT src_key, dst_key, relation, note FROM fact_edge
               WHERE campaign_id = ? AND (src_key = ? OR dst_key = ?)""",
            (self.campaign_id, key, key),
        ):
            entry = dict(row)
            out["out" if entry["src_key"] == key else "in"].append(entry)
        return out

    def fact_edges(self, relation: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM fact_edge WHERE campaign_id = ?"
        params: list[Any] = [self.campaign_id]
        if relation:
            sql += " AND relation = ?"
            params.append(relation)
        return [dict(r) for r in self.conn.execute(sql + " ORDER BY id", params)]

    # ------------------------------------------------------------------
    def attack_paths(self, max_depth: int = 8, max_paths: int = 40) -> list[list[dict[str, Any]]]:
        """Reconstruct privilege paths from the `enables` edges.

        Each path runs from a fact nothing else enables — an entry point — to
        one that enables nothing further. This is what makes the graph worth
        keeping: the path is the finding a red team reports, and here it is
        assembled from evidenced steps rather than asserted in prose.
        """
        facts = {
            row["fact_key"]: dict(row)
            for row in self.conn.execute(
                """SELECT fact_key, category, summary, confidence, negative,
                          related_finding_id, agent
                   FROM fact
                   WHERE campaign_id = ? AND confidence != 'deprecated'""",
                (self.campaign_id,),
            )
        }

        forward: dict[str, list[str]] = {}
        has_incoming: set[str] = set()
        for edge in self.fact_edges("enables"):
            src, dst = edge["src_key"], edge["dst_key"]
            if src not in facts or dst not in facts:
                continue  # an edge to a retracted fact is not a step
            forward.setdefault(src, []).append(dst)
            has_incoming.add(dst)

        roots = [k for k in facts if k not in has_incoming and k in forward]
        paths: list[list[dict[str, Any]]] = []

        def walk(node: str, trail: list[str]) -> None:
            if len(paths) >= max_paths:
                return
            nxt = [n for n in forward.get(node, []) if n not in trail]
            if not nxt or len(trail) >= max_depth:
                if len(trail) > 1:
                    paths.append([facts[k] for k in trail])
                return
            for child in nxt:
                walk(child, [*trail, child])

        for root in sorted(roots):
            walk(root, [root])

        # Longest first: the deepest chain is the one the client needs to see.
        paths.sort(key=len, reverse=True)
        return paths

    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        """Campaign state, for the live view and the report header."""
        counts = {
            row["status"]: row["n"]
            for row in self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM finding WHERE campaign_id = ? GROUP BY status",
                (self.campaign_id,),
            )
        }
        severities = {
            row["severity"] or "unrated": row["n"]
            for row in self.conn.execute(
                """SELECT severity, COUNT(*) AS n FROM finding
                   WHERE campaign_id = ? AND status = 'confirmed' GROUP BY severity""",
                (self.campaign_id,),
            )
        }
        assets = self.conn.execute(
            "SELECT COUNT(*) AS n FROM asset WHERE campaign_id = ?", (self.campaign_id,)
        ).fetchone()["n"]
        commands = self.conn.execute(
            "SELECT COUNT(*) AS n FROM command_log WHERE campaign_id = ?", (self.campaign_id,)
        ).fetchone()["n"]
        return {
            "assets": assets,
            "commands": commands,
            "findings_by_status": counts,
            "confirmed_by_severity": severities,
        }
