"""Report assembly.

Builds the client deliverable from the campaign record. The structure, the
tables, the evidence and the appendices are assembled deterministically from
the database, so the report cannot claim a finding the record does not hold or
a severity the arbiter did not set.

The narrative sections have a computed default, and `narrate()` can have the
reporter agent rewrite them in prose from the same confirmed record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..acknowledge import load as load_rulings
from ..audit import AuditLog
from ..engagement import Engagement
from ..knowledge import KnowledgeBase
from ..sensitive import read_manifest as read_sensitive_manifest
from .chains import prepare as prepare_chains
from .cvss import severity_rank

TEMPLATES = Path(__file__).parent / "templates"
EVIDENCE_LIMIT = 4_000

_NUMBERS = {
    1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
    7: "seven", 8: "eight", 9: "nine", 10: "ten",
}


def _spell(value: int) -> str:
    """Small numbers read better spelled out in a sentence an executive scans."""
    return _NUMBERS.get(value, str(value))


# Abbreviations whose full stop does not end a sentence. Splitting on ". " cut
# the first remediation in the lab report at "on the User include (e.g.", which
# is the line an executive reads first.
_ABBREVIATIONS = (
    "e.g.", "i.e.", "etc.", "cf.", "vs.", "approx.", "resp.", "incl.",
    "no.", "vol.", "ch.", "fig.", "al.",
)

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\[`'\"])")


def _first_sentence(text: str) -> str:
    """The first sentence of a remediation, for the priorities list.

    Falls back to the whole text when no sentence boundary is found, because a
    remediation that is one long sentence is better read in full than cut.
    """
    text = " ".join(text.split()).strip()
    if not text:
        return ""

    for candidate in _SENTENCE_END.split(text):
        candidate = candidate.strip()
        if not candidate:
            continue
        lowered = candidate.casefold()
        if any(lowered.endswith(abbr) for abbr in _ABBREVIATIONS):
            continue  # not a sentence end — keep going and take more
        return candidate if candidate.endswith((".", "!", "?")) else candidate + "."

    return text if text.endswith((".", "!", "?")) else text + "."


RISK_STATEMENTS = {
    "Critical": (
        "At least one finding allows an attacker to compromise a system or its data "
        "directly, with no credentials and no user interaction. This should be treated "
        "as an active exposure rather than a scheduled remediation item."
    ),
    "High": (
        "Findings were confirmed that would let an attacker obtain unauthorised access "
        "to systems or data, though each requires some precondition. Remediation should "
        "be scheduled ahead of routine work."
    ),
    "Medium": (
        "No finding on its own leads to compromise, but several weaken the overall "
        "security posture and would assist an attacker who gained an initial foothold. "
        "These should be addressed in the normal maintenance cycle."
    ),
    "Low": (
        "The issues identified are hygiene and configuration weaknesses with limited "
        "individual impact. The assessed surface held up to testing reasonably well."
    ),
    "Informational": (
        "No exploitable weaknesses were confirmed on the assessed surface within this "
        "engagement's scope and window."
    ),
}


@dataclass
class ReportBuilder:
    engagement: Engagement
    kb: KnowledgeBase
    audit: AuditLog
    campaign_id: str
    executive_summary: str | None = None

    # ------------------------------------------------------------------
    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        for finding in findings:
            key = (finding.get("severity") or "none").lower()
            counts[key] = counts.get(key, 0) + 1
        counts["total"] = len(findings)
        counts["theoretical"] = len(self.kb.findings("theoretical"))
        return counts

    @staticmethod
    def _risk_level(counts: dict[str, int]) -> str:
        if counts["critical"]:
            return "Critical"
        if counts["high"]:
            return "High"
        if counts["medium"]:
            return "Medium"
        if counts["low"]:
            return "Low"
        return "Informational"

    def _compose_summary(self, counts: dict[str, int], risk: str) -> str:
        client = self.engagement.engagement.client
        surface = self.kb.summary()["assets"]
        chains = prepare_chains(self.kb.attack_paths(), self.kb.findings("confirmed"))

        if not counts["total"]:
            body = (
                f"This assessment examined {surface} asset(s) across {client}'s authorized "
                f"external surface and confirmed no exploitable weaknesses within the "
                f"engagement's scope and window."
            )
        else:
            headline = ", ".join(
                f"{counts[name]} {name}"
                for name in ("critical", "high", "medium", "low")
                if counts[name]
            )
            body = (
                f"This assessment examined {surface} asset(s) across {client}'s authorized "
                f"surface and confirmed {counts['total']} finding(s): {headline}. "
                f"Each was independently reviewed, challenged and adjudicated before "
                f"inclusion in this report."
            )

        # A chain is the sentence a non-technical reader acts on: not that four
        # weaknesses exist, but that one leads to the next and the last reaches
        # something that matters.
        proven = [c for c in chains if c["fully_confirmed"] and c["length"] >= 2]
        if proven:
            longest = proven[0]
            steps = _spell(longest["length"])
            if len(proven) == 1:
                lead_in = (
                    " More consequentially, they do not stand alone: a "
                    f"{steps}-step path leads"
                )
            else:
                lead_in = (
                    f" More consequentially, {_spell(len(proven))} separate paths "
                    f"chain these weaknesses together. The longest runs {steps} "
                    f"steps,"
                )
            body += (
                f"{lead_in} from {longest['steps'][0]['summary']} through to "
                f"{longest['steps'][-1]['summary']}. Every link was evidenced on "
                f"its own, which also means breaking any single one of them breaks "
                f"the whole path."
            )

        if counts["theoretical"]:
            body += (
                f" A further {counts['theoretical']} weakness(es) were identified but could "
                f"not be proven within the agreed rules of engagement; these are set out "
                f"separately and warrant internal verification."
            )

        return body

    def _priorities(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        top = sorted(
            findings,
            key=lambda f: (severity_rank(f.get("severity")), -(f.get("cvss_score") or 0.0)),
        )[:4]
        return [
            {
                "title": f["title"],
                "severity": f.get("severity") or "unrated",
                "cvss_score": f.get("cvss_score"),
                "asset": f["asset"],
                "one_line": _first_sentence(f.get("remediation") or f["summary"]),
            }
            for f in top
        ]

    def _decorate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        decorated = []
        for finding in findings:
            item = dict(finding)
            item["evidence"] = [
                {
                    "label": entry["label"],
                    "kind": entry["kind"],
                    "content": entry["content"][:EVIDENCE_LIMIT]
                    + ("\n… evidence truncated for the report" if len(entry["content"]) > EVIDENCE_LIMIT else ""),
                }
                for entry in self.kb.evidence_for(finding["id"])
            ]
            rulings = self.kb.arbitrations_for(finding["id"])
            item["adjudication"] = rulings[-1]["rationale"] if rulings else ""
            decorated.append(item)
        return sorted(
            decorated,
            key=lambda f: (severity_rank(f.get("severity")), -(f.get("cvss_score") or 0.0), f["id"]),
        )

    def _integrity(self) -> dict[str, Any]:
        intact, reason, entries = self.audit.verify()
        refusals = self.kb.conn.execute(
            "SELECT COUNT(*) AS n FROM command_log WHERE campaign_id = ? AND decision = 'refused'",
            (self.campaign_id,),
        ).fetchone()["n"]
        # Credential material a target handed back, which is in the output
        # directory because it is the proof. The report says what is there so
        # the evidence is handled as what it is rather than as ordinary logs.
        marked = read_sensitive_manifest(self.audit.path.parent / "output")
        return {
            "entries": entries,
            "verdict": ("Verified — " + reason) if intact else ("FAILED — " + reason),
            "contract_fingerprint": self.engagement.integrity.fingerprint or "unsigned",
            "refusals": refusals,
            "sensitive_outputs": [
                {"file": m.path, "kinds": ", ".join(m.kinds)} for m in marked
            ],
            "overruled_halts": self._overruled_halts(),
        }

    def _overruled_halts(self) -> list[dict[str, str]]:
        """Halts an agent raised that an operator had already ruled on.

        An override of the campaign's strongest guardrail is not something the
        report may be silent about: it names the condition, the decision in the
        operator's own words, and who made it.
        """
        campaign_dir = self.audit.path.parent
        rulings = {r.pattern: r for r in load_rulings(campaign_dir)}
        if not rulings:
            return []

        raised: dict[str, int] = {}
        for entry in self.audit.entries():
            if entry.event == "halt.overruled":
                pattern = str(entry.data.get("pattern", ""))
                raised[pattern] = raised.get(pattern, 0) + 1

        return [
            {
                "condition": ruling.pattern,
                "ruling": ruling.ruling,
                "operator": ruling.operator,
                "raised": raised.get(pattern, 0),
            }
            for pattern, ruling in sorted(rulings.items())
        ]

    def _limits(self, counts: dict[str, int]) -> str:
        roe = self.engagement.rules_of_engagement
        parts = [
            "This was a point-in-time assessment bounded by the scope, window and rules "
            "of engagement set out in section 2.",
        ]
        if not roe.exploitation.allowed:
            parts.append(
                "Proof-of-concept exploitation was not authorized, so findings were "
                "established by observation and inference rather than by demonstration. "
                "Some weaknesses can only be confirmed by exploitation and may therefore "
                "be understated or absent."
            )
        elif roe.exploitation.stop_at_proof:
            parts.append(
                "Exploitation stopped at the point of proof by agreement, so the full "
                "extent of what an attacker could reach from each finding was not explored."
            )
        if not roe.credential_testing.allowed:
            parts.append(
                "Authentication testing was not authorized, so weaknesses in password "
                "policy, account lockout and credential handling were not assessed."
            )
        if self.engagement.exclusions.url_paths or self.engagement.exclusions.domains:
            parts.append(
                "Excluded assets and paths listed in section 2.2 were not examined at all; "
                "no assurance is offered over them."
            )
        if counts["theoretical"]:
            parts.append(
                "Weaknesses in section 6 are unproven and should be verified internally "
                "before being accepted or dismissed."
            )
        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    def context(self) -> dict[str, Any]:
        confirmed = self.kb.findings("confirmed")
        counts = self._severity_counts(confirmed)
        risk = self._risk_level(counts)
        decorated = self._decorate(confirmed)
        summary = self.kb.summary()

        exclusions = self.engagement.exclusions
        exclusion_items = (
            [f"`{d.name}`" for d in exclusions.domains]
            + [f"`{ip}`" for ip in exclusions.ips]
            + [f"`{cidr}`" for cidr in exclusions.cidrs]
            + [f"any URL path containing `{path}`" for path in exclusions.url_paths]
        )

        kind_tally: dict[str, int] = {}
        for asset in self.kb.assets():
            kind_tally[asset["kind"]] = kind_tally.get(asset["kind"], 0) + 1
        assets_by_kind = sorted(kind_tally.items(), key=lambda pair: -pair[1])

        chains = prepare_chains(self.kb.attack_paths(), confirmed)

        return {
            "chains": chains,
            "meta": self.engagement.engagement,
            "window": {
                "start": self.engagement.window.start.strftime("%Y-%m-%d %H:%M %Z"),
                "end": self.engagement.window.end.strftime("%Y-%m-%d %H:%M %Z"),
            },
            "scope": self.engagement.scope,
            "exclusions": {"any": bool(exclusion_items), "entries": exclusion_items},
            "roe": self.engagement.rules_of_engagement,
            "generated_on": datetime.now(tz=ZoneInfo("UTC")).strftime("%Y-%m-%d"),
            "executive_summary": self.executive_summary or self._compose_summary(counts, risk),
            "risk_level": risk,
            "risk_statement": RISK_STATEMENTS[risk],
            "counts": counts,
            "priorities": self._priorities(confirmed),
            "findings": decorated,
            "theoretical": self._decorate(self.kb.findings("theoretical")),
            "assets_by_kind": assets_by_kind,
            "services": self.kb.services(),
            "roadmap": [
                {
                    "id": f["id"],
                    "severity": f.get("severity") or "unrated",
                    "asset": f["asset"],
                    "action": (f.get("remediation") or "See finding detail.").split(". ")[0].rstrip(".") + ".",
                }
                for f in decorated
            ],
            "coverage": {
                "assets": summary["assets"],
                "commands": summary["commands"],
                "rulings": sum(summary["findings_by_status"].get(s, 0)
                               for s in ("confirmed", "rejected", "theoretical")),
                "rejected": summary["findings_by_status"].get("rejected", 0),
            },
            "integrity": self._integrity(),
            "limits": self._limits(counts),
        }

    def render(self) -> str:
        env = Environment(
            loader=FileSystemLoader(TEMPLATES),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        return env.get_template("report.md.j2").render(**self.context())

    def write(self, destination: str | Path) -> Path:
        path = Path(destination)
        if path.suffix != ".md":
            path = path.with_suffix(".md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    async def narrate(
        self,
        *,
        mcp_servers: dict[str, Any] | None = None,
        context_brief: str = "",
    ) -> str:
        """Have the reporter agent write the executive summary in prose.

        It is given only the confirmed record, so it cannot introduce a finding
        that was not adjudicated.
        """
        from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

        from ..agents.roster import REPORTER_PROMPT
        from ..models import Role, effort_for, model_for

        data = self.context()
        digest = "\n".join(
            f"- {f['id']} [{(f.get('severity') or 'unrated')}"
            + (f" / CVSS {f['cvss_score']}" if f.get("cvss_score") else "")
            + f"] {f['title']} on {f['asset']} — {f['summary']}"
            for f in data["findings"]
        ) or "No findings were confirmed."

        prompt = f"""Write the executive summary for this report. Two to four
paragraphs of prose, for readers who will not read past it. No tool names, no
CVE identifiers, no jargon. Say what the overall risk is in the
organisation's own terms and what should be done first.

Client: {data['meta'].client}
Mission: {data['meta'].mission}
Assets examined: {data['coverage']['assets']}
Overall risk: {data['risk_level']}
Confirmed: {data['counts']['total']} ({data['counts']['critical']} critical, {data['counts']['high']} high, {data['counts']['medium']} medium, {data['counts']['low']} low)
Unproven weaknesses reported separately: {data['counts']['theoretical']}

Confirmed findings:
{digest}

Write only the summary text itself, with no heading."""

        options = ClaudeAgentOptions(
            system_prompt=f"{context_brief}\n\n{REPORTER_PROMPT}",
            model=model_for(Role.REPORTER),
            effort=effort_for(Role.REPORTER),
            mcp_servers=mcp_servers or {},
            allowed_tools=[],
            setting_sources=[],
            max_turns=3,
        )

        written = ""
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage) and message.result:
                written = message.result.strip()

        if written:
            self.executive_summary = written
        return self.executive_summary or ""
