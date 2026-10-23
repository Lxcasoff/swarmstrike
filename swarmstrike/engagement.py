"""The engagement contract: what this campaign is allowed to touch.

Everything downstream reads its authority from here. The contract is signed
with an HMAC key held outside the repository, so a campaign cannot be widened
by editing a YAML file after the client signed off on it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from datetime import datetime, time
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, Field, field_validator

SCOPE_KEY_ENV = "SWARMSTRIKE_SCOPE_KEY"


class ContractError(Exception):
    """The contract is missing, malformed, unsigned or has been tampered with."""


# --------------------------------------------------------------------------
#  Contract shape
# --------------------------------------------------------------------------
class Authorizer(BaseModel):
    name: str
    role: str
    email: str
    authorization_ref: str
    signed_on: str


class EngagementMeta(BaseModel):
    id: str
    client: str
    mission: str
    reference: str = ""
    authorized_by: Authorizer


class Window(BaseModel):
    start: datetime
    end: datetime
    timezone: str = "UTC"
    daily_allowed_hours: str | None = None

    @field_validator("start", "end")
    @classmethod
    def _require_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("window bounds must carry a UTC offset, e.g. 2026-10-20T08:00:00+02:00")
        return v

    def _daily_bounds(self) -> tuple[time, time] | None:
        if not self.daily_allowed_hours:
            return None
        try:
            raw_start, raw_end = self.daily_allowed_hours.split("-", 1)
            return (
                time.fromisoformat(raw_start.strip()),
                time.fromisoformat(raw_end.strip()),
            )
        except ValueError as exc:
            raise ContractError(
                f"daily_allowed_hours must look like '08:00-20:00', got {self.daily_allowed_hours!r}"
            ) from exc

    def status(self, now: datetime | None = None) -> tuple[bool, str]:
        """Return (open, reason). Reason is human-readable for the audit log."""
        now = now or datetime.now(tz=ZoneInfo("UTC"))
        if now < self.start:
            return False, f"engagement window opens {self.start.isoformat()}"
        if now > self.end:
            return False, f"engagement window closed {self.end.isoformat()}"

        bounds = self._daily_bounds()
        if bounds is not None:
            local = now.astimezone(ZoneInfo(self.timezone)).time()
            lo, hi = bounds
            # A range that wraps midnight (e.g. 22:00-06:00) is read as such.
            inside = lo <= local <= hi if lo <= hi else (local >= lo or local <= hi)
            if not inside:
                return False, (
                    f"outside daily window {self.daily_allowed_hours} "
                    f"({local.strftime('%H:%M')} {self.timezone})"
                )
        return True, "within engagement window"


class DomainRule(BaseModel):
    name: str
    include_subdomains: bool = True

    @field_validator("name")
    @classmethod
    def _normalise(cls, v: str) -> str:
        return v.strip().lower().rstrip(".")


class ScopeBlock(BaseModel):
    domains: list[DomainRule] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    require_resolved_ip_in_scope: bool = False

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
        nets += [ipaddress.ip_network(f"{ip}/32" if ":" not in ip else f"{ip}/128") for ip in self.ips]
        return nets


class Exclusions(BaseModel):
    domains: list[DomainRule] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    url_paths: list[str] = Field(default_factory=list)

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
        nets += [ipaddress.ip_network(f"{ip}/32" if ":" not in ip else f"{ip}/128") for ip in self.ips]
        return nets


class TestAccount(BaseModel):
    username: str
    note: str = ""


class CredentialTesting(BaseModel):
    allowed: bool = False
    accounts: list[TestAccount] = Field(default_factory=list)


class Exploitation(BaseModel):
    allowed: bool = False
    stop_at_proof: bool = True


class RulesOfEngagement(BaseModel):
    intensity: Literal["quiet", "normal", "aggressive"] = "normal"
    max_requests_per_second: int = 10
    max_concurrent_tools: int = 4

    forbid_destructive: bool = True
    forbid_denial_of_service: bool = True
    forbid_data_modification: bool = True
    forbid_persistence: bool = True
    forbid_social_engineering: bool = True
    forbid_pivot_outside_scope: bool = True

    credential_testing: CredentialTesting = Field(default_factory=CredentialTesting)
    exploitation: Exploitation = Field(default_factory=Exploitation)


class Budget(BaseModel):
    max_usd: float = 25.0
    max_tokens: int = 20_000_000
    max_wall_clock_minutes: int = 180


class EmergencyContact(BaseModel):
    name: str = ""
    phone: str = ""


class Contacts(BaseModel):
    emergency_stop: EmergencyContact = Field(default_factory=EmergencyContact)
    halt_on: list[str] = Field(default_factory=list)


class Integrity(BaseModel):
    fingerprint: str | None = None
    signature: str | None = None
    signed_at: str | None = None


class Engagement(BaseModel):
    schema_version: int = 1
    engagement: EngagementMeta
    window: Window
    scope: ScopeBlock
    exclusions: Exclusions = Field(default_factory=Exclusions)
    rules_of_engagement: RulesOfEngagement = Field(default_factory=RulesOfEngagement)
    budget: Budget = Field(default_factory=Budget)
    contacts: Contacts = Field(default_factory=Contacts)
    integrity: Integrity = Field(default_factory=Integrity)

    # Not part of the signed payload; set on load for error messages.
    source_path: Path | None = Field(default=None, exclude=True)

    # ----------------------------------------------------------------------
    #  Integrity
    # ----------------------------------------------------------------------
    def canonical_bytes(self) -> bytes:
        """Byte form that the signature covers: everything but `integrity`."""
        payload: dict[str, Any] = self.model_dump(mode="json", exclude={"integrity", "source_path"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def expected_signature(self, key: bytes) -> str:
        return hmac.new(key, self.canonical_bytes(), hashlib.sha256).hexdigest()

    @property
    def is_signed(self) -> bool:
        return bool(self.integrity.signature and self.integrity.fingerprint)

    def verify(self, key: bytes | None = None) -> tuple[bool, str]:
        """Check the contract has not changed since it was signed."""
        if not self.is_signed:
            return False, "contract is unsigned (run: swarmstrike engagement sign <file>)"

        if self.integrity.fingerprint != self.fingerprint():
            return False, (
                "contract content does not match its fingerprint — it was edited after signing"
            )

        key = key if key is not None else load_scope_key()
        if key is None:
            return False, f"{SCOPE_KEY_ENV} is not set, cannot verify the signature"

        if not hmac.compare_digest(self.integrity.signature or "", self.expected_signature(key)):
            return False, "signature does not match — wrong signing key, or the contract was altered"

        return True, f"contract verified ({self.integrity.fingerprint[:16]}…)"

    def require_verified(self, key: bytes | None = None) -> None:
        ok, reason = self.verify(key)
        if not ok:
            raise ContractError(reason)


# --------------------------------------------------------------------------
#  Loading / signing
# --------------------------------------------------------------------------
def load_scope_key() -> bytes | None:
    raw = os.environ.get(SCOPE_KEY_ENV, "").strip()
    return raw.encode() if raw else None


def load(path: str | Path) -> Engagement:
    path = Path(path)
    if not path.is_file():
        raise ContractError(f"no engagement contract at {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ContractError(f"{path} is not valid YAML: {exc}") from exc

    engagement = Engagement.model_validate(data)
    engagement.source_path = path
    return engagement


def sign_file(path: str | Path, key: bytes | None = None) -> Engagement:
    """Sign a contract in place, preserving the author's comments and layout."""
    path = Path(path)
    key = key if key is not None else load_scope_key()
    if key is None:
        raise ContractError(
            f"{SCOPE_KEY_ENV} is not set. Generate one with:  openssl rand -hex 32"
        )

    engagement = load(path)
    # Sign the contract as it would be without any prior signature, so that
    # re-signing an already-signed file is idempotent.
    engagement.integrity = Integrity()
    fingerprint = engagement.fingerprint()
    signature = engagement.expected_signature(key)
    signed_at = datetime.now(tz=ZoneInfo("UTC")).isoformat()

    # Rewrite only the integrity block, leaving the rest of the file byte-identical.
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text) or {}
    doc["integrity"] = {
        "fingerprint": fingerprint,
        "signature": signature,
        "signed_at": signed_at,
    }
    head, sep, _ = text.partition("\nintegrity:")
    block = yaml.safe_dump({"integrity": doc["integrity"]}, sort_keys=False, default_flow_style=False)
    path.write_text((head + "\n" + block) if sep else (text.rstrip() + "\n\n" + block), encoding="utf-8")

    engagement.integrity = Integrity(
        fingerprint=fingerprint, signature=signature, signed_at=signed_at
    )
    return engagement
