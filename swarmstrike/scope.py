"""Scope enforcement.

Agents propose commands; this module decides whether they may run. It is the
only thing standing between an autonomous swarm and a target the client never
authorized, so it fails closed: anything it cannot positively place inside the
engagement scope is refused.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from .engagement import Engagement

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeViolation(Exception):
    """A proposed action falls outside the engagement contract."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str = ""

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise ScopeViolation(f"[{self.rule}] {self.reason}")


ALLOW = Decision(True, "within scope", "scope.match")


# ---------------------------------------------------------------------------
#  Networks that are never in scope, whatever the contract says.
#  Loopback is the toolbox container itself; link-local carries the cloud
#  metadata endpoint (169.254.169.254). Neither belongs to a client.
# ---------------------------------------------------------------------------
HARD_DENY_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

# Private ranges are allowed only when the contract lists them explicitly —
# an internal engagement must say so rather than inherit it by accident.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


# ---------------------------------------------------------------------------
#  Categorically refused command shapes, mapped to the rule that forbids them.
#  Checked before scope: an in-scope target does not license a destructive act.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ForbiddenPattern:
    pattern: re.Pattern[str]
    rule: str
    why: str


def _p(expr: str, rule: str, why: str) -> ForbiddenPattern:
    return ForbiddenPattern(re.compile(expr, re.IGNORECASE), rule, why)


FORBIDDEN_PATTERNS: list[ForbiddenPattern] = [
    # -- Destruction of data or systems ------------------------------------
    _p(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+/", "forbid_destructive", "recursive delete"),
    _p(r"\b(mkfs|fdisk|shred|wipefs)\b", "forbid_destructive", "filesystem destruction"),
    _p(r"\bdd\b.*\bof=/dev/", "forbid_destructive", "raw device write"),
    _p(r"\b(shutdown|reboot|halt|poweroff)\b", "forbid_destructive", "host shutdown"),
    _p(r":\(\)\s*\{.*\};\s*:", "forbid_destructive", "fork bomb"),
    _p(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "forbid_data_modification", "destructive SQL"),
    _p(r"\b(TRUNCATE|DELETE\s+FROM)\b", "forbid_data_modification", "destructive SQL"),

    # -- Denial of service --------------------------------------------------
    _p(r"--script[= ]\S*\bdos\b", "forbid_denial_of_service", "nmap DoS script category"),
    _p(r"\b(hping3|slowloris|t50|mhddos|goldeneye)\b", "forbid_denial_of_service", "DoS tool"),
    _p(r"\bab\b.*-n\s*\d{6,}", "forbid_denial_of_service", "flood-scale request volume"),
    _p(r"--safe-checks[= ]?(no|0|false)", "forbid_denial_of_service", "unsafe check mode"),

    # -- Writing to or altering the target ----------------------------------
    _p(r"--(os-shell|os-pwn|os-cmd|file-write|file-dest)\b", "forbid_data_modification",
       "sqlmap write/shell beyond proof"),
    _p(r"\bmsfconsole\b|\bmeterpreter\b", "forbid_persistence", "post-exploitation framework"),
    _p(r"\b(crontab|systemctl\s+enable|schtasks)\b", "forbid_persistence", "persistence mechanism"),
    _p(r"--upload\b|--put\b", "forbid_data_modification", "upload to target"),

    # -- Social engineering --------------------------------------------------
    _p(r"\b(setoolkit|gophish|evilginx|king-phisher)\b", "forbid_social_engineering",
       "phishing framework"),
    _p(r"\bswaks\b|\bsendemail\b", "forbid_social_engineering", "mail injection"),
]

# Authentication-testing tools. Gated on rules_of_engagement.credential_testing.
CREDENTIAL_TOOLS = re.compile(
    r"\b(hydra|medusa|ncrack|patator|crowbar|kerbrute|john|hashcat)\b", re.IGNORECASE
)

# Flags whose value is a local file, not a target.
FILE_VALUE_FLAGS = {
    "-o", "-oN", "-oX", "-oG", "-oA", "-oJ", "--output", "--out", "-output",
    "-w", "--wordlist", "-t", "--templates", "-iL", "--input-file", "-l", "-L", "-P",
    "--config", "-c", "--log", "--report", "--csv", "--json", "-H", "--header",
}

# Extensions that make a dotted token a filename rather than a hostname.
FILE_EXTENSIONS = {
    "txt", "json", "xml", "html", "htm", "yaml", "yml", "csv", "log", "md", "py",
    "sh", "conf", "cfg", "ini", "pem", "key", "crt", "db", "sqlite", "tmp", "out",
    "lst", "dic", "gz", "zip", "tar", "nmap", "gnmap", "jsonl", "sarif",
}

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+\.?$",
    re.IGNORECASE,
)


class ScopeGuard:
    """Decides what the swarm may touch, from the signed engagement contract."""

    def __init__(self, engagement: Engagement, resolve: bool = True) -> None:
        self.engagement = engagement
        self.resolve = resolve
        self._roe = engagement.rules_of_engagement

        self._scope_nets = engagement.scope.networks()
        self._excluded_nets = engagement.exclusions.networks()
        self._scope_domains = engagement.scope.domains
        self._excluded_domains = engagement.exclusions.domains
        self._excluded_paths = [p.lower() for p in engagement.exclusions.url_paths]

        # A private range counts as in-scope only if the contract named it.
        self._private_authorized = [
            net for net in self._scope_nets
            if any(net.subnet_of(p) for p in PRIVATE_NETWORKS if net.version == p.version)
        ]
        self._resolution_cache: dict[str, list[IPAddress]] = {}

    # ------------------------------------------------------------------
    #  Time
    # ------------------------------------------------------------------
    def check_window(self, now: datetime | None = None) -> Decision:
        open_, reason = self.engagement.window.status(now)
        return Decision(open_, reason, "window" if not open_ else "window.open")

    # ------------------------------------------------------------------
    #  Addresses
    # ------------------------------------------------------------------
    def _check_ip(self, ip: IPAddress, origin: str) -> Decision:
        for net in HARD_DENY_NETWORKS:
            if ip.version == net.version and ip in net:
                return Decision(
                    False,
                    f"{origin} resolves to {ip}, a loopback/link-local address that is never "
                    f"in scope (this is the toolbox itself or a cloud metadata endpoint)",
                    "hard_deny",
                )

        for net in self._excluded_nets:
            if ip.version == net.version and ip in net:
                return Decision(False, f"{origin} ({ip}) is explicitly excluded by the contract",
                                "exclusions")

        in_private = any(ip.version == p.version and ip in p for p in PRIVATE_NETWORKS)
        if in_private and not any(
            ip.version == n.version and ip in n for n in self._private_authorized
        ):
            return Decision(
                False,
                f"{origin} ({ip}) is a private address and the contract does not list that "
                f"range in scope",
                "private_not_authorized",
            )

        for net in self._scope_nets:
            if ip.version == net.version and ip in net:
                return Decision(True, f"{origin} ({ip}) matches in-scope {net}", "scope.cidr")

        return Decision(False, f"{origin} ({ip}) is not in any in-scope range", "scope.miss")

    def _resolve(self, host: str) -> list[IPAddress]:
        if host in self._resolution_cache:
            return self._resolution_cache[host]
        addrs: list[IPAddress] = []
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                if family in (socket.AF_INET, socket.AF_INET6):
                    addrs.append(ipaddress.ip_address(sockaddr[0]))
        except (socket.gaierror, ValueError):
            addrs = []
        deduped = list(dict.fromkeys(addrs))
        self._resolution_cache[host] = deduped
        return deduped

    @staticmethod
    def _domain_matches(host: str, rule_name: str, include_subdomains: bool) -> bool:
        host = host.lower().rstrip(".")
        if host == rule_name:
            return True
        return include_subdomains and host.endswith("." + rule_name)

    def check_host(self, host: str) -> Decision:
        """Validate a hostname or address literal against the contract."""
        host = host.strip().lower().rstrip(".")
        if not host:
            return Decision(False, "empty host", "malformed")

        try:
            return self._check_ip(ipaddress.ip_address(host), host)
        except ValueError:
            pass  # not a literal address; treat as a name

        for rule in self._excluded_domains:
            if self._domain_matches(host, rule.name, rule.include_subdomains):
                return Decision(False, f"{host} is explicitly excluded by the contract",
                                "exclusions")

        matched = next(
            (r for r in self._scope_domains
             if self._domain_matches(host, r.name, r.include_subdomains)),
            None,
        )
        if matched is None:
            return Decision(False, f"{host} is not an in-scope domain", "scope.miss")

        if self.resolve and self.engagement.scope.require_resolved_ip_in_scope:
            addrs = self._resolve(host)
            if not addrs:
                return Decision(
                    False,
                    f"{host} is in scope by name but does not resolve, and the contract "
                    f"requires the resolved address to be in scope",
                    "resolution.failed",
                )
            for ip in addrs:
                verdict = self._check_ip(ip, host)
                if not verdict.allowed:
                    return verdict

        return Decision(True, f"{host} matches in-scope domain {matched.name}", "scope.domain")

    def check_url(self, url: str) -> Decision:
        parts = urlsplit(url if "://" in url else f"//{url}", scheme="http")
        if not parts.hostname:
            return Decision(False, f"cannot read a host out of {url!r}", "malformed")

        path = (parts.path or "/").lower()
        for excluded in self._excluded_paths:
            if excluded in path:
                return Decision(False, f"path {parts.path} is excluded by the contract",
                                "exclusions.path")

        return self.check_host(parts.hostname)

    # ------------------------------------------------------------------
    #  Commands
    # ------------------------------------------------------------------
    def _check_forbidden(self, line: str) -> Decision:
        for entry in FORBIDDEN_PATTERNS:
            if not getattr(self._roe, entry.rule, True):
                continue  # the contract permits this class of action
            if entry.pattern.search(line):
                return Decision(
                    False,
                    f"{entry.why} — refused by rules_of_engagement.{entry.rule}",
                    entry.rule,
                )

        if CREDENTIAL_TOOLS.search(line) and not self._roe.credential_testing.allowed:
            return Decision(
                False,
                "authentication testing is not authorized "
                "(rules_of_engagement.credential_testing.allowed is false)",
                "credential_testing",
            )
        return ALLOW

    def extract_targets(self, argv: list[str]) -> list[str]:
        """Pull every token out of a command line that names a network target."""
        targets: list[str] = []
        skip_next = False

        for index, token in enumerate(argv):
            if skip_next:
                skip_next = False
                continue
            if index == 0:
                continue  # the binary itself

            flag = token.split("=", 1)[0]
            if flag in FILE_VALUE_FLAGS:
                skip_next = "=" not in token
                continue
            if token.startswith("-"):
                # A flag may still carry a target: --url=https://host/
                value = token.split("=", 1)[1] if "=" in token else ""
                if value:
                    targets.extend(_classify(value))
                continue

            targets.extend(_classify(token))

        return list(dict.fromkeys(targets))

    def check_command(self, argv: list[str]) -> Decision:
        """The gate every tool invocation passes through."""
        if not argv:
            return Decision(False, "empty command", "malformed")

        window = self.check_window()
        if not window.allowed:
            return window

        line = " ".join(argv)
        forbidden = self._check_forbidden(line)
        if not forbidden.allowed:
            return forbidden

        targets = self.extract_targets(argv)
        if not targets:
            return Decision(
                False,
                f"no target could be read out of `{line}` — swarmstrike refuses commands "
                f"whose scope it cannot verify. Name the target explicitly.",
                "unverifiable",
            )

        for target in targets:
            verdict = self.check_url(target) if "://" in target else self.check_host(target)
            if not verdict.allowed:
                return verdict

        return Decision(True, f"all targets in scope: {', '.join(targets)}", "scope.match")


def _classify(token: str) -> list[str]:
    """Return the token if it names a network target, else nothing."""
    token = token.strip().strip(",;'\"")
    if not token:
        return []

    if "://" in token:
        return [token]

    if "/" in token and not token.startswith("/"):
        try:
            ipaddress.ip_network(token, strict=False)
            return [token.split("/", 1)[0]]
        except ValueError:
            pass

    try:
        ipaddress.ip_address(token)
        return [token]
    except ValueError:
        pass

    # host:port
    bare = token.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", token) else token

    if HOSTNAME_RE.match(bare):
        if bare.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS:
            return []  # a filename, not a host
        return [bare]

    return []
