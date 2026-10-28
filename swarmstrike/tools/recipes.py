"""Declarative tool recipes.

A recipe describes one assessment tool: the binary, its typed parameters, what
it is for, and how intrusive it is. Agents choose a recipe and supply
parameters; this module turns that into an argument vector.

The design follows CyberStrikeAI's YAML tool recipes (Apache-2.0, see NOTICE),
which is a better shape than hardcoding each tool in Python: the tool surface
grows by adding a file, and the breadth a red team needs stops being a code
change. What is added here is the risk tier — every recipe declares how far it
goes, and the engagement contract decides whether that far is authorized.

Two properties hold for every recipe, and the tests enforce them:

* **Nothing reaches a shell.** Parameters become individual argv elements, so a
  value can never introduce an extra argument, a pipe or a redirection.
* **The contract outranks the recipe.** A recipe's risk tier is checked against
  the engagement's rules of engagement before the scope guard even runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ..engagement import Engagement

RECIPE_DIR = Path(__file__).parent / "recipes"


class RecipeError(Exception):
    """A recipe is malformed, or the parameters given do not fit it."""


class NotAuthorized(Exception):
    """The engagement contract does not authorize this class of action."""


# ---------------------------------------------------------------------------
#  Risk tiers
# ---------------------------------------------------------------------------
class Risk(StrEnum):
    """How far a recipe goes. The contract decides how far is allowed."""

    PASSIVE = "passive"                      # no packets to the target at all
    ACTIVE = "active"                        # ordinary interaction: scan, probe, fuzz
    INTRUSIVE = "intrusive"                  # confirms a vulnerability
    CREDENTIALED = "credentialed"            # authentication testing
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POST_EXPLOITATION = "post_exploitation"  # enumeration from a foothold
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"        # proving a path out, with canary data only
    EVASION = "evasion"                      # exercising detection capability
    DESTRUCTIVE = "destructive"              # never authorized by any contract


def authorize_risk(risk: Risk, engagement: Engagement) -> tuple[bool, str]:
    """Does this contract authorize this tier? Returns (allowed, reason)."""
    roe = engagement.rules_of_engagement
    red = roe.red_team

    if risk is Risk.DESTRUCTIVE:
        return False, (
            "destructive actions are refused by swarmstrike regardless of contract"
        )

    if risk in (Risk.PASSIVE, Risk.ACTIVE):
        return True, f"{risk.value} actions are within the engagement"

    if risk is Risk.INTRUSIVE:
        if not roe.exploitation.allowed:
            return False, (
                "proof-of-concept exploitation is not authorized "
                "(rules_of_engagement.exploitation.allowed is false)"
            )
        return True, "exploitation authorized, stopping at proof"

    if risk is Risk.CREDENTIALED:
        if not roe.credential_testing.allowed:
            return False, (
                "authentication testing is not authorized "
                "(rules_of_engagement.credential_testing.allowed is false)"
            )
        return True, "authentication testing authorized against named accounts"

    # Everything below is red team territory and needs the block switched on.
    if not red.enabled:
        return False, (
            f"{risk.value} is a red team action and this engagement is not a red "
            f"team engagement (rules_of_engagement.red_team.enabled is false)"
        )

    gate: dict[Risk, tuple[bool, str]] = {
        Risk.POST_EXPLOITATION: (red.post_exploitation, "red_team.post_exploitation"),
        Risk.PRIVILEGE_ESCALATION: (red.privilege_escalation, "red_team.privilege_escalation"),
        Risk.LATERAL_MOVEMENT: (red.lateral_movement, "red_team.lateral_movement"),
        Risk.EVASION: (red.evasion, "red_team.evasion"),
        Risk.EXFILTRATION: (red.exfiltration_simulation, "red_team.exfiltration_simulation"),
    }
    if risk in gate:
        allowed, flag = gate[risk]
        if not allowed:
            return False, f"{risk.value} is not authorized ({flag} is false)"
        return True, f"{risk.value} authorized by {flag}"

    if risk is Risk.PERSISTENCE:
        # Two switches have to agree: the standing prohibition has to be lifted
        # and the red team block has to name it.
        if roe.forbid_persistence:
            return False, (
                "persistence is forbidden (rules_of_engagement.forbid_persistence "
                "is true); lift it explicitly in the contract if the engagement "
                "genuinely covers it"
            )
        if not red.persistence:
            return False, "persistence is not authorized (red_team.persistence is false)"
        return True, "persistence authorized, and the contract requires cleanup"

    return False, f"unknown risk tier {risk.value!r}"


# ---------------------------------------------------------------------------
#  Parameter shapes
# ---------------------------------------------------------------------------
ParamType = Literal["string", "integer", "boolean", "enum"]
ParamFormat = Literal["positional", "flag", "flag_value", "repeat"]

# A parameter value becomes one argv element, so shell metacharacters cannot do
# anything. This rejects the ones that indicate an agent has misunderstood that
# and is trying to build a shell command.
SHELL_SHAPED = re.compile(r"[;&|`$\n\r]|\$\(|\|\||&&|>>|<<")


class Parameter(BaseModel):
    name: str
    type: ParamType = "string"
    description: str = ""
    required: bool = False

    format: ParamFormat = "flag_value"
    flag: str | None = None
    position: int | None = None

    default: Any = None
    # Carries a credential. Its value is replaced before the command is
    # written to the audit log, the campaign database, the evidence file on
    # disk or the output handed back to the agent. Flag names cannot decide
    # this: `-p` is a port list for nmap and a password for netexec.
    sensitive: bool = False
    choices: list[str] = Field(default_factory=list)
    pattern: str | None = None
    minimum: int | None = None
    maximum: int | None = None

    @model_validator(mode="after")
    def _coherent(self) -> Parameter:
        if self.format in ("flag", "flag_value", "repeat") and not self.flag:
            raise ValueError(f"parameter {self.name!r} is {self.format} but declares no flag")
        if self.format == "positional" and self.position is None:
            raise ValueError(f"positional parameter {self.name!r} declares no position")
        if self.type == "enum" and not self.choices:
            raise ValueError(f"enum parameter {self.name!r} declares no choices")
        return self

    # ------------------------------------------------------------------
    def coerce(self, value: Any) -> Any:
        """Validate and normalise one supplied value."""
        if self.type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            return bool(value)

        if self.type == "integer":
            try:
                number = int(str(value).strip())
            except (TypeError, ValueError) as exc:
                raise RecipeError(f"{self.name} must be an integer, got {value!r}") from exc
            if self.minimum is not None and number < self.minimum:
                raise RecipeError(f"{self.name} must be at least {self.minimum}")
            if self.maximum is not None and number > self.maximum:
                raise RecipeError(f"{self.name} must be at most {self.maximum}")
            return number

        text = str(value).strip()
        if not text:
            raise RecipeError(f"{self.name} was given an empty value")

        if SHELL_SHAPED.search(text):
            raise RecipeError(
                f"{self.name} contains shell syntax ({text!r}). Recipes build an "
                f"argument vector, never a shell command — pass the value alone."
            )

        if self.type == "enum" and text not in self.choices:
            raise RecipeError(
                f"{self.name} must be one of {', '.join(self.choices)}, got {text!r}"
            )
        if self.pattern and not re.fullmatch(self.pattern, text):
            raise RecipeError(f"{self.name}={text!r} does not match {self.pattern}")
        return text

    def render(self, value: Any) -> list[str]:
        """Turn a validated value into argv elements."""
        if self.format == "flag":
            return [str(self.flag)] if value else []
        if self.format == "positional":
            return [str(value)]
        if self.format == "repeat":
            parts: list[str] = []
            for item in str(value).split(","):
                item = item.strip()
                if item:
                    parts += [str(self.flag), item]
            return parts
        return [str(self.flag), str(value)]


# ---------------------------------------------------------------------------
#  The recipe
# ---------------------------------------------------------------------------
class Recipe(BaseModel):
    name: str
    binary: str
    summary: str
    description: str = ""

    domains: list[str] = Field(default_factory=list)
    risk: Risk = Risk.ACTIVE
    needs_raw_socket: bool = False
    timeout_s: int = 900

    # Flags always passed, before any parameter.
    defaults: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)

    # Shown to the agent verbatim: what this tool is good for and what it costs.
    guidance: str = ""

    @field_validator("name", "binary")
    @classmethod
    def _plain(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError(f"{value!r} is not a plain tool name")
        return value

    @model_validator(mode="after")
    def _unique_parameters(self) -> Recipe:
        seen = [p.name for p in self.parameters]
        duplicates = {n for n in seen if seen.count(n) > 1}
        if duplicates:
            raise ValueError(f"{self.name}: duplicate parameters {sorted(duplicates)}")
        return self

    # ------------------------------------------------------------------
    def build_argv(self, supplied: dict[str, Any]) -> list[str]:
        """Validate parameters and produce the argument vector.

        Unknown parameters are refused rather than ignored: silently dropping
        one would mean an agent believes it constrained a scan that then ran
        unconstrained.
        """
        known = {p.name: p for p in self.parameters}
        unknown = sorted(set(supplied) - set(known))
        if unknown:
            raise RecipeError(
                f"{self.name} has no parameter(s) {', '.join(unknown)}. "
                f"Accepts: {', '.join(known) or 'none'}"
            )

        missing = [p.name for p in self.parameters if p.required and supplied.get(p.name) in (None, "")]
        if missing:
            raise RecipeError(f"{self.name} requires {', '.join(missing)}")

        argv = [self.binary, *self.defaults]

        positional: list[tuple[int, str]] = []
        for parameter in self.parameters:
            raw = supplied.get(parameter.name, parameter.default)
            if raw in (None, ""):
                continue
            value = parameter.coerce(raw)
            if parameter.type == "boolean" and not value:
                continue
            if parameter.format == "positional":
                positional.append((parameter.position or 0, str(value)))
            else:
                argv += parameter.render(value)

        argv += [value for _, value in sorted(positional)]
        return argv

    def secret_values(self, supplied: dict[str, Any]) -> list[str]:
        """The values in this invocation that must never be written down."""
        secrets: list[str] = []
        for parameter in self.parameters:
            if not parameter.sensitive:
                continue
            raw = supplied.get(parameter.name, parameter.default)
            if raw in (None, "", True, False):
                continue
            text = str(raw).strip()
            # A one- or two-character secret would redact far too much.
            if len(text) > 2:
                secrets.append(text)
        return secrets

    def authorize(self, engagement: Engagement) -> tuple[bool, str]:
        return authorize_risk(self.risk, engagement)

    def for_agent(self) -> dict[str, Any]:
        """How the recipe is described to an agent choosing a tool."""
        return {
            "name": self.name,
            "summary": self.summary,
            "domains": self.domains,
            "risk": self.risk.value,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "required": p.required,
                    "description": p.description,
                    **({"choices": p.choices} if p.choices else {}),
                }
                for p in self.parameters
            ],
            **({"guidance": self.guidance} if self.guidance else {}),
        }


# ---------------------------------------------------------------------------
#  Registry
# ---------------------------------------------------------------------------
@dataclass
class RecipeBook:
    recipes: dict[str, Recipe] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.recipes)

    def __contains__(self, name: object) -> bool:
        return name in self.recipes

    def get(self, name: str) -> Recipe:
        recipe = self.recipes.get(name)
        if recipe is None:
            close = ", ".join(sorted(self.recipes)[:12])
            raise RecipeError(f"no recipe named {name!r}. Available includes: {close}")
        return recipe

    def binaries(self) -> set[str]:
        return {r.binary for r in self.recipes.values()}

    def available_to(self, engagement: Engagement, domains: list[str] | None = None) -> list[Recipe]:
        """Recipes this contract authorizes, optionally narrowed by domain."""
        out = []
        for recipe in sorted(self.recipes.values(), key=lambda r: (r.risk.value, r.name)):
            allowed, _ = recipe.authorize(engagement)
            if not allowed:
                continue
            if domains and not (set(recipe.domains) & set(domains)):
                continue
            out.append(recipe)
        return out


def load_recipes(directory: str | Path | None = None) -> RecipeBook:
    """Load every recipe in a directory. A bad recipe is reported, not fatal."""
    path = Path(directory) if directory else RECIPE_DIR
    book = RecipeBook()
    if not path.is_dir():
        return book

    for file in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
        try:
            raw = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            recipe = Recipe.model_validate(raw)
        except Exception as exc:  # noqa: BLE001 — one bad file must not blind the rest
            book.errors[file.name] = f"{type(exc).__name__}: {exc}"
            continue
        if recipe.name in book.recipes:
            book.errors[file.name] = f"duplicate recipe name {recipe.name!r}"
            continue
        book.recipes[recipe.name] = recipe

    return book
