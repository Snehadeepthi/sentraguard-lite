"""Policy loading.

The policy (detectors, thresholds, scoring knobs and regex rules) lives in
app/policy.json so rules can be tuned without touching code. It is validated
with Pydantic and every regex is compiled once at startup, so a bad rule
fails fast at boot instead of on the first request.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.json"

# Flags used for every rule: case-insensitive, ^/$ match per line.
RULE_FLAGS = re.IGNORECASE | re.MULTILINE


class Thresholds(BaseModel):
    block_score: int = Field(ge=0, le=100)
    transform_score: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def check_order(self) -> "Thresholds":
        if self.transform_score > self.block_score:
            raise ValueError("transform_score must be <= block_score")
        return self


class Scoring(BaseModel):
    per_extra_match: int = Field(default=5, ge=0, le=50)
    per_extra_tag: int = Field(default=10, ge=0, le=50)
    pii_cap: int = Field(default=60, ge=0, le=100)


class RuleConfig(BaseModel):
    id: str
    severity: int = Field(ge=0, le=100)
    pattern: str


class PolicyConfig(BaseModel):
    version: str
    detectors: list[str]
    thresholds: Thresholds
    scoring: Scoring = Scoring()
    rules: dict[str, list[RuleConfig]]


@dataclass(frozen=True)
class CompiledRule:
    id: str
    severity: int
    regex: re.Pattern[str]


@dataclass(frozen=True)
class Policy:
    config: PolicyConfig
    prompt_injection_rules: tuple[CompiledRule, ...]
    rag_injection_rules: tuple[CompiledRule, ...]

    def public_view(self) -> dict:
        """What GET /policy exposes. Regex rules are deliberately NOT exposed:
        publishing exact detection patterns makes them trivial to evade."""
        return {
            "version": self.config.version,
            "detectors": list(self.config.detectors),
            "thresholds": self.config.thresholds.model_dump(),
        }


def _compile(rules: list[RuleConfig]) -> tuple[CompiledRule, ...]:
    compiled = []
    for r in rules:
        try:
            compiled.append(CompiledRule(r.id, r.severity, re.compile(r.pattern, RULE_FLAGS)))
        except re.error as exc:  # fail fast at startup
            raise ValueError(f"Invalid regex in rule '{r.id}': {exc}") from exc
    return tuple(compiled)


def load_policy(path: str | Path | None = None) -> Policy:
    path = Path(path or os.getenv("POLICY_PATH") or DEFAULT_POLICY_PATH)
    config = PolicyConfig.model_validate(json.loads(path.read_text(encoding="utf-8")))
    return Policy(
        config=config,
        prompt_injection_rules=_compile(config.rules.get("prompt_injection", [])),
        rag_injection_rules=_compile(config.rules.get("rag_injection", [])),
    )


@lru_cache(maxsize=1)
def get_policy() -> Policy:
    """Process-wide cached policy (loaded once)."""
    return load_policy()
