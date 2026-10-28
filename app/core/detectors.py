"""Detectors: small, pure functions over a string.

Each detector returns a list of Finding objects (character spans + severity).
They never mutate input and never do I/O, which keeps them easy to unit-test
and fully deterministic.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

from app.core.policy import CompiledRule

# Tags (kept as constants so typos fail loudly)
PROMPT_INJECTION = "prompt_injection"
PII = "pii"
RAG_INJECTION = "rag_injection"

EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")

# Phone: optional +country code, optional (area), then 7-14 more digits with
# optional space/dot/dash separators. A digit-count check (10-15, E.164 max)
# filters out dates, short IDs, etc.
PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d(?:[\s.-]?\d){6,13}(?!\w)"
)
PHONE_MIN_DIGITS, PHONE_MAX_DIGITS = 10, 15

# Invisible characters commonly used to split keywords and dodge filters.
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"), None)


@dataclass(frozen=True)
class Finding:
    tag: str            # prompt_injection | pii | rag_injection
    rule_id: str        # e.g. "ignore_previous_instructions", "email", "phone"
    severity: int       # 0-100
    start: int          # span in the normalized text
    end: int
    matched: str        # the matched text (never returned raw for PII)


def normalize(text: str) -> str:
    """NFKC-normalize (folds full-width / compatibility chars such as
    'ｉｇｎｏｒｅ' -> 'ignore') and strip zero-width characters."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def _run_rules(text: str, rules: Iterable[CompiledRule], tag: str) -> list[Finding]:
    findings = []
    for rule in rules:
        for m in rule.regex.finditer(text):
            if m.end() > m.start():
                findings.append(Finding(tag, rule.id, rule.severity, m.start(), m.end(), m.group(0)))
    return findings


def detect_prompt_injection(text: str, rules: Iterable[CompiledRule]) -> list[Finding]:
    """Jailbreak / instruction-override phrases in the user prompt."""
    return _run_rules(text, rules, PROMPT_INJECTION)


def detect_rag_injection(
    text: str, rag_rules: Iterable[CompiledRule], prompt_rules: Iterable[CompiledRule]
) -> list[Finding]:
    """Instructions hidden in a retrieved document.

    Retrieved content should be *data*, never instructions, so any jailbreak
    phrase found in a document is also treated as RAG injection.
    """
    return _run_rules(text, rag_rules, RAG_INJECTION) + _run_rules(text, prompt_rules, RAG_INJECTION)


def detect_pii(text: str, severity: int = 40) -> list[Finding]:
    """Emails and phone numbers."""
    findings = [Finding(PII, "email", severity, m.start(), m.end(), m.group(0)) for m in EMAIL_RE.finditer(text)]
    email_spans = [(f.start, f.end) for f in findings]
    for m in PHONE_RE.finditer(text):
        digits = sum(c.isdigit() for c in m.group(0))
        inside_email = any(s <= m.start() < e for s, e in email_spans)
        if PHONE_MIN_DIGITS <= digits <= PHONE_MAX_DIGITS and not inside_email:
            findings.append(Finding(PII, "phone", severity, m.start(), m.end(), m.group(0)))
    return findings


REPLACEMENTS = {
    "email": "[REDACTED_EMAIL]",
    "phone": "[REDACTED_PHONE]",
}
INSTRUCTION_PLACEHOLDER = "[REMOVED_INSTRUCTION]"


def apply_redactions(text: str, findings: list[Finding]) -> str:
    """Replace every finding span with a placeholder.

    Overlapping spans are merged; when an instruction span overlaps a PII span
    the instruction placeholder wins (the whole span is removed anyway).
    """
    if not findings:
        return text
    spans = sorted(
        ((f.start, f.end, REPLACEMENTS.get(f.rule_id, INSTRUCTION_PLACEHOLDER)) for f in findings),
        key=lambda s: (s[0], -s[1]),
    )
    merged: list[list] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:  # overlap -> extend
            prev = merged[-1]
            prev[1] = max(prev[1], end)
            if label == INSTRUCTION_PLACEHOLDER:
                prev[2] = INSTRUCTION_PLACEHOLDER
        else:
            merged.append([start, end, label])
    out, cursor = [], 0
    for start, end, label in merged:
        out.append(text[cursor:start])
        out.append(label)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def redact_pii(text: str) -> str:
    """Convenience helper: redact only emails/phones."""
    return apply_redactions(text, detect_pii(text))
