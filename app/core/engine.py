"""Decision engine: runs detectors, scores, decides, sanitizes.

Pure function of (prompt, context docs, policy) -> result dict.
No I/O, no randomness, no clock: same input always yields the same output.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from app.core.detectors import (
    PII,
    PROMPT_INJECTION,
    RAG_INJECTION,
    Finding,
    apply_redactions,
    detect_pii,
    detect_prompt_injection,
    detect_rag_injection,
    normalize,
    redact_pii,
)
from app.core.policy import Policy

ALLOW, TRANSFORM, BLOCK = "allow", "transform", "block"
EVIDENCE_MAX_CHARS = 100


@dataclass(frozen=True)
class Doc:
    id: str
    text: str


def score_tag(tag: str, findings: list[Finding], policy: Policy) -> int:
    """Strongest finding sets the base; each extra finding adds a small bump."""
    if not findings:
        return 0
    s = policy.config.scoring
    score = max(f.severity for f in findings) + s.per_extra_match * (len(findings) - 1)
    cap = s.pii_cap if tag == PII else 100
    return min(cap, score)


def combine_scores(tag_scores: dict[str, int], policy: Policy) -> int:
    """Worst tag sets the base; each additional risk category adds a bump."""
    active = [v for v in tag_scores.values() if v > 0]
    if not active:
        return 0
    return min(100, max(active) + policy.config.scoring.per_extra_tag * (len(active) - 1))


def decide(score: int, policy: Policy) -> str:
    t = policy.config.thresholds
    if score >= t.block_score:
        return BLOCK
    if score >= t.transform_score:
        return TRANSFORM
    return ALLOW


def _evidence(f: Finding, count: int) -> str:
    if f.tag == PII:
        # Never echo the PII value itself.
        return f"detected {count} {f.rule_id}(s); values redacted"
    snippet = " ".join(redact_pii(f.matched).split())  # redact PII inside the phrase too
    if len(snippet) > EVIDENCE_MAX_CHARS:
        snippet = snippet[: EVIDENCE_MAX_CHARS - 3] + "..."
    return f"matched phrase: {snippet}"


def _reasons(findings_by_source: "OrderedDict[str, list[Finding]]") -> list[dict]:
    """One reason per (source, tag, rule), in a stable order."""
    reasons = []
    for source, findings in findings_by_source.items():
        grouped: "OrderedDict[tuple[str, str], list[Finding]]" = OrderedDict()
        for f in sorted(findings, key=lambda f: (f.start, f.rule_id)):
            grouped.setdefault((f.tag, f.rule_id), []).append(f)
        for (tag, rule_id), group in grouped.items():
            reasons.append(
                {"tag": tag, "rule": rule_id, "source": source, "evidence": _evidence(group[0], len(group))}
            )
    return reasons


def analyze(prompt: str, context_docs: list[Doc], policy: Policy) -> dict:
    enabled = set(policy.config.detectors)
    findings_by_source: "OrderedDict[str, list[Finding]]" = OrderedDict()

    # --- prompt ---
    norm_prompt = normalize(prompt)
    prompt_findings: list[Finding] = []
    if PROMPT_INJECTION in enabled:
        prompt_findings += detect_prompt_injection(norm_prompt, policy.prompt_injection_rules)
    if PII in enabled:
        prompt_findings += detect_pii(norm_prompt)
    findings_by_source["prompt"] = prompt_findings

    # --- retrieved context docs ---
    norm_docs: list[tuple[str, str]] = []
    for doc in context_docs:
        text = normalize(doc.text)
        doc_findings: list[Finding] = []
        if RAG_INJECTION in enabled:
            doc_findings += detect_rag_injection(text, policy.rag_injection_rules, policy.prompt_injection_rules)
        if PII in enabled:
            doc_findings += detect_pii(text)
        findings_by_source[f"context_docs[{doc.id}]"] = doc_findings
        norm_docs.append((doc.id, text))

    all_findings = [f for fs in findings_by_source.values() for f in fs]

    # --- scoring & decision ---
    tag_scores = {
        tag: score_tag(tag, [f for f in all_findings if f.tag == tag], policy)
        for tag in policy.config.detectors
    }
    risk_score = combine_scores(tag_scores, policy)
    decision = decide(risk_score, policy)
    risk_tags = [tag for tag in policy.config.detectors if tag_scores.get(tag, 0) > 0]

    # --- sanitization ---
    # Always sanitize, whatever the decision: a blocked response must not echo
    # raw PII back to the caller either. For "allow" there is nothing to
    # redact, so the sanitized text equals the (normalized) input.
    sanitized_prompt = apply_redactions(norm_prompt, findings_by_source["prompt"])
    sanitized_docs = [
        {"id": doc_id, "text": apply_redactions(text, findings_by_source[f"context_docs[{doc_id}]"])}
        for doc_id, text in norm_docs
    ]

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_tags": risk_tags,
        "sanitized_prompt": sanitized_prompt,
        "sanitized_context_docs": sanitized_docs,
        "reasons": _reasons(findings_by_source),
    }


def summarize_for_log(result: dict) -> dict:
    """Non-sensitive summary that is safe to log (no text, no PII)."""
    return {
        "decision": result["decision"],
        "risk_score": result["risk_score"],
        "risk_tags": result["risk_tags"],
        "reason_count": len(result["reasons"]),
        "rules": sorted({r["rule"] for r in result["reasons"]}),
    }
