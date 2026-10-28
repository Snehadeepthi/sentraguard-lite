"""Pydantic request/response models (the API contract)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PROMPT_CHARS = 20_000
MAX_DOC_CHARS = 20_000
MAX_DOCS = 10


class _Strict(BaseModel):
    # Unknown fields are rejected so typos (e.g. "promt") fail loudly.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class ContextDoc(_Strict):
    id: str = Field(min_length=1, max_length=128, examples=["doc-1"])
    text: str = Field(max_length=MAX_DOC_CHARS)


class Metadata(_Strict):
    app_id: str = Field(min_length=1, max_length=128, examples=["support-bot"])
    user_id: str = Field(min_length=1, max_length=128, examples=["u-123"])
    request_id: str = Field(min_length=1, max_length=128, examples=["req-001"])


class AnalyzeRequest(_Strict):
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)
    context_docs: list[ContextDoc] = Field(default_factory=list, max_length=MAX_DOCS)
    metadata: Metadata

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("prompt must not be blank")
        return v


class Reason(BaseModel):
    tag: Literal["prompt_injection", "pii", "rag_injection"]
    rule: str
    source: str
    evidence: str


class SanitizedDoc(BaseModel):
    id: str
    text: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int = Field(ge=0, le=100)
    risk_tags: list[str]
    sanitized_prompt: str
    sanitized_context_docs: list[SanitizedDoc]
    reasons: list[Reason]


class Thresholds(BaseModel):
    block_score: int
    transform_score: int


class PolicyResponse(BaseModel):
    version: str
    detectors: list[str]
    thresholds: Thresholds


class ErrorDetail(BaseModel):
    field: str
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] = []


class ErrorResponse(BaseModel):
    error: ErrorBody
