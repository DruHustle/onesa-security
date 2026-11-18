from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CollectorRegistration(StrictModel):
    name: str = Field(min_length=3, max_length=150)


class AssetInput(StrictModel):
    external_ref: str = Field(min_length=4, max_length=150, pattern=r"^[A-Za-z0-9_.:-]+$")
    category: Literal["endpoint", "server", "application", "cloud"]
    label: str = Field(min_length=1, max_length=150)
    os_family: Literal["linux", "windows", "macos", "other"] | None = None


class EventInput(StrictModel):
    external_id: str = Field(min_length=8, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    event_type: Literal["auth.failure", "auth.success", "iam.privilege_change", "endpoint.persistence", "host.posture"]
    subject_ref: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    asset_ref: str | None = Field(default=None, max_length=150, pattern=r"^[A-Za-z0-9_.:-]+$")
    occurred_at: datetime


class AlertChange(StrictModel):
    status: Literal["open", "investigating", "closed"]
    assigned_to: str | None = Field(default=None, max_length=255)
    disposition: str | None = Field(default=None, max_length=300)


class PolicyUpdate(StrictModel):
    expected_version: int = Field(ge=0)
    block_injection: bool
    redact_pii: bool


class InspectRequest(StrictModel):
    text: str = Field(min_length=1, max_length=20000)
    action_type: Literal["message", "tool"] = "message"


class ChatMessage(StrictModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=20000)


class ChatRequest(StrictModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=30)
    stream: bool = False


class FindingInput(StrictModel):
    external_id: str = Field(min_length=8, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    asset_ref: str = Field(min_length=4, max_length=150, pattern=r"^[A-Za-z0-9_.:-]+$")
    title: str = Field(min_length=5, max_length=150)
    category: Literal["configuration", "software", "exposure", "identity"]
    severity: Literal["low", "medium", "high", "critical"]
    cve_id: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,10}$", max_length=24)
    evidence_ref: str = Field(min_length=8, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")


class FindingResolution(StrictModel):
    verification: Literal["verified_resolved", "false_positive", "accepted_risk"]
    evidence_ref: str = Field(min_length=8, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    note: str = Field(min_length=15, max_length=300)


class RemediationRequest(StrictModel):
    finding_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    action_type: Literal["patch_plan", "configuration_hardening", "credential_rotation", "firewall_review"]
    action_summary: str = Field(min_length=15, max_length=500)
    impact_summary: str = Field(min_length=15, max_length=500)
    rollback_plan: str = Field(min_length=15, max_length=500)
    dry_run: Literal[True]


class RemediationDecision(StrictModel):
    decision: Literal["approve", "reject"]
    note: str = Field(min_length=15, max_length=300)


class AgentSpanInput(StrictModel):
    trace_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    span_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    parent_span_id: str | None = Field(default=None, pattern=r"^[0-9a-f-]{36}$")
    agent_ref: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$")
    phase: Literal["inference", "retrieval", "planning", "policy", "tool_review", "response"]
    outcome: Literal["success", "denied", "error", "timeout"]
    elapsed_us: int = Field(ge=0, le=60_000_000)
    occurred_at: datetime
