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
    role: Literal["user", "assistant", "system"]
    content: str = Field(min_length=1, max_length=20000)


class ChatRequest(StrictModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=30)
    stream: bool = False
