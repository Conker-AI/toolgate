"""Request bodies of the ToolGate HTTP API."""

from typing import Literal

from pydantic import BaseModel, Field, StrictInt

from toolgate.core.access_policy import Decision


class SecretCreate(BaseModel):
    name: str
    value: str


class SecretUpdate(BaseModel):
    value: str


class AgentKeyCreate(BaseModel):
    name: str
    scopes: list[str] = []


class AgentKeyScopes(BaseModel):
    scopes: list[str] = []


class V2Service(BaseModel):
    id: str | None = None
    name: str
    description: str = ""
    secret_refs: list[str] = []
    health: str = "unknown"
    destination_policy: dict = {}
    status: str = "active"


class V2Tool(BaseModel):
    id: str
    name: str | None = None
    description: str = ""
    service_id: str | None = None
    category: str = "controlled"
    inputs: list[dict] = []
    outputs: list[dict] = []
    execution: dict = {}
    policy: dict = {}
    authorization: str = "auto"
    version: StrictInt = Field(default=1, ge=1)
    expected_version: StrictInt | None = Field(default=None, ge=1)
    status: str = "active"


class V2Automation(BaseModel):
    id: str
    name: str | None = None
    description: str = ""
    inputs: list[dict] = []
    workflow: list[dict] = []
    policy: dict = {}
    authorization: str = "auto"
    schedule: str | None = None
    version: StrictInt = Field(default=1, ge=1)
    expected_version: StrictInt | None = Field(default=None, ge=1)
    status: str = "draft"


class V2Request(BaseModel):
    """Informational owner messages; verification is issued only by an invocation."""

    kind: str
    title: str
    details: str
    payload: dict = {}
    severity: str = "info"


class V2RequestDecision(BaseModel):
    status: str
    note: str = ""


class OwnerDecision(BaseModel):
    model_config = {"extra": "forbid"}
    status: Literal["approved", "rejected", "dismissed"]
    note: str = Field(default="", max_length=2000)


class OwnerLockdown(BaseModel):
    model_config = {"extra": "forbid", "strict": True}
    enabled: bool


class V2Invoke(BaseModel):
    args: dict = {}
    approval_request_id: str | None = None
    action_id: str | None = None
    job_id: str | None = None
    published_version: StrictInt | None = Field(default=None, ge=1)
    expected_publication_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    # A policy delegate's resolution of the owner's access settings for this exact action.
    decision: Decision | None = None


class V2Publish(BaseModel):
    expected_version: StrictInt = Field(ge=1)


class PortMapping(BaseModel):
    model_config = {"extra": "forbid"}
    hostAddress: str = Field(min_length=1, max_length=45)
    hostPort: StrictInt = Field(ge=1, le=65535)
    containerPort: StrictInt = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]


class PortReviewRequest(BaseModel):
    model_config = {"extra": "forbid"}
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation: Literal["create", "edit", "remove"]
    mapping: PortMapping | None = None
    original: PortMapping | None = None


# 0: a request waits until the owner answers; he may look once or twice a day. A positive value
# bounds the wait instead (approvals.create_verification_request keeps it within 15 to 900 seconds).
DEFAULT_CONFIRMATION_EXPIRY_SECONDS = 0


class V2Settings(BaseModel):
    generation_model: str = "qwen3:4b"
    event_retention_days: int = 90
    default_confirmation_expiry_seconds: int = DEFAULT_CONFIRMATION_EXPIRY_SECONDS
    producthunt_commercial_use_approved: bool = False


class VerificationMethodCreate(BaseModel):
    name: str
    secret_ref: str


class VerificationCallback(BaseModel):
    method_id: str
    request_id: str
    decision: str
    nonce: str


class PortFinalizationRequest(BaseModel):
    model_config = {"extra": "forbid"}
    action_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:/-]+$")
    approval_request_id: str | None = Field(default=None, min_length=1, max_length=160)
