from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    services: Dict[str, str] = Field(default_factory=dict)


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., description="Unique identifier for the AI agent")
    name: str = Field(..., description="Human-readable agent name")
    role: str = Field(..., description="RBAC role: ResearchAgent | DeveloperAgent | OperationsAgent")


class AgentRegisterResponse(BaseModel):
    agent_id: str
    role: str
    api_key: str = Field(
        ...,
        description="Plaintext API key — shown ONCE. Store it securely. Pass it in X-Agent-Key header."
    )
    message: str


class ActionEvaluationRequest(BaseModel):
    agent_id: str = Field(..., description="Unique identifier for the AI agent")
    action: str = Field(..., description="Action name or type being attempted")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters associated with the action")
    requested_at: str = Field(..., description="ISO-8601 timestamp of the request")


class ActionEvaluationResponse(BaseModel):
    decision: str = Field(..., description="Decision: allow | block | require_human_approval")
    risk_level: str = Field(..., description="Risk Level: low | medium | high")
    reason: str = Field(..., description="Explanation of the evaluation decision")
    model_version: Optional[str] = None
    feature_schema_version: Optional[int] = None
    policy_version: Optional[str] = None
    request_id: Optional[str] = None


class AuditLogItem(BaseModel):
    id: str
    agent_id: str
    action: str
    parameters: Dict[str, Any]
    requested_at: str
    decision: str
    risk_level: str
    reason: str
    evaluated_at: str
    model_version: Optional[str] = None
    feature_schema_version: Optional[int] = None
    policy_version: Optional[str] = None
    request_id: Optional[str] = None
    evaluation_timestamp: Optional[str] = None


class ApprovalResolutionRequest(BaseModel):
    approval_id: str = Field(..., description="The ID of the pending approval record to resolve")
    status: str = Field(..., description="The status of approval: approved | rejected")


class ApprovalResolutionResponse(BaseModel):
    status: str
    approval_id: str
    resolution: str

class OperatorLoginRequest(BaseModel):
    username: str
    password: str

class OperatorLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str

class AgentStatusUpdate(BaseModel):
    is_active: bool

class AgentInfo(BaseModel):
    id: str
    name: str
    role: str
    is_active: bool
    created_at: datetime
    active_credential_id: Optional[str] = None
