import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Index, CheckConstraint, Boolean, Integer
from sqlalchemy.orm import relationship
from app.core.database import Base


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    role = Column(String, nullable=False)
    # DEPRECATED: Phase 2 api_key_hash. Use AgentCredential table for Phase 3+.
    api_key_hash = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    action_logs = relationship("ActionLog", back_populates="agent", cascade="all, delete-orphan")
    credentials = relationship("AgentCredential", back_populates="agent", cascade="all, delete-orphan")


class AgentCredential(Base):
    __tablename__ = "agent_credentials"

    id = Column(String, primary_key=True, index=True)  # key_id
    agent_id = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    secret_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)

    agent = relationship("Agent", back_populates="credentials")


class Operator(Base):
    __tablename__ = "operators"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # "admin" or "reviewer"
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint("role IN ('admin', 'reviewer')", name="ck_operators_role"),
    )


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String, nullable=False)
    parameters = Column(JSON, nullable=False)
    # Constrained to known valid risk levels
    risk_level = Column(String, nullable=False)
    # Constrained to known valid decision outcomes
    decision = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    # Indexed for efficient sort on GET /audit-log
    requested_at = Column(DateTime, nullable=False, index=True)
    
    # Model and Policy Governance Tracing metadata
    model_version = Column(String, nullable=True)
    feature_schema_version = Column(Integer, nullable=True)
    policy_version = Column(String, nullable=True)
    request_id = Column(String, nullable=True)
    evaluation_timestamp = Column(DateTime, nullable=True, default=datetime.utcnow)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint(
            "risk_level IN ('low', 'medium', 'high')",
            name="ck_action_logs_risk_level"
        ),
        CheckConstraint(
            "decision IN ('allow', 'block', 'require_human_approval')",
            name="ck_action_logs_decision"
        ),
        # Composite index for agent_id + requested_at (supports filtered+sorted audit-log queries)
        Index("ix_action_logs_agent_id_requested_at", "agent_id", "requested_at"),
    )

    agent = relationship("Agent", back_populates="action_logs")
    pending_approvals = relationship("PendingApproval", back_populates="action_log", cascade="all, delete-orphan")


class PendingApproval(Base):
    __tablename__ = "pending_approvals"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    action_log_id = Column(String, ForeignKey("action_logs.id", ondelete="CASCADE"), nullable=False, index=True)
    # Constrained to known valid approval lifecycle states
    status = Column(String, default="pending", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected')",
            name="ck_pending_approvals_status"
        ),
    )

    action_log = relationship("ActionLog", back_populates="pending_approvals")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, index=True, nullable=True)  # Null indicates global policy
    rule_name = Column(String, nullable=False)
    rules_json = Column(JSON, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, unique=True, default=lambda: str(uuid.uuid4()), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String, nullable=False, index=True)
    
    # Legacy fields
    actor_id = Column(String, nullable=True, index=True)
    status = Column(String, nullable=True)
    details = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)

    # Phase 7 fields
    severity = Column(String, nullable=True, default="info", index=True)
    source = Column(String, nullable=True, default="system")
    agent_id = Column(String, ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True)
    operator_id = Column(String, nullable=True)
    request_id = Column(String, nullable=True, index=True)
    action_log_id = Column(String, ForeignKey("action_logs.id", ondelete="SET NULL"), nullable=True)
    model_version = Column(String, nullable=True)
    policy_version = Column(String, nullable=True)
    incident_id = Column(String, nullable=True, index=True)
    description = Column(String, nullable=True, default="")
    metadata_json = Column(JSON, nullable=True)
    previous_event_hash = Column(String, nullable=True, default="GENESIS")
    event_hash = Column(String, nullable=True, default="")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity"
        ),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)  # 'low', 'medium', 'high', 'critical'
    status = Column(String, nullable=False, index=True) # 'open', 'investigating', 'contained', 'resolved', 'closed'
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=False)
    assigned_to = Column(String, nullable=True, index=True)
    affected_agent_id = Column(String, nullable=True)
    affected_model_version = Column(String, nullable=True)
    affected_policy_version = Column(String, nullable=True)
    resolution_notes = Column(String, nullable=True)

    __table_args__ = (
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="ck_incidents_severity"),
        CheckConstraint("status IN ('open', 'investigating', 'contained', 'resolved', 'closed')", name="ck_incidents_status"),
    )


class SystemSettings(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True)
    value = Column(JSON, nullable=False)


class ModelRegistry(Base):
    __tablename__ = "model_registry"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_version = Column(String, unique=True, index=True, nullable=False)
    feature_schema_version = Column(Integer, nullable=False)
    dataset_version = Column(String, nullable=False)
    artifact_path = Column(String, nullable=False)
    sha256 = Column(String, nullable=False)
    status = Column(String, nullable=False)  # "candidate", "active", "retired"
    metrics_json = Column(JSON, nullable=False)  # stores metrics as JSON dictionary
    created_at = Column(DateTime, default=datetime.utcnow)
    activated_at = Column(DateTime, nullable=True)
    retired_at = Column(DateTime, nullable=True)

    __table_args__ = (
        CheckConstraint("status IN ('candidate', 'active', 'retired')", name="ck_model_registry_status"),
    )


class ModelAuditEvent(Base):
    __tablename__ = "model_audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_version = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)  # registered, activated, rollback, activation_failed, checksum_failed, load_failed, drift_warning, drift_critical
    previous_model_version = Column(String, nullable=True)
    operator_id = Column(String, nullable=True)
    request_id = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    reason = Column(String, nullable=True)
    success = Column(Boolean, default=True)

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('registered', 'activated', 'rollback', 'activation_failed', 'checksum_failed', 'load_failed', 'drift_warning', 'drift_critical')",
            name="ck_model_audit_events_event_type"
        ),
    )
