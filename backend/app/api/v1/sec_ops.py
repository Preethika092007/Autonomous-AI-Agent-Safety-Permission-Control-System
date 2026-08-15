import json
import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.core.database import get_db
from app.core.auth import get_current_operator, require_admin_operator as check_admin
from app.models import Operator, SecurityEvent, SystemSettings
from app.core.audit_chain import verify_audit_chain, append_security_event
from app.core.metrics import system_lockdowns_counter, audit_chain_corruption_gauge

logger = logging.getLogger("aura.sec_ops")

router = APIRouter()

# In-memory fast cache of lockdown state (synchronized via Redis Pub/Sub)
_lockdown_state = {"enabled": False}


def load_lockdown_from_db(db: Session) -> bool:
    """Helper to load system lockdown settings from PostgreSQL / SQLite authoritative state."""
    setting = db.query(SystemSettings).filter(SystemSettings.key == "system_lockdown").first()
    if not setting:
        # Seed default
        setting = SystemSettings(key="system_lockdown", value={"enabled": False})
        db.add(setting)
        db.commit()
    enabled = setting.value.get("enabled", False)
    _lockdown_state["enabled"] = enabled
    return enabled


def set_lockdown_in_db(db: Session, enabled: bool):
    """Helper to persist system lockdown settings in PostgreSQL / SQLite."""
    setting = db.query(SystemSettings).filter(SystemSettings.key == "system_lockdown").first()
    if not setting:
        setting = SystemSettings(key="system_lockdown", value={"enabled": enabled})
        db.add(setting)
    else:
        setting.value = {"enabled": enabled}
    db.commit()
    _lockdown_state["enabled"] = enabled


@router.post("/lockdown", response_model=dict)
def trigger_lockdown(
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(check_admin)
):
    """Trigger a global system lockdown. Fails closed all evaluate-action operations."""
    set_lockdown_in_db(db, True)
    
    # 1. Publish to Redis channel aura_security_events for multi-instance sync
    try:
        import redis
        from app.core.config import settings
        r = redis.from_url(settings.REDIS_URL)
        r.publish("aura_security_events", json.dumps({"event": "lockdown_state_changed", "enabled": True}))
    except Exception as e:
        logger.warning(f"Failed to publish lockdown event to Redis Pub/Sub: {e}")

    # 2. Append SecurityEvent log to hash-chain
    append_security_event(
        event_type="emergency_lockdown",
        severity="critical",
        source="operator_api",
        description=f"Global emergency lockdown triggered by admin '{current_operator.username}'. System fails closed.",
        db=db,
        operator_id=current_operator.username
    )
    system_lockdowns_counter.inc()

    return {"status": "locked_down", "message": "Global safety lockdown enabled. System is now failing closed."}


@router.post("/unlock", response_model=dict)
def release_lockdown(
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(check_admin)
):
    """Release system lockdown and restore normal safety checks."""
    set_lockdown_in_db(db, False)

    # 1. Publish to Redis channel
    try:
        import redis
        from app.core.config import settings
        r = redis.from_url(settings.REDIS_URL)
        r.publish("aura_security_events", json.dumps({"event": "lockdown_state_changed", "enabled": False}))
    except Exception as e:
        logger.warning(f"Failed to publish unlock event to Redis Pub/Sub: {e}")

    # 2. Append SecurityEvent log to hash-chain
    append_security_event(
        event_type="emergency_unlock",
        severity="critical",
        source="operator_api",
        description=f"Global safety lockdown released by admin '{current_operator.username}'.",
        db=db,
        operator_id=current_operator.username
    )

    return {"status": "normal", "message": "Global safety lockdown released."}


@router.get("/status", response_model=dict)
def get_lockdown_status(db: Session = Depends(get_db), current_operator: Operator = Depends(get_current_operator)):
    """Retrieve the current lockdown state of the security platform."""
    # Ensure local in-memory flag matches authoritative DB state
    enabled = load_lockdown_from_db(db)
    return {"lockdown_enabled": enabled}


@router.get("/audit/verify", response_model=dict)
def verify_audit_logs(db: Session = Depends(get_db), current_operator: Operator = Depends(check_admin)):
    """Verify cryptographic integrity of the security audit log chain."""
    report = verify_audit_chain(db)
    if not report["valid"]:
        # Raise Conflict if tampering is detected
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Audit chain verification failed: Hash sequence corruption detected.",
                "report": report
            }
        )
    return report


@router.get("/audit/export", response_model=dict)
def export_audit_logs(
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(check_admin),
    start_time: Optional[str] = Query(None, description="ISO format start datetime filter"),
    end_time: Optional[str] = Query(None, description="ISO format end datetime filter"),
    severity: Optional[str] = Query(None, description="Severity category filter"),
    event_type: Optional[str] = Query(None, description="Event classification filter"),
    agent_id: Optional[str] = Query(None, description="Target agent filter"),
    incident_id: Optional[str] = Query(None, description="Linked incident filter"),
    page: int = Query(1, ge=1, description="Page index"),
    limit: int = Query(100, ge=1, le=1000, description="Items per page")
):
    """Export paginated compliance-audited security events."""
    query = db.query(SecurityEvent)
    
    # Apply filters
    if start_time:
        try:
            dt = datetime.fromisoformat(start_time)
            query = query.filter(SecurityEvent.timestamp >= dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_time format. Use ISO-8601.")
            
    if end_time:
        try:
            dt = datetime.fromisoformat(end_time)
            query = query.filter(SecurityEvent.timestamp <= dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_time format. Use ISO-8601.")

    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if agent_id:
        query = query.filter(SecurityEvent.agent_id == agent_id)
    if incident_id:
        query = query.filter(SecurityEvent.incident_id == incident_id)

    # Sort chronologically as requested
    query = query.order_by(SecurityEvent.timestamp.asc())
    
    total = query.count()
    offset = (page - 1) * limit
    events = query.offset(offset).limit(limit).all()

    exported_events = []
    for e in events:
        exported_events.append({
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "severity": e.severity,
            "source": e.source,
            "agent_id": e.agent_id,
            "operator_id": e.operator_id,
            "request_id": e.request_id,
            "action_log_id": e.action_log_id,
            "model_version": e.model_version,
            "policy_version": e.policy_version,
            "incident_id": e.incident_id,
            "description": e.description,
            "metadata_json": e.metadata_json,
            "previous_event_hash": e.previous_event_hash,
            "event_hash": e.event_hash
        })

    return {
        "metadata": {
            "filters": {
                "start_time": start_time,
                "end_time": end_time,
                "severity": severity,
                "event_type": event_type,
                "agent_id": agent_id,
                "incident_id": incident_id
            },
            "exported_at": datetime.utcnow().isoformat(),
            "total_records": total,
            "page": page,
            "limit": limit
        },
        "events": exported_events
    }
