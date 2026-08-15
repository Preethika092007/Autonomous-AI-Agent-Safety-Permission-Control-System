import os
import json
import hashlib
import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import xgboost as xgb
import shap

from app.core.database import get_db
from app.core.config import settings
from app.core.auth import get_current_operator
from app.models import Operator, ModelRegistry, ModelAuditEvent, ActionLog
from app.api.v1.schemas import AuditLogItem
from app.core.metrics import (
    model_activation_counter,
    model_rollback_counter,
    model_checksum_failures_counter,
    ml_drift_score_gauge,
    ml_drift_events_counter
)
from app.core.redis import get_redis
from app.core.audit_chain import append_security_event

logger = logging.getLogger("aura.models_gov")
router = APIRouter()

def check_admin(operator: Operator = Depends(get_current_operator)):
    if operator.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required for this action."
        )
    return operator

def _compute_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

@router.get("", response_model=List[dict])
def list_models(db: Session = Depends(get_db), current_operator: Operator = Depends(get_current_operator)):
    """List all registered models."""
    models = db.query(ModelRegistry).order_by(ModelRegistry.created_at.desc()).all()
    result = []
    for m in models:
        result.append({
            "id": m.id,
            "model_version": m.model_version,
            "feature_schema_version": m.feature_schema_version,
            "dataset_version": m.dataset_version,
            "status": m.status,
            "metrics": m.metrics_json,
            "sha256": m.sha256,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "activated_at": m.activated_at.isoformat() if m.activated_at else None,
            "retired_at": m.retired_at.isoformat() if m.retired_at else None,
        })
    return result

@router.get("/health", response_model=dict)
def get_model_health(db: Session = Depends(get_db), current_operator: Operator = Depends(get_current_operator)):
    """Retrieve runtime model health status and data drift statistics."""
    from app.api.v1.endpoints import get_risk_engine
    re = get_risk_engine()

    # Calculate drift metrics (last 1 hour window)
    psi_score, drift_status = re.drift_monitor.calculate_psi(3600)
    
    # Expose drift metrics to Prometheus
    ml_drift_score_gauge.labels(feature="text_length", model_version=re.model_version or "unknown").set(psi_score)
    if drift_status != "normal":
        ml_drift_events_counter.labels(severity=drift_status, model_version=re.model_version or "unknown").inc()

    # Determine status
    if re.sync_status == "synchronized":
        model_status = "healthy"
    elif re.sync_status == "degraded":
        model_status = "degraded"
    else:
        model_status = "unavailable"

    # Get last evaluation timestamp
    last_eval_str = None
    if re.drift_monitor.history:
        last_eval_time = re.drift_monitor.history[-1][0]
        last_eval_str = datetime.fromtimestamp(last_eval_time).isoformat()
    else:
        # Check DB ActionLog
        latest_log = db.query(ActionLog).order_by(ActionLog.evaluated_at.desc()).first()
        if latest_log:
            last_eval_str = latest_log.evaluated_at.isoformat()

    return {
        "active_model": re.model_version or "None",
        "model_status": model_status,
        "checksum_valid": re.sync_status in ("synchronized", "degraded"),
        "artifact_loaded": re.model is not None,
        "last_evaluation_at": last_eval_str,
        "drift_status": drift_status,
        "drift_score": round(psi_score, 4),
        "instance_sync": re.sync_status
    }


@router.get("/{model_version}", response_model=dict)
def get_model_details(model_version: str, db: Session = Depends(get_db), current_operator: Operator = Depends(get_current_operator)):
    """Retrieve details of a registered model."""
    m = db.query(ModelRegistry).filter(ModelRegistry.model_version == model_version).first()
    if not m:
        raise HTTPException(status_code=404, detail=f"Model version {model_version} not found in registry.")
    return {
        "id": m.id,
        "model_version": m.model_version,
        "feature_schema_version": m.feature_schema_version,
        "dataset_version": m.dataset_version,
        "status": m.status,
        "metrics": m.metrics_json,
        "sha256": m.sha256,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "activated_at": m.activated_at.isoformat() if m.activated_at else None,
        "retired_at": m.retired_at.isoformat() if m.retired_at else None,
    }

@router.post("/{model_version}/activate", response_model=dict)
def activate_model(model_version: str, db: Session = Depends(get_db), current_operator: Operator = Depends(check_admin)):
    """Activate a model version atomically."""
    # Find model in registry
    model = db.query(ModelRegistry).filter(ModelRegistry.model_version == model_version).first()
    if not model:
        raise HTTPException(status_code=404, detail=f"Model version {model_version} not found in registry.")

    # 1. Verify artifact exists
    if not os.path.exists(model.artifact_path):
        # Event audit log
        audit = ModelAuditEvent(
            model_version=model_version,
            event_type="load_failed",
            operator_id=current_operator.username,
            reason="Artifact physical file missing",
            success=False
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=400, detail="Model artifact binary file missing on disk.")

    # 2. Verify SHA-256 Checksum
    actual_sha = _compute_sha256(model.artifact_path)
    if actual_sha != model.sha256:
        model_checksum_failures_counter.labels(model_version=model_version).inc()
        audit = ModelAuditEvent(
            model_version=model_version,
            event_type="checksum_failed",
            operator_id=current_operator.username,
            reason=f"Checksum mismatch: expected {model.sha256}, actual {actual_sha}",
            success=False
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=400, detail="Model integrity check failed (SHA-256 mismatch).")

    # 3. Test Load Validation
    try:
        temp_model = xgb.XGBClassifier()
        temp_model.load_model(model.artifact_path)
        shap.TreeExplainer(temp_model)
    except Exception as e:
        audit = ModelAuditEvent(
            model_version=model_version,
            event_type="load_failed",
            operator_id=current_operator.username,
            reason=f"Failed test loading/shap generation: {e}",
            success=False
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=400, detail=f"Artifact is incompatible or failed to load: {e}")

    # Verify schema version
    if model.feature_schema_version != 1:
        audit = ModelAuditEvent(
            model_version=model_version,
            event_type="activation_failed",
            operator_id=current_operator.username,
            reason=f"Schema version {model.feature_schema_version} incompatible with engine (v1)",
            success=False
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=400, detail=f"Incompatible schema version: {model.feature_schema_version}")

    # 4. Atomic Switch in DB
    current_active = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
    previous_version = current_active.model_version if current_active else None

    if current_active:
        current_active.status = "retired"
        current_active.retired_at = datetime.utcnow()

    model.status = "active"
    model.activated_at = datetime.utcnow()

    # Create Audit Event
    audit = ModelAuditEvent(
        model_version=model_version,
        event_type="activated",
        previous_model_version=previous_version,
        operator_id=current_operator.username,
        reason="Admin operator request",
        success=True
    )
    db.add(audit)
    db.commit()

    # 5. Broadcast hot swap to all cluster nodes via Redis Pub/Sub
    try:
        rc = get_redis()
        event_payload = {
            "event": "model_activated",
            "model_version": model_version,
            "previous_model_version": previous_version
        }
        rc.publish("aura_model_events", json.dumps(event_payload))
    except Exception as redis_err:
        logger.warning(f"Redis publish active event failed: {redis_err}")

    # 6. Apply hot swap on the current instance immediately
    from app.api.v1.endpoints import get_risk_engine
    re = get_risk_engine()
    re.reload_active_model()

    model_activation_counter.labels(model_version=model_version, status="success").inc()

    return {
        "model_version": model_version,
        "status": "active",
        "previous_model_version": previous_version,
        "activated_at": model.activated_at.isoformat(),
        "message": f"Successfully activated model {model_version}."
    }

@router.post("/rollback", response_model=dict)
def rollback_model(db: Session = Depends(get_db), current_operator: Operator = Depends(check_admin)):
    """Rollback to the most recently active/retired compatible model."""
    # Find the most recently active/retired model (excluding the current active one)
    current_active = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
    if not current_active:
        raise HTTPException(status_code=409, detail="No active model exists to roll back from.")

    # Find last retired model that had activated_at populated
    rollback_model = db.query(ModelRegistry)\
        .filter(ModelRegistry.status == "retired", ModelRegistry.activated_at.isnot(None))\
        .order_by(ModelRegistry.activated_at.desc())\
        .first()

    if not rollback_model:
        # Fallback to last registered model (excluding current active)
        rollback_model = db.query(ModelRegistry)\
            .filter(ModelRegistry.model_version != current_active.model_version)\
            .order_by(ModelRegistry.created_at.desc())\
            .first()

    if not rollback_model:
        raise HTTPException(status_code=409, detail="No compatible previously registered model found for rollback.")

    # Validate rollback model loading
    if not os.path.exists(rollback_model.artifact_path):
        raise HTTPException(status_code=400, detail=f"Rollback model {rollback_model.model_version} file missing on disk.")

    actual_sha = _compute_sha256(rollback_model.artifact_path)
    if actual_sha != rollback_model.sha256:
        raise HTTPException(status_code=400, detail=f"Rollback model {rollback_model.model_version} integrity checksum failed.")

    # Atomically Swap in DB
    current_active.status = "retired"
    current_active.retired_at = datetime.utcnow()

    rollback_model.status = "active"
    rollback_model.activated_at = datetime.utcnow()

    # Log Audit Event
    audit = ModelAuditEvent(
        model_version=rollback_model.model_version,
        event_type="rollback",
        previous_model_version=current_active.model_version,
        operator_id=current_operator.username,
        reason="Admin operator rollback request",
        success=True
    )
    db.add(audit)
    db.commit()

    # Redis PubSub Broadcast
    try:
        rc = get_redis()
        event_payload = {
            "event": "model_activated",
            "model_version": rollback_model.model_version,
            "previous_model_version": current_active.model_version
        }
        rc.publish("aura_model_events", json.dumps(event_payload))
    except Exception as redis_err:
        logger.warning(f"Redis publish rollback event failed: {redis_err}")

    # Local Swap
    from app.api.v1.endpoints import get_risk_engine
    re = get_risk_engine()
    re.reload_active_model()

    model_rollback_counter.labels(model_version=rollback_model.model_version, status="success").inc()

    return {
        "model_version": rollback_model.model_version,
        "status": "active",
        "previous_model_version": current_active.model_version,
        "activated_at": rollback_model.activated_at.isoformat(),
        "message": f"Successfully rolled back to model {rollback_model.model_version}."
    }


@router.post("/emergency-retire", response_model=dict)
def emergency_retire(db: Session = Depends(get_db), current_operator: Operator = Depends(check_admin)):
    """Immediately retire the active model and fallback to known-good or lockdown."""
    current_active = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
    if not current_active:
        raise HTTPException(status_code=409, detail="No active model exists to retire.")

    # Find fallback candidates
    candidates = db.query(ModelRegistry)\
        .filter(
            ModelRegistry.model_version != current_active.model_version,
            ModelRegistry.feature_schema_version == 1
        )\
        .order_by(ModelRegistry.activated_at.desc(), ModelRegistry.created_at.desc())\
        .all()

    fallback_model = None
    for cand in candidates:
        if os.path.exists(cand.artifact_path):
            actual_sha = _compute_sha256(cand.artifact_path)
            if actual_sha == cand.sha256:
                fallback_model = cand
                break

    if fallback_model:
        # Swap atomically in DB
        current_active.status = "retired"
        current_active.retired_at = datetime.utcnow()
        current_active.feature_schema_version = -1
        fallback_model.status = "active"
        fallback_model.activated_at = datetime.utcnow()
        db.commit()

        # Audit event logs
        audit = ModelAuditEvent(
            model_version=fallback_model.model_version,
            event_type="rollback",
            previous_model_version=current_active.model_version,
            operator_id=current_operator.username,
            reason="Emergency model retirement fallback",
            success=True
        )
        db.add(audit)
        db.commit()

        # Append SecurityEvent
        append_security_event(
            event_type="model_rollback",
            severity="high",
            source="model_gov_api",
            description=f"Model v{current_active.model_version} retired under emergency. Falling back to v{fallback_model.model_version}.",
            db=db,
            operator_id=current_operator.username,
            model_version=fallback_model.model_version
        )

        # Redis PubSub Broadcast
        try:
            rc = get_redis()
            rc.publish("aura_model_events", json.dumps({
                "event": "model_activated",
                "model_version": fallback_model.model_version,
                "previous_model_version": current_active.model_version
            }))
        except Exception as redis_err:
            logger.warning(f"Redis publish emergency retire event failed: {redis_err}")

        # Local reload
        from app.api.v1.endpoints import get_risk_engine
        re = get_risk_engine()
        re.reload_active_model()

        return {
            "retired_model": current_active.model_version,
            "active_model": fallback_model.model_version,
            "status": "fallback_activated",
            "message": f"Successfully retired model {current_active.model_version} and fell back to model {fallback_model.model_version}."
        }
    else:
        # No fallback model exists! Activate system lockdown
        from app.api.v1.sec_ops import set_lockdown_in_db
        set_lockdown_in_db(db, True)

        current_active.status = "retired"
        current_active.retired_at = datetime.utcnow()
        current_active.feature_schema_version = -1
        db.commit()

        # Audit event logs
        audit = ModelAuditEvent(
            model_version=current_active.model_version,
            event_type="load_failed",
            operator_id=current_operator.username,
            reason="Emergency retirement. No fallback. System lockdown activated.",
            success=False
        )
        db.add(audit)
        db.commit()

        # Append SecurityEvent for lockdown
        append_security_event(
            event_type="emergency_lockdown",
            severity="critical",
            source="model_gov_api",
            description=f"Emergency model retirement failed to find fallback. Global system lockdown activated.",
            db=db,
            operator_id=current_operator.username,
            model_version=current_active.model_version
        )

        # Publish system lockdown via Redis security events channel
        try:
            rc = get_redis()
            rc.publish("aura_security_events", json.dumps({"event": "lockdown_state_changed", "enabled": True}))
        except Exception as redis_err:
            logger.warning(f"Redis publish emergency lockdown event failed: {redis_err}")

        # Unload running active model
        from app.api.v1.endpoints import get_risk_engine
        re = get_risk_engine()
        re.reload_active_model()

        raise HTTPException(
            status_code=503,
            detail="Emergency model retired. No fallback model available. Global lockdown activated."
        )


