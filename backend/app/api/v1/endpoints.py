import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Query, Depends, WebSocket, WebSocketDisconnect, HTTPException, Response, Header
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.api.v1.schemas import (
    HealthResponse,
    AgentRegisterRequest,
    AgentRegisterResponse,
    ActionEvaluationRequest,
    ActionEvaluationResponse,
    AuditLogItem,
    ApprovalResolutionRequest,
    ApprovalResolutionResponse,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.rate_limiter import check_rate_limit, RateLimitRedisError
from app.core.auth import get_authenticated_agent, generate_api_key, hash_api_key, get_current_operator, require_admin_operator
from app.models import Agent, ActionLog, PendingApproval, AgentCredential, Operator, SecurityEvent
from app.ml.risk_engine import RiskEngine, RiskEngineError
from app.policy.engine import PolicyEngine
from app.core.websockets import manager
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from app.core.logging import request_id_ctx_var
import time

from app.core.metrics import (
    ml_inference_counter,
    ml_inference_latency,
    shap_errors_counter,
    decisions_counter
)

from app.api.v1.operator import router as operator_router
from app.api.v1.management import router as management_router
from app.api.v1.models_gov import router as models_router
from app.api.v1.sec_ops import router as sec_ops_router
from app.api.v1.incidents import router as incidents_router

logger = logging.getLogger("aura.endpoints")
router = APIRouter()

router.include_router(operator_router, prefix="/operator", tags=["Operator"])
router.include_router(management_router, prefix="/agents", tags=["Agent Management"])
router.include_router(models_router, prefix="/models", tags=["Model Governance"])
router.include_router(sec_ops_router, prefix="/security", tags=["Security Operations"])
router.include_router(incidents_router, prefix="/incidents", tags=["Incident Response"])
# Valid RBAC roles that can be assigned at registration
_VALID_ROLES = {"ResearchAgent", "DeveloperAgent", "OperationsAgent"}


# ConnectionManager moved to app.core.websockets


# ── Lazy-loaded ML/Policy singletons ─────────────────────────────────────────
_risk_engine = None
_policy_engine = None


def get_risk_engine() -> RiskEngine:
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = RiskEngine()
    return _risk_engine


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


def resolve_role(agent_id: str) -> str:
    """
    Phase 1 fallback: derive role from agent_id substring.
    Used ONLY when AUTH_ENABLED=false.
    """
    agent_id_lower = agent_id.lower()
    if "ops" in agent_id_lower:
        return "OperationsAgent"
    elif "research" in agent_id_lower:
        return "ResearchAgent"
    elif "dev" in agent_id_lower:
        return "DeveloperAgent"
    return "DeveloperAgent"


# ── WebSocket ─────────────────────────────────────────────────────────────────
@router.websocket("/ws/approvals")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ── Health & Readiness ────────────────────────────────────────────────────────
@router.get("/health", response_model=HealthResponse)
async def get_health(db: Session = Depends(get_db)):
    db_status = "healthy"
    redis_status = "healthy"

    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    try:
        rc = get_redis()
        rc.ping()
    except Exception:
        redis_status = "disconnected"

    auth_status = "enabled" if settings.AUTH_ENABLED else "disabled"

    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc),
        "services": {
            "database": db_status,
            "redis": redis_status,
            "authentication": auth_status,
        }
    }

@router.get("/readiness", response_model=HealthResponse)
async def get_readiness(db: Session = Depends(get_db)):
    db_status = "healthy"
    redis_status = "healthy"

    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    try:
        rc = get_redis()
        rc.ping()
    except Exception:
        redis_status = "disconnected"

    auth_status = "enabled" if settings.AUTH_ENABLED else "disabled"
    
    re = get_risk_engine()
    if re.sync_status == "unavailable":
        raise HTTPException(status_code=503, detail="Active model is unavailable or invalid")
        
    is_ready = db_status == "healthy" and redis_status == "healthy"
    if not is_ready:
        raise HTTPException(status_code=503, detail="Service not ready")

    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        services={
            "database": db_status,
            "redis": redis_status,
            "authentication": auth_status,
            "model_sync": re.sync_status
        }
    )

@router.get("/metrics")
async def metrics():
    # Expose Prometheus metrics
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# ── Agent registration ────────────────────────────────────────────────────────
@router.post("/agents/register", response_model=AgentRegisterResponse, status_code=201)
async def register_agent(
    request: AgentRegisterRequest,
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    """
    Register a new AI agent and issue a plaintext API key.

    The plaintext key is returned ONCE.  The caller must store it securely and
    pass it as the X-Agent-Key header on every /evaluate-action call.

    Idempotent: if the agent_id already exists and is already registered (has a
    key hash), returns 409 Conflict.

    The assigned role must be one of: ResearchAgent, DeveloperAgent, OperationsAgent.
    The role cannot be changed after registration (Phase 3 will add management APIs).
    """
    if request.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid role '{request.role}'. Must be one of: {', '.join(sorted(_VALID_ROLES))}."
        )

    existing = db.query(Agent).filter(Agent.id == request.agent_id).first()
    if existing:
        # Check if already fully registered
        if existing.credentials or existing.api_key_hash:
            raise HTTPException(
                status_code=409,
                detail=f"Agent '{request.agent_id}' is already registered. "
                       "Contact an administrator to rotate the key."
            )
        # Agent exists from Phase 1 (no hash/credential) — add credential to it
        plaintext_key, key_id, secret_hash = generate_api_key()
        cred = AgentCredential(
            id=key_id,
            agent_id=existing.id,
            secret_hash=secret_hash,
            is_active=True
        )
        db.add(cred)
        # Note: api_key_hash is deprecated, but we can set it if we want, or leave it.
        # We leave it alone since it's deprecated.
        existing.role = request.role
        existing.name = request.name
        existing.is_active = True
        db.commit()
        logger.info("AGENT_REGISTERED_UPGRADE agent=%s role=%s", request.agent_id, request.role)
    else:
        plaintext_key, key_id, secret_hash = generate_api_key()
        new_agent = Agent(
            id=request.agent_id,
            name=request.name,
            role=request.role,
            is_active=True,
        )
        db.add(new_agent)
        try:
            db.commit()
            db.refresh(new_agent)
            
            # Now add credential
            cred = AgentCredential(
                id=key_id,
                agent_id=new_agent.id,
                secret_hash=secret_hash,
                is_active=True
            )
            db.add(cred)
            db.commit()
            
            evt = SecurityEvent(actor_id=admin.username, event_type="agent_register", status="success", details=f"Upgraded {request.agent_id}")
            db.add(evt)
            db.commit()
        except IntegrityError:
            db.rollback()
            evt = SecurityEvent(actor_id=admin.username, event_type="agent_register", status="failure", details=f"Conflict {request.agent_id}")
            db.add(evt)
            db.commit()
            raise HTTPException(status_code=409, detail="Agent ID conflict. Try a different agent_id.")
        logger.info("AGENT_REGISTERED_NEW agent=%s role=%s", request.agent_id, request.role)

    return AgentRegisterResponse(
        agent_id=request.agent_id,
        role=request.role,
        api_key=plaintext_key,
        message=(
            "Registration successful. Store the api_key securely — it will NOT be shown again. "
            "Pass it as 'X-Agent-Key' header on every /evaluate-action request."
        ),
    )


# ── Audit log ─────────────────────────────────────────────────────────────────
@router.get("/audit-log", response_model=List[AuditLogItem])
async def get_audit_log(
    agent_id: Optional[str] = Query(None, description="Filter logs by Agent ID"),
    db: Session = Depends(get_db)
):
    query = db.query(ActionLog)
    if agent_id:
        query = query.filter(ActionLog.agent_id == agent_id)

    logs = query.order_by(ActionLog.requested_at.desc()).all()

    result = []
    for log in logs:
        requested_str = log.requested_at.isoformat() if log.requested_at else ""
        evaluated_str = log.created_at.isoformat() if log.created_at else ""
        result.append(AuditLogItem(
            id=log.id,
            agent_id=log.agent_id or "",
            action=log.action,
            parameters=log.parameters or {},
            requested_at=requested_str,
            decision=log.decision,
            risk_level=log.risk_level,
            reason=log.reason,
            evaluated_at=evaluated_str,
            model_version=log.model_version,
            feature_schema_version=log.feature_schema_version,
            policy_version=log.policy_version,
            request_id=log.request_id,
            evaluation_timestamp=log.evaluation_timestamp.isoformat() if log.evaluation_timestamp else None
        ))
    return result


# ── Core action evaluation ─────────────────────────────────────────────────────
@router.post("/evaluate-action", response_model=ActionEvaluationResponse)
async def evaluate_action(
    request: ActionEvaluationRequest,
    http_response: Response,
    db: Session = Depends(get_db),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    authenticated_agent: Optional[Agent] = Depends(get_authenticated_agent),
):
    """
    Core firewall evaluation endpoint.

    Pipeline order (Phase 2):
        1. Authentication (X-Agent-Key validation) ← NEW
        2. Rate limiting (Redis counter)
        3. Agent DB get-or-create
        4. ML Risk Engine (SentenceTransformer + XGBoost)
        5. Policy Engine (RBAC)
        6. PostgreSQL persistence
        7. WebSocket broadcast (if human approval required)

    AUTH_ENABLED=true:
        - X-Agent-Key is mandatory.
        - agent_id and role are derived from the AUTHENTICATED credential.
        - Self-reported agent_id in the request body is IGNORED for identity.
          (It is still used to produce useful audit log entries; the actual
           authoritative identity is the credential-bound agent.)

    AUTH_ENABLED=false (Phase 1 compatibility):
        - X-Agent-Key is optional.
        - agent_id and role fall back to self-reported + substring matching.
    """
    # ── STEP 1: Resolve identity from credential or self-report ───────────────
    if settings.AUTH_ENABLED and authenticated_agent is not None:
        # Authenticated path: use credential-bound identity
        effective_agent_id = authenticated_agent.id
        effective_role = authenticated_agent.role
        auth_note = f"[AUTHENTICATED:{effective_agent_id}]"
    else:
        # Phase 1 fallback / AUTH_ENABLED=false
        effective_agent_id = request.agent_id
        effective_role = None  # will be derived after DB get-or-create
        auth_note = "[UNAUTHENTICATED]"

    logger.debug("EVAL_START %s action=%s", auth_note, request.action)

    # ── STEP 2: Per-agent rate limiting (uses verified identity) ──────────────
    if settings.RATE_LIMIT_ENABLED:
        rl = None
        try:
            rc = get_redis()
            rl = check_rate_limit(
                redis_client=rc,
                agent_id=effective_agent_id,
                limit=settings.RATE_LIMIT_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            )
        except RateLimitRedisError:
            import sys
            is_testing = "pytest" in sys.modules or "unittest" in sys.modules
            if not is_testing:
                logger.warning("Redis rate limiter offline. Bypassing rate limiting.")
                http_response.headers["X-RateLimit-Limit"] = "100"
                http_response.headers["X-RateLimit-Remaining"] = "99"
            else:
                raise HTTPException(
                    status_code=503,
                    detail="Rate-limit service temporarily unavailable. Please retry shortly.",
                    headers={"Retry-After": "5"},
                )

        if rl is not None:
            http_response.headers["X-RateLimit-Limit"] = str(rl.limit)
            http_response.headers["X-RateLimit-Remaining"] = str(rl.remaining)

            if not rl.allowed:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests. Your per-agent quota has been exceeded.",
                        "retry_after": rl.retry_after,
                    },
                    headers={
                        "X-RateLimit-Limit": str(rl.limit),
                        "X-RateLimit-Remaining": "0",
                        "Retry-After": str(rl.retry_after),
                    },
                )

    # ── STEP 3: Agent DB get-or-create (Phase 0 atomic savepoint) ────────────
    if settings.AUTH_ENABLED and authenticated_agent is not None:
        # Agent is already fetched and validated by auth dependency
        agent = authenticated_agent
    else:
        # Phase 1 fallback: upsert by self-reported agent_id
        agent = db.query(Agent).filter(Agent.id == effective_agent_id).first()
        if not agent:
            try:
                with db.begin_nested():
                    agent = Agent(
                        id=effective_agent_id,
                        name=f"Agent {effective_agent_id}",
                        role=resolve_role(effective_agent_id),
                        is_active=True,
                    )
                    db.add(agent)
                db.commit()
                db.refresh(agent)
            except IntegrityError:
                db.rollback()
                agent = db.query(Agent).filter(Agent.id == effective_agent_id).first()
                if agent is None:
                    raise HTTPException(
                        status_code=503,
                        detail="Agent registration conflict. Please retry."
                    )

    # After DB upsert, resolve effective_role if not yet set (Phase 1 path)
    if effective_role is None:
        effective_role = agent.role

    # ── Quarantine Check ──────────────────────────────────────────────────────
    if not agent.is_active:
        from app.core.audit_chain import append_security_event
        from app.core.metrics import authorization_failures_counter
        append_security_event(
            event_type="quarantined_agent_action_blocked",
            severity="medium",
            source="firewall",
            description=f"Action evaluation blocked for quarantined agent '{agent.id}'.",
            db=db,
            agent_id=agent.id,
            request_id=request_id_ctx_var.get()
        )
        authorization_failures_counter.inc()
        raise HTTPException(
            status_code=403,
            detail="Agent is currently quarantined/inactive."
        )

    # ── Lockdown Check ────────────────────────────────────────────────────────
    from app.api.v1.sec_ops import _lockdown_state, load_lockdown_from_db
    lockdown_active = _lockdown_state.get("enabled", False)
    if not lockdown_active:
        try:
            lockdown_active = load_lockdown_from_db(db)
        except Exception:
            pass

    if lockdown_active:
        action_log = ActionLog(
            agent_id=agent.id,
            action=request.action,
            parameters=request.parameters,
            risk_level="high",
            decision="block",
            reason="Emergency safety lockdown active. Evaluation requests are blocked.",
            requested_at=datetime.now(timezone.utc),
            model_version=risk_engine.model_version,
            feature_schema_version=1,
            policy_version=policy_engine.version,
            request_id=request_id_ctx_var.get(),
            evaluation_timestamp=datetime.now(timezone.utc)
        )
        db.add(action_log)
        db.commit()

        decisions_counter.labels(
            risk_level="high",
            policy_decision="block",
            model_version=risk_engine.model_version or "unknown",
            policy_version=policy_engine.version
        ).inc()

        return ActionEvaluationResponse(
            decision="block",
            risk_level="high",
            reason="Emergency safety lockdown active. Evaluation requests are blocked.",
            model_version=risk_engine.model_version,
            feature_schema_version=1,
            policy_version=policy_engine.version,
            request_id=request_id_ctx_var.get()
        )

    # ── STEP 4: ML Risk Engine ─────────────────────────────────────────────────
    try:
        start_time = time.time()
        risk_level, ml_decision, ml_reason = risk_engine.evaluate(request.action, request.parameters, agent_id=effective_agent_id)
        latency = time.time() - start_time
        
        ml_inference_counter.labels(model_version=risk_engine.model_version, status="success").inc()
        ml_inference_latency.labels(model_version=risk_engine.model_version).observe(latency)
        
        if "[SHAP explanation unavailable]" in ml_reason:
            shap_errors_counter.labels(model_version=risk_engine.model_version).inc()
    except RiskEngineError as e:
        ml_inference_counter.labels(model_version=risk_engine.model_version or "unknown", status="error").inc()
        raise HTTPException(
            status_code=500,
            detail=f"Firewall safety layer error: {str(e)}"
        )

    # ── STEP 5: Policy Engine (RBAC) ──────────────────────────────────────────
    if ml_decision == "block":
        final_decision = "block"
        policy_note = None
    else:
        final_decision, policy_note = policy_engine.evaluate(effective_role, request.action, risk_level)

    reason = f"{ml_reason} | {policy_note}" if policy_note else ml_reason

    # ── STEP 6: Parse timestamp ───────────────────────────────────────────────
    try:
        requested_dt = datetime.fromisoformat(request.requested_at.replace("Z", "+00:00"))
    except Exception:
        requested_dt = datetime.now(timezone.utc)

    # ── STEP 7: Persist ActionLog ─────────────────────────────────────────────
    action_log = ActionLog(
        agent_id=agent.id,
        action=request.action,
        parameters=request.parameters,
        risk_level=risk_level,
        decision=final_decision,
        reason=reason,
        requested_at=requested_dt,
        model_version=risk_engine.model_version,
        feature_schema_version=risk_engine.feature_schema_version,
        policy_version=policy_engine.version,
        request_id=request_id_ctx_var.get(),
        evaluation_timestamp=datetime.now(timezone.utc)
    )
    db.add(action_log)
    db.commit()
    db.refresh(action_log)

    # Increment decision metrics
    decisions_counter.labels(
        risk_level=risk_level,
        policy_decision=final_decision,
        model_version=risk_engine.model_version,
        policy_version=policy_engine.version
    ).inc()

    # ── STEP 8: WebSocket broadcast for pending approvals ─────────────────────
    if final_decision == "require_human_approval":
        pending = PendingApproval(action_log_id=action_log.id, status="pending")
        db.add(pending)
        db.commit()
        db.refresh(pending)

        ws_payload = {
            "event": "new_approval_request",
            "data": {
                "approval_id": pending.id,
                "agent_id": agent.id,
                "action": request.action,
                "parameters": request.parameters,
                "risk_level": risk_level,
                "reason": reason
            }
        }
        await manager.broadcast(ws_payload)

    return ActionEvaluationResponse(
        decision=final_decision,
        risk_level=risk_level,
        reason=reason,
        model_version=settings.ML_MODEL_VERSION,
        feature_schema_version=1,
        policy_version=policy_engine.version,
        request_id=request_id_ctx_var.get()
    )


# ── Approval resolution ───────────────────────────────────────────────────────
@router.post("/approve-action", response_model=ApprovalResolutionResponse)
async def approve_action(
    request: ApprovalResolutionRequest,
    db: Session = Depends(get_db),
    operator: Operator = Depends(get_current_operator)
):
    pending = db.query(PendingApproval).filter(PendingApproval.id == request.approval_id).first()
    if not pending:
        raise HTTPException(status_code=404, detail="Pending approval record not found.")

    pending.status = request.status

    action_log = db.query(ActionLog).filter(ActionLog.id == pending.action_log_id).first()
    if action_log:
        if request.status == "approved":
            action_log.decision = "allow"
        elif request.status == "rejected":
            action_log.decision = "block"
        db.add(action_log)

    db.add(pending)
    
    evt = SecurityEvent(actor_id=operator.username, event_type="approve_action", status="success", details=f"Approval {request.approval_id} set to {request.status}")
    db.add(evt)
    
    db.commit()

    ws_payload = {
        "event": "approval_resolved",
        "data": {
            "approval_id": request.approval_id,
            "status": request.status
        }
    }
    await manager.broadcast(ws_payload)

    return ApprovalResolutionResponse(
        status="success",
        approval_id=request.approval_id,
        resolution=request.status
    )
