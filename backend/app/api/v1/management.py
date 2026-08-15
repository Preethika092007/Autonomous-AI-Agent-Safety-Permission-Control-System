import logging
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Agent, AgentCredential, Operator, SecurityEvent
from app.core.auth import require_admin_operator, generate_api_key
from app.api.v1.schemas import AgentInfo, AgentStatusUpdate

logger = logging.getLogger("aura.management")
router = APIRouter()

@router.get("/", response_model=List[AgentInfo])
async def list_agents(
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    agents = db.query(Agent).all()
    result = []
    for a in agents:
        active_cred = next((c for c in a.credentials if c.is_active), None)
        result.append(AgentInfo(
            id=a.id,
            name=a.name,
            role=a.role,
            is_active=a.is_active,
            created_at=a.created_at,
            active_credential_id=active_cred.id if active_cred else None
        ))
    return result

@router.get("/{agent_id}", response_model=AgentInfo)
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    active_cred = next((c for c in a.credentials if c.is_active), None)
    return AgentInfo(
        id=a.id,
        name=a.name,
        role=a.role,
        is_active=a.is_active,
        created_at=a.created_at,
        active_credential_id=active_cred.id if active_cred else None
    )

@router.patch("/{agent_id}/status")
async def update_agent_status(
    agent_id: str,
    status_update: AgentStatusUpdate,
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    agent.is_active = status_update.is_active
    
    evt = SecurityEvent(actor_id=admin.username, event_type="agent_status_toggle", status="success", details=f"Agent {agent_id} is_active={agent.is_active}")
    db.add(evt)
    db.commit()
    return {"status": "success", "agent_id": agent.id, "is_active": agent.is_active}

@router.post("/{agent_id}/rotate-key")
async def rotate_agent_key(
    agent_id: str,
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Deactivate existing keys
    for cred in agent.credentials:
        if cred.is_active:
            cred.is_active = False
            cred.revoked_at = datetime.now(timezone.utc)
            
    # Generate new key
    plaintext_key, key_id, secret_hash = generate_api_key()
    new_cred = AgentCredential(
        id=key_id,
        agent_id=agent.id,
        secret_hash=secret_hash,
        is_active=True
    )
    db.add(new_cred)
    
    evt = SecurityEvent(actor_id=admin.username, event_type="agent_rotate_key", status="success", details=f"Agent {agent_id} key rotated")
    db.add(evt)
    db.commit()
    
    return {
        "status": "success",
        "agent_id": agent.id,
        "api_key": plaintext_key,
        "message": "Key rotated successfully. Store the api_key securely — it will NOT be shown again."
    }


@router.post("/{agent_id}/quarantine")
async def quarantine_agent(
    agent_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    admin: Operator = Depends(require_admin_operator)
):
    """Quarantine an agent and revoke all its active credentials, linking to an incident."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    incident_id = payload.get("incident_id")
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id is required to quarantine agent.")

    agent.is_active = False

    # Revoke all credentials
    for cred in agent.credentials:
        if cred.is_active:
            cred.is_active = False
            cred.revoked_at = datetime.now(timezone.utc)

    db.commit()

    # Append SecurityEvent to the chronological audit chain
    from app.core.audit_chain import append_security_event
    from app.core.metrics import agent_quarantines_counter
    
    append_security_event(
        event_type="agent_quarantine",
        severity="high",
        source="operator_api",
        description=f"Agent '{agent_id}' quarantined by operator '{admin.username}'. Linked to Incident {incident_id}.",
        db=db,
        operator_id=admin.username,
        agent_id=agent_id,
        incident_id=incident_id
    )
    agent_quarantines_counter.inc()

    return {
        "status": "success",
        "agent_id": agent.id,
        "is_active": False,
        "message": f"Agent '{agent_id}' quarantined and all active credentials revoked."
    }
