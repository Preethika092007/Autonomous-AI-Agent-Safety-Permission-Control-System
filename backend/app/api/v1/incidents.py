import uuid
import logging
import time
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.auth import get_current_operator, require_admin_operator as check_admin
from app.models import Operator, Incident, SecurityEvent
from app.core.audit_chain import append_security_event
from app.core.metrics import incidents_counter, incident_resolution_seconds

logger = logging.getLogger("aura.incidents")

router = APIRouter()

# Schema definitions
class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=5)
    severity: str = Field("medium", pattern="^(low|medium|high|critical)$")
    affected_agent_id: Optional[str] = None
    affected_model_version: Optional[str] = None
    affected_policy_version: Optional[str] = None

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(None, pattern="^(open|investigating|contained|resolved|closed)$")
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    created_at: str
    updated_at: str
    resolved_at: Optional[str] = None
    created_by: str
    assigned_to: Optional[str] = None
    affected_agent_id: Optional[str] = None
    affected_model_version: Optional[str] = None
    affected_policy_version: Optional[str] = None
    resolution_notes: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(get_current_operator)
):
    """Retrieve all logged security incidents."""
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    res = []
    for inc in incidents:
        res.append(IncidentResponse(
            incident_id=inc.incident_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=inc.status,
            created_at=inc.created_at.isoformat() if inc.created_at else "",
            updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
            resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
            created_by=inc.created_by,
            assigned_to=inc.assigned_to,
            affected_agent_id=inc.affected_agent_id,
            affected_model_version=inc.affected_model_version,
            affected_policy_version=inc.affected_policy_version,
            resolution_notes=inc.resolution_notes
        ))
    return res


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(get_current_operator)
):
    """Get detail specifications of a single security incident."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return IncidentResponse(
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
        resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
        created_by=inc.created_by,
        assigned_to=inc.assigned_to,
        affected_agent_id=inc.affected_agent_id,
        affected_model_version=inc.affected_model_version,
        affected_policy_version=inc.affected_policy_version,
        resolution_notes=inc.resolution_notes
    )


@router.post("", response_model=IncidentResponse, status_code=201)
def create_incident(
    body: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(get_current_operator)
):
    """Declare a new security operational incident."""
    req_id = request.headers.get("X-Request-ID")
    inc_uuid = str(uuid.uuid4())
    
    inc = Incident(
        incident_id=inc_uuid,
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        created_by=current_operator.username,
        affected_agent_id=body.affected_agent_id,
        affected_model_version=body.affected_model_version,
        affected_policy_version=body.affected_policy_version
    )
    db.add(inc)
    db.commit()

    # Append SecurityEvent
    append_security_event(
        event_type="incident_created",
        severity=body.severity,
        source="operator_api",
        description=f"Incident {inc_uuid} '{body.title}' created by operator '{current_operator.username}'.",
        db=db,
        operator_id=current_operator.username,
        request_id=req_id,
        agent_id=body.affected_agent_id,
        model_version=body.affected_model_version,
        policy_version=body.affected_policy_version,
        incident_id=inc_uuid
    )
    incidents_counter.labels(severity=body.severity, status="open").inc()

    return IncidentResponse(
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
        resolved_at=None,
        created_by=inc.created_by,
        assigned_to=inc.assigned_to,
        affected_agent_id=inc.affected_agent_id,
        affected_model_version=inc.affected_model_version,
        affected_policy_version=inc.affected_policy_version,
        resolution_notes=inc.resolution_notes
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(get_current_operator)
):
    """Modify details, ownership, or status of an incident."""
    req_id = request.headers.get("X-Request-ID")
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    # Authorization Check: only admin can reassign incidents
    if body.assigned_to is not None and current_operator.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Only admin operators can assign incidents."
        )

    # Perform updates
    updates = []
    if body.title is not None:
        inc.title = body.title
        updates.append("title")
    if body.description is not None:
        inc.description = body.description
        updates.append("description")
    if body.severity is not None:
        inc.severity = body.severity
        updates.append(f"severity={body.severity}")
    if body.status is not None:
        inc.status = body.status
        updates.append(f"status={body.status}")
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
        updates.append(f"assigned_to={body.assigned_to}")
    if body.resolution_notes is not None:
        inc.resolution_notes = body.resolution_notes
        updates.append("resolution_notes")

    if updates:
        inc.updated_at = datetime.utcnow()
        db.commit()

        # Log change
        append_security_event(
            event_type="incident_updated",
            severity=inc.severity,
            source="operator_api",
            description=f"Incident {incident_id} updated by operator '{current_operator.username}': Changes ({', '.join(updates)}).",
            db=db,
            operator_id=current_operator.username,
            request_id=req_id,
            incident_id=incident_id
        )
        incidents_counter.labels(severity=inc.severity, status=inc.status).inc()

    return IncidentResponse(
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
        resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
        created_by=inc.created_by,
        assigned_to=inc.assigned_to,
        affected_agent_id=inc.affected_agent_id,
        affected_model_version=inc.affected_model_version,
        affected_policy_version=inc.affected_policy_version,
        resolution_notes=inc.resolution_notes
    )


@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
def resolve_incident(
    incident_id: str,
    request: Request,
    notes: dict = None,
    db: Session = Depends(get_db),
    current_operator: Operator = Depends(get_current_operator)
):
    """Transition an incident state to resolved."""
    req_id = request.headers.get("X-Request-ID")
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    res_notes = notes.get("resolution_notes", "") if notes else ""

    inc.status = "resolved"
    inc.resolved_at = datetime.utcnow()
    inc.updated_at = datetime.utcnow()
    inc.resolution_notes = res_notes
    db.commit()

    # Track resolution time duration metric
    resolution_time = (inc.resolved_at - inc.created_at).total_seconds()
    incident_resolution_seconds.observe(resolution_time)

    # Log change
    append_security_event(
        event_type="incident_resolved",
        severity=inc.severity,
        source="operator_api",
        description=f"Incident {incident_id} marked RESOLVED by operator '{current_operator.username}'.",
        db=db,
        operator_id=current_operator.username,
        request_id=req_id,
        incident_id=incident_id
    )
    incidents_counter.labels(severity=inc.severity, status="resolved").inc()

    return IncidentResponse(
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
        resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
        created_by=inc.created_by,
        assigned_to=inc.assigned_to,
        affected_agent_id=inc.affected_agent_id,
        affected_model_version=inc.affected_model_version,
        affected_policy_version=inc.affected_policy_version,
        resolution_notes=inc.resolution_notes
    )
