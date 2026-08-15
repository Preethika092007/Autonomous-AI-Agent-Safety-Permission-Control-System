import json
import hashlib
import logging
import threading
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text, event
from app.models import SecurityEvent
from app.core.database import get_db

logger = logging.getLogger("aura.audit_chain")

_chain_lock = threading.Lock()


def generate_canonical_payload(event: SecurityEvent) -> dict:
    """Generate a deterministic dict payload of the security event, omitting metadata/hashes."""
    ts_str = ""
    if event.timestamp:
        if isinstance(event.timestamp, datetime):
            ts_str = event.timestamp.isoformat()
        else:
            ts_str = str(event.timestamp)
            
    return {
        "event_id": str(event.event_id) if event.event_id else "",
        "timestamp": ts_str,
        "event_type": str(event.event_type) if event.event_type else "",
        "severity": str(event.severity) if event.severity else "",
        "source": str(event.source) if event.source else "",
        "agent_id": str(event.agent_id) if event.agent_id else None,
        "operator_id": str(event.operator_id) if event.operator_id else None,
        "request_id": str(event.request_id) if event.request_id else None,
        "action_log_id": str(event.action_log_id) if event.action_log_id else None,
        "model_version": str(event.model_version) if event.model_version else None,
        "policy_version": str(event.policy_version) if event.policy_version else None,
        "incident_id": str(event.incident_id) if event.incident_id else None,
        "description": str(event.description) if event.description else "",
        "metadata_json": event.metadata_json if event.metadata_json is not None else None
    }


def compute_event_hash(canonical_payload: dict, previous_hash: str) -> str:
    """Compute the SHA-256 hash of the canonical payload concatenated with the previous hash."""
    payload_str = json.dumps(canonical_payload, sort_keys=True)
    combined = payload_str + previous_hash
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


@event.listens_for(SecurityEvent, 'before_insert')
def before_insert_security_event(mapper, connection, target: SecurityEvent):
    """SQLAlchemy hook to automatically hash and chain all SecurityEvent insertions."""
    with _chain_lock:
        if not target.timestamp:
            target.timestamp = datetime.utcnow()
        if not target.event_id:
            target.event_id = str(uuid.uuid4())
        if not target.severity:
            target.severity = "info"
        if not target.source:
            target.source = "operator_api" if target.actor_id else "system"
        if not target.operator_id and target.actor_id:
            target.operator_id = target.actor_id
        if not target.description:
            target.description = target.details or f"Event: {target.event_type} - {target.status or ''}"

        # If event_hash is not yet computed, compute it now
        if not target.event_hash:
            try:
                res = connection.execute(text(
                    "SELECT event_hash FROM security_events ORDER BY timestamp DESC, id DESC LIMIT 1"
                )).fetchone()
                previous_hash = res[0] if res else "GENESIS"
            except Exception:
                previous_hash = "GENESIS"

            target.previous_event_hash = previous_hash
            canonical = generate_canonical_payload(target)
            target.event_hash = compute_event_hash(canonical, previous_hash)


def append_security_event(
    event_type: str,
    severity: str,
    source: str,
    description: str,
    db: Session = None,
    agent_id: str = None,
    operator_id: str = None,
    request_id: str = None,
    action_log_id: str = None,
    model_version: str = None,
    policy_version: str = None,
    incident_id: str = None,
    metadata_json: dict = None
) -> SecurityEvent:
    """
    Append a security event to the tamper-evident audit chain safely under a thread lock.
    """
    local_session = False
    if db is None:
        db = next(get_db())
        local_session = True

    try:
        # Instantiate new SecurityEvent. The before_insert listener will automatically
        # handle timestamping, parameter defaults, and cryptographic chaining.
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=source,
            description=description,
            agent_id=agent_id,
            operator_id=operator_id,
            request_id=request_id,
            action_log_id=action_log_id,
            model_version=model_version,
            policy_version=policy_version,
            incident_id=incident_id,
            metadata_json=metadata_json
        )
        db.add(event)
        db.flush()

        if local_session:
            db.commit()
        
        # Expose event metrics
        from app.core.metrics import security_events_counter
        security_events_counter.labels(event_type=event_type, severity=severity).inc()

        return event
    except Exception as e:
        logger.error(f"Failed to append security event to audit chain: {e}")
        if local_session:
            db.rollback()
        raise e
    finally:
        if local_session:
            db.close()


def verify_audit_chain(db: Session) -> dict:
    """
    Verify the integrity of the security audit chain chronologically.
    Returns validation status, count checked, and first corrupt event_id.
    """
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc()).all()
    
    previous_hash = "GENESIS"
    checked_count = 0
    first_invalid_event_id = None
    valid = True

    for event in events:
        checked_count += 1
        canonical = generate_canonical_payload(event)
        computed = compute_event_hash(canonical, event.previous_event_hash)

        # Check 1: Computed hash matches stored event_hash
        if computed != event.event_hash:
            valid = False
            first_invalid_event_id = event.event_id
            logger.error(f"Audit chain verification failed: Hash mismatch on event {event.event_id}")
            break

        # Check 2: Stored previous_hash matches running previous_hash
        if event.previous_event_hash != previous_hash:
            valid = False
            first_invalid_event_id = event.event_id
            logger.error(f"Audit chain verification failed: Chain break on event {event.event_id}")
            break

        previous_hash = event.event_hash

    # Track Prometheus results
    from app.core.metrics import audit_chain_verifications_counter, audit_chain_corruption_gauge
    result_lbl = "valid" if valid else "invalid"
    audit_chain_verifications_counter.labels(result=result_lbl).inc()
    audit_chain_corruption_gauge.set(0 if valid else 1)

    return {
        "valid": valid,
        "events_checked": checked_count,
        "first_invalid_event_id": first_invalid_event_id,
        "verified_at": datetime.utcnow().isoformat()
    }
