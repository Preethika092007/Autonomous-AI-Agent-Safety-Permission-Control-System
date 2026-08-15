import sys
import os
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Path & env bootstrap
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
os.environ["DATABASE_URL"] = "sqlite:///./test_sec_ops.db"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["AUTH_ENABLED"] = "true"

if os.path.exists("./test_sec_ops.db"):
    try:
        os.remove("./test_sec_ops.db")
    except Exception:
        pass

# Import modules first to ensure they are registered in sys.modules
import app.core.auth
import app.api.v1.operator
import app.api.v1.endpoints
import app.core.websockets
import app.api.v1.sec_ops
import app.api.v1.models_gov

# Mock Redis globally
mock_redis = MagicMock()
mock_redis.get.return_value = None
mock_redis.incr.return_value = 1
mock_redis.ping.return_value = True

patchers = []

from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal, engine, Base, get_db
from app.core.config import settings
from app.models import Agent, ActionLog, Operator, AgentCredential, SecurityEvent, Incident, ModelRegistry, SystemSettings
from app.core.auth import generate_api_key, create_access_token
from app.core.audit_chain import append_security_event, verify_audit_chain

client = TestClient(app)


def setup_module():
    # Start mocks cleanly
    p1 = patch("app.core.auth.get_redis", return_value=mock_redis)
    p2 = patch("app.api.v1.operator.get_redis", return_value=mock_redis)
    p3 = patch("app.api.v1.endpoints.get_redis", return_value=mock_redis)
    p4 = patch("app.core.websockets.get_redis", return_value=mock_redis)
    p5 = patch("redis.from_url", return_value=mock_redis)
    p6 = patch("app.api.v1.models_gov.get_redis", return_value=mock_redis)
    patchers.extend([p1, p2, p3, p4, p5, p6])
    for p in patchers:
        p.start()

    settings.AUTH_ENABLED = True
    settings.RATE_LIMIT_ENABLED = False
    # Reset DB tables completely to prevent database contamination
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with next(get_db()) as db:
        import bcrypt
        
        # 1. Create admin operator
        hashed_pwd = bcrypt.hashpw(b"adminpwd123", bcrypt.gensalt(rounds=4)).decode()
        admin = Operator(username="admin_secops", password_hash=hashed_pwd, role="admin")
        db.add(admin)
        
        # 2. Create reviewer operator
        reviewer = Operator(username="reviewer_secops", password_hash=hashed_pwd, role="reviewer")
        db.add(reviewer)

        # Use real active model paths
        real_ubj = "app/ml/registry/aura-risk-model_1.0.0.ubj"
        
        import hashlib
        def get_sha255(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                h.update(f.read())
            return h.hexdigest()

        real_sha = get_sha255(real_ubj)

        # 3. Create dummy active model pointing to real booster
        active_model = ModelRegistry(
            model_version="v2026-active",
            feature_schema_version=1,
            dataset_version="ds-1",
            artifact_path=real_ubj,
            sha256=real_sha,
            status="active",
            metrics_json={}
        )
        db.add(active_model)
        
        # 4. Create dummy candidate model pointing to real booster
        candidate_model = ModelRegistry(
            model_version="v2026-candidate",
            feature_schema_version=1,
            dataset_version="ds-1",
            artifact_path=real_ubj,
            sha256=real_sha,
            status="candidate",
            metrics_json={}
        )
        db.add(candidate_model)

        db.commit()


def teardown_module():
    for p in patchers:
        try:
            p.stop()
        except Exception:
            pass
    if os.path.exists("./test_sec_ops.db"):
        try:
            os.remove("./test_sec_ops.db")
        except Exception:
            pass


@pytest.fixture
def admin_headers():
    token = create_access_token({"sub": "admin_secops"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def reviewer_headers():
    token = create_access_token({"sub": "reviewer_secops"})
    return {"Authorization": f"Bearer {token}"}


def test_unauthorized_endpoints():
    """Verify non-admin operators receive 403 or 401 on restricted endpoints."""
    # Status requires authentication
    r = client.get("/api/v1/security/status")
    assert r.status_code == 401

    # Lockdown requires admin
    token = create_access_token({"sub": "reviewer_secops"})
    rev_headers = {"Authorization": f"Bearer {token}"}
    
    r = client.post("/api/v1/security/lockdown", headers=rev_headers)
    assert r.status_code == 403

    r = client.post("/api/v1/security/unlock", headers=rev_headers)
    assert r.status_code == 403


def test_lockdown_and_evaluate_block(admin_headers):
    """Test triggering global lockdown and verify evaluate-action fails closed."""
    # Register agent
    r = client.post(
        "/api/v1/agents/register",
        json={"agent_id": "test-agent-lockdown", "name": "Test Agent", "role": "DeveloperAgent"},
        headers=admin_headers
    )
    assert r.status_code == 201
    agent_key = r.json()["api_key"]

    # Trigger lockdown
    r = client.post("/api/v1/security/lockdown", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "locked_down"

    # Status check
    r = client.get("/api/v1/security/status", headers=admin_headers)
    assert r.json()["lockdown_enabled"] is True

    # Try evaluate action while locked down
    payload = {
        "agent_id": "test-agent-lockdown",
        "action": "read_file",
        "parameters": {"file": "logs.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    r = client.post(
        "/api/v1/evaluate-action",
        json=payload,
        headers={"X-Agent-Key": agent_key}
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "block"
    assert "lockdown" in r.json()["reason"]

    # Release lockdown
    r = client.post("/api/v1/security/unlock", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "normal"

    # Try evaluate action again
    r = client.post(
        "/api/v1/evaluate-action",
        json=payload,
        headers={"X-Agent-Key": agent_key}
    )
    assert r.status_code == 200
    assert r.json()["decision"] in ["allow", "require_human_approval"]


def test_incidents_workflow(admin_headers, reviewer_headers):
    """Verify incidents CRUD, access role checks, and resolution."""
    # 1. List initially empty
    r = client.get("/api/v1/incidents", headers=reviewer_headers)
    assert r.status_code == 200
    initial_count = len(r.json())

    # 2. Create Incident
    payload = {
        "title": "Anomaly in SentenceTransformer embeddings",
        "description": "Risk values spiked unusually from dev-agent cluster.",
        "severity": "high",
        "affected_agent_id": "test-agent-lockdown"
    }
    r = client.post("/api/v1/incidents", json=payload, headers=reviewer_headers)
    assert r.status_code == 201
    inc = r.json()
    assert inc["title"] == payload["title"]
    assert inc["status"] == "open"
    inc_id = inc["incident_id"]

    # 3. List contains the new incident
    r = client.get("/api/v1/incidents", headers=reviewer_headers)
    assert len(r.json()) == initial_count + 1

    # 4. Reviewer tries to assign (Forbidden)
    r = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"assigned_to": "admin_secops"},
        headers=reviewer_headers
    )
    assert r.status_code == 403

    # 5. Admin assigns incident (Success)
    r = client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"assigned_to": "reviewer_secops", "severity": "critical"},
        headers=admin_headers
    )
    assert r.status_code == 200
    assert r.json()["assigned_to"] == "reviewer_secops"
    assert r.json()["severity"] == "critical"

    # 6. Resolve Incident
    r = client.post(
        f"/api/v1/incidents/{inc_id}/resolve",
        json={"resolution_notes": "Recalibrated SentenceTransformer dimensions. Issue contained."},
        headers=reviewer_headers
    )
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert "Recalibrated" in r.json()["resolution_notes"]


def test_agent_quarantine(admin_headers):
    """Test quarantining an agent, key revocation, and evaluate blocking."""
    # Register a new agent
    r = client.post(
        "/api/v1/agents/register",
        json={"agent_id": "suspect-agent-007", "name": "Agent 007", "role": "OperationsAgent"},
        headers=admin_headers
    )
    assert r.status_code == 201
    agent_key = r.json()["api_key"]

    # Create dummy incident
    r = client.post(
        "/api/v1/incidents",
        json={"title": "quarantine incident", "description": "quarantine link", "severity": "medium"},
        headers=admin_headers
    )
    inc_id = r.json()["incident_id"]

    # Quarantine agent
    r = client.post(
        f"/api/v1/agents/suspect-agent-007/quarantine",
        json={"incident_id": inc_id},
        headers=admin_headers
    )
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    # Try evaluate action with quarantined key
    payload = {
        "agent_id": "suspect-agent-007",
        "action": "write_file",
        "parameters": {"file": "malicious.sh", "content": "rm -rf /"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    r = client.post(
        "/api/v1/evaluate-action",
        json=payload,
        headers={"X-Agent-Key": agent_key}
    )
    # Check that quarantine blocked it
    assert r.status_code == 401
    assert "invalid api key" in r.json()["detail"].lower()


def test_audit_integrity_and_tampering(admin_headers):
    """Test audit chain verification and verify failure on record modification."""
    # 1. Clean verify
    r = client.get("/api/v1/security/audit/verify", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["valid"] is True

    # 2. Tamper with the database records directly
    db = SessionLocal()
    try:
        last_event = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).first()
        assert last_event is not None
        # Modify description to break the hash signature
        last_event.description = "TAMPERED VALUE"
        db.commit()
    finally:
        db.close()

    # 3. Verify should return HTTP 409 Conflict
    r = client.get("/api/v1/security/audit/verify", headers=admin_headers)
    assert r.status_code == 409
    assert r.json()["detail"]["report"]["valid"] is False


def test_audit_export(admin_headers):
    """Verify audit log compliance export pagination and sorting."""
    r = client.get(
        "/api/v1/security/audit/export",
        params={"page": 1, "limit": 10},
        headers=admin_headers
    )
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert "metadata" in data
    assert len(data["events"]) <= 10
    
    # Chronological sort check (timestamp asc)
    events = data["events"]
    if len(events) > 1:
        t1 = datetime.fromisoformat(events[0]["timestamp"])
        t2 = datetime.fromisoformat(events[1]["timestamp"])
        assert t1 <= t2


def test_emergency_model_retirement(admin_headers):
    """Verify emergency retirement with fallback and lockdown triggers."""
    db = SessionLocal()
    try:
        db.query(ModelRegistry).filter(ModelRegistry.model_version == "1.0.0").delete()
        db.query(ModelRegistry).filter(ModelRegistry.model_version == "v2026-active").update({"status": "active", "feature_schema_version": 1})
        db.query(ModelRegistry).filter(ModelRegistry.model_version == "v2026-candidate").update({"status": "candidate", "feature_schema_version": 1})
        db.commit()
    finally:
        db.close()
    # Call emergency retire. Since v2026-candidate feature_schema_version is 1 and checksum matches, it falls back
    r = client.post("/api/v1/models/emergency-retire", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["active_model"] == "v2026-candidate"
    assert r.json()["status"] == "fallback_activated"

    # Now retire v2026-candidate. Since no other models exist, it should trigger lockdown and return 503
    r = client.post("/api/v1/models/emergency-retire", headers=admin_headers)
    assert r.status_code == 503
    assert "Global lockdown activated" in r.json()["detail"]
    
    # Verify lockdown is indeed enabled in status
    r = client.get("/api/v1/security/status", headers=admin_headers)
    assert r.json()["lockdown_enabled"] is True
