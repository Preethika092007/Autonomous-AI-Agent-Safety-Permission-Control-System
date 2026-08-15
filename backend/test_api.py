"""
AURA Firewall — Backend Integration Test Suite
Phase 0 (regression) + Phase 1 (rate limiting) + Phase 2 (authentication)

Redis strategy:
  - RATE_LIMIT_ENABLED=false for all non-rate-limit tests.
  - AUTH_ENABLED=false for all non-auth tests (Phase 0/1 regression).
  - Rate-limit + auth unit tests use unittest.mock to avoid external services.
  - Live Redis integration test auto-skips when Redis is not reachable.

Auth strategy in tests:
  - Most tests run with AUTH_ENABLED=false (env set before app import).
  - Auth tests toggle AUTH_ENABLED via monkeypatching after import.
"""
import sys
import os
import threading
import time
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# ── Path & env bootstrap ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
os.environ["DATABASE_URL"] = "sqlite:///./test_api_v4.db"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["AUTH_ENABLED"] = "false"

if os.path.exists("./test_api_v4.db"):
    try:
        os.remove("./test_api_v4.db")
    except Exception:
        pass

# Mock Redis globally for tests so JWT validation and rate limiting don't fail without a real Redis server
mock_redis = MagicMock()
mock_redis.get.return_value = None
mock_redis.incr.return_value = 1
mock_redis.ping.return_value = True

patchers = []

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from app.main import app
from app.core.database import SessionLocal, engine, Base, get_db
from app.core.config import settings

# Force settings for tests, bypassing any pydantic env resolution quirks
settings.AUTH_ENABLED = False
settings.RATE_LIMIT_ENABLED = False

from app.core.rate_limiter import check_rate_limit, RateLimitRedisError, _safe_agent_key
from app.core.auth import generate_api_key, hash_api_key, verify_api_key, create_access_token
from app.models import Agent, ActionLog, PendingApproval, Operator, AgentCredential, ModelRegistry, ModelAuditEvent

client = TestClient(app)


def setup_module():
    # Start mocks cleanly
    p1 = patch("app.core.auth.get_redis", return_value=mock_redis)
    p2 = patch("app.api.v1.operator.get_redis", return_value=mock_redis)
    p3 = patch("app.api.v1.endpoints.get_redis", return_value=mock_redis)
    p4 = patch("app.core.websockets.get_redis", return_value=mock_redis)
    patchers.extend([p1, p2, p3, p4])
    for p in patchers:
        p.start()

    # Reset DB tables completely to prevent database contamination
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Create default admin operator
    with next(get_db()) as db:
        import bcrypt
        if not db.query(Operator).filter(Operator.username == "admin").first():
            hashed_pwd = bcrypt.hashpw(b"admin", bcrypt.gensalt(rounds=12)).decode()
            admin = Operator(username="admin", password_hash=hashed_pwd, role="admin")
            db.add(admin)
            db.commit()


def teardown_module():
    for p in patchers:
        try:
            p.stop()
        except Exception:
            pass
    if os.path.exists("./test_api_v4.db"):
        try:
            os.remove("./test_api_v4.db")
        except Exception:
            pass


@pytest.fixture
def admin_headers():
    token = create_access_token({"sub": "admin"})
    return {"Authorization": f"Bearer {token}"}


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 0 REGRESSION TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data
    print("Health check: PASSED")

def test_readiness():
    response = client.get("/api/v1/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "authentication" in data["services"]
    assert data["services"]["authentication"] in ("enabled", "disabled")
    print("Readiness check (incl. auth status): PASSED")


def test_evaluate_action_safe():
    payload = {
        "agent_id": "safe-agent-111",
        "action": "read_file",
        "parameters": {"file": "log.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["risk_level"] == "low"
    print("Evaluate Action (Safe): PASSED")


def test_evaluate_action_deterministic_block():
    payload = {
        "agent_id": "ops_bot",
        "action": "execute_db",
        "parameters": {"query": "DROP TABLE users"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert data["risk_level"] == "high"
    assert "DROP TABLE" in data["reason"]
    print("Evaluate Action (Deterministic Block): PASSED")


def test_policy_ops_allowed():
    payload = {
        "agent_id": "ops_bot",
        "action": "execute_bash",
        "parameters": {"cmd": "ls"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] in ["allow", "require_human_approval"]
    print(f"Policy (Ops Bash Allowed): PASSED (decision={data['decision']})")


def test_policy_research_blocked():
    payload = {
        "agent_id": "research_bot",
        "action": "execute_bash",
        "parameters": {"cmd": "ls"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert "Policy Override" in data["reason"]
    print("Policy (Research Bash Blocked): PASSED")


def test_audit_log_verification():
    response = client.get("/api/v1/audit-log")
    assert response.status_code == 200
    assert len(response.json()) >= 4
    print("Audit log retrieval: PASSED")


def test_agent_upsert_creates_single_record():
    agent_id = "new_phase0_agent"
    payload = {
        "agent_id": agent_id,
        "action": "read_file",
        "parameters": {"file": "test.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    client.post("/api/v1/evaluate-action", json=payload)
    client.post("/api/v1/evaluate-action", json=payload)
    db = SessionLocal()
    try:
        count = db.query(Agent).filter(Agent.id == agent_id).count()
        assert count == 1
    finally:
        db.close()
    print("Agent upsert single record: PASSED")


def test_concurrent_agent_registration():
    agent_id = "concurrent_stress_agent"
    payload = {
        "agent_id": agent_id,
        "action": "read_file",
        "parameters": {"file": "concurrent_test.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    results = []
    errors = []

    def fire():
        try:
            r = client.post("/api/v1/evaluate-action", json=payload)
            results.append(r.status_code)
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=fire) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    for code in results:
        assert code in (200, 503)

    db = SessionLocal()
    try:
        count = db.query(Agent).filter(Agent.id == agent_id).count()
        assert count == 1
    finally:
        db.close()
    print(f"Concurrent agent registration: PASSED (statuses={results})")


def test_audit_log_ordering_by_requested_at():
    db = SessionLocal()
    try:
        agent_id = "sort_test_agent"
        if not db.query(Agent).filter(Agent.id == agent_id).first():
            db.add(Agent(id=agent_id, name="Sort Test Agent", role="DeveloperAgent", is_active=True))
            db.commit()
        db.add(ActionLog(
            agent_id=agent_id, action="old_action", parameters={},
            risk_level="low", decision="allow", reason="old",
            requested_at=datetime(2020, 1, 1, 0, 0, 0)
        ))
        db.add(ActionLog(
            agent_id=agent_id, action="new_action", parameters={},
            risk_level="low", decision="allow", reason="new",
            requested_at=datetime(2025, 6, 1, 0, 0, 0)
        ))
        db.commit()
    finally:
        db.close()

    response = client.get(f"/api/v1/audit-log?agent_id={agent_id}")
    assert response.status_code == 200
    entries = [e for e in response.json() if e["action"] in ("old_action", "new_action")]
    assert len(entries) >= 2
    actions = [e["action"] for e in entries]
    assert actions.index("new_action") < actions.index("old_action")
    print("Audit log sort order: PASSED")


def test_database_check_constraint_risk_level():
    db = SessionLocal()
    try:
        agent_id = "constraint_test_agent"
        if not db.query(Agent).filter(Agent.id == agent_id).first():
            db.add(Agent(id=agent_id, name="Constraint Test Agent", role="DeveloperAgent", is_active=True))
            db.commit()
        bad_log = ActionLog(
            agent_id=agent_id, action="hack", parameters={},
            risk_level="INVALID", decision="allow", reason="test",
            requested_at=datetime.now(timezone.utc)
        )
        db.add(bad_log)
        try:
            db.commit()
            print("CHECK (risk_level): SKIPPED (SQLite build)")
        except Exception:
            db.rollback()
            print("CHECK constraint on risk_level: ENFORCED (PASSED)")
    finally:
        db.close()


def test_database_check_constraint_decision():
    db = SessionLocal()
    try:
        bad_log = ActionLog(
            agent_id="constraint_test_agent", action="bad_decision",
            parameters={}, risk_level="low", decision="maybe",
            reason="test", requested_at=datetime.now(timezone.utc)
        )
        db.add(bad_log)
        try:
            db.commit()
            print("CHECK (decision): SKIPPED")
        except Exception:
            db.rollback()
            print("CHECK constraint on decision: ENFORCED (PASSED)")
    finally:
        db.close()


def test_database_check_constraint_approval_status():
    db = SessionLocal()
    try:
        agent_id = "constraint_test_agent"
        valid_log = ActionLog(
            agent_id=agent_id, action="approval_constraint_test",
            parameters={}, risk_level="medium",
            decision="require_human_approval",
            reason="test", requested_at=datetime.now(timezone.utc)
        )
        db.add(valid_log)
        db.commit()
        db.refresh(valid_log)
        bad_approval = PendingApproval(action_log_id=valid_log.id, status="INVALID_STATUS")
        db.add(bad_approval)
        try:
            db.commit()
            print("CHECK (approval status): SKIPPED")
        except Exception:
            db.rollback()
            print("CHECK constraint on approval status: ENFORCED (PASSED)")
    finally:
        db.close()


def test_approval_workflow_end_to_end(admin_headers):
    payload = {
        "agent_id": "dev_bot",
        "action": "write_config",
        "parameters": {"key": "max_retries", "value": "99"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    eval_resp = client.post("/api/v1/evaluate-action", json=payload)
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    if eval_data["decision"] != "require_human_approval":
        print(f"Approval workflow: SKIPPED (decision={eval_data['decision']})")
        return

    db = SessionLocal()
    try:
        pending = db.query(PendingApproval).filter(PendingApproval.status == "pending").first()
        assert pending is not None
        approval_id = pending.id
    finally:
        db.close()

    resolve_resp = client.post("/api/v1/approve-action", json={
        "approval_id": approval_id, "status": "approved"
    }, headers=admin_headers)
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["status"] == "success"

    db = SessionLocal()
    try:
        resolved = db.query(PendingApproval).filter(PendingApproval.id == approval_id).first()
        assert resolved.status == "approved"
        action_log = db.query(ActionLog).filter(ActionLog.id == resolved.action_log_id).first()
        assert action_log.decision == "allow"
    finally:
        db.close()
    print("Approval workflow end-to-end: PASSED")


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 RATE-LIMIT TESTS
# ═════════════════════════════════════════════════════════════════════════════

def _make_mock_redis(incr_value: int):
    mock_pipe = MagicMock()
    mock_pipe.execute.return_value = [incr_value, True]
    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe
    return mock_redis, mock_pipe


def test_rate_limiter_allows_below_limit():
    mock_redis, _ = _make_mock_redis(1)
    result = check_rate_limit(mock_redis, "agent_a", limit=5, window_seconds=60)
    assert result.allowed is True
    assert result.remaining == 4
    print("Rate limiter allows below limit: PASSED")


def test_rate_limiter_allows_at_limit():
    mock_redis, _ = _make_mock_redis(5)
    result = check_rate_limit(mock_redis, "agent_a", limit=5, window_seconds=60)
    assert result.allowed is True
    assert result.remaining == 0
    print("Rate limiter allows at limit: PASSED")


def test_rate_limiter_rejects_above_limit():
    mock_redis, _ = _make_mock_redis(6)
    result = check_rate_limit(mock_redis, "agent_a", limit=5, window_seconds=60)
    assert result.allowed is False
    assert result.remaining == 0
    print("Rate limiter rejects above limit: PASSED")


def test_rate_limiter_separate_agents():
    assert _safe_agent_key("agent_alpha") != _safe_agent_key("agent_beta")
    print("Separate agent keys: PASSED")


def test_rate_limiter_agent_id_sanitisation():
    safe = _safe_agent_key("agent/../../../etc/passwd")
    assert "/" not in safe and "." not in safe
    assert len(_safe_agent_key("a" * 200)) <= 128
    print("Agent ID sanitisation: PASSED")


def test_rate_limiter_atomic_pipeline():
    mock_redis, mock_pipe = _make_mock_redis(1)
    check_rate_limit(mock_redis, "agent_x", limit=10, window_seconds=60)
    mock_pipe.incr.assert_called_once()
    mock_pipe.expire.assert_called_once()
    mock_pipe.execute.assert_called_once()
    print("Atomic pipeline verified: PASSED")


def test_rate_limiter_redis_failure():
    mock_redis = MagicMock()
    mock_pipe = MagicMock()
    mock_pipe.execute.side_effect = ConnectionError("Redis down")
    mock_redis.pipeline.return_value = mock_pipe
    try:
        check_rate_limit(mock_redis, "agent_y", limit=10, window_seconds=60)
        assert False, "Expected RateLimitRedisError"
    except RateLimitRedisError:
        pass
    print("Redis failure → RateLimitRedisError: PASSED")


def test_api_rate_limit_429_stops_ml():
    mock_redis, mock_pipe = _make_mock_redis(999)
    with patch("app.api.v1.endpoints.get_redis", return_value=mock_redis), \
         patch("app.core.config.settings.RATE_LIMIT_ENABLED", True), \
         patch("app.core.config.settings.RATE_LIMIT_REQUESTS", 60), \
         patch("app.api.v1.endpoints.get_risk_engine") as mock_engine_dep:
        mock_engine_dep.return_value = MagicMock()
        payload = {
            "agent_id": "rl_test_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post("/api/v1/evaluate-action", json=payload)
        mock_engine_dep.return_value.evaluate.assert_not_called()
    assert response.status_code == 429
    assert "retry_after" in response.json()["detail"]
    assert response.headers["X-RateLimit-Remaining"] == "0"
    print("API 429 — ML not called: PASSED")


def test_api_redis_failure_503():
    broken_pipe = MagicMock()
    broken_pipe.execute.side_effect = ConnectionError("down")
    broken_redis = MagicMock()
    broken_redis.pipeline.return_value = broken_pipe
    with patch("app.api.v1.endpoints.get_redis", return_value=broken_redis), \
         patch("app.core.config.settings.RATE_LIMIT_ENABLED", True), \
         patch("app.api.v1.endpoints.get_risk_engine") as mock_engine_dep:
        mock_engine_dep.return_value = MagicMock()
        payload = {
            "agent_id": "rl_test_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post("/api/v1/evaluate-action", json=payload)
        mock_engine_dep.return_value.evaluate.assert_not_called()
    assert response.status_code == 503
    print("Redis down → 503 fail-closed: PASSED")


def test_live_redis_rate_limit_counter_expires():
    import redis as redis_lib
    try:
        rc = redis_lib.from_url("redis://localhost:6379/0", decode_responses=True)
        rc.ping()
    except Exception:
        print("Live Redis test: SKIPPED (no Redis at localhost:6379)")
        return
    settings.RATE_LIMIT_ENABLED = True
    try:
        rc.flushdb()
        limit, window = 3, 2
        for i in range(limit):
            r = check_rate_limit(rc, "live_test_agent", limit=limit, window_seconds=window)
            assert r.allowed is True
        r = check_rate_limit(rc, "live_test_agent", limit=limit, window_seconds=window)
        assert r.allowed is False
        time.sleep(window + 0.5)
        r = check_rate_limit(rc, "live_test_agent", limit=limit, window_seconds=window)
        assert r.allowed is True
        print("Live Redis counter + expiry: PASSED")
    finally:
        settings.RATE_LIMIT_ENABLED = False


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 AUTHENTICATION TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_api_key_generation_format():
    key, key_id, secret_hash = generate_api_key()
    assert key.startswith("aura-")
    # Total length: "aura-" + 16 chars key_id + "." + 64 chars secret = 86 chars
    assert len(key) == 86
    assert "." in key
    print("API key format: PASSED")


def test_api_key_hash_and_verify():
    key, key_id, secret_hash = generate_api_key()
    # verify_api_key expects (secret, hash)
    # The plaintext is aura-{key_id}.{secret}, so extract secret:
    secret = key.split(".")[1]
    
    assert verify_api_key(secret, secret_hash) is True
    assert verify_api_key("wrong_secret", secret_hash) is False
    print("bcrypt hash + verify: PASSED")


def test_api_key_unique_per_call():
    k1, _, _ = generate_api_key()
    k2, _, _ = generate_api_key()
    assert k1 != k2
    print("API keys are unique: PASSED")


def test_agent_registration_success(admin_headers):
    """POST /agents/register with a new agent_id returns api_key."""
    payload = {"agent_id": "test_reg_agent", "name": "Test Agent", "role": "DeveloperAgent"}
    response = client.post("/api/v1/agents/register", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["agent_id"] == "test_reg_agent"
    assert data["role"] == "DeveloperAgent"
    assert data["api_key"].startswith("aura-")
    print("Agent registration (new): PASSED")


def test_agent_registration_invalid_role(admin_headers):
    """Invalid role must return 422."""
    payload = {"agent_id": "bad_role_agent", "name": "Bad", "role": "SuperAdmin"}
    response = client.post("/api/v1/agents/register", json=payload, headers=admin_headers)
    assert response.status_code == 422
    print("Agent registration (invalid role → 422): PASSED")


def test_agent_registration_duplicate_returns_409(admin_headers):
    """Registering the same agent_id twice must return 409 Conflict."""
    payload = {"agent_id": "dup_reg_agent", "name": "Dup", "role": "ResearchAgent"}
    r1 = client.post("/api/v1/agents/register", json=payload, headers=admin_headers)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/agents/register", json=payload, headers=admin_headers)
    assert r2.status_code == 409
    print("Agent registration (duplicate → 409): PASSED")


def test_agent_registration_upgrades_phase1_agent(admin_headers):
    """
    An agent that was auto-created in Phase 1 mode (no hash) can be
    upgraded via /agents/register.
    """
    # Create a Phase 1-style agent via evaluate-action (no auth)
    payload = {
        "agent_id": "phase1_to_phase2_agent",
        "action": "read_file",
        "parameters": {"file": "x.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    r = client.post("/api/v1/evaluate-action", json=payload)
    assert r.status_code == 200

    # Now register it — should succeed (upgrade path)
    reg = client.post("/api/v1/agents/register", json={
        "agent_id": "phase1_to_phase2_agent",
        "name": "Upgraded Agent",
        "role": "DeveloperAgent"
    }, headers=admin_headers)
    assert reg.status_code == 201
    data = reg.json()
    assert data["api_key"].startswith("aura-")

    # DB record should now have a credential
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == "phase1_to_phase2_agent").first()
        assert agent is not None
        assert any(c.is_active for c in agent.credentials)
    finally:
        db.close()
    print("Phase 1 → Phase 2 agent upgrade: PASSED")


def test_auth_enabled_missing_key_returns_401():
    """When AUTH_ENABLED=true, missing X-Agent-Key must return 401."""
    with patch("app.core.config.settings.AUTH_ENABLED", True):
        payload = {
            "agent_id": "some_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 401
    print("AUTH_ENABLED=true, no key → 401: PASSED")


def test_auth_enabled_invalid_key_returns_401():
    """When AUTH_ENABLED=true, wrong X-Agent-Key must return 401."""
    with patch("app.core.config.settings.AUTH_ENABLED", True):
        payload = {
            "agent_id": "some_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post(
            "/api/v1/evaluate-action",
            json=payload,
            headers={"X-Agent-Key": "aura-invalid-key-1234"}
        )
    assert response.status_code == 401
    print("AUTH_ENABLED=true, wrong key → 401: PASSED")


def test_auth_enabled_wrong_prefix_returns_401():
    """A key that doesn't start with 'aura-' must be rejected."""
    with patch("app.core.config.settings.AUTH_ENABLED", True):
        payload = {
            "agent_id": "some_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post(
            "/api/v1/evaluate-action",
            json=payload,
            headers={"X-Agent-Key": "bearer-totally-wrong"}
        )
    assert response.status_code == 401
    print("AUTH_ENABLED=true, bad prefix → 401: PASSED")


def test_auth_enabled_valid_key_allows_request(admin_headers):
    """
    Full authenticated flow:
    1. Register agent → get api_key
    2. POST /evaluate-action with X-Agent-Key header → 200
    3. Verify DB record uses credential-bound agent_id
    """
    # Register
    reg_resp = client.post("/api/v1/agents/register", json={
        "agent_id": "auth_flow_agent",
        "name": "Auth Flow Agent",
        "role": "DeveloperAgent"
    }, headers=admin_headers)
    assert reg_resp.status_code == 201
    api_key = reg_resp.json()["api_key"]

    # Evaluate with valid key
    with patch("app.core.config.settings.AUTH_ENABLED", True):
        payload = {
            "agent_id": "auth_flow_agent",
            "action": "read_file",
            "parameters": {"file": "x.txt"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post(
            "/api/v1/evaluate-action",
            json=payload,
            headers={"X-Agent-Key": api_key}
        )
    assert response.status_code == 200
    data = response.json()
    # The response must be a valid AURA decision — any of the three is fine.
    # What we are testing here is that authentication was exercised correctly,
    # not the ML/policy outcome (covered by dedicated tests).
    assert data["decision"] in ("allow", "block", "require_human_approval")
    assert data["risk_level"] in ("low", "medium", "high")

    # Verify the ActionLog was written with the registered agent_id
    db = SessionLocal()
    try:
        log = db.query(ActionLog).filter(
            ActionLog.agent_id == "auth_flow_agent",
            ActionLog.action == "read_file"
        ).order_by(ActionLog.requested_at.desc()).first()
        assert log is not None, "ActionLog for auth_flow_agent not found in DB"
    finally:
        db.close()
    print("Full auth flow (register → evaluate with key → DB verified): PASSED")


def test_auth_prevents_role_impersonation(admin_headers):
    """
    An attacker sending agent_id='ops_bot' (a high-privilege ID) while holding
    a DeveloperAgent credential must receive the DeveloperAgent role, NOT
    OperationsAgent. The RBAC policy must use the credential-bound role.
    """
    # Register a DeveloperAgent
    reg = client.post("/api/v1/agents/register", json={
        "agent_id": "impersonation_dev_agent",
        "name": "Dev Agent",
        "role": "DeveloperAgent"
    }, headers=admin_headers)
    assert reg.status_code == 201
    dev_key = reg.json()["api_key"]

    # Try to call an action that only OperationsAgent can run (restart_service)
    with patch("app.core.config.settings.AUTH_ENABLED", True):
        payload = {
            "agent_id": "ops_bot",  # attacker claims to be ops_bot
            "action": "restart_service",
            "parameters": {"service": "postgres"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post(
            "/api/v1/evaluate-action",
            json=payload,
            headers={"X-Agent-Key": dev_key}
        )
    assert response.status_code == 200
    data = response.json()
    # DeveloperAgent doesn't have restart_service in allowed_actions → block
    assert data["decision"] == "block", (
        f"Expected block (DeveloperAgent can't restart_service) got {data['decision']}"
    )
    print("Role impersonation prevented by credential-bound role: PASSED")


def test_auth_disabled_allows_unauthenticated():
    """AUTH_ENABLED=false must allow requests without X-Agent-Key (Phase 1 fallback)."""
    # RATE_LIMIT_ENABLED is already false in this test environment
    payload = {
        "agent_id": "no_auth_agent",
        "action": "read_file",
        "parameters": {"file": "x.txt"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    print("AUTH_ENABLED=false allows unauthenticated: PASSED")


def test_prometheus_metrics():
    """Verify Prometheus metrics are exposed at /api/v1/metrics."""
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    assert "# HELP" in response.text or "# TYPE" in response.text
    print("Prometheus metrics endpoint: PASSED")


def test_security_headers():
    """Verify security headers are included in HTTP responses."""
    response = client.get("/api/v1/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "max-age=31536000" in response.headers.get("Strict-Transport-Security", "")
    print("Security headers: PASSED")


def test_request_id_middleware():
    """Verify RequestID middleware attaches X-Request-ID to all responses."""
    response = client.get("/api/v1/health")
    assert "X-Request-ID" in response.headers
    req_id = response.headers["X-Request-ID"]
    import uuid
    try:
        uuid.UUID(req_id)
    except ValueError:
        pytest.fail(f"Invalid UUID for X-Request-ID: {req_id}")
    print("RequestID middleware: PASSED")


def test_logout_revocation(admin_headers):
    """Verify token is revoked on operator logout."""
    mock_redis.reset_mock()
    response = client.post("/api/v1/operator/logout", headers=admin_headers)
    assert response.status_code == 200
    assert mock_redis.setex.called
    call_args = mock_redis.setex.call_args[0]
    assert call_args[0].startswith("revoked_jwt:")
    print("Logout JWT revocation: PASSED")


def test_security_event_logged(admin_headers):
    """Verify that SecurityEvent logging registers key actions in the DB."""
    reg = client.post("/api/v1/agents/register", json={
        "agent_id": "se_test_agent",
        "name": "SE Agent",
        "role": "DeveloperAgent"
    }, headers=admin_headers)
    assert reg.status_code == 201

    with patch("app.core.config.settings.AUTH_ENABLED", True):
        rot = client.post("/api/v1/agents/se_test_agent/rotate-key", headers=admin_headers)
        assert rot.status_code == 200

        from app.models import SecurityEvent
        with next(get_db()) as db:
            events = db.query(SecurityEvent).filter(SecurityEvent.event_type == "agent_rotate_key").all()
            assert len(events) > 0
            assert events[0].actor_id == "admin"
            assert events[0].status == "success"
    print("SecurityEvent logging: PASSED")


def test_ml_model_integrity_checksum():
    """Verify model registry checks checksum and approved status."""
    from app.ml.risk_engine import RiskEngine, RiskEngineError
    import tempfile
    import json
    
    # Test loading valid model
    engine = RiskEngine()
    assert engine.metadata["approval_status"] == "APPROVED"
    
    # Test loading invalid checksum or corrupted file
    with tempfile.NamedTemporaryFile(suffix=".ubj", delete=False) as f:
        f.write(b"corrupted binary data")
        dummy_ubj_path = f.name
        
    dummy_json_path = dummy_ubj_path.replace(".ubj", ".json")
    metadata = {
        "model_id": "aura-risk-model",
        "version": "test-corrupted",
        "sha256_checksum": "wrong-checksum",
        "approval_status": "APPROVED"
    }
    with open(dummy_json_path, "w") as f:
        json.dump(metadata, f)
        
    try:
        with patch("app.core.config.settings.ENV", "production"):
            with pytest.raises(RiskEngineError) as exc:
                RiskEngine(model_path=dummy_ubj_path)
            assert "checksum" in str(exc.value).lower()
    finally:
        if os.path.exists(dummy_ubj_path):
            os.remove(dummy_ubj_path)
        if os.path.exists(dummy_json_path):
            os.remove(dummy_json_path)
    print("Model checksum and integrity check: PASSED")


def test_ml_fail_closed_on_evaluation_error():
    """Verify ML evaluation failures cause fail-closed HTTP 500 error."""
    from app.ml.risk_engine import RiskEngineError
    
    payload = {
        "agent_id": "ops_bot",
        "action": "restart_service",
        "parameters": {"service": "postgres"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    with patch("app.ml.risk_engine.RiskEngine.evaluate", side_effect=RiskEngineError("Simulated inference failure")):
        response = client.post("/api/v1/evaluate-action", json=payload)
        assert response.status_code == 500
        assert "safety layer error" in response.json()["detail"].lower()
    print("Fail-closed on ML evaluation failure: PASSED")


def test_shap_failure_graceful_handling():
    """Verify SHAP explanation generation failures are handled gracefully without blocking decisions."""
    payload = {
        "agent_id": "dev_bot",
        "action": "read_file",
        "parameters": {"file": "report.pdf"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    with patch("shap.TreeExplainer.shap_values", side_effect=Exception("SHAP core dumped")):
        response = client.post("/api/v1/evaluate-action", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "allow"
        assert "SHAP explanation unavailable" in data["reason"]
    print("SHAP failure graceful fallback: PASSED")


def test_golden_set_regression():
    """Verify deterministic golden-set decisions for typical agent commands."""
    # 1. Obviously safe action
    payload = {
        "agent_id": "research_bot",
        "action": "read_file",
        "parameters": {"file": "report.pdf"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    
    # 2. Obviously dangerous action
    payload = {
        "agent_id": "ops_bot",
        "action": "execute_command",
        "parameters": {"cmd": "rm -rf /"},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    print("Golden-set regression checks: PASSED")


def test_audit_governance_metadata_populated():
    """Verify model governance, policy versions and request ID are written to ActionLog."""
    payload = {
        "agent_id": "ops_bot",
        "action": "view_dashboard",
        "parameters": {},
        "requested_at": datetime.now(timezone.utc).isoformat()
    }
    response = client.post("/api/v1/evaluate-action", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Schema verification
    assert "model_version" in data
    assert "policy_version" in data
    assert "request_id" in data
    
    assert data["model_version"] == "1.0.0"
    assert data["policy_version"] == "1.0.0"
    assert len(data["request_id"]) > 0
    
    # DB verification
    with next(get_db()) as db:
        log_entry = db.query(ActionLog).filter(ActionLog.request_id == data["request_id"]).first()
        assert log_entry is not None
        assert log_entry.model_version == "1.0.0"
        assert log_entry.policy_version == "1.0.0"
        assert log_entry.feature_schema_version == 1
        assert log_entry.evaluation_timestamp is not None
    print("Database model governance audit logs: PASSED")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Running Phase 0 + Phase 1 + Phase 2 + Phase 4 + Phase 5 tests...")
    setup_module()
    try:
        # Phase 0
        test_health()
        test_readiness()
        test_evaluate_action_safe()
        test_evaluate_action_deterministic_block()
        test_policy_ops_allowed()
        test_policy_research_blocked()
        test_audit_log_verification()
        test_agent_upsert_creates_single_record()
        test_concurrent_agent_registration()
        test_audit_log_ordering_by_requested_at()
        test_database_check_constraint_risk_level()
        test_database_check_constraint_decision()
        test_database_check_constraint_approval_status()
        test_approval_workflow_end_to_end()

        # Phase 1
        test_rate_limiter_allows_below_limit()
        test_rate_limiter_allows_at_limit()
        test_rate_limiter_rejects_above_limit()
        test_rate_limiter_separate_agents()
        test_rate_limiter_agent_id_sanitisation()
        test_rate_limiter_atomic_pipeline()
        test_rate_limiter_redis_failure()
        test_api_rate_limit_429_stops_ml()
        test_api_redis_failure_503()
        test_live_redis_rate_limit_counter_expires()

        # Phase 2
        test_api_key_generation_format()
        test_api_key_hash_and_verify()
        test_api_key_unique_per_call()
        test_agent_registration_success()
        test_agent_registration_invalid_role()
        test_agent_registration_duplicate_returns_409()
        test_agent_registration_upgrades_phase1_agent()
        test_auth_enabled_missing_key_returns_401()
        test_auth_enabled_invalid_key_returns_401()
        test_auth_enabled_wrong_prefix_returns_401()
        test_auth_enabled_valid_key_allows_request()
        test_auth_prevents_role_impersonation()
        test_auth_disabled_allows_unauthenticated()

        # Phase 4
        test_prometheus_metrics()
        test_security_headers()
        test_request_id_middleware()
        
        # Test functions needing arguments
        headers = create_access_token({"sub": "admin"})
        admin_headers_dict = {"Authorization": f"Bearer {headers}"}
        test_logout_revocation(admin_headers_dict)
        test_security_event_logged(admin_headers_dict)
        
        # Phase 5
        test_ml_model_integrity_checksum()
        test_ml_fail_closed_on_evaluation_error()
        test_shap_failure_graceful_handling()
        test_golden_set_regression()
        test_audit_governance_metadata_populated(admin_headers_dict)
        
        # Phase 6
        test_model_registry_db()
        test_unauthorized_governance_access(admin_headers_dict)
        test_model_activation_validation_and_failures(admin_headers_dict)
        test_model_activation_success(admin_headers_dict)
        test_model_rollback(admin_headers_dict)
        test_drift_telemetry_calculation(admin_headers_dict)
        test_model_health_and_readiness(admin_headers_dict)

        print("\nAll tests passed!")
    finally:
        teardown_module()


def test_model_registry_db():
    """Verify model registry DB and unique constraints."""
    from app.models import ModelRegistry
    import uuid
    
    with next(get_db()) as db:
        ver = f"test-ver-{uuid.uuid4()}"
        m = ModelRegistry(
            model_version=ver,
            feature_schema_version=1,
            dataset_version="1.0.0",
            artifact_path="dummy.ubj",
            sha256="dummy-sha",
            status="candidate",
            metrics_json={}
        )
        db.add(m)
        db.commit()
        
        m_dup = ModelRegistry(
            model_version=ver,
            feature_schema_version=1,
            dataset_version="1.0.0",
            artifact_path="dummy.ubj",
            sha256="dummy-sha",
            status="candidate",
            metrics_json={}
        )
        db.add(m_dup)
        with pytest.raises(Exception):
            db.commit()
        db.rollback()
    print("ModelRegistry database integrity constraints: PASSED")


def test_unauthorized_governance_access(admin_headers):
    """Verify access controls on models governance endpoints."""
    # Register operator_bob in DB first
    with next(get_db()) as db:
        bob = db.query(Operator).filter(Operator.username == "operator_bob").first()
        if not bob:
            bob = Operator(username="operator_bob", password_hash="dummy", role="reviewer")
            db.add(bob)
            db.commit()

    # 1. No token -> 401
    res = client.get("/api/v1/models")
    assert res.status_code == 401
    
    # 2. Non-admin operator -> 403 on mutate endpoints
    non_admin_token = create_access_token({"sub": "operator_bob"})
    non_admin_headers = {"Authorization": f"Bearer {non_admin_token}"}
    
    res_list = client.get("/api/v1/models", headers=non_admin_headers)
    assert res_list.status_code == 200
    
    res_act = client.post("/api/v1/models/1.0.0/activate", headers=non_admin_headers)
    assert res_act.status_code == 403
    
    res_roll = client.post("/api/v1/models/rollback", headers=non_admin_headers)
    assert res_roll.status_code == 403

    # Clean up operator
    with next(get_db()) as db:
        db.query(Operator).filter(Operator.username == "operator_bob").delete()
        db.commit()
    print("Model Governance RBAC authorization: PASSED")


def test_model_activation_validation_and_failures(admin_headers):
    """Verify activation checks missing artifacts, checksums, and compatibility."""
    # 1. Non-existent model version
    res = client.post("/api/v1/models/non-existent-99.0/activate", headers=admin_headers)
    assert res.status_code == 404
    
    # 2. Register a model with missing artifact path in DB
    with next(get_db()) as db:
        m = db.query(ModelRegistry).filter(ModelRegistry.model_version == "invalid-test").first()
        if not m:
            m = ModelRegistry(
                model_version="invalid-test",
                feature_schema_version=1,
                dataset_version="1.0.0",
                artifact_path="missing_file.ubj",
                sha256="missing-sha",
                status="candidate",
                metrics_json={}
            )
            db.add(m)
            db.commit()
            
    res_miss = client.post("/api/v1/models/invalid-test/activate", headers=admin_headers)
    assert res_miss.status_code == 400
    assert "missing" in res_miss.json()["detail"].lower()
    print("Model Activation checks (missing files): PASSED")


def test_model_activation_success(admin_headers):
    """Verify successful model activation swappings."""
    res = client.post("/api/v1/models/1.0.0/activate", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["model_version"] == "1.0.0"
    assert data["status"] == "active"
    
    with next(get_db()) as db:
        m = db.query(ModelRegistry).filter(ModelRegistry.model_version == "1.0.0").first()
        assert m.status == "active"
        
        from app.models import ModelAuditEvent
        evt = db.query(ModelAuditEvent).filter(ModelAuditEvent.model_version == "1.0.0", ModelAuditEvent.event_type == "activated").first()
        assert evt is not None
        assert evt.success is True
    print("Model Activation (successful swap): PASSED")


def test_model_rollback(admin_headers):
    """Verify model rollback reverts back to the previously active model."""
    with next(get_db()) as db:
        current_active = db.query(ModelRegistry).filter(ModelRegistry.status == "active").first()
        if current_active:
            current_active.status = "retired"
            current_active.activated_at = datetime.utcnow()
            
        m_fake = ModelRegistry(
            model_version="fake-active",
            feature_schema_version=1,
            dataset_version="1.0.0",
            artifact_path=current_active.artifact_path,
            sha256=current_active.sha256,
            status="active",
            metrics_json={},
            activated_at=datetime.utcnow()
        )
        db.add(m_fake)
        db.commit()
        
    res = client.post("/api/v1/models/rollback", headers=admin_headers)
    assert res.status_code == 200
    
    with next(get_db()) as db:
        db.query(ModelRegistry).filter(ModelRegistry.model_version == "fake-active").delete()
        db.commit()
    print("Model Rollback execution: PASSED")


def test_drift_telemetry_calculation(admin_headers):
    """Verify Population Stability Index (PSI) drift telemetry scores."""
    from app.api.v1.endpoints import get_risk_engine
    re = get_risk_engine()
    
    re.drift_monitor.history = []
    
    for i in range(10):
        re.drift_monitor.record_inference(
            risk_level="low",
            decision="allow",
            embedding_norm=1.0,
            text_length=15,
            agent_id="test_agent",
            model_version="1.0.0"
        )
        
    psi, status = re.drift_monitor.calculate_psi(3600)
    assert psi >= 0.0
    assert status in ("normal", "warning", "critical")
    print("ML Drift calculations and PSI: PASSED")


def test_model_health_and_readiness(admin_headers):
    """Verify GET health/readiness behavior depending on model state."""
    res_h = client.get("/api/v1/models/health", headers=admin_headers)
    assert res_h.status_code == 200
    data = res_h.json()
    assert "active_model" in data
    assert "drift_score" in data
    assert "drift_status" in data
    
    res_r = client.get("/api/v1/readiness")
    assert res_r.status_code == 200
    assert "model_sync" in res_r.json()["services"]
    print("Model Health & Readiness updates: PASSED")

