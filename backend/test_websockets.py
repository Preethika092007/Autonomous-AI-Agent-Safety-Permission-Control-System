import sys
import os
from datetime import datetime, timezone

# Add the directory containing 'app' to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Force SQLite database URL and disable auth/rate limiting for tests
os.environ["DATABASE_URL"] = "sqlite:///./test_ws.db"
os.environ["AUTH_ENABLED"] = "false"
os.environ["RATE_LIMIT_ENABLED"] = "false"

# Clear test database if it exists
if os.path.exists("./test_ws.db"):
    try:
        os.remove("./test_ws.db")
    except Exception:
        pass

from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal, engine, Base
from app.models import Agent, ActionLog, PendingApproval, Operator
from app.core.auth import create_access_token

from unittest.mock import MagicMock, patch
mock_redis = MagicMock()
mock_redis.get.return_value = None
mock_redis.incr.return_value = 1
mock_redis.ping.return_value = True
mock_redis.publish.side_effect = Exception("Force in-memory broadcast fallback")

mock_pubsub = MagicMock()
mock_pubsub.get_message.return_value = None
mock_redis.pubsub.return_value = mock_pubsub

patchers = []

client = TestClient(app)

def setup_module():
    # Start mocks cleanly
    p1 = patch("app.core.auth.get_redis", return_value=mock_redis)
    p2 = patch("app.api.v1.operator.get_redis", return_value=mock_redis)
    p3 = patch("app.api.v1.endpoints.get_redis", return_value=mock_redis)
    p4 = patch("app.core.websockets.get_redis", return_value=mock_redis)
    p5 = patch("redis.from_url", return_value=mock_redis)
    patchers.extend([p1, p2, p3, p4, p5])
    for p in patchers:
        p.start()

    from app.core.config import settings
    from app.api.v1.sec_ops import _lockdown_state
    settings.AUTH_ENABLED = False
    settings.RATE_LIMIT_ENABLED = False
    _lockdown_state["enabled"] = False
    # Reset DB tables completely to prevent database contamination
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        import bcrypt
        if not db.query(Operator).filter(Operator.username == "admin").first():
            hashed_pwd = bcrypt.hashpw(b"admin", bcrypt.gensalt(rounds=4)).decode()
            admin = Operator(username="admin", password_hash=hashed_pwd, role="admin")
            db.add(admin)
            db.commit()
    finally:
        db.close()

    from app.api.v1.endpoints import get_risk_engine
    get_risk_engine().reload_active_model()

def teardown_module():
    # Clean up DB file
    for p in patchers:
        try:
            p.stop()
        except Exception:
            pass
    if os.path.exists("./test_ws.db"):
        try:
            os.remove("./test_ws.db")
        except Exception:
            pass

def test_websocket_approval_flow():
    # 1. Establish WebSocket client connection
    with client.websocket_connect("/api/v1/ws/approvals") as websocket:
        # 2. Trigger an action that requires human approval
        payload = {
            "agent_id": "ops_bot",
            "action": "execute_bash",
            "parameters": {"cmd": "ls"},
            "requested_at": datetime.now(timezone.utc).isoformat()
        }
        response = client.post("/api/v1/evaluate-action", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "require_human_approval"
        
        # 3. Receive websocket broadcast payload
        ws_msg = websocket.receive_json()
        assert ws_msg["event"] == "new_approval_request"
        approval_id = ws_msg["data"]["approval_id"]
        assert ws_msg["data"]["action"] == "execute_bash"
        assert ws_msg["data"]["agent_id"] == "ops_bot"
        print("WebSocket broadcast 'new_approval_request': RECEIVED & VERIFIED")

        # 4. Resolve the approval via the approve-action REST endpoint
        resolve_payload = {
            "approval_id": approval_id,
            "status": "approved"
        }
        token = create_access_token({"sub": "admin"})
        admin_headers = {"Authorization": f"Bearer {token}"}
        res_response = client.post("/api/v1/approve-action", json=resolve_payload, headers=admin_headers)
        assert res_response.status_code == 200
        res_data = res_response.json()
        assert res_data["status"] == "success"
        assert res_data["resolution"] == "approved"
        
        # 5. Receive resolution broadcast via WebSocket
        ws_resolve_msg = websocket.receive_json()
        assert ws_resolve_msg["event"] == "approval_resolved"
        assert ws_resolve_msg["data"]["approval_id"] == approval_id
        assert ws_resolve_msg["data"]["status"] == "approved"
        print("WebSocket broadcast 'approval_resolved': RECEIVED & VERIFIED")

        # 6. Verify database records are updated correctly
        db = SessionLocal()
        try:
            pending = db.query(PendingApproval).filter(PendingApproval.id == approval_id).first()
            assert pending is not None
            assert pending.status == "approved"

            action_log = db.query(ActionLog).filter(ActionLog.id == pending.action_log_id).first()
            assert action_log is not None
            assert action_log.decision == "allow"  # Approved maps to allow
            print("Database updates (PendingApproval status and ActionLog decision): VERIFIED")
        finally:
            db.close()

if __name__ == "__main__":
    print("Running WebSocket and Human Approval Workflow Integration Tests...")
    setup_module()
    try:
        test_websocket_approval_flow()
        print("All tests passed successfully!")
    finally:
        teardown_module()
