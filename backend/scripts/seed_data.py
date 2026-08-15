"""
AURA Firewall — Traffic Seeder / Simulator

Sends a continuous stream of realistic agent actions to POST /evaluate-action.

Authentication:
    When AUTH_ENABLED=false (default), requests are sent without X-Agent-Key
    (Phase 1 fallback behaviour — agent_id is self-reported).

    When AUTH_ENABLED=true, each agent must have a pre-registered API key.
    Set the following environment variables (obtained from POST /agents/register):
        SEED_KEY_RESEARCH_BOT   — API key for research_bot
        SEED_KEY_DEV_BOT        — API key for dev_bot
        SEED_KEY_OPS_BOT        — API key for ops_bot
    If a key is missing in authenticated mode, that agent's requests are skipped.
"""
import time
import random
import os
from datetime import datetime, timezone
import httpx

backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
evaluate_url = f"{backend_url}/api/v1/evaluate-action"
auth_enabled = os.getenv("AUTH_ENABLED", "false").lower() == "true"

# Agent API keys (only relevant when AUTH_ENABLED=true)
agent_keys = {
    "research_bot": os.getenv("SEED_KEY_RESEARCH_BOT", ""),
    "dev_bot":      os.getenv("SEED_KEY_DEV_BOT", ""),
    "ops_bot":      os.getenv("SEED_KEY_OPS_BOT", ""),
}

# ── Auto-Registration and Authentication Bootstrap ────────────────────────────
admin_token = ""
try:
    login_url = f"{backend_url}/api/v1/operator/login"
    login_payload = {
        "username": "admin",
        "password": os.getenv("INITIAL_ADMIN_PASSWORD", "Preethi@2007")
    }
    login_response = httpx.post(login_url, data=login_payload, timeout=5.0)
    if login_response.status_code == 200:
        admin_token = login_response.json().get("access_token", "")
        print("Successfully authenticated as admin operator for auto-registration.")
except Exception as e:
    print(f"Admin authentication skipped/failed (optional): {e}")

if admin_token:
    headers = {"Authorization": f"Bearer {admin_token}"}
    for agent_id, role, name in [
        ("research_bot", "ResearchAgent", "Research Bot"),
        ("dev_bot", "DeveloperAgent", "Developer Bot"),
        ("ops_bot", "OperationsAgent", "Operations Bot")
    ]:
        if not agent_keys.get(agent_id):
            try:
                reg_url = f"{backend_url}/api/v1/agents/register"
                reg_payload = {"agent_id": agent_id, "name": name, "role": role}
                reg_response = httpx.post(reg_url, json=reg_payload, headers=headers, timeout=5.0)
                if reg_response.status_code == 201:
                    data = reg_response.json()
                    agent_keys[agent_id] = data["api_key"]
                    print(f"Auto-registered {agent_id} -> key={data['api_key']}")
                elif reg_response.status_code == 409:
                    rotate_url = f"{backend_url}/api/v1/agents/{agent_id}/rotate-key"
                    rot_response = httpx.post(rotate_url, headers=headers, timeout=5.0)
                    if rot_response.status_code == 200:
                        data = rot_response.json()
                        agent_keys[agent_id] = data["api_key"]
                        print(f"Auto-rotated {agent_id} key -> key={data['api_key']}")
            except Exception as e:
                print(f"Failed to auto-register/rotate {agent_id}: {e}")

if any(agent_keys.values()):
    auth_enabled = True

actions = [
    # ResearchAgent (research_bot)
    {"agent_id": "research_bot", "action": "read_file",    "parameters": {"file": "scientific_paper.pdf"}},
    {"agent_id": "research_bot", "action": "scrape_web",   "parameters": {"url": "https://arxiv.org/abs/2405.0001"}},
    {"agent_id": "research_bot", "action": "execute_bash", "parameters": {"cmd": "ls"}},  # banned action

    # DeveloperAgent (dev_bot)
    {"agent_id": "dev_bot", "action": "read_file",    "parameters": {"file": "src/App.tsx"}},
    {"agent_id": "dev_bot", "action": "write_config", "parameters": {"key": "max_connections", "value": "500"}},
    {"agent_id": "dev_bot", "action": "write_file",   "parameters": {"file": "temp.txt", "content": "debug=true"}},

    # OperationsAgent (ops_bot)
    {"agent_id": "ops_bot", "action": "restart_service", "parameters": {"service": "postgres"}},
    {"agent_id": "ops_bot", "action": "execute_db",      "parameters": {"query": "DROP TABLE users"}},   # hard block
    {"agent_id": "ops_bot", "action": "execute_bash",    "parameters": {"cmd": "rm -rf /"}},             # hard block
    {"agent_id": "ops_bot", "action": "execute_bash",    "parameters": {"cmd": "cat /etc/passwd"}},      # hard block
    {"agent_id": "ops_bot", "action": "execute_bash",    "parameters": {"cmd": "ls -la"}},               # allowed
]

print(f"Starting AURA Firewall Traffic Simulator -> {evaluate_url}")
print(f"Authentication mode: {'ENABLED' if auth_enabled else 'DISABLED (Phase 1 fallback)'}")
print("Ctrl+C to terminate...")

while True:
    action = random.choice(actions).copy()
    agent_id = action["agent_id"]
    action["requested_at"] = datetime.now(timezone.utc).isoformat()

    # Build request headers
    headers = {}
    if auth_enabled:
        key = agent_keys.get(agent_id, "")
        if not key:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] SKIP {agent_id}: no SEED_KEY set for this agent")
            time.sleep(1)
            continue
        headers["X-Agent-Key"] = key

    try:
        response = httpx.post(evaluate_url, json=action, headers=headers, timeout=10.0)
        if response.status_code == 200:
            res = response.json()
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Agent: {agent_id:<12} | Action: {action['action']:<15} | "
                f"Risk: {res.get('risk_level'):<6} | Decision: {res.get('decision'):<24}"
            )
        elif response.status_code == 429:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] RATE LIMITED {agent_id}: retry in {response.headers.get('Retry-After', '?')}s")
        elif response.status_code == 401:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] AUTH FAILURE {agent_id}: check SEED_KEY env vars")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] HTTP {response.status_code} for {agent_id}: {response.text[:80]}")
    except Exception as exc:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {exc}")

    time.sleep(3)
