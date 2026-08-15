import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

try:
    import torch
    torch.set_num_threads(1)
    torch.set_grad_enabled(False)
except ImportError:
    pass

import gc
gc.collect()

from contextlib import asynccontextmanager
import uuid
import sys
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from app.core.database import engine, Base, get_db
from app.core.config import settings
from app.core.logging import configure_logging, request_id_ctx_var
import app.models
from app.api.v1.endpoints import router as api_v1_router


def _apply_idempotent_migrations():
    """
    Apply database-level indexes and CHECK constraints that cannot be declared
    purely via SQLAlchemy `create_all` on pre-existing tables.

    These statements are written to be idempotent:
    - PostgreSQL: uses `IF NOT EXISTS` for index creation and `DO $$ ... $$` blocks
      for constraint addition, suppressing errors when they already exist.
    - SQLite: SQLAlchemy `create_all` already applies the constraints at table
      creation time for new databases; we skip the ALTER TABLE path because SQLite
      does not support ADD CONSTRAINT on existing tables, and test databases are
      always freshly created.
    """
    is_postgres = settings.DATABASE_URL.startswith("postgresql")
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")

    with engine.connect() as conn:
        if is_postgres:
            # ── Index: ActionLog.requested_at ───────────────────────────────
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_action_logs_requested_at "
                "ON action_logs (requested_at);"
            ))

            # ── Composite Index: agent_id + requested_at ────────────────────
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_action_logs_agent_id_requested_at "
                "ON action_logs (agent_id, requested_at);"
            ))

            # ── CHECK: ActionLog.risk_level ─────────────────────────────────
            conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.table_constraints
                        WHERE table_name='action_logs'
                          AND constraint_name='ck_action_logs_risk_level'
                    ) THEN
                        ALTER TABLE action_logs
                        ADD CONSTRAINT ck_action_logs_risk_level
                        CHECK (risk_level IN ('low', 'medium', 'high'));
                    END IF;
                END $$;
            """))

            # ── CHECK: ActionLog.decision ───────────────────────────────────
            conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.table_constraints
                        WHERE table_name='action_logs'
                          AND constraint_name='ck_action_logs_decision'
                    ) THEN
                        ALTER TABLE action_logs
                        ADD CONSTRAINT ck_action_logs_decision
                        CHECK (decision IN ('allow', 'block', 'require_human_approval'));
                    END IF;
                END $$;
            """))

            # ── CHECK: PendingApproval.status ───────────────────────────────
            conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.table_constraints
                        WHERE table_name='pending_approvals'
                          AND constraint_name='ck_pending_approvals_status'
                    ) THEN
                        ALTER TABLE pending_approvals
                        ADD CONSTRAINT ck_pending_approvals_status
                        CHECK (status IN ('pending', 'approved', 'rejected'));
                    END IF;
                END $$;
            """))

            # ── Phase 2: agents.api_key_hash (nullable bcrypt hash) ────────────
            conn.execute(text(
                "ALTER TABLE agents ADD COLUMN IF NOT EXISTS "
                "api_key_hash VARCHAR;"
            ))

            # ── Phase 2: agents.is_active (boolean, defaults true) ────────────
            # ── Phase 7 Indices ─────────────────────────────────────────────
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_timestamp ON security_events (timestamp);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_severity ON security_events (severity);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_event_type ON security_events (event_type);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_agent_id ON security_events (agent_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_incident_id ON security_events (incident_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_events_request_id ON security_events (request_id);"))
            
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents (severity);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_created_at ON incidents (created_at);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_incidents_assigned_to ON incidents (assigned_to);"))

            conn.commit()
            print("[AURA] Idempotent PostgreSQL indexes applied.")

        # ── Phase 3: Data Migration (PostgreSQL & SQLite) ─────────────────
        # Migrate existing Agent.api_key_hash to AgentCredential table if column exists
        try:
            res = conn.execute(text("PRAGMA table_info(agents)"))
            cols = [row[1] for row in res.fetchall()]
        except Exception:
            cols = []

        if not cols:
            try:
                res = conn.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='agents' AND column_name='api_key_hash'"
                ))
                cols = [row[0] for row in res.fetchall()]
            except Exception:
                pass

        if "api_key_hash" in cols:
            conn.execute(text("""
                INSERT INTO agent_credentials (id, agent_id, secret_hash, is_active, created_at)
                SELECT
                    SUBSTR(api_key_hash, 1, 16) AS id, -- Dummy deterministic key_id for migrated
                    id AS agent_id,
                    api_key_hash AS secret_hash,
                    is_active,
                    created_at
                FROM agents
                WHERE api_key_hash IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM agent_credentials WHERE agent_credentials.agent_id = agents.id
                  )
            """))
            conn.commit()
def _migrate_security_events_table():
    """
    Handles migration of the security_events table.
    - SQLite: Drop the legacy security_events table if it exists so that
      Base.metadata.create_all creates the new schema with all the new Phase 7 columns.
    - PostgreSQL: Alter table to add the new Phase 7 columns if they don't already exist.
    """
    is_postgres = settings.DATABASE_URL.startswith("postgresql")
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")

    with engine.connect() as conn:
        if is_sqlite:
            try:
                res = conn.execute(text("PRAGMA table_info(security_events)")).fetchall()
                cols = [row[1] for row in res]
                if cols and "event_hash" not in cols:
                    conn.execute(text("DROP TABLE security_events;"))
                    conn.commit()
                    print("[AURA] Dropped legacy security_events table in SQLite for schema upgrade.")
            except Exception as e:
                print(f"[AURA] Warning checking/dropping SQLite table: {e}")

        elif is_postgres:
            new_cols = [
                ("severity", "VARCHAR"),
                ("source", "VARCHAR"),
                ("agent_id", "VARCHAR"),
                ("operator_id", "VARCHAR"),
                ("request_id", "VARCHAR"),
                ("action_log_id", "VARCHAR"),
                ("model_version", "VARCHAR"),
                ("policy_version", "VARCHAR"),
                ("incident_id", "VARCHAR"),
                ("description", "VARCHAR"),
                ("metadata_json", "JSONB"),
                ("previous_event_hash", "VARCHAR"),
                ("event_hash", "VARCHAR"),
                ("actor_id", "VARCHAR"),
                ("status", "VARCHAR"),
                ("details", "VARCHAR"),
                ("ip_address", "VARCHAR"),
            ]
            for col_name, col_type in new_cols:
                try:
                    conn.execute(text(f"ALTER TABLE security_events ADD COLUMN IF NOT EXISTS {col_name} {col_type};"))
                except Exception as e:
                    print(f"[AURA] Warning adding column {col_name} in PostgreSQL: {e}")
            conn.commit()
            print("[AURA] PostgreSQL security_events columns verified/added.")


def _migrate_action_logs_table():
    """
    Handles migration of the action_logs table by adding missing Phase 5/6 columns:
    - model_version
    - feature_schema_version
    - policy_version
    - request_id
    - evaluation_timestamp
    """
    is_postgres = settings.DATABASE_URL.startswith("postgresql")
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")

    cols_to_add = [
        ("model_version", "VARCHAR"),
        ("feature_schema_version", "INTEGER"),
        ("policy_version", "VARCHAR"),
        ("request_id", "VARCHAR"),
        ("evaluation_timestamp", "TIMESTAMP"),
    ]

    with engine.connect() as conn:
        if is_sqlite:
            try:
                res = conn.execute(text("PRAGMA table_info(action_logs)")).fetchall()
                existing_cols = [row[1] for row in res]
                for col_name, col_type in cols_to_add:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE action_logs ADD COLUMN {col_name} {col_type};"))
                        conn.commit()
                        print(f"[AURA] Added column {col_name} to action_logs in SQLite.")
            except Exception as e:
                print(f"[AURA] Warning adding column to action_logs in SQLite: {e}")

        elif is_postgres:
            for col_name, col_type in cols_to_add:
                try:
                    conn.execute(text(f"ALTER TABLE action_logs ADD COLUMN IF NOT EXISTS {col_name} {col_type};"))
                    conn.commit()
                except Exception as e:
                    print(f"[AURA] Warning adding column {col_name} to action_logs in PostgreSQL: {e}")


def _migrate_agents_table():
    """
    Handles migration of the agents table by adding missing Phase 2 columns:
    - api_key_hash
    - is_active
    """
    is_postgres = settings.DATABASE_URL.startswith("postgresql")
    is_sqlite = settings.DATABASE_URL.startswith("sqlite")

    cols_to_add = [
        ("api_key_hash", "VARCHAR"),
        ("is_active", "BOOLEAN DEFAULT 1"),
    ]

    with engine.connect() as conn:
        if is_sqlite:
            try:
                res = conn.execute(text("PRAGMA table_info(agents)")).fetchall()
                existing_cols = [row[1] for row in res]
                for col_name, col_type in cols_to_add:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE agents ADD COLUMN {col_name} {col_type};"))
                        conn.commit()
                        print(f"[AURA] Added column {col_name} to agents in SQLite.")
            except Exception as e:
                print(f"[AURA] Warning adding column to agents in SQLite: {e}")

        elif is_postgres:
            for col_name, col_type in cols_to_add:
                try:
                    conn.execute(text(f"ALTER TABLE agents ADD COLUMN IF NOT EXISTS {col_name} {col_type};"))
                    conn.commit()
                except Exception as e:
                    print(f"[AURA] Warning adding column {col_name} to agents in PostgreSQL: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure audit_chain listeners are registered
    import app.core.audit_chain
    # 0. Run pre-migration hooks
    _migrate_security_events_table()
    _migrate_action_logs_table()
    _migrate_agents_table()
    # 1. Create any new tables defined in models (idempotent — never drops existing)
    Base.metadata.create_all(bind=engine)
    # 2. Apply indexes and constraints to pre-existing tables
    _apply_idempotent_migrations()
    
    # 3. Seed default admin operator
    if settings.AUTH_ENABLED and not settings.INITIAL_ADMIN_PASSWORD:
        if settings.ENV == "production":
            print("[AURA] FATAL: AUTH_ENABLED=True but INITIAL_ADMIN_PASSWORD is not set. Refusing to start in production.", file=sys.stderr)
            sys.exit(1)
        else:
            settings.INITIAL_ADMIN_PASSWORD = "admin"
            print("[AURA] WARNING: INITIAL_ADMIN_PASSWORD is not set in development. Falling back to default 'admin'.")

    with next(get_db()) as db:
        from app.models import Operator
        import bcrypt
        if not db.query(Operator).filter(Operator.username == settings.INITIAL_ADMIN_USERNAME).first():
            if settings.INITIAL_ADMIN_PASSWORD:
                hashed_pwd = bcrypt.hashpw(settings.INITIAL_ADMIN_PASSWORD.encode(), bcrypt.gensalt(rounds=12)).decode()
                admin = Operator(username=settings.INITIAL_ADMIN_USERNAME, password_hash=hashed_pwd, role="admin")
                db.add(admin)
                db.commit()
                print(f"[AURA] Initial Admin Operator created ({settings.INITIAL_ADMIN_USERNAME}/<hidden>).")

    # 4. Start Redis pubsub for websockets
    from app.core.websockets import start_pubsub_listener
    start_pubsub_listener()

    yield

configure_logging()

app = FastAPI(
    title="Autonomous AI Agent Safety & Permission Control System",
    description="Local middleware firewall intercepting agent actions, scoring risk, and enforcing policy.",
    version="1.0.0",
    lifespan=lifespan
)

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request_id_ctx_var.set(req_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# CORS configuration
allow_origins = [o.strip() for o in settings.CORS_ALLOWED_ORIGINS.split(",")] if settings.CORS_ALLOWED_ORIGINS else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_v1_router, prefix="/api/v1")
