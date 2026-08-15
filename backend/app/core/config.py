from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./app.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    ENV: str = "development"

    # ── Phase 1: Per-agent rate limiting ──────────────────────────────────────
    # Master switch. Set false to disable rate limiting (e.g., unit tests).
    RATE_LIMIT_ENABLED: bool = False

    # Maximum number of /evaluate-action calls allowed per agent per window.
    RATE_LIMIT_REQUESTS: int = 60

    # Rolling window length in seconds.
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ── Phase 2/4: Authentication ─────────────────────────────────────────────
    # Master switch. Set false to run in Phase 1 compatibility mode.
    AUTH_ENABLED: bool = True

    # ── Phase 4: Production Hardening ─────────────────────────────────────────
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_PASSWORD: str = ""  # Must be provided in env
    
    JWT_SECRET_KEY: str = "super-secret-jwt-key-replace-in-production"
    JWT_EXPIRE_MINUTES: int = 30
    
    AUTH_LOGIN_RATE_LIMIT_REQUESTS: int = 10
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 60
    
    CORS_ALLOWED_ORIGINS: str = "http://localhost:5173"

    # ── Phase 5: Machine Learning Evaluation & Governance ─────────────────────
    ML_MODEL_VERSION: str = "1.0.0"
    ML_MODEL_REGISTRY_DIR: str = "app/ml/registry"
    ML_HIGH_RISK_THRESHOLD: float = 0.5
    ML_MEDIUM_RISK_THRESHOLD: float = 0.3
    ML_FAIL_CLOSED: bool = True
    POLICY_VERSION: str = "1.0.0"

    # ── Phase 6: Model Governance & Drift Monitoring ──────────────────────────
    MODEL_GOVERNANCE_ENABLED: bool = True
    ML_DRIFT_MONITORING_ENABLED: bool = True
    ML_DRIFT_WARNING_THRESHOLD: float = 0.10
    ML_DRIFT_CRITICAL_THRESHOLD: float = 0.25
    MODEL_SYNC_TIMEOUT_SECONDS: int = 30

    class Config:
        env_file = ".env"


settings = Settings()
