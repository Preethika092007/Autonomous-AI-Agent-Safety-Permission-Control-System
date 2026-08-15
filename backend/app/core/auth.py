"""
aura.core.auth
==============

Agent authentication via shared-secret API key (X-Agent-Key header).
Operator authentication via JWT Bearer tokens.
"""

import secrets
import logging
import bcrypt
import jwt
import uuid
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import Header, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.core.redis import get_redis
from app.models import Agent, AgentCredential, Operator

logger = logging.getLogger("aura.auth")

_KEY_PREFIX = "aura-"
_SECRET_BYTES = 32
_JWT_ALGORITHM = "HS256"

if settings.AUTH_ENABLED and settings.ENV == "production":
    if settings.JWT_SECRET_KEY == "super-secret-jwt-key-replace-in-production":
        print("[AURA] FATAL: Default JWT_SECRET_KEY used in production. Refusing to start.", file=sys.stderr)
        sys.exit(1)
    if len(settings.JWT_SECRET_KEY) < 32:
        print("[AURA] FATAL: JWT_SECRET_KEY must be at least 32 characters in production.", file=sys.stderr)
        sys.exit(1)

# This specifies that endpoints depending on oauth2_scheme expect a Bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/operator/login")


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new cryptographically secure API key.
    Returns: (plaintext_key, key_id, secret_hash)
    """
    key_id = secrets.token_hex(8)
    secret = secrets.token_hex(_SECRET_BYTES)
    plaintext_key = f"{_KEY_PREFIX}{key_id}.{secret}"
    secret_hash = bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=12)).decode()
    return plaintext_key, key_id, secret_hash


def hash_api_key(plaintext: str) -> str:
    """Used for legacy Phase 2 key generation and seeding."""
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_api_key(plaintext_secret: str, hashed: str) -> bool:
    """Constant-time bcrypt check."""
    try:
        return bcrypt.checkpw(plaintext_secret.encode(), hashed.encode())
    except Exception:
        return False


def get_authenticated_agent(
    x_agent_key: str = Header(default=None, alias="X-Agent-Key"),
    db: Session = Depends(get_db),
) -> Agent:
    if not settings.AUTH_ENABLED:
        return None  # type: ignore[return-value]

    if not x_agent_key:
        logger.warning("AUTH_MISSING_KEY: request had no X-Agent-Key header")
        raise HTTPException(
            status_code=401,
            detail="Missing X-Agent-Key header. Register your agent first.",
            headers={"WWW-Authenticate": "X-Agent-Key"},
        )

    if not x_agent_key.startswith(_KEY_PREFIX):
        logger.warning("AUTH_INVALID_PREFIX: key does not start with expected prefix")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key format.",
            headers={"WWW-Authenticate": "X-Agent-Key"},
        )

    # Parse O(1) key format: aura-{key_id}.{secret}
    # Fallback to Phase 2 format (no dot): aura-{secret} -> requires O(n) scan
    key_body = x_agent_key[len(_KEY_PREFIX):]
    if "." in key_body:
        # Phase 3 format: O(1) lookup
        key_id, secret = key_body.split(".", 1)
        cred = db.query(AgentCredential).filter(AgentCredential.id == key_id).first()
        if cred and cred.is_active and verify_api_key(secret, cred.secret_hash):
            agent = cred.agent
            if not agent.is_active:
                raise HTTPException(status_code=403, detail="Agent account is deactivated.")
            return agent
        raise HTTPException(status_code=401, detail="Invalid API key.")
    else:
        # Phase 2 fallback: O(n) scan
        agents = db.query(Agent).filter(
            Agent.api_key_hash.isnot(None),
            Agent.is_active == True
        ).all()
        for candidate in agents:
            if candidate.api_key_hash and verify_api_key(x_agent_key, candidate.api_key_hash):
                return candidate
        
        raise HTTPException(status_code=401, detail="Invalid API key.")


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp()), "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=_JWT_ALGORITHM)


def get_current_operator(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Operator:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[_JWT_ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None or jti is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        # Check revocation in Redis
        try:
            redis = get_redis()
            if redis.get(f"revoked_jwt:{jti}"):
                raise HTTPException(status_code=401, detail="Token has been revoked")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Redis failure during JWT validation: {e}")
            if settings.ENV == "development":
                logger.warning("Redis is offline. Bypassing JWT revocation check in development environment.")
            else:
                # Redis failure should fail closed
                raise HTTPException(status_code=503, detail="Service unavailable")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    operator = db.query(Operator).filter(Operator.username == username).first()
    if operator is None:
        raise HTTPException(status_code=401, detail="Operator not found")
    return operator

def require_admin_operator(operator: Operator = Depends(get_current_operator)) -> Operator:
    if operator.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return operator
