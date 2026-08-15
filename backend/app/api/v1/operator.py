import logging
import bcrypt
import jwt
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.core.redis import get_redis
from app.models import Operator, SecurityEvent
from app.core.auth import create_access_token, get_current_operator, oauth2_scheme, _JWT_ALGORITHM
from app.api.v1.schemas import OperatorLoginResponse
from app.core.rate_limiter import RateLimitRedisError

logger = logging.getLogger("aura.operator")
router = APIRouter()

@router.post("/login", response_model=OperatorLoginResponse)
async def login_operator(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "unknown"
    
    # 1. Rate Limiting via Redis
    try:
        redis = get_redis()
        rate_key = f"rate_limit:login:{ip_address}:{form_data.username}"
        current_count = redis.incr(rate_key)
        if current_count == 1:
            redis.expire(rate_key, settings.AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS)
        
        if current_count > settings.AUTH_LOGIN_RATE_LIMIT_REQUESTS:
            logger.warning(f"Login rate limit exceeded for IP {ip_address}")
            raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.", headers={"Retry-After": str(settings.AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS)})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Redis failure during login rate limiting: {e}")
        if settings.ENV == "development":
            logger.warning("Redis is offline. Bypassing login rate limiter in development environment.")
        else:
            # Fail closed on redis failure for login
            raise HTTPException(status_code=503, detail="Service unavailable")

    operator = db.query(Operator).filter(Operator.username == form_data.username).first()
    if not operator or not bcrypt.checkpw(form_data.password.encode(), operator.password_hash.encode()):
        # Log failure
        evt = SecurityEvent(actor_id=form_data.username, event_type="login", status="failure", ip_address=ip_address, details="Invalid credentials")
        db.add(evt)
        db.commit()
        # Opaque error message
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Log success
    evt = SecurityEvent(actor_id=operator.username, event_type="login", status="success", ip_address=ip_address)
    db.add(evt)
    db.commit()

    access_token = create_access_token(data={"sub": operator.username})
    return OperatorLoginResponse(access_token=access_token, role=operator.role)

@router.post("/logout")
async def logout_operator(
    request: Request,
    token: str = Depends(oauth2_scheme),
    current_operator: Operator = Depends(get_current_operator),
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "unknown"
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[_JWT_ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            import time
            ttl = exp - int(time.time())
            if ttl > 0:
                redis = get_redis()
                redis.setex(f"revoked_jwt:{jti}", ttl, "revoked")
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")
        
    # Log logout
    evt = SecurityEvent(actor_id=current_operator.username, event_type="logout", status="success", ip_address=ip_address)
    db.add(evt)
    db.commit()
    
    return {"status": "ok", "message": "Logged out successfully"}

@router.get("/me")
async def get_operator_me(current_operator: Operator = Depends(get_current_operator)):
    return {
        "id": current_operator.id,
        "username": current_operator.username,
        "role": current_operator.role
    }
