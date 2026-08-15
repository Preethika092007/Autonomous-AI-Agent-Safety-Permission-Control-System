"""
aura.core.rate_limiter
======================

Per-agent, fixed-window rate limiter backed by Redis.

Algorithm — Fixed Window Counter (atomic pipeline):
    key  = aura:ratelimit:evaluate:{safe_agent_id}:{window_id}
    window_id = floor(unix_timestamp / window_seconds)

    Pipeline (atomic, single round-trip):
        INCR  key          → new_count
        EXPIRE key window  → (re)set TTL so the key auto-expires

    If new_count > limit  → rate limit exceeded
    If new_count == 1     → first request in this window, TTL was just set
    Else                  → request within limit

Security notes:
    * agent_id is the rate-limit namespace (NOT a trusted identity in Phase 1).
      Phase 2 will introduce authenticated agent credentials.
    * agent_id characters are sanitised before use in the Redis key to prevent
      key injection or unexpectedly large keys.
    * All Redis I/O errors are surfaced to the caller as RateLimitRedisError so
      the endpoint can apply fail-closed logic without leaking internal details.
"""

import re
import time
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("aura.rate_limiter")

# Characters allowed in the agent_id segment of the Redis key.
# Anything outside [a-zA-Z0-9_\-] is replaced with '_'.
_SAFE_KEY_RE = re.compile(r"[^a-zA-Z0-9_\-]")
_KEY_MAX_LEN = 128          # hard cap on sanitised agent_id length


class RateLimitRedisError(Exception):
    """Raised when Redis is unavailable or returns an unexpected error."""


@dataclass
class RateLimitResult:
    allowed: bool
    count: int           # current window count after this request
    limit: int           # configured maximum
    remaining: int       # requests left in this window (0 when rejected)
    window_seconds: int  # window size
    retry_after: int     # seconds until window resets (only meaningful when allowed=False)


def _safe_agent_key(agent_id: str) -> str:
    """
    Sanitise agent_id for safe inclusion in a Redis key.

    * Replaces any character outside [a-zA-Z0-9_-] with '_'.
    * Truncates to _KEY_MAX_LEN characters.
    * An empty result (e.g., all special chars) becomes 'unknown'.
    """
    sanitised = _SAFE_KEY_RE.sub("_", agent_id)[:_KEY_MAX_LEN]
    return sanitised if sanitised else "unknown"


def check_rate_limit(
    redis_client,
    agent_id: str,
    limit: int,
    window_seconds: int,
) -> RateLimitResult:
    """
    Perform an atomic fixed-window rate-limit check.

    Parameters
    ----------
    redis_client : redis.Redis
        A connected synchronous redis-py client.
    agent_id : str
        The requesting agent identifier (used as the key namespace).
    limit : int
        Maximum allowed requests within window_seconds.
    window_seconds : int
        Length of the rate-limit window in seconds.

    Returns
    -------
    RateLimitResult

    Raises
    ------
    RateLimitRedisError
        If Redis is unreachable or the operation fails for any reason.
    """
    safe_id = _safe_agent_key(agent_id)
    window_id = int(time.time()) // window_seconds
    key = f"aura:ratelimit:evaluate:{safe_id}:{window_id}"

    try:
        # Atomic pipeline: INCR + EXPIRE in a single server round-trip.
        # INCR creates the key if absent (first request in a window) and
        # atomically increments it.  EXPIRE sets/refreshes the TTL so that
        # orphaned keys are cleaned up automatically.
        pipe = redis_client.pipeline(transaction=False)
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = pipe.execute()
        new_count = int(results[0])
    except Exception as exc:
        logger.error("RATE_LIMIT_REDIS_ERROR agent=%s error=%s", agent_id, exc)
        raise RateLimitRedisError(str(exc)) from exc

    remaining = max(0, limit - new_count)
    allowed = new_count <= limit

    # Compute seconds until the current window expires.
    now = int(time.time())
    window_start = window_id * window_seconds
    retry_after = max(0, (window_start + window_seconds) - now)

    if allowed:
        logger.info(
            "RATE_LIMIT_ALLOWED agent=%s count=%d/%d window=%d",
            agent_id, new_count, limit, window_id
        )
    else:
        logger.warning(
            "RATE_LIMIT_REJECTED agent=%s count=%d/%d retry_after=%ds",
            agent_id, new_count, limit, retry_after
        )

    return RateLimitResult(
        allowed=allowed,
        count=new_count,
        limit=limit,
        remaining=remaining,
        window_seconds=window_seconds,
        retry_after=retry_after,
    )
