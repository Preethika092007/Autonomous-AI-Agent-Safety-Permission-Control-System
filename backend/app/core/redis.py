import redis
from app.core.config import settings

# Lazy initialize the Redis client pool with decode_responses and short timeouts
redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0
)

def get_redis():
    return redis_client
