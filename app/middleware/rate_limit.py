from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import redis
import time
import os
import logging

logger = logging.getLogger(__name__)

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True
)

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute

    async def dispatch(self, request: Request, call_next):
        # Stricter limits on auth endpoints to prevent brute force
        limit = self.requests_per_minute
        if request.url.path.startswith("/auth"):
            limit = 10

        identifier = request.client.host
        key = f"rate_limit:{identifier}:{int(time.time() / 60)}"

        try:
            count = redis_client.incr(key)
            redis_client.expire(key, 60)

            if count > limit:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": "60"}
                )
        except redis.RedisError as exc:
            # Fail closed — do NOT allow requests through when Redis is unavailable.
            # Passing through would eliminate brute-force protection and token
            # blocklist enforcement, maximising the attack window during an outage.
            logger.critical(
                "Redis unavailable — rate limiter failing closed. "
                "All requests blocked until Redis recovers. Error: %s",
                exc,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Service temporarily unavailable. Please try again later."
                },
                headers={"Retry-After": "30"},
            )

        return await call_next(request)
