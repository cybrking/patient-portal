"""
JWT blocklist backed by Redis.

Tokens are keyed by their `jti` (JWT ID) claim.  Each entry is stored with
a TTL equal to the token's remaining lifetime so Redis automatically purges
entries that are no longer relevant, keeping memory usage bounded.

Connection settings are read from environment variables:
  REDIS_URL  — e.g. rediss://:password@hostname:6379/0
               (the `rediss://` scheme enables TLS, required for ElastiCache
               with transit_encryption_enabled = true)

Falls back to a simple in-process set when Redis is unavailable so that
development and unit-test environments work without a running Redis instance.
In production the fallback should never be reached; an alarm on the
RedisUnavailable log line is recommended.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis client — initialised lazily so import-time errors don't break startup
# ---------------------------------------------------------------------------

_redis_client = None


def _get_redis():
    """Return a connected redis.Redis instance, or None if unavailable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    redis_url: Optional[str] = os.getenv("REDIS_URL")
    if not redis_url:
        logger.warning(
            "REDIS_URL not set — JWT blocklist will use in-process fallback. "
            "This is NOT safe for multi-process / production deployments."
        )
        return None

    try:
        import redis  # redis-py, already a common FastAPI dependency

        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        # Verify connectivity eagerly
        client.ping()
        _redis_client = client
        logger.info("JWT blocklist connected to Redis")
        return _redis_client
    except Exception as exc:  # pragma: no cover
        logger.error("RedisUnavailable: could not connect to Redis for JWT blocklist: %s", exc)
        return None


# ---------------------------------------------------------------------------
# In-process fallback (single-process / dev only)
# ---------------------------------------------------------------------------

_local_blocklist: dict = {}  # jti -> expiry epoch seconds


def _local_add(jti: str, ttl_seconds: int) -> None:
    import time
    _local_blocklist[jti] = time.time() + ttl_seconds


def _local_is_blocked(jti: str) -> bool:
    import time
    expiry = _local_blocklist.get(jti)
    if expiry is None:
        return False
    if time.time() > expiry:
        # Lazy eviction
        del _local_blocklist[jti]
        return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

BLOCKLIST_KEY_PREFIX = "jwt:blocklist:"


def add_to_blocklist(jti: str, ttl_seconds: int) -> None:
    """
    Mark *jti* as revoked for *ttl_seconds* seconds.

    Args:
        jti: The JWT ID claim value from the token being revoked.
        ttl_seconds: How long (in seconds) to keep the entry.  Should be set
            to the number of seconds until the token's natural expiry.
    """
    r = _get_redis()
    if r is not None:
        try:
            r.setex(f"{BLOCKLIST_KEY_PREFIX}{jti}", ttl_seconds, "1")
            return
        except Exception as exc:
            logger.error("Failed to write jti=%s to Redis blocklist: %s", jti, exc)
            # Fall through to local fallback so logout still works
    _local_add(jti, ttl_seconds)


def is_blocked(jti: str) -> bool:
    """
    Return True if *jti* appears in the blocklist (i.e. the token was revoked).

    Args:
        jti: The JWT ID claim value to check.
    """
    r = _get_redis()
    if r is not None:
        try:
            return r.exists(f"{BLOCKLIST_KEY_PREFIX}{jti}") == 1
        except Exception as exc:
            logger.error(
                "Failed to check jti=%s in Redis blocklist: %s — denying token to fail safe.",
                jti,
                exc,
            )
            # Fail-safe: if we cannot reach the blocklist, deny the request
            # rather than silently allowing potentially revoked tokens.
            return True
    return _local_is_blocked(jti)
