import os
from upstash_redis import Redis


redis = Redis(
    url=os.environ["UPSTASH_REDIS_REST_URL"],
    token=os.environ["UPSTASH_REDIS_REST_TOKEN"],
)


DEFAULT_USER_ID = os.getenv("DEFAULT_USER_ID", "default")


def build_token_key(user_id, service, key):
    return f"fitness:user:{user_id}:service:{service}:{key}"


def get_legacy_token(service, key):
    """
    Reads tokens stored using the old single-user key format.

    Example old key:
        strava:access_token
    """
    return redis.get(f"{service}:{key}")


def get_token(service, key, user_id=DEFAULT_USER_ID):
    """
    Reads a token using the new user-specific key format.

    If the token has not yet been migrated, this temporarily falls back
    to the old single-user key.
    """
    redis_key = build_token_key(user_id, service, key)
    value = redis.get(redis_key)

    if value is not None:
        return value

    # Legacy single-user keys belong only to the configured default user.
    # Without this check, a newly added user with no stored tokens could
    # accidentally inherit the default user's Strava or Withings account.
    if user_id == DEFAULT_USER_ID:
        return get_legacy_token(service, key)

    return None


def set_token(service, key, value, user_id=DEFAULT_USER_ID):
    """
    Saves a token using the new user-specific key format.
    """
    if value is None:
        return

    redis_key = build_token_key(user_id, service, key)
    redis.set(redis_key, value)


def get_service_tokens(service, user_id=DEFAULT_USER_ID):
    return {
        "access_token": get_token(service, "access_token", user_id),
        "refresh_token": get_token(service, "refresh_token", user_id),
        "expires_at": get_token(service, "expires_at", user_id),
        "userid": get_token(service, "userid", user_id),
    }


def save_service_tokens(service, tokens, user_id=DEFAULT_USER_ID):
    for key, value in tokens.items():
        set_token(service, key, value, user_id)

# ---------------------------------------------------------------------------
# Browser account sessions
# ---------------------------------------------------------------------------

BROWSER_SESSION_PREFIX = "fitness:browser_session:"


def save_browser_session(session_id, session_data, ttl_seconds):
    """Store a server-side browser session with automatic expiration."""
    redis.set(f"{BROWSER_SESSION_PREFIX}{session_id}", session_data, ex=ttl_seconds)


def get_browser_session(session_id):
    """Return a stored browser session, or None if it is missing/expired."""
    if not session_id:
        return None
    return redis.get(f"{BROWSER_SESSION_PREFIX}{session_id}")


def delete_browser_session(session_id):
    """Delete a browser session immediately."""
    if session_id:
        redis.delete(f"{BROWSER_SESSION_PREFIX}{session_id}")