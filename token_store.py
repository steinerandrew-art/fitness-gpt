import os
from upstash_redis import Redis


redis = Redis(
    url=os.environ["UPSTASH_REDIS_REST_URL"],
    token=os.environ["UPSTASH_REDIS_REST_TOKEN"],
)

DEFAULT_USER_ID = os.getenv("DEFAULT_USER_ID", "default")
BROWSER_SESSION_PREFIX = "fitness:browser_session:"


def build_token_key(user_id, service, key):
    return f"fitness:user:{user_id}:service:{service}:{key}"


def get_legacy_token(service, key):
    return redis.get(f"{service}:{key}")


def get_token(service, key, user_id=DEFAULT_USER_ID):
    value = redis.get(build_token_key(user_id, service, key))
    if value is not None:
        return value
    if user_id == DEFAULT_USER_ID:
        return get_legacy_token(service, key)
    return None


def set_token(service, key, value, user_id=DEFAULT_USER_ID):
    if value is not None:
        redis.set(build_token_key(user_id, service, key), value)


def delete_token(service, key, user_id=DEFAULT_USER_ID):
    redis.delete(build_token_key(user_id, service, key))


def get_service_tokens(service, user_id=DEFAULT_USER_ID):
    keys = (
        "access_token", "refresh_token", "expires_at", "userid",
        "athlete_id", "athlete_firstname", "athlete_lastname",
    )
    return {key: get_token(service, key, user_id) for key in keys}


def save_service_tokens(service, tokens, user_id=DEFAULT_USER_ID):
    for key, value in tokens.items():
        set_token(service, key, value, user_id)


def delete_service_tokens(service, user_id=DEFAULT_USER_ID):
    for key in (
        "access_token", "refresh_token", "expires_at", "userid",
        "athlete_id", "athlete_firstname", "athlete_lastname",
    ):
        delete_token(service, key, user_id)


def save_browser_session(session_id, session_data, ttl_seconds):
    redis.set(f"{BROWSER_SESSION_PREFIX}{session_id}", session_data, ex=ttl_seconds)


def get_browser_session(session_id):
    if not session_id:
        return None
    return redis.get(f"{BROWSER_SESSION_PREFIX}{session_id}")


def delete_browser_session(session_id):
    if session_id:
        redis.delete(f"{BROWSER_SESSION_PREFIX}{session_id}")
