import os
from upstash_redis import Redis


redis = Redis(
    url=os.environ["UPSTASH_REDIS_REST_URL"],
    token=os.environ["UPSTASH_REDIS_REST_TOKEN"],
)


def get_token(service, key):
    return redis.get(f"{service}:{key}")


def set_token(service, key, value):
    if value is not None:
        redis.set(f"{service}:{key}", value)


def get_service_tokens(service):
    return {
        "access_token": get_token(service, "access_token"),
        "refresh_token": get_token(service, "refresh_token"),
        "expires_at": get_token(service, "expires_at"),
        "userid": get_token(service, "userid"),
    }


def save_service_tokens(service, tokens):
    for key, value in tokens.items():
        set_token(service, key, value)