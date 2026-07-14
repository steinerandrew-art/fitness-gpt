import os
import time
from datetime import datetime, timedelta, timezone

import requests

from token_store import (
    DEFAULT_USER_ID,
    get_service_tokens,
    save_service_tokens,
)


CLIENT_ID = os.environ["STRAVA_CLIENT_ID"]
CLIENT_SECRET = os.environ["STRAVA_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]


def get_strava_tokens(user_id=DEFAULT_USER_ID):
    """
    Loads the latest Strava tokens for the requested user from Redis.

    Tokens are loaded when needed instead of once when the module starts.
    """
    return get_service_tokens("strava", user_id)


# Temporary compatibility object used only by the existing app.py
# callback response. API requests below do not rely on this global object.
tokens = get_strava_tokens()


def exchange_strava_code(code, user_id=DEFAULT_USER_ID):
    response = requests.post(
        "https://www.strava.com/oauth/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
        },
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    token_data = response.json()

    tokens = {
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
        "expires_at": token_data["expires_at"],
    }

    athlete = token_data.get("athlete", {})
    if athlete:
        tokens["athlete_id"] = athlete.get("id")
        tokens["athlete_firstname"] = athlete.get("firstname")
        tokens["athlete_lastname"] = athlete.get("lastname")

    save_service_tokens("strava", tokens, user_id)

    # Keep the existing app.py callback response working during this
    # transitional step. Later, app.py will read the user directly.
    if user_id == DEFAULT_USER_ID:
        globals()["tokens"].clear()
        globals()["tokens"].update(tokens)

    return token_data, None


def ensure_access_token(user_id=DEFAULT_USER_ID):
    tokens = get_strava_tokens(user_id)

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_at = tokens.get("expires_at", 0)

    try:
        expires_at = float(expires_at)
    except (TypeError, ValueError):
        expires_at = 0

    if access_token and time.time() < expires_at - 60:
        return access_token

    if not refresh_token:
        return None

    response = requests.post(
        "https://www.strava.com/oauth/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        timeout=30,
    )

    if response.status_code != 200:
        return None

    token_data = response.json()

    refreshed_tokens = {
        "access_token": token_data["access_token"],
        "refresh_token": token_data["refresh_token"],
        "expires_at": token_data["expires_at"],
    }

    save_service_tokens("strava", refreshed_tokens, user_id)

    return refreshed_tokens["access_token"]


def get_recent_activities(days=14, per_page=100, user_id=DEFAULT_USER_ID):
    access_token = ensure_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Strava yet", 401)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    after_ts = int(cutoff.timestamp())

    response = requests.get(
        "https://www.strava.com/api/v3/athlete/activities",
        headers={"Authorization": f"Bearer {access_token}"},
        params={
            "after": after_ts,
            "page": 1,
            "per_page": per_page,
        },
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    return response.json(), None


def get_activity_detail(activity_id, user_id=DEFAULT_USER_ID):
    access_token = ensure_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Strava yet", 401)

    response = requests.get(
        f"https://www.strava.com/api/v3/activities/{activity_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    return response.json(), None


def get_activity_zones(activity_id, user_id=DEFAULT_USER_ID):
    access_token = ensure_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Strava yet", 401)

    response = requests.get(
        f"https://www.strava.com/api/v3/activities/{activity_id}/zones",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    return response.json(), None


def get_activity_streams(activity_id, user_id=DEFAULT_USER_ID):
    access_token = ensure_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Strava yet", 401)

    response = requests.get(
        f"https://www.strava.com/api/v3/activities/{activity_id}/streams",
        headers={"Authorization": f"Bearer {access_token}"},
        params={
            "keys": "time,watts,moving",
            "key_by_type": "true",
        },
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    return response.json(), None


def get_athlete_zones(user_id=DEFAULT_USER_ID):
    access_token = ensure_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Strava yet", 401)

    response = requests.get(
        "https://www.strava.com/api/v3/athlete/zones",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )

    if response.status_code != 200:
        return None, (response.text, response.status_code)

    return response.json(), None


def extract_zone_data(zones_payload):
    zone_summary = {}

    for zone_group in zones_payload:
        zone_type = zone_group.get("type")
        buckets = zone_group.get("distribution_buckets", [])

        if not zone_type or not buckets:
            continue

        zone_seconds = {}
        zone_minutes = {}
        zone_bounds = []

        for idx, bucket in enumerate(buckets, start=1):
            zone_name = f"z{idx}"
            seconds = bucket.get("time", 0) or 0

            zone_seconds[zone_name] = seconds
            zone_minutes[zone_name] = round(seconds / 60, 1)
            zone_bounds.append({
                "zone": zone_name,
                "min": bucket.get("min"),
                "max": bucket.get("max"),
            })

        zone_summary[zone_type] = {
            "seconds": zone_seconds,
            "minutes": zone_minutes,
            "bounds": zone_bounds,
            "custom_zones": zone_group.get("custom_zones"),
            "sensor_based": zone_group.get("sensor_based"),
            "score": zone_group.get("score"),
            "points": zone_group.get("points"),
        }

    return zone_summary