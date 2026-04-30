import os
import time
from datetime import datetime, timedelta, timezone
from token_store import get_service_tokens, save_service_tokens

import requests


CLIENT_ID = os.environ["STRAVA_CLIENT_ID"]
CLIENT_SECRET = os.environ["STRAVA_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]

tokens = get_service_tokens("strava")


def exchange_strava_code(code):
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

    tokens["access_token"] = token_data["access_token"]
    tokens["refresh_token"] = token_data["refresh_token"]
    tokens["expires_at"] = token_data["expires_at"]
    tokens["athlete"] = token_data.get("athlete", {})
    save_service_tokens("strava", tokens)

    return token_data, None


def ensure_access_token():
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_at = tokens.get("expires_at", 0)

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
    tokens["access_token"] = token_data["access_token"]
    tokens["refresh_token"] = token_data["refresh_token"]
    tokens["expires_at"] = token_data["expires_at"]
    save_service_tokens("strava", tokens)

    return tokens["access_token"]


def get_recent_activities(days=14, per_page=100):
    access_token = ensure_access_token()
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


def get_activity_detail(activity_id):
    access_token = ensure_access_token()
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


def get_activity_zones(activity_id):
    access_token = ensure_access_token()
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