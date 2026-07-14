import os
import time
from datetime import datetime, timedelta, timezone

import requests

from token_store import (
    DEFAULT_USER_ID,
    get_service_tokens,
    save_service_tokens,
)


WITHINGS_CLIENT_ID = os.environ["WITHINGS_CLIENT_ID"]
WITHINGS_CLIENT_SECRET = os.environ["WITHINGS_CLIENT_SECRET"]
WITHINGS_REDIRECT_URI = os.environ["WITHINGS_REDIRECT_URI"]

# Temporary fallback for the existing single-user deployment.
# This can be removed after all users have migrated to Redis-backed tokens.
WITHINGS_REFRESH_TOKEN = os.getenv("WITHINGS_REFRESH_TOKEN")


def get_withings_tokens(user_id=DEFAULT_USER_ID):
    """
    Loads the latest Withings tokens for the requested user from Redis.
    """
    return get_service_tokens("withings", user_id)


def refresh_withings_access_token(user_id=DEFAULT_USER_ID):
    """
    Refreshes the requested user's Withings access token.

    Returns:
        (access_token, None) on success
        (None, (message, status_code)) on failure
    """
    tokens = get_withings_tokens(user_id)
    refresh_token = tokens.get("refresh_token")

    if not refresh_token and user_id == DEFAULT_USER_ID:
        refresh_token = WITHINGS_REFRESH_TOKEN

    if not refresh_token:
        return None, ("Withings is not connected", 401)

    response = requests.post(
        "https://wbsapi.withings.net/v2/oauth2",
        data={
            "action": "requesttoken",
            "grant_type": "refresh_token",
            "client_id": WITHINGS_CLIENT_ID,
            "client_secret": WITHINGS_CLIENT_SECRET,
            "refresh_token": refresh_token,
        },
        timeout=30,
    )

    try:
        data = response.json()
    except ValueError:
        return None, (response.text or "Invalid Withings response", response.status_code)

    if response.status_code != 200 or data.get("status") != 0:
        return None, (
            data.get("error") or data.get("body") or response.text or "Withings token refresh failed",
            response.status_code,
        )

    body = data.get("body", {})

    refreshed_tokens = {
        "access_token": body.get("access_token"),
        "refresh_token": body.get("refresh_token"),
        "userid": body.get("userid"),
        "expires_at": time.time() + body.get("expires_in", 10800),
    }

    save_service_tokens("withings", refreshed_tokens, user_id)

    return refreshed_tokens["access_token"], None


def ensure_withings_access_token(user_id=DEFAULT_USER_ID):
    """
    Returns a valid Withings access token, refreshing it when necessary.
    """
    tokens = get_withings_tokens(user_id)

    access_token = tokens.get("access_token")
    expires_at = tokens.get("expires_at", 0)

    try:
        expires_at = float(expires_at)
    except (TypeError, ValueError):
        expires_at = 0

    if access_token and time.time() < expires_at - 60:
        return access_token, None

    return refresh_withings_access_token(user_id)


def exchange_withings_code(code, user_id=DEFAULT_USER_ID):
    """
    Exchanges a Withings authorization code for user-specific tokens.

    Returns:
        (token_body, None) on success
        (None, (message, status_code)) on failure
    """
    response = requests.post(
        "https://wbsapi.withings.net/v2/oauth2",
        data={
            "action": "requesttoken",
            "grant_type": "authorization_code",
            "client_id": WITHINGS_CLIENT_ID,
            "client_secret": WITHINGS_CLIENT_SECRET,
            "code": code,
            "redirect_uri": WITHINGS_REDIRECT_URI,
        },
        timeout=30,
    )

    try:
        data = response.json()
    except ValueError:
        return None, (response.text or "Invalid Withings response", response.status_code)

    if response.status_code != 200 or data.get("status") != 0:
        return None, (
            data.get("error") or data.get("body") or response.text or "Withings token exchange failed",
            response.status_code,
        )

    body = data.get("body", {})

    tokens = {
        "access_token": body.get("access_token"),
        "refresh_token": body.get("refresh_token"),
        "userid": body.get("userid"),
        "expires_at": time.time() + body.get("expires_in", 10800),
    }

    save_service_tokens("withings", tokens, user_id)

    return body, None


def get_withings_measures(user_id=DEFAULT_USER_ID):
    """
    Retrieves the requested user's recent Withings measurements.

    Returns:
        (body, None) on success
        (None, (message, status_code)) on failure
    """
    access_token, token_error = ensure_withings_access_token(user_id)

    if token_error:
        return None, token_error

    enddate = int(datetime.now(timezone.utc).timestamp())
    startdate = int((datetime.now(timezone.utc) - timedelta(days=14)).timestamp())

    response = requests.post(
        "https://wbsapi.withings.net/measure",
        data={
            "action": "getmeas",
            "meastype": "1,5,6,8,76,77,88",
            "category": 1,
            "startdate": startdate,
            "enddate": enddate,
        },
        headers={
            "Authorization": f"Bearer {access_token}"
        },
        timeout=30,
    )

    try:
        data = response.json()
    except ValueError:
        return None, (response.text or "Invalid Withings response", response.status_code)

    if response.status_code != 200 or data.get("status") != 0:
        return None, (
            data.get("error") or data.get("body") or response.text or "Withings measurement request failed",
            response.status_code,
        )

    return data.get("body", {}), None


def get_withings_summary(user_id=DEFAULT_USER_ID):
    body, error = get_withings_measures(user_id)

    if error:
        message, status = error
        return {
            "status": "not_connected" if status == 401 else "temporarily_unavailable",
            "message": str(message),
        }

    measure_groups = body.get("measuregrps", [])

    parsed_groups = [
        parse_measure_group(group)
        for group in measure_groups
        if any(m.get("type") == 1 for m in group.get("measures", []))
    ]

    latest = parsed_groups[0] if parsed_groups else None
    recent_measurements = parsed_groups[:14]
    trends = calculate_weight_trends(recent_measurements)

    return {
        "status": "connected",
        "latest": latest,
        "trends": trends,
        "recent_measurement_count": len(parsed_groups),
        "recent_measurements": recent_measurements,
    }


MEASURE_TYPES = {
    1: "weight_kg",
    5: "fat_free_mass_kg",
    6: "fat_ratio_pct",
    8: "fat_mass_kg",
    76: "muscle_mass_kg",
    77: "hydration_kg",
    88: "bone_mass_kg",
}


def convert_measure_value(measure):
    return measure["value"] * (10 ** measure["unit"])


def parse_measure_group(group):
    parsed = {
        "date_unix": group.get("date"),
        "date": datetime.fromtimestamp(
            group.get("date"), timezone.utc
        ).isoformat() if group.get("date") else None,
        "timezone": group.get("timezone"),
        "model": group.get("model"),
        "measurements": {},
    }

    for measure in group.get("measures", []):
        measure_type = measure.get("type")
        field_name = MEASURE_TYPES.get(measure_type)

        if not field_name:
            continue

        parsed["measurements"][field_name] = round(
            convert_measure_value(measure), 3
        )

    if "weight_kg" in parsed["measurements"]:
        parsed["measurements"]["weight_lb"] = round(
            parsed["measurements"]["weight_kg"] * 2.20462, 1
        )

    return parsed


def average(values):
    clean_values = [value for value in values if value is not None]

    if not clean_values:
        return None

    return sum(clean_values) / len(clean_values)


def calculate_weight_trends(parsed_groups):
    """
    parsed_groups should be newest-first.
    """
    weights = [
        group.get("measurements", {}).get("weight_lb")
        for group in parsed_groups
        if group.get("measurements", {}).get("weight_lb") is not None
    ]

    if len(weights) < 2:
        return {
            "status": "insufficient_data"
        }

    simple_change = weights[0] - weights[-1]

    recent_count = min(3, len(weights))
    older_count = min(3, len(weights))

    recent_avg = average(weights[:recent_count])
    older_avg = average(weights[-older_count:])

    smoothed_change = None
    if recent_avg is not None and older_avg is not None:
        smoothed_change = recent_avg - older_avg

    return {
        "status": "ok",
        "weight_change_simple_lb": round(simple_change, 1),
        "weight_change_smoothed_lb": (
            round(smoothed_change, 1)
            if smoothed_change is not None
            else None
        ),
        "latest_weight_lb": round(weights[0], 1),
        "oldest_weight_lb": round(weights[-1], 1),
        "latest_3_avg_weight_lb": (
            round(recent_avg, 1)
            if recent_avg is not None
            else None
        ),
        "oldest_3_avg_weight_lb": (
            round(older_avg, 1)
            if older_avg is not None
            else None
        ),
        "measurement_count": len(weights),
    }