from datetime import datetime, timedelta, timezone
import os
import time

import requests

from token_store import DEFAULT_USER_ID, get_service_tokens, save_service_tokens


WITHINGS_CLIENT_ID = os.environ["WITHINGS_CLIENT_ID"]
WITHINGS_CLIENT_SECRET = os.environ["WITHINGS_CLIENT_SECRET"]
WITHINGS_REDIRECT_URI = os.environ["WITHINGS_REDIRECT_URI"]
WITHINGS_REFRESH_TOKEN = os.getenv("WITHINGS_REFRESH_TOKEN")


def get_withings_tokens(user_id=DEFAULT_USER_ID):
    return get_service_tokens("withings", user_id)


def withings_connection(user_id=DEFAULT_USER_ID):
    tokens = get_withings_tokens(user_id)
    return {
        "connected": bool(tokens.get("refresh_token") or tokens.get("access_token")),
        "withings_user_id": tokens.get("userid"),
        "expires_at": tokens.get("expires_at"),
    }


def refresh_withings_access_token(user_id=DEFAULT_USER_ID):
    tokens = get_withings_tokens(user_id)
    refresh_token = tokens.get("refresh_token")

    if not refresh_token and user_id == DEFAULT_USER_ID:
        refresh_token = WITHINGS_REFRESH_TOKEN

    if not refresh_token:
        return None

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
        return None

    if response.status_code != 200 or data.get("status") != 0:
        return None

    body = data.get("body") or {}
    save_service_tokens("withings", {
        "access_token": body.get("access_token"),
        "refresh_token": body.get("refresh_token"),
        "userid": body.get("userid") or tokens.get("userid"),
        "expires_at": int(time.time()) + int(body.get("expires_in", 10800)),
    }, user_id)

    return body.get("access_token")


def ensure_withings_access_token(user_id=DEFAULT_USER_ID):
    tokens = get_withings_tokens(user_id)
    access_token = tokens.get("access_token")
    try:
        expires_at = float(tokens.get("expires_at") or 0)
    except (TypeError, ValueError):
        expires_at = 0

    if access_token and time.time() < expires_at - 60:
        return access_token
    return refresh_withings_access_token(user_id)


def exchange_withings_code(code, user_id=DEFAULT_USER_ID):
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
        return None, (response.text, response.status_code)

    if response.status_code != 200 or data.get("status") != 0:
        return None, (data, response.status_code or 400)

    body = data.get("body") or {}
    save_service_tokens("withings", {
        "access_token": body.get("access_token"),
        "refresh_token": body.get("refresh_token"),
        "userid": body.get("userid"),
        "expires_at": int(time.time()) + int(body.get("expires_in", 10800)),
    }, user_id)

    return body, None


def get_withings_measures(user_id=DEFAULT_USER_ID):
    access_token = ensure_withings_access_token(user_id)
    if not access_token:
        return None, ("Not connected to Withings", 401)

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
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )

    try:
        data = response.json()
    except ValueError:
        return None, (response.text, response.status_code)

    if response.status_code != 200 or data.get("status") != 0:
        return None, (data, response.status_code or 400)

    return data.get("body", {}), None


def get_withings_summary(user_id=DEFAULT_USER_ID):
    body, error = get_withings_measures(user_id)
    if error:
        status_code = error[1] if isinstance(error, tuple) and len(error) > 1 else None
        return {"status": "not_connected" if status_code == 401 else "temporarily_unavailable"}

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
        field_name = MEASURE_TYPES.get(measure.get("type"))
        if field_name:
            parsed["measurements"][field_name] = round(convert_measure_value(measure), 3)

    if "weight_kg" in parsed["measurements"]:
        parsed["measurements"]["weight_lb"] = round(
            parsed["measurements"]["weight_kg"] * 2.20462, 1
        )
    return parsed


def average(values):
    clean = [value for value in values if value is not None]
    return sum(clean) / len(clean) if clean else None


def calculate_weight_trends(parsed_groups):
    weights = [
        group.get("measurements", {}).get("weight_lb")
        for group in parsed_groups
        if group.get("measurements", {}).get("weight_lb") is not None
    ]
    if len(weights) < 2:
        return {"status": "insufficient_data"}

    recent_avg = average(weights[:min(3, len(weights))])
    older_avg = average(weights[-min(3, len(weights)):])
    smoothed_change = (
        recent_avg - older_avg
        if recent_avg is not None and older_avg is not None
        else None
    )
    return {
        "status": "ok",
        "weight_change_simple_lb": round(weights[0] - weights[-1], 1),
        "weight_change_smoothed_lb": round(smoothed_change, 1) if smoothed_change is not None else None,
        "latest_weight_lb": round(weights[0], 1),
        "oldest_weight_lb": round(weights[-1], 1),
        "latest_3_avg_weight_lb": round(recent_avg, 1) if recent_avg is not None else None,
        "oldest_3_avg_weight_lb": round(older_avg, 1) if older_avg is not None else None,
        "measurement_count": len(weights),
    }
