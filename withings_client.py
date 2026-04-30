from datetime import datetime, timedelta, timezone

import os
import requests

WITHINGS_CLIENT_ID = os.environ["WITHINGS_CLIENT_ID"]
WITHINGS_CLIENT_SECRET = os.environ["WITHINGS_CLIENT_SECRET"]
WITHINGS_REDIRECT_URI = os.environ["WITHINGS_REDIRECT_URI"]

withings_tokens = {}


def exchange_withings_code(code):
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

    data = response.json()

    if response.status_code != 200 or data.get("status") != 0:
        return None, (data, 400)

    body = data["body"]

    withings_tokens["access_token"] = body["access_token"]
    withings_tokens["refresh_token"] = body["refresh_token"]
    withings_tokens["userid"] = body["userid"]
    withings_tokens["expires_in"] = body["expires_in"]

    return body, None


def get_withings_summary():
    body, error = get_withings_measures()

    if error:
        return {
            "status": "not_connected",
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
        "recent_measurements": recent_measurements
    }

def get_withings_measures():
    access_token = withings_tokens.get("access_token")

    if not access_token:
        return None, ("Not connected to Withings yet", 401)

    enddate = int(datetime.now(timezone.utc).timestamp())
    startdate = int((datetime.now(timezone.utc) - timedelta(days=14)).timestamp())
    
    response = requests.post(
        "https://wbsapi.withings.net/measure",
        data={
            "action": "getmeas",
            "meastype": "1,5,6,8,76,77,88",
            "category": 1,
            "startdate": startdate,   # 👈 ADD
            "enddate": enddate,       # 👈 ADD
        },
        headers={
            "Authorization": f"Bearer {access_token}"
        },
        timeout=30,
    )

    data = response.json()

    if response.status_code != 200 or data.get("status") != 0:
        return None, (data, 400)

    return data.get("body", {}), None

from datetime import datetime, timezone


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
        "measurements": {}
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
    clean_values = [v for v in values if v is not None]

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
        "weight_change_smoothed_lb": round(smoothed_change, 1) if smoothed_change is not None else None,
        "latest_weight_lb": round(weights[0], 1),
        "oldest_weight_lb": round(weights[-1], 1),
        "latest_3_avg_weight_lb": round(recent_avg, 1) if recent_avg is not None else None,
        "oldest_3_avg_weight_lb": round(older_avg, 1) if older_avg is not None else None,
        "measurement_count": len(weights)
    }