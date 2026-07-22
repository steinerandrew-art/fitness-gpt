import base64
import hashlib
import hmac
import json
import os
import time

from flask import Flask, jsonify, redirect, request

from strava_client import (
    CLIENT_ID,
    REDIRECT_URI,
    get_recent_activities,
    get_activity_detail,
    get_activity_zones,
    get_activity_streams,
    get_athlete_zones,
    extract_zone_data,
    exchange_strava_code,
)

from training_zones import summarize_power_stream_intensity

from withings_client import (
    get_withings_summary,
    exchange_withings_code,
    WITHINGS_CLIENT_ID,
    WITHINGS_REDIRECT_URI,
)

from datetime import datetime, timezone
from functools import wraps

from token_store import DEFAULT_USER_ID

app = Flask(__name__)


def configured_api_users():
    """Return an API-key-to-user-ID mapping from Render variables."""
    users = {}

    default_key = os.getenv("FITNESS_API_KEY_ANDREW")
    if default_key:
        users[default_key] = DEFAULT_USER_ID

    second_user_id = os.getenv("SECOND_USER_ID")
    second_user_key = os.getenv("FITNESS_API_KEY_SECOND_USER")
    if second_user_id and second_user_key:
        users[second_user_key] = second_user_id

    return users


def user_id_for_api_key(api_key):
    if not api_key:
        return None

    for configured_key, user_id in configured_api_users().items():
        if hmac.compare_digest(api_key, configured_key):
            return user_id

    return None


def api_key_from_request():
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()

    return request.headers.get("X-API-Key")


def require_api_user(view_function):
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        user_id = user_id_for_api_key(api_key_from_request())
        if not user_id:
            return jsonify({
                "error": "Valid API key required",
                "authentication": "Send Authorization: Bearer <API key>"
            }), 401

        return view_function(user_id, *args, **kwargs)

    return wrapped


def oauth_state_secret():
    secret = os.getenv("OAUTH_STATE_SECRET")
    if not secret:
        raise RuntimeError("OAUTH_STATE_SECRET is not configured")
    return secret.encode("utf-8")


def create_oauth_state(user_id, service):
    payload = {
        "user_id": user_id,
        "service": service,
        "issued_at": int(time.time()),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    signature = hmac.new(
        oauth_state_secret(),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def read_oauth_state(state, expected_service):
    if not state or "." not in state:
        return None

    encoded_payload, supplied_signature = state.rsplit(".", 1)
    expected_signature = hmac.new(
        oauth_state_secret(),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(supplied_signature, expected_signature):
        return None

    padded_payload = encoded_payload + "=" * (-len(encoded_payload) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded_payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None

    if payload.get("service") != expected_service:
        return None

    issued_at = payload.get("issued_at", 0)
    if not isinstance(issued_at, int) or time.time() - issued_at > 900:
        return None

    user_id = payload.get("user_id")
    if user_id not in configured_api_users().values():
        return None

    return user_id


def connection_form(service_name, action_path):
    return f"""
    <h1>Connect {service_name}</h1>
    <p>Enter the API key assigned to the user whose {service_name} account is being connected.</p>
    <form method="post" action="{action_path}">
      <label>API key: <input type="password" name="api_key" required></label>
      <button type="submit">Continue to {service_name}</button>
    </form>
    """

@app.route("/")
def home():
    return """
    <h1>Fitness GPT backend is running</h1>
    <p><a href="/login">Connect Strava for a user</a></p>
    <p><a href="/connect/withings">Connect Withings for a user</a></p>
    <p><a href="/workouts">View workouts</a></p>
    <p><a href="/summary">View summary</a></p>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return connection_form("Strava", "/login")

    user_id = user_id_for_api_key(request.form.get("api_key"))
    if not user_id:
        return "Invalid API key", 401

    state = create_oauth_state(user_id, "strava")
    auth_url = (
        "https://www.strava.com/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        "&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        "&approval_prompt=force"
        "&scope=read,activity:read_all,profile:read_all"
        f"&state={state}"
    )
    return redirect(auth_url)


@app.route("/exchange_token")
def exchange_token():
    code = request.args.get("code")
    error = request.args.get("error")
    user_id = read_oauth_state(request.args.get("state"), "strava")

    if not user_id:
        return "Invalid or expired OAuth state", 400

    if error:
        return f"Authorization failed: {error}", 400

    if not code:
        return "Missing authorization code", 400

    token_data, error = exchange_strava_code(code, user_id=user_id)

    if error:
        message, status = error
        return f"Token exchange failed: {message}", status

    return jsonify({
        "message": "Strava connected successfully",
        "user_id": user_id,
        "athlete": token_data.get("athlete", {}),
        "expires_at": token_data.get("expires_at")
    })


@app.route("/activity/<int:activity_id>")
@require_api_user
def activity_detail(user_id, activity_id):
    detail, error = get_activity_detail(activity_id, user_id=user_id)
    if error:
        message, status = error
        return jsonify({"error": message}), status
    return jsonify(detail)

BIKE_SPORTS = {"Ride", "VirtualRide"}

def parse_strava_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def has_power(a):
    return bool(
        a.get("average_watts")
        or a.get("weighted_average_watts")
        or a.get("device_watts")
    )

def activity_quality_score(a):
    score = 0
    name = (a.get("name") or "").lower()

    if a.get("sport_type") == "VirtualRide":
        score += 100
    if "zwift" in name:
        score += 50
    if has_power(a):
        score += 40
    if (a.get("distance") or 0) > 0:
        score += 20
    if (a.get("total_elevation_gain") or 0) > 0:
        score += 10

    return score

def are_duplicate_bike_activities(a, b):
    if a.get("sport_type") not in BIKE_SPORTS:
        return False
    if b.get("sport_type") not in BIKE_SPORTS:
        return False

    a_start = parse_strava_time(a.get("start_date"))
    b_start = parse_strava_time(b.get("start_date"))

    if not a_start or not b_start:
        return False

    start_diff_s = abs((a_start - b_start).total_seconds())
    elapsed_diff_s = abs((a.get("elapsed_time") or 0) - (b.get("elapsed_time") or 0))

    a_elapsed = a.get("elapsed_time") or 0
    b_elapsed = b.get("elapsed_time") or 0
    longer_elapsed = max(a_elapsed, b_elapsed)

    if longer_elapsed == 0:
        return False

    duration_close = elapsed_diff_s <= 300 or elapsed_diff_s / longer_elapsed <= 0.15

    a_hr = a.get("average_heartrate")
    b_hr = b.get("average_heartrate")
    hr_close = (
        a_hr is None
        or b_hr is None
        or abs(a_hr - b_hr) <= 5
    )

    return start_diff_s <= 300 and duration_close and hr_close

def dedupe_activities(activities):
    kept = []
    removed = []

    for activity in sorted(activities, key=lambda x: x.get("start_date") or ""):
        matched_index = None

        for i, existing in enumerate(kept):
            if are_duplicate_bike_activities(activity, existing):
                matched_index = i
                break

        if matched_index is None:
            kept.append(activity)
            continue

        existing = kept[matched_index]

        if activity_quality_score(activity) > activity_quality_score(existing):
            kept[matched_index] = activity
            removed.append({
                "removed_id": existing.get("id"),
                "removed_name": existing.get("name"),
                "kept_id": activity.get("id"),
                "kept_name": activity.get("name"),
                "reason": "duplicate bike activity; kept richer activity"
            })
        else:
            removed.append({
                "removed_id": activity.get("id"),
                "removed_name": activity.get("name"),
                "kept_id": existing.get("id"),
                "kept_name": existing.get("name"),
                "reason": "duplicate bike activity; kept richer activity"
            })

    return kept, removed


@app.route("/workouts")
@require_api_user
def workouts(user_id):
    activities, error = get_recent_activities(days=14, per_page=100, user_id=user_id)
    if error:
        message, status = error

        if status == 401 or "Not connected to Strava yet" in str(message):
            return jsonify({"error": "Strava is not connected for this user"}), 401

        return jsonify({"error": message}), status

    activities, dedupe_removed = dedupe_activities(activities)
    
    enriched = []

    for a in activities:
        activity_id = a.get("id")
        zones = {}

        if activity_id:
            zones_payload, zones_error = get_activity_zones(activity_id, user_id=user_id)
            if not zones_error:
                zones = extract_zone_data(zones_payload)

        enriched.append({
            "id": activity_id,
            "name": a.get("name"),
            "sport_type": a.get("sport_type"),
            "start_date": a.get("start_date"),
            "distance_m": a.get("distance", 0),
            "moving_time_s": a.get("moving_time", 0),
            "elapsed_time_s": a.get("elapsed_time", 0),
            "total_elevation_gain_m": a.get("total_elevation_gain", 0),
            "avg_heartrate": a.get("average_heartrate"),
            "max_heartrate": a.get("max_heartrate"),
            "has_heartrate": a.get("has_heartrate", False),

            # legacy-friendly fields
            "hr_zone_seconds": zones.get("heartrate", {}).get("seconds"),
            "hr_zone_minutes": zones.get("heartrate", {}).get("minutes"),
            "hr_zone_bounds": zones.get("heartrate", {}).get("bounds"),

            # generalized structure: heartrate, power, pace, etc.
            "zones": zones
        })

    return jsonify({
    "workouts": enriched,
    "dedupe": {
        "removed_count": len(dedupe_removed),
        "removed": dedupe_removed
    }
    })


@app.route("/connect/withings", methods=["GET", "POST"])
def connect_withings():
    if request.method == "GET":
        return connection_form("Withings", "/connect/withings")

    user_id = user_id_for_api_key(request.form.get("api_key"))
    if not user_id:
        return "Invalid API key", 401

    state = create_oauth_state(user_id, "withings")
    auth_url = (
        "https://account.withings.com/oauth2_user/authorize2"
        "?response_type=code"
        f"&client_id={WITHINGS_CLIENT_ID}"
        f"&redirect_uri={WITHINGS_REDIRECT_URI}"
        "&scope=user.info,user.metrics"
        f"&state={state}"
    )
    return redirect(auth_url)


@app.route("/callback/withings")
def callback_withings():
    code = request.args.get("code")
    error = request.args.get("error")
    user_id = read_oauth_state(request.args.get("state"), "withings")

    if not user_id:
        return "Invalid or expired OAuth state", 400

    if error:
        return f"Withings authorization failed: {error}", 400

    if not code:
        return "Missing Withings authorization code", 400

    token_data, token_error = exchange_withings_code(code, user_id=user_id)

    if token_error:
        message, status = token_error
        return jsonify({
            "error": "Withings token exchange failed",
            "details": message
        }), status

    return jsonify({
        "message": "Withings connected successfully",
        "user_id": user_id,
        "userid": token_data.get("userid"),
        "expires_in": token_data.get("expires_in")
    })


def build_coaching_insights(summary_data, withings_data):
    insights = []

    total_hours = summary_data.get("total_moving_time_hr", 0)
    workout_count = summary_data.get("workout_count", 0)
    sport_counts = summary_data.get("sport_counts", {})
    flags = summary_data.get("flags", [])

    if "high_training_volume" in flags:
        insights.append(
            f"High training volume: {total_hours} hours across {workout_count} workouts in this period."
        )

    if workout_count >= 10:
        insights.append(
            "Workout frequency is high, so recovery quality should be watched closely."
        )

    if len(sport_counts) >= 3:
        insights.append(
            "Training mix is diversified across multiple activity types."
        )

    withings_status = withings_data.get("status")

    if withings_status == "connected":
        trends = withings_data.get("trends", {})
        smoothed_weight_change = trends.get("weight_change_smoothed_lb")

        if smoothed_weight_change is not None:
            if abs(smoothed_weight_change) < 1:
                insights.append(
                    f"Smoothed weight trend is stable at {smoothed_weight_change:+.1f} lb."
                )
            elif smoothed_weight_change > 0:
                insights.append(
                    f"Smoothed weight trend is up {smoothed_weight_change:+.1f} lb; consider hydration, sodium, soreness, and training load before treating it as tissue gain."
                )
            else:
                insights.append(
                    f"Smoothed weight trend is down {smoothed_weight_change:+.1f} lb; watch whether energy and workout quality remain strong."
                )

        latest = withings_data.get("latest") or {}
        measurements = latest.get("measurements", {})

        if measurements.get("weight_lb") is not None:
            insights.append(
                f"Latest weight is {measurements.get('weight_lb')} lb."
            )

        if measurements.get("fat_ratio_pct") is not None:
            insights.append(
                f"Latest body fat estimate is {measurements.get('fat_ratio_pct')}%, which should be treated as directional rather than exact."
            )

    elif withings_status in {"not_connected", "temporarily_unavailable"}:
        insights.append(
            "Withings data was unavailable, so coaching is based on Strava data only."
        )

    if not insights:
        insights.append("Not enough combined training and body data yet to generate useful insights.")

    return insights


def summarize_zone_minutes(zones, preferred_types):
    """
    Returns zone minutes for the first available preferred zone type.
    Example preferred_types: ["power", "heartrate"]
    """
    for zone_type in preferred_types:
        zone_data = zones.get(zone_type)
        if zone_data and zone_data.get("minutes"):
            return {
                "zone_type": zone_type,
                "minutes": zone_data.get("minutes"),
                "bounds": zone_data.get("bounds")
            }

    return {
        "zone_type": None,
        "minutes": {},
        "bounds": []
    }


def get_zone_minutes(zones, zone_type):
    zone_data = zones.get(zone_type, {})
    return zone_data.get("minutes", {}) or {}

def zone_sum(minutes, zone_names):
    return sum(minutes.get(z, 0) or 0 for z in zone_names)

def has_zone_data(minutes):
    return sum(minutes.values()) > 0

def classify_from_minutes(easy_minutes, moderate_minutes, hard_minutes):
    if hard_minutes >= 15:
        return "hard"
    if hard_minutes >= 5 or moderate_minutes >= 15:
        return "moderate"
    return "easy"


def classify_running_intensity(pace_minutes, hr_minutes):
    pace_hard = pace_minutes["z4"] + pace_minutes["z5"]
    pace_moderate = pace_minutes["z3"]

    hr_hard = hr_minutes["z4"] + hr_minutes["z5"]
    hr_moderate = hr_minutes["z3"]

    if pace_hard >= 15 or hr_hard >= 15:
        return "hard"

    if pace_hard >= 5 or hr_hard >= 5 or pace_moderate >= 20 or hr_moderate >= 20:
        return "moderate"

    return "easy"


def build_intensity_summary(activities):
    intensity_summary = {
        "hard_workout_count": 0,
        "moderate_workout_count": 0,
        "easy_workout_count": 0,
        "workouts": []
    }

    for a in activities:
        activity_id = a.get("id")
        sport = a.get("sport_type", "Unknown")
        name = a.get("name")

        zones = a.get("zones", {})

        power_minutes = get_zone_minutes(zones, "power")
        hr_minutes = get_zone_minutes(zones, "heartrate")
        pace_minutes = get_zone_minutes(zones, "pace")

        if sport in ["VirtualRide", "Ride"]:
            stream_power = a.get("power_stream_intensity", {})
            has_stream_power = stream_power.get("has_power_stream", False)

            if has_stream_power:
                easy_minutes = stream_power.get("easy_minutes", 0)
                moderate_minutes = stream_power.get("moderate_minutes", 0)
                hard_minutes = stream_power.get("hard_minutes", 0)
                primary_zone_type = "ftp_power_streams"
            else:
                hard_minutes = zone_sum(hr_minutes, ["z4", "z5"])
                moderate_minutes = zone_sum(hr_minutes, ["z3"])
                easy_minutes = zone_sum(hr_minutes, ["z1", "z2"])
                primary_zone_type = "heartrate"

            intensity = classify_from_minutes(
                easy_minutes,
                moderate_minutes,
                hard_minutes
            )

        elif sport == "Run":
            if has_zone_data(pace_minutes):
                primary_zone_type = "pace"
                easy_minutes = zone_sum(pace_minutes, ["z1", "z2"])
                moderate_minutes = zone_sum(pace_minutes, ["z3"])
                hard_minutes = zone_sum(pace_minutes, ["z4", "z5", "z6"])
            else:
                primary_zone_type = "heartrate"
                easy_minutes = zone_sum(hr_minutes, ["z1", "z2"])
                moderate_minutes = zone_sum(hr_minutes, ["z3"])
                hard_minutes = zone_sum(hr_minutes, ["z4", "z5"])

            intensity = classify_from_minutes(
                easy_minutes,
                moderate_minutes,
                hard_minutes
            )

        else:
            primary_zone_type = "heartrate"
            easy_minutes = zone_sum(hr_minutes, ["z1", "z2"])
            moderate_minutes = zone_sum(hr_minutes, ["z3"])
            hard_minutes = zone_sum(hr_minutes, ["z4", "z5"])

            intensity = classify_from_minutes(
                easy_minutes,
                moderate_minutes,
                hard_minutes
            )

        zone_total_minutes = easy_minutes + moderate_minutes + hard_minutes
        moving_minutes = (a.get("moving_time") or 0) / 60

        zone_minutes_check = {
            "zone_total_minutes": round(zone_total_minutes, 1),
            "moving_minutes": round(moving_minutes, 1),
            "difference_minutes": round(zone_total_minutes - moving_minutes, 1),
            "close_enough": abs(zone_total_minutes - moving_minutes) <= 5
        }
        
        if intensity == "hard":
            intensity_summary["hard_workout_count"] += 1
        elif intensity == "moderate":
            intensity_summary["moderate_workout_count"] += 1
        else:
            intensity_summary["easy_workout_count"] += 1

        intensity_summary["workouts"].append({
            "id": activity_id,
            "name": name,
            "sport_type": sport,
            "start_date": a.get("start_date"),
            "zone_type_used": primary_zone_type,
            "easy_minutes": round(easy_minutes, 1),
            "moderate_minutes": round(moderate_minutes, 1),
            "hard_minutes": round(hard_minutes, 1),
            "intensity": intensity,
            "zone_minutes_check": zone_minutes_check
        })

    return intensity_summary


def calculate_readiness(summary_data, withings_data):
    reasons = []
    caution_points = 0

    flags = summary_data.get("flags", [])

    if "high_training_volume" in flags:
        reasons.append("Training volume is elevated, but this is interpreted cautiously because daily activity is normal for you.")

    weight_change = None

    if withings_data.get("status") == "connected":
        weight_change = (
            withings_data
            .get("trends", {})
            .get("weight_change_smoothed_lb")
        )

    if weight_change is not None:
        if abs(weight_change) < 1:
            reasons.append("Smoothed weight trend is stable.")
        elif weight_change < -1.5:
            caution_points += 1
            reasons.append("Weight trend is down meaningfully, which may suggest under-fueling or fluid loss.")
        elif weight_change > 1.5:
            caution_points += 1
            reasons.append("Weight trend is up meaningfully, which may reflect water retention, soreness, or recovery stress.")

    if caution_points >= 2:
        level = "low"
    elif caution_points == 1:
        level = "moderate"
    else:
        level = "moderate_high"

    return {
        "level": level,
        "caution_points": caution_points,
        "reasons": reasons
    }


@app.route("/summary")
@require_api_user
def summary(user_id):
    activities, error = get_recent_activities(days=14, per_page=100, user_id=user_id)
    if error:
        message, status = error

        if status == 401:
            return jsonify({"error": "Strava is not connected for this user"}), 401

        return jsonify({
            "error": message,
            "status": status
        }), status

    activities, dedupe_removed = dedupe_activities(activities)

    for a in activities:
        activity_id = a.get("id")
        zones = {}

        if activity_id:
            zones_payload, zones_error = get_activity_zones(activity_id, user_id=user_id)
            if not zones_error:
                zones = extract_zone_data(zones_payload)

        a["zones"] = zones

        if a.get("sport_type") in ["Ride", "VirtualRide"]:
            streams_payload, streams_error = get_activity_streams(activity_id, user_id=user_id)
            if not streams_error:
                a["power_stream_intensity"] = summarize_power_stream_intensity(streams_payload)
    
    workout_count = len(activities)
    total_distance_m = sum(a.get("distance", 0) or 0 for a in activities)
    total_moving_time_s = sum(a.get("moving_time", 0) or 0 for a in activities)
    total_elevation_gain_m = sum(a.get("total_elevation_gain", 0) or 0 for a in activities)

    sport_counts = {}
    for a in activities:
        sport = a.get("sport_type", "Unknown")
        sport_counts[sport] = sport_counts.get(sport, 0) + 1

    total_distance_km = round(total_distance_m / 1000, 1)
    total_distance_mi = round(total_distance_m * 0.000621371, 1)
    total_moving_time_hr = round(total_moving_time_s / 3600, 2)

    flags = []
    if workout_count == 0:
        flags.append("no_recent_training")
    if total_moving_time_hr > 10:
        flags.append("high_training_volume")
    
    intensity_summary = build_intensity_summary(activities)

    simulate_withings_failure = (
        os.getenv("SIMULATE_WITHINGS_FAILURE", "false").lower() == "true"
    )

    if simulate_withings_failure:
        withings_data = {
            "status": "temporarily_unavailable",
            "message": (
                "Withings access is being intentionally disabled for testing. "
                "Coaching is based on Strava data only."
            ),
        }
    else:
        try:
            withings_data = get_withings_summary(user_id=user_id)
        except Exception as exc:
            app.logger.exception("Withings summary failed for user %s", user_id)
            withings_data = {
                "status": "temporarily_unavailable",
                "message": "Withings could not be accessed. Coaching is based on Strava data only.",
                "error_type": type(exc).__name__,
            }

    withings_status = withings_data.get("status", "temporarily_unavailable")

    if withings_status == "connected":
        coaching_basis = ["strava", "withings"]
        assessment_level = "complete"
        missing_sources = []
    else:
        coaching_basis = ["strava"]
        assessment_level = "partial"
        missing_sources = ["withings"]

    summary_data = {
        "debug_version": "multiuser-step6-api-auth",
        "user_id": user_id,
        "period_days": 14,
        "workout_count": workout_count,
        "total_distance_km": total_distance_km,
        "total_distance_mi": total_distance_mi,
        "total_moving_time_hr": total_moving_time_hr,
        "total_elevation_gain_m": round(total_elevation_gain_m, 0),
        "sport_counts": sport_counts,
        "flags": flags,
        "readiness": "unknown",
        "withings": withings_data,
        "data_availability": {
            "strava": "connected",
            "withings": withings_status,
            "coaching_basis": coaching_basis,
        },
        "assessment_completeness": {
            "level": assessment_level,
            "available_sources": coaching_basis,
            "missing_sources": missing_sources,
        },
        "intensity_summary": intensity_summary,
        "dedupe": {
            "removed_count": len(dedupe_removed),
            "removed": dedupe_removed
        },
    }

    summary_data["insights"] = build_coaching_insights(summary_data, withings_data)
    summary_data["readiness"] = calculate_readiness(summary_data, withings_data)

    return jsonify(summary_data)


@app.route("/activity/<int:activity_id>/zones")
@require_api_user
def activity_zones(user_id, activity_id):
    zones, error = get_activity_zones(activity_id, user_id=user_id)
    if error:
        message, status = error
      
        if status == 401:
            return jsonify({"error": "Strava is not connected for this user"}), 401

        return jsonify({"error": message}), status
    return jsonify(zones)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)