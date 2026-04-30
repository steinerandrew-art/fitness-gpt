from flask import Flask, jsonify, redirect, request

from strava_client import (
    CLIENT_ID,
    REDIRECT_URI,
    tokens,
    get_recent_activities,
    get_activity_detail,
    get_activity_zones,
    extract_zone_data,
    exchange_strava_code,
)

from withings_client import (
    get_withings_summary,
    exchange_withings_code,
    WITHINGS_CLIENT_ID,
    WITHINGS_REDIRECT_URI,
)

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h1>Fitness GPT backend is running</h1>
    <p><a href="/login">Connect Strava</a></p>
    <p><a href="/connect/withings">Connect Withings</a></p>
    <p><a href="/workouts">View workouts</a></p>
    <p><a href="/summary">View summary</a></p>
    """


@app.route("/login")
def login():
    auth_url = (
        "https://www.strava.com/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        "&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        "&approval_prompt=force"
        "&scope=read,activity:read_all"
    )
    return redirect(auth_url)


@app.route("/exchange_token")
def exchange_token():
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        return f"Authorization failed: {error}", 400

    if not code:
        return "Missing authorization code", 400

    token_data, error = exchange_strava_code(code)

    if error:
        message, status = error
        return f"Token exchange failed: {message}", status

    return jsonify({
        "message": "Strava connected successfully",
        "athlete": tokens.get("athlete", {}),
        "expires_at": tokens.get("expires_at")
    })


@app.route("/activity/<int:activity_id>")
def activity_detail(activity_id):
    detail, error = get_activity_detail(activity_id)
    if error:
        message, status = error
        return jsonify({"error": message}), status
    return jsonify(detail)


@app.route("/workouts")
def workouts():
    activities, error = get_recent_activities(days=14, per_page=25)
    if error:
        message, status = error
      
        if status == 401:
            return redirect("/login")  # 👈 key change

        return jsonify({"error": message}), status

    enriched = []

    for a in activities:
        activity_id = a.get("id")
        zones = {}

        if activity_id:
            zones_payload, zones_error = get_activity_zones(activity_id)
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

    return jsonify({"workouts": enriched})


@app.route("/connect/withings")
def connect_withings():
    auth_url = (
        "https://account.withings.com/oauth2_user/authorize2"
        "?response_type=code"
        f"&client_id={WITHINGS_CLIENT_ID}"
        f"&redirect_uri={WITHINGS_REDIRECT_URI}"
        "&scope=user.info,user.metrics"
        "&state=withings"
    )
    return redirect(auth_url)


@app.route("/callback/withings")
def callback_withings():
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        return f"Withings authorization failed: {error}", 400

    if not code:
        return "Missing Withings authorization code", 400

    token_data, token_error = exchange_withings_code(code)

    if token_error:
        message, status = token_error
        return jsonify({
            "error": "Withings token exchange failed",
            "details": message
        }), status

    return jsonify({
        "message": "Withings connected successfully",
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

    latest = withings_data.get("latest", {})
    measurements = latest.get("measurements", {})

    if measurements.get("weight_lb") is not None:
        insights.append(
            f"Latest weight is {measurements.get('weight_lb')} lb."
        )

    if measurements.get("fat_ratio_pct") is not None:
        insights.append(
            f"Latest body fat estimate is {measurements.get('fat_ratio_pct')}%, which should be treated as directional rather than exact."
        )

    if not insights:
        insights.append("Not enough combined training and body data yet to generate useful insights.")

    return insights


@app.route("/summary")
def summary():
    activities, error = get_recent_activities(days=14, per_page=100)
    if error:
        message, status = error
      
        if status == 401:
            return redirect("/login")  # 👈 key change

        return jsonify({"error": message}), status

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

    withings_data = get_withings_summary()

    if (
        withings_data.get("status") == "not_connected"
        or withings_data.get("details") == "Not connected to Withings yet"
    ):
        return redirect("/connect/withings")

    summary_data = {
        "period_days": 14,
        "workout_count": workout_count,
        "total_distance_km": total_distance_km,
        "total_distance_mi": total_distance_mi,
        "total_moving_time_hr": total_moving_time_hr,
        "total_elevation_gain_m": round(total_elevation_gain_m, 0),
        "sport_counts": sport_counts,
        "flags": flags,
        "readiness": "unknown",
        "withings": withings_data
    }

    summary_data["insights"] = build_coaching_insights(summary_data, withings_data)

    return jsonify(summary_data)


@app.route("/activity/<int:activity_id>/zones")
def activity_zones(activity_id):
    zones, error = get_activity_zones(activity_id)
    if error:
        message, status = error
      
        if status == 401:
            return redirect("/login")  # 👈 key change

        return jsonify({"error": message}), status
    return jsonify(zones)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)