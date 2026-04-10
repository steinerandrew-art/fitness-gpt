from flask import Flask, jsonify, redirect, request
import requests
import time
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

import os

CLIENT_ID = os.environ["STRAVA_CLIENT_ID"]
CLIENT_SECRET = os.environ["STRAVA_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]

tokens = {}

def ensure_access_token():
    """Refresh the Strava access token if it is missing or expired."""
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
    return tokens["access_token"]

def get_recent_activities(days=7, per_page=100):
    """Fetch recent Strava activities from the last N days."""
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

@app.route("/")
def home():
    return """
    <h1>Fitness GPT backend is running</h1>
    <p><a href="/login">Connect Strava</a></p>
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
        return f"Token exchange failed: {response.text}", 400

    token_data = response.json()
    tokens["access_token"] = token_data["access_token"]
    tokens["refresh_token"] = token_data["refresh_token"]
    tokens["expires_at"] = token_data["expires_at"]
    tokens["athlete"] = token_data.get("athlete", {})

    return jsonify({
        "message": "Strava connected successfully",
        "athlete": tokens["athlete"],
        "expires_at": tokens["expires_at"]
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
    activities, error = get_recent_activities(days=7, per_page=25)
    if error:
        message, status = error
        return jsonify({"error": message}), status

    enriched = []

    for a in activities:
        activity_id = a.get("id")
        avg_hr = a.get("average_heartrate")
        max_hr = a.get("max_heartrate")
        has_hr = a.get("has_heartrate", False)

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
            "avg_heartrate": avg_hr,
            "max_heartrate": max_hr,
            "has_heartrate": has_hr,

            # legacy-friendly fields
            "hr_zone_seconds": zones.get("heartrate", {}).get("seconds"),
            "hr_zone_minutes": zones.get("heartrate", {}).get("minutes"),
            "hr_zone_bounds": zones.get("heartrate", {}).get("bounds"),

            # new generalized structure
            "zones": zones
        })

    return jsonify({"workouts": enriched})

@app.route("/summary")
def summary():
    activities, error = get_recent_activities(days=7, per_page=100)
    if error:
        message, status = error
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

    return jsonify({
        "period_days": 7,
        "workout_count": workout_count,
        "total_distance_km": total_distance_km,
        "total_distance_mi": total_distance_mi,
        "total_moving_time_hr": total_moving_time_hr,
        "total_elevation_gain_m": round(total_elevation_gain_m, 0),
        "sport_counts": sport_counts,
        "flags": flags,
        "readiness": "unknown"
    })

@app.route("/activity/<int:activity_id>/zones")
def activity_zones(activity_id):
    zones, error = get_activity_zones(activity_id)
    if error:
        message, status = error
        return jsonify({"error": message}), status
    return jsonify(zones)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)