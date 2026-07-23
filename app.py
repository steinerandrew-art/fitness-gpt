import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from html import escape

import requests

from flask import Flask, jsonify, make_response, redirect, request

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

from token_store import (
    DEFAULT_USER_ID,
    delete_browser_session,
    get_browser_session,
    save_browser_session,
)

app = Flask(__name__)


ONBOARDING_STEPS = [
    {"key": "profile", "label": "Profile", "path": "/onboarding/profile"},
    {"key": "training", "label": "Training profile", "path": "/onboarding/training"},
    {"key": "goals", "label": "Goals", "path": "/onboarding/goals"},
    {"key": "strava", "label": "Connect Strava", "path": "/onboarding/strava"},
    {"key": "withings", "label": "Connect Withings", "path": "/onboarding/withings"},
    {"key": "integrations", "label": "AI integrations", "path": "/onboarding/integrations"},
]

COMMON_TIMEZONES = [
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Phoenix",
    "America/Los_Angeles",
    "America/Anchorage",
    "Pacific/Honolulu",
    "America/Toronto",
    "America/Vancouver",
    "Europe/London",
    "Europe/Paris",
    "Asia/Tokyo",
    "Australia/Sydney",
]

ACTIVITY_OPTIONS = [
    ("road_cycling", "Road cycling"),
    ("gravel_cycling", "Gravel cycling"),
    ("mountain_biking", "Mountain biking"),
    ("indoor_cycling", "Indoor cycling"),
    ("running", "Running"),
    ("walking", "Walking"),
    ("strength_training", "Strength training"),
    ("cross_country_skiing", "Cross-country skiing"),
    ("other", "Other activity"),
]

ACTIVITY_FREQUENCY_OPTIONS = [
    ("never", "Rarely or never"),
    ("monthly", "A few times per month"),
    ("weekly", "About weekly"),
    ("several_weekly", "Several times per week"),
    ("most_days", "Most days"),
]

COACHING_STYLE_OPTIONS = [
    ("adaptive", "Adaptive — adjust recommendations to readiness and circumstances"),
    ("analytical", "Analytical — emphasize data, rationale, and trends"),
    ("direct", "Direct — concise recommendations with minimal cushioning"),
    ("encouraging", "Encouraging — supportive framing and reinforcement"),
]

EQUIPMENT_OPTIONS = [
    ("smart_trainer", "Smart trainer"),
    ("power_meter", "Bike power meter"),
    ("heart_rate_monitor", "Heart-rate monitor"),
    ("gps_watch", "GPS watch"),
    ("gym_access", "Gym access"),
    ("treadmill", "Treadmill"),
    ("rowing_machine", "Rowing machine"),
]

PLATFORM_OPTIONS = [
    ("zwift", "Zwift"),
    ("trainerroad", "TrainerRoad"),
    ("wahoo_systm", "Wahoo SYSTM"),
    ("peloton", "Peloton"),
    ("rouvy", "Rouvy"),
]


def configured_api_users():
    """Return an API-key-to-user-ID mapping from named Render variables.

    Every environment variable named FITNESS_API_KEY_<USER> becomes one user.
    For example:
        FITNESS_API_KEY_ANDREW -> andrew
        FITNESS_API_KEY_MAGGIE -> maggie
        FITNESS_API_KEY_KELLY -> kelly
    """
    users = {}
    prefix = "FITNESS_API_KEY_"

    for variable_name, api_key in os.environ.items():
        if not variable_name.startswith(prefix) or not api_key:
            continue

        user_suffix = variable_name[len(prefix):]

        # Ignore the temporary generic variable used in Step 6. Named user
        # variables are now the source of truth.
        if user_suffix == "SECOND_USER":
            continue

        user_id = user_suffix.lower()

        if not user_id.replace("_", "").isalnum():
            app.logger.warning(
                "Ignoring invalid API-key variable name: %s",
                variable_name,
            )
            continue

        existing_user = users.get(api_key)
        if existing_user and existing_user != user_id:
            raise RuntimeError(
                "The same fitness API key is assigned to multiple users"
            )

        users[api_key] = user_id

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


# ===========================================================================
# Supabase-backed browser accounts
# ===========================================================================

ACCOUNT_COOKIE_NAME = "fitness_account_session"
ACCOUNT_SESSION_SECONDS = 60 * 60 * 24 * 14


def required_environment(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is not configured")
    return value.rstrip("/")


def supabase_url():
    return required_environment("SUPABASE_URL")


def supabase_publishable_key():
    return required_environment("SUPABASE_PUBLISHABLE_KEY")


def supabase_secret_key():
    return required_environment("SUPABASE_SECRET_KEY")


def flask_session_secret():
    return required_environment("FLASK_SESSION_SECRET").encode("utf-8")


def account_cookie_value(session_id):
    signature = hmac.new(
        flask_session_secret(),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{session_id}.{signature}"


def session_id_from_cookie():
    cookie_value = request.cookies.get(ACCOUNT_COOKIE_NAME)
    if not cookie_value or "." not in cookie_value:
        return None

    session_id, supplied_signature = cookie_value.rsplit(".", 1)
    expected_signature = hmac.new(
        flask_session_secret(),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(supplied_signature, expected_signature):
        return None

    return session_id


def supabase_headers(key, access_token=None):
    headers = {"apikey": key, "Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


def supabase_error_message(response, fallback):
    try:
        payload = response.json()
    except ValueError:
        return fallback
    return (
        payload.get("msg")
        or payload.get("message")
        or payload.get("error_description")
        or payload.get("error")
        or fallback
    )


def lookup_email_for_identifier(identifier):
    identifier = (identifier or "").strip()
    if "@" in identifier:
        return identifier.lower()

    response = requests.get(
        f"{supabase_url()}/rest/v1/profiles",
        headers=supabase_headers(supabase_secret_key(), supabase_secret_key()),
        params={"select": "email", "username": f"ilike.{identifier}", "limit": "1"},
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning("Supabase username lookup failed: %s", supabase_error_message(response, "unknown error"))
        return None
    rows = response.json()
    return rows[0].get("email") if rows else None


def supabase_password_login(email, password):
    response = requests.post(
        f"{supabase_url()}/auth/v1/token",
        params={"grant_type": "password"},
        headers=supabase_headers(supabase_publishable_key()),
        json={"email": email, "password": password},
        timeout=15,
    )
    if response.status_code != 200:
        return None, supabase_error_message(response, "The email/username or password was not accepted.")
    return response.json(), None


def supabase_signup(email, password, username, display_name):
    response = requests.post(
        f"{supabase_url()}/auth/v1/signup",
        headers=supabase_headers(supabase_publishable_key()),
        json={
            "email": email,
            "password": password,
            "data": {"username": username, "display_name": display_name or username},
        },
        timeout=15,
    )
    if response.status_code not in {200, 201}:
        return None, supabase_error_message(response, "The account could not be created.")
    return response.json(), None


def supabase_refresh_session(refresh_token):
    response = requests.post(
        f"{supabase_url()}/auth/v1/token",
        params={"grant_type": "refresh_token"},
        headers=supabase_headers(supabase_publishable_key()),
        json={"refresh_token": refresh_token},
        timeout=15,
    )
    return response.json() if response.status_code == 200 else None


def supabase_profile(user_id, access_token):
    response = requests.get(
        f"{supabase_url()}/rest/v1/profiles",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        params={
            "select": "id,username,email,display_name,timezone,units,onboarding_completed,created_at",
            "id": f"eq.{user_id}",
            "limit": "1",
        },
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning("Supabase profile lookup failed: %s", supabase_error_message(response, "unknown error"))
        return None
    rows = response.json()
    return rows[0] if rows else None


def update_supabase_profile(user_id, access_token, updates):
    response = requests.patch(
        f"{supabase_url()}/rest/v1/profiles",
        headers={
            **supabase_headers(supabase_publishable_key(), access_token),
            "Prefer": "return=representation",
        },
        params={"id": f"eq.{user_id}"},
        json=updates,
        timeout=15,
    )
    if response.status_code not in {200, 204}:
        message = supabase_error_message(
            response,
            "The profile could not be saved.",
        )
        app.logger.warning("Supabase profile update failed: %s", message)
        return None, message

    rows = response.json() if response.content else []
    return (rows[0] if rows else updates), None


def supabase_single_row(table, user_id, access_token, select="*"):
    response = requests.get(
        f"{supabase_url()}/rest/v1/{table}",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        params={
            "select": select,
            "user_id": f"eq.{user_id}",
            "limit": "1",
        },
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Supabase %s lookup failed: %s",
            table,
            supabase_error_message(response, "unknown error"),
        )
        return None
    rows = response.json()
    return rows[0] if rows else None


def upsert_supabase_row(table, access_token, row, conflict_column="user_id"):
    response = requests.post(
        f"{supabase_url()}/rest/v1/{table}",
        headers={
            **supabase_headers(supabase_publishable_key(), access_token),
            "Prefer": "resolution=merge-duplicates,return=representation",
        },
        params={"on_conflict": conflict_column},
        json=row,
        timeout=15,
    )
    if response.status_code not in {200, 201}:
        message = supabase_error_message(
            response,
            f"The {table.replace('_', ' ')} could not be saved.",
        )
        app.logger.warning("Supabase %s upsert failed: %s", table, message)
        return None, message
    rows = response.json() if response.content else []
    return (rows[0] if rows else row), None


def coaching_profile(user_id, access_token):
    return supabase_single_row(
        "coaching_profiles",
        user_id,
        access_token,
        select=(
            "user_id,primary_focus,activity_preferences,weekday_minutes,weekend_minutes,"
            "coaching_style,equipment,indoor_platforms,created_at,updated_at"
        ),
    )


def profile_step_complete(profile):
    return bool(
        profile
        and profile.get("display_name")
        and profile.get("timezone")
        and profile.get("units") in {"imperial", "metric"}
    )


def training_step_complete(training):
    return bool(
        training
        and isinstance(training.get("activity_preferences"), dict)
        and any(
            (value or {}).get("priority", 0) > 0
            for value in training.get("activity_preferences", {}).values()
        )
        and isinstance(training.get("weekday_minutes"), int)
        and isinstance(training.get("weekend_minutes"), int)
        and training.get("coaching_style")
    )


def onboarding_state(profile, training):
    completion = {
        "profile": profile_step_complete(profile),
        "training": training_step_complete(training),
        # Later deployments will replace these placeholders with real checks.
        "goals": False,
        "strava": False,
        "withings": False,
        "integrations": False,
    }
    next_step = next(
        (step for step in ONBOARDING_STEPS if not completion[step["key"]]),
        None,
    )
    return {
        "completion": completion,
        "next_step": next_step,
        "complete": next_step is None,
    }


def onboarding_progress_html(state, current_key=None):
    items = []
    for step in ONBOARDING_STEPS:
        key = step["key"]
        if state["completion"].get(key):
            status = "✓"
            css_class = "complete"
        elif key == current_key:
            status = "→"
            css_class = "current"
        else:
            status = ""
            css_class = "pending"
        if key in {"profile", "training", "goals"} or state["completion"].get(key):
            content = (
                f'<a href="{escape(step["path"])}">'
                f'<span>{escape(step["label"])}</span><strong>{status}</strong></a>'
            )
        else:
            content = (
                f'<div class="wizard-step-disabled">'
                f'<span>{escape(step["label"])}</span><strong>{status}</strong></div>'
            )
        items.append(f'<li class="{css_class}">{content}</li>')
    return '<ol class="wizard-progress">' + ''.join(items) + '</ol>'


def parse_bounded_minutes(value, label):
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return None, f"{label} must be a whole number of minutes."
    if not 0 <= minutes <= 1440:
        return None, f"{label} must be between 0 and 1,440 minutes."
    return minutes, None


def create_account_session(auth_payload):
    user = auth_payload.get("user") or {}
    session_id = secrets.token_urlsafe(32)
    expires_at = auth_payload.get("expires_at") or int(time.time()) + int(auth_payload.get("expires_in", 3600))
    session_data = {
        "user_id": user.get("id"),
        "email": user.get("email"),
        "access_token": auth_payload.get("access_token"),
        "refresh_token": auth_payload.get("refresh_token"),
        "expires_at": int(expires_at),
    }
    if not all([session_data["user_id"], session_data["access_token"], session_data["refresh_token"]]):
        raise RuntimeError("Supabase returned an incomplete login session")
    save_browser_session(session_id, session_data, ACCOUNT_SESSION_SECONDS)
    return session_id


def current_account_session():
    session_id = session_id_from_cookie()
    session_data = get_browser_session(session_id)
    if not session_id or not session_data:
        return None, None

    if isinstance(session_data, str):
        try:
            session_data = json.loads(session_data)
        except json.JSONDecodeError:
            delete_browser_session(session_id)
            return None, None

    if session_data.get("expires_at", 0) <= int(time.time()) + 60:
        refreshed = supabase_refresh_session(session_data.get("refresh_token"))
        if not refreshed:
            delete_browser_session(session_id)
            return None, None
        user = refreshed.get("user") or {}
        session_data.update({
            "user_id": user.get("id") or session_data.get("user_id"),
            "email": user.get("email") or session_data.get("email"),
            "access_token": refreshed.get("access_token"),
            "refresh_token": refreshed.get("refresh_token"),
            "expires_at": int(refreshed.get("expires_at") or (time.time() + int(refreshed.get("expires_in", 3600)))),
        })
        save_browser_session(session_id, session_data, ACCOUNT_SESSION_SECONDS)
    return session_id, session_data


def require_account(view_function):
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        _, session_data = current_account_session()
        if not session_data:
            return redirect("/login")
        return view_function(session_data, *args, **kwargs)

    return wrapped


def account_page(title, body):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} · Fitness Coaching</title>
<style>
body{{margin:0;background:#f5f7fa;color:#17202a;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{width:min(640px,calc(100% - 32px));margin:48px auto;background:white;border:1px solid #dfe4ea;border-radius:14px;padding:28px;box-shadow:0 8px 24px rgba(0,0,0,.06)}}
h1{{margin-top:0}} label{{display:block;margin:16px 0 6px;font-weight:600}} input,select{{width:100%;box-sizing:border-box;padding:11px;border:1px solid #aab2bd;border-radius:8px;font:inherit}} code{{background:#eef1f4;border-radius:4px;padding:2px 5px}}
button,.button{{display:inline-block;margin-top:20px;padding:11px 16px;border:0;border-radius:8px;background:#1f5f99;color:white;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}}
.secondary{{background:#5d6d7e}} .error{{padding:12px;border-radius:8px;background:#fdecea;color:#922b21}} .success{{padding:12px;border-radius:8px;background:#eafaf1;color:#196f3d}}
dl{{display:grid;grid-template-columns:150px 1fr;gap:10px 16px}} dt{{font-weight:700}} dd{{margin:0}}
fieldset{{margin:20px 0;padding:16px;border:1px solid #dfe4ea;border-radius:10px}} legend{{font-weight:700;padding:0 6px}}
.check-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px 16px}} .check-grid label{{display:flex;align-items:flex-start;gap:8px;margin:0;font-weight:500}} .check-grid input{{width:auto;margin-top:3px}}
.wizard-progress{{list-style:none;padding:0;margin:0 0 24px;display:grid;gap:8px}} .wizard-progress li{{display:flex;justify-content:space-between;padding:9px 12px;border-radius:8px;background:#f1f3f5}} .wizard-progress .complete{{background:#eafaf1}} .wizard-progress .current{{background:#eaf2f8;font-weight:700}}
.actions{{display:flex;gap:12px;flex-wrap:wrap;align-items:center}} .muted{{color:#5d6d7e}}
</style></head><body><main>{body}</main></body></html>"""


def login_form(error_message=None):
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    return account_page("Log in", f"""
<h1>Log in</h1>{error_html}
<form method="post" action="/login">
<label for="identifier">Email or username</label><input id="identifier" name="identifier" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Log in</button></form>
<p>Need an account? <a href="/register">Create one</a>.</p>""")


def registration_form(error_message=None):
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    return account_page("Create account", f"""
<h1>Create an account</h1>{error_html}
<form method="post" action="/register">
<label for="email">Email</label><input id="email" type="email" name="email" autocomplete="email" required>
<label for="username">Username</label><input id="username" name="username" pattern="[A-Za-z0-9_-]{{3,30}}" autocomplete="username" required>
<label for="display_name">Display name</label><input id="display_name" name="display_name" autocomplete="name">
<label for="password">Password</label><input id="password" type="password" name="password" minlength="8" autocomplete="new-password" required>
<button type="submit">Create account</button></form>
<p>Already registered? <a href="/login">Log in</a>.</p>""")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_account_session()[1]:
        return redirect("/account")
    if request.method == "GET":
        return registration_form()

    email = request.form.get("email", "").strip().lower()
    username = request.form.get("username", "").strip()
    display_name = request.form.get("display_name", "").strip()
    password = request.form.get("password", "")

    if not re.fullmatch(r"[A-Za-z0-9_-]{3,30}", username):
        return registration_form("Username must be 3–30 characters using letters, numbers, underscores, or hyphens."), 400
    if len(password) < 8:
        return registration_form("Password must contain at least eight characters."), 400

    auth_payload, error = supabase_signup(email, password, username, display_name)
    if error:
        return registration_form(error), 400
    if not auth_payload.get("access_token"):
        return account_page("Check your email", """
<h1>Check your email</h1><p class="success">Your account was created. Supabase will send the confirmation message on behalf of Fitness Coaching, so the sender may appear as Supabase. Follow that link, then return here to log in.</p>
<p><a class="button" href="/login">Go to login</a></p>""")

    session_id = create_account_session(auth_payload)
    response = make_response(redirect("/account"))
    response.set_cookie(ACCOUNT_COOKIE_NAME, account_cookie_value(session_id), max_age=ACCOUNT_SESSION_SECONDS, secure=True, httponly=True, samesite="Lax")
    return response


@app.route("/login", methods=["GET", "POST"])
def account_login():
    if current_account_session()[1]:
        return redirect("/account")
    if request.method == "GET":
        return login_form()

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    email = lookup_email_for_identifier(identifier)
    if not email:
        return login_form("The email/username or password was not accepted."), 401

    auth_payload, error = supabase_password_login(email, password)
    if error:
        return login_form("The email/username or password was not accepted."), 401

    session_id = create_account_session(auth_payload)
    response = make_response(redirect("/account"))
    response.set_cookie(ACCOUNT_COOKIE_NAME, account_cookie_value(session_id), max_age=ACCOUNT_SESSION_SECONDS, secure=True, httponly=True, samesite="Lax")
    return response


@app.route("/logout", methods=["POST"])
def account_logout():
    session_id, session_data = current_account_session()
    if session_data:
        try:
            requests.post(
                f"{supabase_url()}/auth/v1/logout",
                headers=supabase_headers(supabase_publishable_key(), session_data.get("access_token")),
                timeout=15,
            )
        except requests.RequestException:
            app.logger.warning("Supabase logout request failed")
    delete_browser_session(session_id)
    response = make_response(redirect("/login"))
    response.delete_cookie(ACCOUNT_COOKIE_NAME, secure=True, httponly=True, samesite="Lax")
    return response


@app.route("/onboarding")
@require_account
def onboarding(session_data):
    profile = supabase_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    training = coaching_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    state = onboarding_state(profile, training)
    destination = state["next_step"]["path"] if state["next_step"] else "/account"
    return redirect(destination)


@app.route("/onboarding/profile", methods=["GET", "POST"])
@require_account
def onboarding_profile(session_data):
    profile = supabase_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    if not profile:
        return account_page(
            "Onboarding error",
            '<h1>Profile unavailable</h1>'
            '<p class="error">The profile record could not be loaded.</p>',
        ), 500

    training = coaching_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    state = onboarding_state(profile, training)
    error_message = None

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        timezone_name = request.form.get("timezone", "").strip()
        units = request.form.get("units", "").strip()

        if not display_name:
            error_message = "Display name is required."
        elif len(display_name) > 100:
            error_message = "Display name must be 100 characters or fewer."
        elif timezone_name not in COMMON_TIMEZONES:
            error_message = "Choose a supported time zone."
        elif units not in {"imperial", "metric"}:
            error_message = "Choose imperial or metric units."
        else:
            _, error_message = update_supabase_profile(
                session_data["user_id"],
                session_data["access_token"],
                {
                    "display_name": display_name,
                    "timezone": timezone_name,
                    "units": units,
                    "onboarding_completed": False,
                },
            )
            if not error_message:
                return redirect("/onboarding/training")

    error_html = (
        f'<p class="error">{escape(error_message)}</p>'
        if error_message else ""
    )
    display_name = request.form.get(
        "display_name",
        profile.get("display_name") or "",
    )
    timezone_name = request.form.get(
        "timezone",
        profile.get("timezone") or "America/Denver",
    )
    units = request.form.get(
        "units",
        profile.get("units") or "imperial",
    )

    timezone_options = ''.join(
        f'<option value="{escape(zone)}" '
        f'{"selected" if zone == timezone_name else ""}>{escape(zone)}</option>'
        for zone in COMMON_TIMEZONES
    )
    imperial_selected = "selected" if units == "imperial" else ""
    metric_selected = "selected" if units == "metric" else ""

    return account_page(
        "Profile setup",
        f"""
{onboarding_progress_html(state, "profile")}
<h1>Profile</h1>
<p>Set the personal details shared by every coaching integration.</p>
{error_html}
<form method="post" action="/onboarding/profile">
<label for="display_name">Display name</label>
<input id="display_name" name="display_name" maxlength="100" value="{escape(display_name)}" required>
<label for="timezone">Time zone</label>
<select id="timezone" name="timezone" required>{timezone_options}</select>
<p class="muted">The browser will select its detected time zone when it appears in this list.</p>
<label for="units">Measurement units</label>
<select id="units" name="units" required>
<option value="imperial" {imperial_selected}>Imperial</option>
<option value="metric" {metric_selected}>Metric</option>
</select>
<div class="actions"><button type="submit">Save and continue</button><a href="/account">Return to account</a></div>
</form>
<script>
const detectedZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const timeZoneSelect = document.getElementById('timezone');
if (detectedZone && [...timeZoneSelect.options].some(option => option.value === detectedZone)) {{
  if (!timeZoneSelect.value) timeZoneSelect.value = detectedZone;
}}
</script>""",
    )


@app.route("/onboarding/training", methods=["GET", "POST"])
@require_account
def onboarding_training(session_data):
    profile = supabase_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    if not profile_step_complete(profile):
        return redirect("/onboarding/profile")

    training = coaching_profile(
        session_data["user_id"],
        session_data["access_token"],
    ) or {}
    state = onboarding_state(profile, training)
    error_message = None

    saved_preferences = training.get("activity_preferences") or {}

    if request.method == "POST":
        coaching_style = request.form.get("coaching_style", "").strip()
        weekday_minutes, weekday_error = parse_bounded_minutes(
            request.form.get("weekday_minutes"),
            "Weekday duration",
        )
        weekend_minutes, weekend_error = parse_bounded_minutes(
            request.form.get("weekend_minutes"),
            "Weekend duration",
        )
        equipment = {key: key in request.form for key, _ in EQUIPMENT_OPTIONS}
        indoor_platforms = [
            key for key, _ in PLATFORM_OPTIONS if key in request.form
        ]

        activity_preferences = {}
        priority_values = []
        valid_frequencies = {key for key, _ in ACTIVITY_FREQUENCY_OPTIONS}
        for key, label in ACTIVITY_OPTIONS:
            raw_priority = request.form.get(f"priority_{key}", "0")
            frequency = request.form.get(f"frequency_{key}", "never")
            try:
                priority = int(raw_priority)
            except ValueError:
                priority = -1
            if not 0 <= priority <= 5:
                error_message = f"Priority for {label} must be between 0 and 5."
                break
            if frequency not in valid_frequencies:
                error_message = f"Choose a valid frequency for {label}."
                break
            activity_preferences[key] = {
                "priority": priority,
                "frequency": frequency,
            }
            if priority > 0:
                priority_values.append(priority)

        if not error_message and not priority_values:
            error_message = "Give at least one activity a priority from 1 to 5."
        elif not error_message and len(priority_values) != len(set(priority_values)):
            error_message = "Use each non-zero priority only once so the ranking is unambiguous."
        elif not error_message and weekday_error:
            error_message = weekday_error
        elif not error_message and weekend_error:
            error_message = weekend_error
        elif not error_message and coaching_style not in {key for key, _ in COACHING_STYLE_OPTIONS}:
            error_message = "Choose a coaching style."
        else:
            ranked = sorted(
                (
                    (details["priority"], key, label)
                    for key, label in ACTIVITY_OPTIONS
                    for details in [activity_preferences[key]]
                    if details["priority"] > 0
                ),
                key=lambda item: item[0],
            )
            primary_focus = ranked[0][2] if ranked else None
            _, error_message = upsert_supabase_row(
                "coaching_profiles",
                session_data["access_token"],
                {
                    "user_id": session_data["user_id"],
                    "primary_focus": primary_focus,
                    "activity_preferences": activity_preferences,
                    "weekday_minutes": weekday_minutes,
                    "weekend_minutes": weekend_minutes,
                    "coaching_style": coaching_style,
                    "equipment": equipment,
                    "indoor_platforms": indoor_platforms,
                },
            )
            if not error_message:
                return redirect("/onboarding/goals")

    weekday_minutes = request.form.get(
        "weekday_minutes",
        str(training.get("weekday_minutes") if training.get("weekday_minutes") is not None else 60),
    )
    weekend_minutes = request.form.get(
        "weekend_minutes",
        str(training.get("weekend_minutes") if training.get("weekend_minutes") is not None else 120),
    )
    coaching_style = request.form.get(
        "coaching_style",
        training.get("coaching_style") or "adaptive",
    )
    saved_equipment = training.get("equipment") or {}
    saved_platforms = training.get("indoor_platforms") or []

    style_options = ''.join(
        f'<option value="{escape(key)}" '
        f'{"selected" if key == coaching_style else ""}>{escape(label)}</option>'
        for key, label in COACHING_STYLE_OPTIONS
    )
    equipment_html = ''.join(
        f'<label><input type="checkbox" name="{escape(key)}" '
        f'{"checked" if (key in request.form if request.method == "POST" else saved_equipment.get(key)) else ""}>'
        f'<span>{escape(label)}</span></label>'
        for key, label in EQUIPMENT_OPTIONS
    )
    platforms_html = ''.join(
        f'<label><input type="checkbox" name="{escape(key)}" '
        f'{"checked" if (key in request.form if request.method == "POST" else key in saved_platforms) else ""}>'
        f'<span>{escape(label)}</span></label>'
        for key, label in PLATFORM_OPTIONS
    )

    frequency_options_by_activity = {}
    activity_rows = []
    for key, label in ACTIVITY_OPTIONS:
        saved = saved_preferences.get(key) or {}
        priority = request.form.get(
            f"priority_{key}",
            str(saved.get("priority", 0)),
        )
        frequency = request.form.get(
            f"frequency_{key}",
            saved.get("frequency", "never"),
        )
        priority_options = ''.join(
            f'<option value="{value}" {"selected" if str(value) == str(priority) else ""}>'
            f'{"Not ranked" if value == 0 else value}</option>'
            for value in range(0, 6)
        )
        frequency_options = ''.join(
            f'<option value="{escape(value)}" {"selected" if value == frequency else ""}>'
            f'{escape(text)}</option>'
            for value, text in ACTIVITY_FREQUENCY_OPTIONS
        )
        activity_rows.append(
            f'<div class="activity-row-label">{escape(label)}</div>'
            f'<select name="priority_{escape(key)}" aria-label="Priority for {escape(label)}">{priority_options}</select>'
            f'<select name="frequency_{escape(key)}" aria-label="Frequency for {escape(label)}">{frequency_options}</select>'
        )

    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""

    return account_page(
        "Training profile",
        f"""
{onboarding_progress_html(state, "training")}
<h1>Training profile</h1>
<p>Rank the activities you most want coaching to favor, and separately describe how often each is realistically available. Priority 1 is highest; leave activities unranked when they should rarely drive recommendations.</p>
{error_html}
<form method="post" action="/onboarding/training">
<fieldset><legend>Activity preferences</legend>
<div class="activity-grid"><div class="heading">Activity</div><div class="heading">Priority</div><div class="heading">Typical availability</div>{''.join(activity_rows)}</div>
</fieldset>
<label for="weekday_minutes">Typical weekday workout duration</label>
<input id="weekday_minutes" type="number" name="weekday_minutes" min="0" max="1440" step="5" value="{escape(str(weekday_minutes))}" required>
<label for="weekend_minutes">Typical weekend workout duration</label>
<input id="weekend_minutes" type="number" name="weekend_minutes" min="0" max="1440" step="5" value="{escape(str(weekend_minutes))}" required>
<label for="coaching_style">Default coaching style</label>
<select id="coaching_style" name="coaching_style" required>{style_options}</select>
<fieldset><legend>Equipment and access</legend><div class="check-grid">{equipment_html}</div></fieldset>
<fieldset><legend>Indoor platforms</legend><div class="check-grid">{platforms_html}</div></fieldset>
<div class="actions"><button type="submit">Save and continue</button><a href="/onboarding/profile">Back</a></div>
</form>""",
    )


@app.route("/onboarding/goals")
@require_account
def onboarding_goals(session_data):
    profile = supabase_profile(session_data["user_id"], session_data["access_token"])
    training = coaching_profile(session_data["user_id"], session_data["access_token"])
    if not profile_step_complete(profile):
        return redirect("/onboarding/profile")
    if not training_step_complete(training):
        return redirect("/onboarding/training")
    state = onboarding_state(profile, training)
    return account_page(
        "Goals coming next",
        f"""
{onboarding_progress_html(state, "goals")}
<h1>Goals</h1>
<p class="success">Your profile and training defaults are saved.</p>
<p>The goals data model and editing interface are the next onboarding stage. Goals remain incomplete until that stage is deployed.</p>
<div class="actions"><a class="button" href="/account">Return to account</a><a href="/onboarding/training">Edit training profile</a></div>""",
    )


@app.route("/account")
@require_account
def account(session_data):
    profile = supabase_profile(session_data["user_id"], session_data["access_token"])
    if not profile:
        return account_page(
            "Account error",
            '<h1>Account unavailable</h1>'
            '<p class="error">You are logged in, but the matching profile record could not be loaded.</p>',
        ), 500

    training = coaching_profile(
        session_data["user_id"],
        session_data["access_token"],
    )
    state = onboarding_state(profile, training)
    next_step = state["next_step"]
    next_html = (
        f'<p><strong>Next step:</strong> {escape(next_step["label"])}</p>'
        f'<p><a class="button" href="{escape(next_step["path"])}">Continue onboarding</a></p>'
        if next_step
        else '<p class="success">Onboarding complete.</p>'
    )
    training_summary = "Not configured"
    if training_step_complete(training):
        training_summary = (
            f'{escape(training.get("primary_focus") or "")} · '
            f'{escape(str(training.get("weekday_minutes")))} min weekdays · '
            f'{escape(str(training.get("weekend_minutes")))} min weekends'
        )

    return account_page(
        "Account",
        f"""
<h1>{escape(profile.get("display_name") or profile["username"])}</h1>
<p class="success">Browser account authentication is working.</p>
<dl><dt>Display name</dt><dd>{escape(profile.get("display_name") or "")}</dd>
<dt>Username</dt><dd>{escape(profile.get("username") or "")}</dd>
<dt>Email</dt><dd>{escape(profile.get("email") or session_data.get("email") or "")}</dd>
<dt>Time zone</dt><dd>{escape(profile.get("timezone") or "")}</dd>
<dt>Units</dt><dd>{escape(profile.get("units") or "")}</dd>
<dt>Training profile</dt><dd>{training_summary}</dd>
<dt>Onboarding</dt><dd>{"Complete" if state["complete"] else "In progress"}</dd></dl>
{next_html}
<p><a href="/onboarding/profile">Edit profile</a>{' · <a href="/onboarding/training">Edit training profile</a>' if training else ''}</p>
<form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form>""",
    )


SETUP_COOKIE_NAME = "fitness_setup_session"
SETUP_SESSION_SECONDS = 1800


def create_setup_session(user_id):
    payload = {
        "user_id": user_id,
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


def read_setup_session():
    session_value = request.cookies.get(SETUP_COOKIE_NAME)
    if not session_value or "." not in session_value:
        return None

    encoded_payload, supplied_signature = session_value.rsplit(".", 1)
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

    issued_at = payload.get("issued_at", 0)
    if not isinstance(issued_at, int) or time.time() - issued_at > SETUP_SESSION_SECONDS:
        return None

    user_id = payload.get("user_id")
    if user_id not in configured_api_users().values():
        return None

    return user_id


def setup_login_form(error_message=None):
    error_html = f"<p><strong>{error_message}</strong></p>" if error_message else ""
    return f"""
    <h1>Fitness account setup</h1>
    <p>Enter your fitness API key once. This browser will remember the selected user for 30 minutes.</p>
    {error_html}
    <form method="post" action="/setup">
      <label>API key: <input type="password" name="api_key" required></label>
      <button type="submit">Open setup page</button>
    </form>
    """


def setup_dashboard(user_id, message=None):
    message_html = f"<p><strong>{message}</strong></p>" if message else ""
    return f"""
    <h1>Fitness account setup</h1>
    <p>Setting up accounts for <strong>{user_id}</strong>.</p>
    {message_html}
    <p><a href="/connect/strava">Connect or reconnect Strava</a></p>
    <p><a href="/connect/withings">Connect or reconnect Withings</a></p>
    <form method="post" action="/setup/logout">
      <button type="submit">Finish setup / switch user</button>
    </form>
    """

@app.route("/")
def home():
    return """
    <h1>Fitness GPT backend is running</h1>
    <p><a href="/account">Account login and profile</a></p>
    <p><a href="/setup">Legacy API-key setup</a></p>
    <p><a href="/workouts">View workouts</a></p>
    <p><a href="/summary">View summary</a></p>
    """


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        user_id = user_id_for_api_key(request.form.get("api_key"))
        if not user_id:
            return setup_login_form("Invalid API key"), 401

        response = make_response(redirect("/setup"))
        response.set_cookie(
            SETUP_COOKIE_NAME,
            create_setup_session(user_id),
            max_age=SETUP_SESSION_SECONDS,
            secure=True,
            httponly=True,
            samesite="Lax",
        )
        return response

    user_id = read_setup_session()
    if not user_id:
        return setup_login_form()

    return setup_dashboard(user_id)


@app.route("/setup/logout", methods=["POST"])
def setup_logout():
    response = make_response(redirect("/setup"))
    response.delete_cookie(
        SETUP_COOKIE_NAME,
        secure=True,
        httponly=True,
        samesite="Lax",
    )
    return response


@app.route("/connect/strava")
def connect_strava():
    user_id = read_setup_session()
    if not user_id:
        return redirect("/setup")

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

    athlete = token_data.get("athlete", {})
    athlete_name = " ".join(
        part for part in [athlete.get("firstname"), athlete.get("lastname")] if part
    ) or "the selected account"

    return setup_dashboard(
        user_id,
        f"Strava connected successfully for {athlete_name}.",
    )


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


@app.route("/connect/withings")
def connect_withings():
    user_id = read_setup_session()
    if not user_id:
        return redirect("/setup")

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

    return setup_dashboard(
        user_id,
        "Withings connected successfully.",
    )


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
        "debug_version": "multiuser-step11-training-state-machine",
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