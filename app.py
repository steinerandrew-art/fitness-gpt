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

from flask import Flask, Response, g, jsonify, make_response, redirect, request

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
    strava_connection,
)

from training_zones import summarize_power_stream_intensity

from withings_client import (
    get_withings_summary,
    exchange_withings_code,
    withings_connection,
    WITHINGS_CLIENT_ID,
    WITHINGS_REDIRECT_URI,
)

from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlencode, urlparse

from onboarding_support import (
    ACTIVITY_FREQUENCY_OPTIONS,
    ACTIVITY_GROUPS,
    ACTIVITY_OPTIONS,
    LEGACY_ACTIVITY_ALIASES,
    COACHING_STYLE_OPTIONS,
    COMMON_TIMEZONES,
    EQUIPMENT_OPTIONS,
    GOAL_PRIORITY_OPTIONS,
    GOAL_STATUS_OPTIONS,
    MAX_GOALS,
    ONBOARDING_STEPS,
    PLATFORM_OPTIONS,
    context_step_complete,
    goals_step_complete,
    onboarding_progress_html,
    onboarding_state,
    profile_step_complete,
    training_step_complete,
)

from token_store import (
    DEFAULT_USER_ID,
    delete_browser_session,
    delete_service_tokens,
    get_browser_session,
    save_browser_session,
)

app = Flask(__name__)


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


def api_key_digest(api_key):
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def account_user_id_for_api_key(api_key):
    if not api_key:
        return None

    try:
        response = requests.get(
            f"{supabase_url()}/rest/v1/ai_integrations",
            headers=supabase_headers(supabase_secret_key()),
            params={
                "select": "user_id",
                "api_key_hash": f"eq.{api_key_digest(api_key)}",
                "enabled": "eq.true",
                "limit": "1",
            },
            timeout=20,
        )
    except requests.RequestException as exc:
        app.logger.exception("Supabase API-key validation request failed")
        return None

    if response.status_code != 200:
        app.logger.warning(
            "Could not validate account API key: %s",
            supabase_error_message(response, "unknown Supabase error"),
        )
        return None

    try:
        rows = response.json()
    except ValueError:
        app.logger.error(
            "Supabase API-key validation returned non-JSON content: %r",
            response.text[:500],
        )
        return None

    return rows[0].get("user_id") if rows else None


def user_id_for_api_key(api_key):
    if not api_key:
        return None

    for configured_key, user_id in configured_api_users().items():
        if hmac.compare_digest(api_key, configured_key):
            return user_id

    return account_user_id_for_api_key(api_key)


def api_key_from_request():
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()

    return request.headers.get("X-API-Key")


def oauth_token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def service_rows(table, params):
    response = requests.get(
        f"{supabase_url()}/rest/v1/{table}",
        headers=supabase_headers(supabase_secret_key(), supabase_secret_key()),
        params=params,
        timeout=20,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Supabase service lookup failed for %s: %s",
            table,
            supabase_error_message(response, "unknown Supabase error"),
        )
        return []
    try:
        return response.json()
    except ValueError:
        return []


def service_insert(table, payload):
    response = requests.post(
        f"{supabase_url()}/rest/v1/{table}",
        headers={
            **supabase_headers(supabase_secret_key(), supabase_secret_key()),
            "Prefer": "return=representation",
        },
        json=payload,
        timeout=20,
    )
    if response.status_code not in {200, 201}:
        return None, supabase_error_message(response, f"Could not insert {table}")
    rows = response.json()
    return (rows[0] if rows else payload), None


def service_update(table, filters, payload):
    response = requests.patch(
        f"{supabase_url()}/rest/v1/{table}",
        headers={
            **supabase_headers(supabase_secret_key(), supabase_secret_key()),
            "Prefer": "return=representation",
        },
        params=filters,
        json=payload,
        timeout=20,
    )
    if response.status_code not in {200, 204}:
        return None, supabase_error_message(response, f"Could not update {table}")
    rows = response.json() if response.text else []
    return (rows[0] if rows else payload), None


def oauth_user_for_access_token(token):
    if not token:
        return None
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = service_rows(
        "oauth_access_tokens",
        {
            "select": "user_id,client_id,scope,resource,expires_at,revoked_at",
            "token_hash": f"eq.{oauth_token_digest(token)}",
            "revoked_at": "is.null",
            "expires_at": f"gt.{now_iso}",
            "limit": "1",
        },
    )
    return rows[0] if rows else None


def identity_for_bearer_credential(credential):
    user_id = user_id_for_api_key(credential)
    if user_id:
        return user_id, "api_key"

    oauth_token = oauth_user_for_access_token(credential)
    if oauth_token:
        return oauth_token.get("user_id"), "oauth"

    return None, None


def user_id_for_bearer_credential(credential):
    user_id, _authentication = identity_for_bearer_credential(credential)
    return user_id


def require_api_user(view_function):
    @wraps(view_function)
    def wrapped(*args, **kwargs):
        user_id, authentication = identity_for_bearer_credential(api_key_from_request())
        if not user_id:
            return jsonify({
                "error": "Valid bearer credential required",
                "authentication": "Send Authorization: Bearer <API key or OAuth access token>"
            }), 401

        g.api_authentication = authentication
        return view_function(user_id, *args, **kwargs)

    return wrapped


def oauth_state_secret():
    secret = os.getenv("OAUTH_STATE_SECRET")
    if not secret:
        raise RuntimeError("OAUTH_STATE_SECRET is not configured")
    return secret.encode("utf-8")


def create_oauth_state(user_id, service, flow="legacy"):
    payload = {
        "user_id": user_id,
        "service": service,
        "flow": flow,
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


def read_oauth_state_payload(state, expected_service):
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
    if not isinstance(user_id, str) or not user_id or len(user_id) > 128:
        return None
    return payload


def read_oauth_state(state, expected_service):
    payload = read_oauth_state_payload(state, expected_service)
    return payload.get("user_id") if payload else None


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



def supabase_ai_integration(user_id, access_token):
    response = requests.get(
        f"{supabase_url()}/rest/v1/ai_integrations",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        params={
            "select": "user_id,key_prefix,enabled,providers,created_at,updated_at",
            "user_id": f"eq.{user_id}",
            "limit": "1",
        },
        timeout=20,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Could not load AI integration: %s",
            supabase_error_message(response, "unknown Supabase error"),
        )
        return None
    rows = response.json()
    return rows[0] if rows else None


def upsert_ai_integration(user_id, access_token, values):
    payload = {"user_id": user_id, **values}
    response = requests.post(
        f"{supabase_url()}/rest/v1/ai_integrations",
        headers={
            **supabase_headers(supabase_publishable_key(), access_token),
            "Prefer": "resolution=merge-duplicates,return=representation",
        },
        params={"on_conflict": "user_id"},
        json=payload,
        timeout=20,
    )
    if response.status_code not in {200, 201}:
        return None, supabase_error_message(
            response,
            "Could not save AI integration",
        )
    rows = response.json()
    return (rows[0] if rows else payload), None


def service_single_row(table, user_id, id_column="user_id", select="*"):
    response = requests.get(
        f"{supabase_url()}/rest/v1/{table}",
        headers=supabase_headers(supabase_secret_key(), supabase_secret_key()),
        params={
            "select": select,
            id_column: f"eq.{user_id}",
            "limit": "1",
        },
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Service lookup failed for %s: %s",
            table,
            supabase_error_message(response, "unknown error"),
        )
        return None
    rows = response.json()
    return rows[0] if rows else None


def service_coaching_goals(user_id):
    response = requests.get(
        f"{supabase_url()}/rest/v1/coaching_goals",
        headers=supabase_headers(supabase_secret_key(), supabase_secret_key()),
        params={
            "select": (
                "id,user_id,priority,title,status,priority_level,"
                "description,created_at,updated_at"
            ),
            "user_id": f"eq.{user_id}",
            "order": "priority.asc",
        },
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Service coaching goals lookup failed: %s",
            supabase_error_message(response, "unknown error"),
        )
        return []
    return response.json()



def finalize_onboarding_if_complete(user_id, access_token, state):
    if not state.get("complete"):
        return False

    profile = supabase_profile(user_id, access_token) or {}
    if profile.get("onboarding_completed"):
        return True

    _, error = update_supabase_profile(
        user_id,
        access_token,
        {"onboarding_completed": True},
    )
    if error:
        app.logger.warning(
            "Could not finalize onboarding for %s: %s",
            user_id,
            error,
        )
        return False
    return True

def api_coaching_context(user_id):
    profile = service_single_row(
        "profiles",
        user_id,
        id_column="id",
        select=(
            "id,username,display_name,timezone,units,date_of_birth,"
            "biological_sex,height_value,height_source,weather_location,"
            "max_hr_override,resting_hr_override,ftp_override,"
            "withings_onboarding_status,onboarding_completed"
        ),
    )
    training = service_single_row(
        "coaching_profiles",
        user_id,
        select=(
            "user_id,primary_focus,activity_preferences,weekday_minutes,"
            "weekend_minutes,coaching_style,equipment,indoor_platforms,"
            "bad_weather_strategy,created_at,updated_at"
        ),
    )
    context = service_single_row(
        "coaching_contexts",
        user_id,
        select=(
            "user_id,coaching_preferences,training_philosophy,"
            "lifestyle_constraints,additional_context,created_at,updated_at"
        ),
    )
    goals = service_coaching_goals(user_id)

    return {
        "profile": profile or {},
        "training_profile": training or {},
        "coaching_context": context or {},
        "goals": goals,
    }

def supabase_profile(user_id, access_token):
    response = requests.get(
        f"{supabase_url()}/rest/v1/profiles",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        params={
            "select": ("id,username,email,display_name,timezone,units,date_of_birth,"
                       "biological_sex,height_value,height_source,weather_location,"
                       "max_hr_override,resting_hr_override,ftp_override,"
                       "withings_onboarding_status,onboarding_completed,created_at"),
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
            "coaching_style,equipment,indoor_platforms,bad_weather_strategy,"
            "created_at,updated_at"
        ),
    )


def coaching_context(user_id, access_token):
    return supabase_single_row(
        "coaching_contexts",
        user_id,
        access_token,
        select=(
            "user_id,coaching_preferences,training_philosophy,"
            "lifestyle_constraints,additional_context,created_at,updated_at"
        ),
    )


def coaching_goals(user_id, access_token):
    response = requests.get(
        f"{supabase_url()}/rest/v1/coaching_goals",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        params={
            "select": (
                "id,user_id,priority,title,status,priority_level,"
                "description,created_at,updated_at"
            ),
            "user_id": f"eq.{user_id}",
            "order": "priority.asc",
        },
        timeout=15,
    )
    if response.status_code != 200:
        app.logger.warning(
            "Supabase coaching goals lookup failed: %s",
            supabase_error_message(response, "unknown error"),
        )
        return []
    return response.json()


def replace_coaching_goals(access_token, goals):
    response = requests.post(
        f"{supabase_url()}/rest/v1/rpc/replace_my_coaching_goals",
        headers=supabase_headers(supabase_publishable_key(), access_token),
        json={"p_goals": goals},
        timeout=15,
    )
    if response.status_code not in {200, 204}:
        message = supabase_error_message(response, "The goals could not be saved.")
        app.logger.warning("Supabase goals replacement failed: %s", message)
        return False, message
    return True, None


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
main{{width:min(860px,calc(100% - 32px));margin:48px auto;background:white;border:1px solid #dfe4ea;border-radius:14px;padding:28px;box-shadow:0 8px 24px rgba(0,0,0,.06)}}
h1{{margin-top:0}} label{{display:block;margin:16px 0 6px;font-weight:600}} input,select,textarea{{width:100%;box-sizing:border-box;padding:11px;border:1px solid #aab2bd;border-radius:8px;font:inherit}} textarea{{min-height:150px;resize:vertical}} code{{background:#eef1f4;border-radius:4px;padding:2px 5px}}
button,.button{{display:inline-block;margin-top:20px;padding:11px 16px;border:0;border-radius:8px;background:#1f5f99;color:white;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}}
.secondary,.button.secondary{{background:#5d6d7e;color:white}} .button.subtle{{background:#e8edf2;color:#273746}} .actions>a:not(.button){{display:inline-block;margin-top:20px;padding:11px 16px;border-radius:8px;background:#e8edf2;color:#273746;font-weight:650;text-decoration:none}} .error{{padding:12px;border-radius:8px;background:#fdecea;color:#922b21}} .success{{padding:12px;border-radius:8px;background:#eafaf1;color:#196f3d}}
dl{{display:grid;grid-template-columns:150px 1fr;gap:10px 16px}} dt{{font-weight:700}} dd{{margin:0}}
fieldset{{margin:20px 0;padding:16px;border:1px solid #dfe4ea;border-radius:10px}} legend{{font-weight:700;padding:0 6px}}
.check-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px 16px}} .check-grid label{{display:flex;align-items:flex-start;gap:8px;margin:0;font-weight:500}} .check-grid input{{width:auto;margin-top:3px}}
.wizard-progress{{list-style:none;padding:0;margin:0 0 24px;display:grid;gap:8px}} .wizard-progress li{{display:flex;justify-content:space-between;padding:9px 12px;border-radius:8px;background:#f1f3f5}} .wizard-progress .complete{{background:#eafaf1}} .wizard-progress .current{{background:#eaf2f8;font-weight:700}}
.actions{{display:flex;gap:12px;flex-wrap:wrap;align-items:center}} .account-actions{{margin:18px 0}} .account-actions .button{{margin-top:0}} .muted{{color:#5d6d7e}}
.table-scroll{{overflow-x:auto}} .preference-table{{width:100%;border-collapse:collapse}} .preference-table th,.preference-table td{{padding:8px;text-align:left;vertical-align:middle;border-bottom:1px solid #e5e8eb}} .preference-table thead th{{font-size:.9rem;color:#5d6d7e}} .preference-table tbody th{{width:64px;text-align:center}} .preference-table select{{min-width:190px}}
</style></head><body><main>{body}
<footer style="margin-top:32px;padding-top:18px;border-top:1px solid #e5e8eb;font-size:.92rem;color:#5d6d7e">
<a href="/privacy">Privacy Policy</a>
</footer></main></body></html>"""


def safe_local_next(value):
    value = (value or "").strip()
    if not value.startswith("/") or value.startswith("//"):
        return "/account"
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return "/account"
    return value


def login_form(error_message=None, next_path="/account"):
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    next_path = safe_local_next(next_path)
    return account_page("Log in", f"""
<h1>Log in</h1>{error_html}
<form method="post" action="/login">
<input type="hidden" name="next" value="{escape(next_path)}">
<label for="identifier">Email or username</label><input id="identifier" name="identifier" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required>
<button type="submit">Log in</button></form>
<p>Need an account? <a href="/register">Create one</a>.</p><p class="muted">By using this service, you acknowledge the <a href="/privacy">Privacy Policy</a>.</p>""")


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
<p>Already registered? <a href="/login">Log in</a>.</p><p class="muted">By creating an account, you acknowledge the <a href="/privacy">Privacy Policy</a>.</p>""")


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
    next_path = safe_local_next(request.values.get("next"))
    if current_account_session()[1]:
        return redirect(next_path)
    if request.method == "GET":
        return login_form(next_path=next_path)

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    email = lookup_email_for_identifier(identifier)
    if not email:
        return login_form("The email/username or password was not accepted.", next_path), 401

    auth_payload, error = supabase_password_login(email, password)
    if error:
        return login_form("The email/username or password was not accepted.", next_path), 401

    session_id = create_account_session(auth_payload)
    response = make_response(redirect(next_path))
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


def account_onboarding_state(user_id, token):
    profile = supabase_profile(user_id, token)
    training = coaching_profile(user_id, token)
    context = coaching_context(user_id, token)
    goals = coaching_goals(user_id, token)
    strava_status = strava_connection(user_id)
    withings_status = withings_connection(user_id)
    withings_skipped = bool(
        profile and profile.get("withings_onboarding_status") == "skipped"
    )
    ai_status = supabase_ai_integration(user_id, token)
    strava_connected = bool(
        isinstance(strava_status, dict) and strava_status.get("connected")
    )
    withings_connected = bool(
        isinstance(withings_status, dict) and withings_status.get("connected")
    )
    state = onboarding_state(
        profile,
        training,
        context,
        goals or [],
        integrations={
            "strava": strava_connected,
            "withings": withings_connected,
            "withings_skipped": withings_skipped,
            "ai": bool(ai_status and ai_status.get("enabled")),
        },
    )
    return (
        profile, training, context, goals,
        strava_status, withings_status, withings_skipped, ai_status, state,
    )


@app.route("/onboarding")
@require_account
def onboarding(session_data):
    user_id = session_data["user_id"]
    token = session_data["access_token"]
    profile = supabase_profile(user_id, token)
    training = coaching_profile(user_id, token)
    context = coaching_context(user_id, token)
    goals = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, goals)
    return redirect(state["next_step"]["path"] if state["next_step"] else "/account")


@app.route("/onboarding/profile", methods=["GET", "POST"])
@require_account
def onboarding_profile(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    profile = supabase_profile(user_id, token)
    if not profile:
        return account_page("Onboarding error", '<h1>Profile unavailable</h1>'), 500

    training = coaching_profile(user_id, token)
    context = coaching_context(user_id, token)
    goals = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, goals)
    error_message = None

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        timezone_name = request.form.get("timezone", "").strip()
        units = request.form.get("units", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        biological_sex = request.form.get("biological_sex", "").strip() or None
        height_value = request.form.get("height_value", "").strip()
        height_source = request.form.get("height_source", "auto").strip()
        weather_location = request.form.get("weather_location", "").strip()
        max_hr_override = request.form.get("max_hr_override", "").strip() or None
        resting_hr_override = request.form.get("resting_hr_override", "").strip() or None
        ftp_override = request.form.get("ftp_override", "").strip() or None

        try:
            height_number = float(height_value)
            if not 30 <= height_number <= 260:
                raise ValueError
        except ValueError:
            error_message = "Enter a valid height."
        if not error_message and not display_name:
            error_message = "Display name is required."
        elif not error_message and timezone_name not in COMMON_TIMEZONES:
            error_message = "Choose a supported time zone."
        elif not error_message and units not in {"imperial", "metric"}:
            error_message = "Choose imperial or metric units."
        elif not error_message and not date_of_birth:
            error_message = "Date of birth is required."
        elif not error_message and biological_sex not in {None, "male", "female", "intersex", "prefer_not"}:
            error_message = "Choose a valid biological sex option."
        elif not error_message and height_source not in {"auto", "manual"}:
            error_message = "Choose a valid height source."
        elif not error_message and not weather_location:
            error_message = "Enter a location for weather-aware coaching."

        if not error_message:
            updates = {
                "display_name": display_name,
                "timezone": timezone_name,
                "units": units,
                "date_of_birth": date_of_birth,
                "biological_sex": biological_sex,
                "height_value": height_number,
                "height_source": height_source,
                "weather_location": weather_location,
                "max_hr_override": int(max_hr_override) if max_hr_override else None,
                "resting_hr_override": int(resting_hr_override) if resting_hr_override else None,
                "ftp_override": int(ftp_override) if ftp_override else None,
                "onboarding_completed": False,
            }
            _, error_message = update_supabase_profile(user_id, token, updates)
            if not error_message:
                return redirect("/onboarding/training")

    def form_value(name, fallback=""):
        return request.form.get(name, profile.get(name) if profile.get(name) is not None else fallback)

    timezone_name = form_value("timezone", "America/Denver")
    units = form_value("units", "imperial")
    timezone_options = "".join(
        f'<option value="{escape(zone)}" {"selected" if zone == timezone_name else ""}>{escape(zone)}</option>'
        for zone in COMMON_TIMEZONES
    )
    sex_value = form_value("biological_sex", "")
    sex_options = [("", "— Optional —"), ("male", "Male"), ("female", "Female"),
                   ("intersex", "Intersex"), ("prefer_not", "Prefer not to say")]
    sex_html = "".join(
        f'<option value="{value}" {"selected" if value == sex_value else ""}>{label}</option>'
        for value, label in sex_options
    )
    source_value = form_value("height_source", "auto")
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""

    return account_page("Personal profile", f"""
{onboarding_progress_html(state, "profile")}
<h1>Personal profile</h1>
<p>Connected Strava and Withings values are used by default. Manual values below act as explicit overrides.</p>
{error_html}
<form method="post">
<label>Display name</label><input name="display_name" value="{escape(str(form_value("display_name")))}" required>
<label>Date of birth</label><input type="date" name="date_of_birth" value="{escape(str(form_value("date_of_birth")))}" required>
<label>Biological sex <span class="muted">(optional; used only where physiologically relevant)</span></label>
<select name="biological_sex">{sex_html}</select>
<label>Height</label>
<div class="form-grid two-column">
<input type="number" step="0.1" name="height_value" value="{escape(str(form_value("height_value")))}" required>
<select name="height_source">
<option value="auto" {"selected" if source_value == "auto" else ""}>Use connected data when available</option>
<option value="manual" {"selected" if source_value == "manual" else ""}>Always use this manual value</option>
</select></div>
<p class="muted">Enter inches for imperial units or centimeters for metric units.</p>
<label>Location for weather-aware coaching</label>
<input name="weather_location" value="{escape(str(form_value("weather_location")))}" placeholder="Salt Lake City, Utah, US" required>
<label>Time zone</label><select name="timezone" required>{timezone_options}</select>
<label>Measurement units</label><select name="units">
<option value="imperial" {"selected" if units == "imperial" else ""}>Imperial</option>
<option value="metric" {"selected" if units == "metric" else ""}>Metric</option>
</select>
<fieldset><legend>Optional manual overrides</legend>
<p class="muted">Leave blank to use Strava, Withings, or calculated values.</p>
<div class="form-grid two-column">
<div><label>Maximum heart rate</label><input type="number" name="max_hr_override" value="{escape(str(form_value("max_hr_override"))) if form_value("max_hr_override") else ""}"></div>
<div><label>Resting heart rate</label><input type="number" name="resting_hr_override" value="{escape(str(form_value("resting_hr_override"))) if form_value("resting_hr_override") else ""}"></div>
</div>
<label>FTP override</label><input type="number" name="ftp_override" value="{escape(str(form_value("ftp_override"))) if form_value("ftp_override") else ""}">
</fieldset>
<div class="actions"><button type="submit">Save and continue</button><a href="/account">Return to Account</a></div>
</form>""")


@app.route("/onboarding/training", methods=["GET", "POST"])
@require_account
def onboarding_training(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    profile = supabase_profile(user_id, token)
    if not profile_step_complete(profile):
        return redirect("/onboarding/profile")
    training = coaching_profile(user_id, token) or {}
    context = coaching_context(user_id, token)
    goals = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, goals)
    error_message = None

    if request.method == "POST":
        weekday_minutes, weekday_error = parse_bounded_minutes(request.form.get("weekday_minutes"), "Weekday duration")
        weekend_minutes, weekend_error = parse_bounded_minutes(request.form.get("weekend_minutes"), "Weekend duration")
        coaching_style = request.form.get("coaching_style", "").strip()
        bad_weather_strategy = request.form.get("bad_weather_strategy", "").strip()
        activity_preferences, selected = {}, []
        valid_activities = {key for key, _ in ACTIVITY_OPTIONS}
        valid_frequencies = {key for key, _ in ACTIVITY_FREQUENCY_OPTIONS}
        for priority in range(1, 6):
            activity = request.form.get(f"activity_{priority}", "").strip()
            frequency = request.form.get(f"frequency_{priority}", "").strip()
            if not activity and not frequency:
                continue
            if activity not in valid_activities or frequency not in valid_frequencies:
                error_message = f"Complete activity priority {priority}."
                break
            if activity in selected:
                error_message = "Each activity may appear only once."
                break
            selected.append(activity)
            activity_preferences[activity] = {"priority": priority, "frequency": frequency}
        if not error_message and not selected:
            error_message = "Choose at least one activity."
        if not error_message and weekday_error:
            error_message = weekday_error
        if not error_message and weekend_error:
            error_message = weekend_error
        if not error_message and coaching_style not in {k for k, _ in COACHING_STYLE_OPTIONS}:
            error_message = "Choose a coaching style."
        if not error_message and not bad_weather_strategy:
            error_message = "Describe what should happen when outdoor conditions are unsuitable."

        if not error_message:
            labels = dict(ACTIVITY_OPTIONS)
            primary_key = min(activity_preferences, key=lambda k: activity_preferences[k]["priority"])
            _, error_message = upsert_supabase_row("coaching_profiles", token, {
                "user_id": user_id,
                "primary_focus": labels[primary_key],
                "activity_preferences": activity_preferences,
                "weekday_minutes": weekday_minutes,
                "weekend_minutes": weekend_minutes,
                "coaching_style": coaching_style,
                "equipment": {k: k in request.form for k, _ in EQUIPMENT_OPTIONS},
                "indoor_platforms": [k for k, _ in PLATFORM_OPTIONS if k in request.form],
                "bad_weather_strategy": bad_weather_strategy,
            })
            if not error_message:
                return redirect("/onboarding/context")

    raw_saved_preferences = training.get("activity_preferences") or {}
    saved_preferences = {}
    for activity_key, preference in raw_saved_preferences.items():
        normalized_key = LEGACY_ACTIVITY_ALIASES.get(activity_key, activity_key)
        # If both an old alias and its new Strava value exist, keep the record
        # with the higher priority (lower number).
        existing = saved_preferences.get(normalized_key)
        if (
            existing is None
            or int((preference or {}).get("priority") or 999)
            < int((existing or {}).get("priority") or 999)
        ):
            saved_preferences[normalized_key] = preference

    by_priority = {
        int(v.get("priority")): (k, v.get("frequency"))
        for k, v in saved_preferences.items() if (v or {}).get("priority")
    }
    rows = []
    for priority in range(1, 6):
        saved_activity, saved_frequency = by_priority.get(priority, ("", ""))
        selected_activity = request.form.get(f"activity_{priority}", saved_activity)
        selected_frequency = request.form.get(f"frequency_{priority}", saved_frequency)
        activity_groups_html = []
        for group_label, activities in ACTIVITY_GROUPS:
            group_options = "".join(
                f'<option value="{key}" {"selected" if key == selected_activity else ""}>{escape(label)}</option>'
                for key, label in activities
            )
            activity_groups_html.append(
                f'<optgroup label="{escape(group_label)}">{group_options}</optgroup>'
            )
        activity_options = (
            '<option value="">— Leave blank —</option>'
            + "".join(activity_groups_html)
        )
        frequency_options = '<option value="">— Select frequency —</option>' + "".join(
            f'<option value="{k}" {"selected" if k == selected_frequency else ""}>{escape(label)}</option>'
            for k, label in ACTIVITY_FREQUENCY_OPTIONS
        )
        rows.append(f'<tr><th>{priority}</th><td><select name="activity_{priority}">{activity_options}</select></td>'
                    f'<td><select name="frequency_{priority}">{frequency_options}</select></td></tr>')

    def checked(key, saved):
        return "checked" if (key in request.form if request.method == "POST" else saved) else ""
    equipment_html = "".join(
        f'<label><input type="checkbox" name="{k}" {checked(k, (training.get("equipment") or {}).get(k))}><span>{escape(label)}</span></label>'
        for k, label in EQUIPMENT_OPTIONS
    )
    platforms_html = "".join(
        f'<label><input type="checkbox" name="{k}" {checked(k, k in (training.get("indoor_platforms") or []))}><span>{escape(label)}</span></label>'
        for k, label in PLATFORM_OPTIONS
    )
    style_value = request.form.get("coaching_style", training.get("coaching_style") or "adaptive")
    style_html = "".join(
        f'<option value="{k}" {"selected" if k == style_value else ""}>{escape(label)}</option>'
        for k, label in COACHING_STYLE_OPTIONS
    )
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    return account_page("Training profile", f"""
{onboarding_progress_html(state, "training")}
<h1>Training profile</h1>{error_html}
<form method="post">
<fieldset><legend>Activity preferences</legend><div class="table-scroll"><table class="preference-table">
<thead><tr><th>Priority</th><th>Activity</th><th>Typical availability</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div></fieldset>
<label>Typical weekday workout duration</label><input type="number" name="weekday_minutes" value="{escape(str(request.form.get("weekday_minutes", training.get("weekday_minutes", 60))))}">
<label>Typical weekend workout duration</label><input type="number" name="weekend_minutes" value="{escape(str(request.form.get("weekend_minutes", training.get("weekend_minutes", 120))))}">
<label>Default coaching style</label><select name="coaching_style">{style_html}</select>
<label>When weather is unsuitable for outdoor training</label>
<textarea name="bad_weather_strategy" placeholder="Include heat, cold, smoke, rain, snow, darkness, or other conditions. Describe preferred substitutions.">{escape(request.form.get("bad_weather_strategy", training.get("bad_weather_strategy") or ""))}</textarea>
<fieldset><legend>Equipment and access</legend><div class="check-grid">{equipment_html}</div></fieldset>
<fieldset><legend>Indoor platforms</legend><div class="check-grid">{platforms_html}</div></fieldset>
<div class="actions"><button type="submit">Save and continue</button><a href="/onboarding/profile">Back</a><a href="/account">Return to Account</a></div>
</form>""")


@app.route("/onboarding/context", methods=["GET", "POST"])
@require_account
def onboarding_context(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    profile = supabase_profile(user_id, token)
    training = coaching_profile(user_id, token)
    if not profile_step_complete(profile):
        return redirect("/onboarding/profile")
    if not training_step_complete(training):
        return redirect("/onboarding/training")
    context = coaching_context(user_id, token) or {}
    goals = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, goals)
    error_message = None
    fields = [
        ("coaching_preferences", "Coaching preferences", "How the coach should communicate, challenge, or question you."),
        ("training_philosophy", "Training habits and philosophy", "How different activities usually function in your training."),
        ("lifestyle_constraints", "Lifestyle and constraints", "Family, work, travel, schedule, injuries, or repeatability constraints."),
        ("additional_context", "Additional standing context", "Anything else the coach should consistently remember."),
    ]
    if request.method == "POST":
        values = {key: request.form.get(key, "").strip() or None for key, _, _ in fields}
        if not any(values.values()):
            error_message = "Enter at least one piece of coaching context."
        else:
            _, error_message = upsert_supabase_row("coaching_contexts", token, {"user_id": user_id, **values})
            if not error_message:
                return redirect("/onboarding/goals")
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    boxes = "".join(
        f'<label>{escape(label)}</label><p class="muted">{escape(help_text)}</p>'
        f'<textarea name="{key}" rows="8">{escape(request.form.get(key, context.get(key) or ""))}</textarea>'
        for key, label, help_text in fields
    )
    return account_page("Coaching context", f"""
{onboarding_progress_html(state, "context")}
<h1>Coaching context</h1>
<p>These are persistent instructions and circumstances, not goals or backend implementation details.</p>
{error_html}<form method="post">{boxes}
<div class="actions"><button type="submit">Save and continue</button><a href="/onboarding/training">Back</a><a href="/account">Return to Account</a></div>
</form>""")


@app.route("/onboarding/goals", methods=["GET", "POST"])
@require_account
def onboarding_goals(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    profile = supabase_profile(user_id, token)
    training = coaching_profile(user_id, token)
    context = coaching_context(user_id, token)
    if not profile_step_complete(profile):
        return redirect("/onboarding/profile")
    if not training_step_complete(training):
        return redirect("/onboarding/training")
    if not context_step_complete(context):
        return redirect("/onboarding/context")
    existing = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, existing)
    error_message = None

    if request.method == "POST":
        submitted = []
        for priority in range(1, MAX_GOALS + 1):
            title = request.form.get(f"goal_title_{priority}", "").strip()
            status = request.form.get(f"goal_status_{priority}", "").strip()
            priority_level = request.form.get(f"goal_priority_{priority}", "").strip()
            description = request.form.get(f"goal_description_{priority}", "").strip()
            if not title:
                if status or priority_level or description:
                    error_message = f"Goal {priority} needs a title or must be blank."
                    break
                continue
            if status not in {k for k, _ in GOAL_STATUS_OPTIONS}:
                error_message = f"Choose a status for goal {priority}."
                break
            if priority_level not in {k for k, _ in GOAL_PRIORITY_OPTIONS}:
                error_message = f"Choose a priority for goal {priority}."
                break
            submitted.append({
                "priority": priority, "title": title, "status": status,
                "priority_level": priority_level, "description": description or None,
            })
        if not error_message and not submitted:
            error_message = "Add at least one goal."
        if not error_message:
            saved, error_message = replace_coaching_goals(token, submitted)
            if saved:
                return redirect("/onboarding/strava")
    else:
        submitted = existing

    goals_by_priority = {int(g.get("priority") or i): g for i, g in enumerate(submitted, 1)}
    cards = []
    for priority in range(1, MAX_GOALS + 1):
        goal = goals_by_priority.get(priority, {})
        title = goal.get("title") or ""
        status_value = goal.get("status") or ("active" if priority == 1 else "")
        level_value = goal.get("priority_level") or ("high" if priority == 1 else "")
        description = goal.get("description") or ""
        status_html = '<option value="">— Select —</option>' + "".join(
            f'<option value="{k}" {"selected" if k == status_value else ""}>{escape(label)}</option>'
            for k, label in GOAL_STATUS_OPTIONS
        )
        level_html = '<option value="">— Select —</option>' + "".join(
            f'<option value="{k}" {"selected" if k == level_value else ""}>{escape(label)}</option>'
            for k, label in GOAL_PRIORITY_OPTIONS
        )
        cards.append(f"""
<fieldset class="goal-card"><legend>Goal {priority}</legend>
<label>Goal</label><input name="goal_title_{priority}" value="{escape(title)}" placeholder="e.g., Gradually reach about 165 lb">
<div class="form-grid two-column">
<div><label>Priority</label><select name="goal_priority_{priority}">{level_html}</select></div>
<div><label>Status</label><select name="goal_status_{priority}">{status_html}</select></div>
</div>
<label>Description and context</label>
<textarea name="goal_description_{priority}" rows="8" placeholder="Explain what this goal means, why it matters, and any tradeoffs or constraints.">{escape(description)}</textarea>
</fieldset>""")
    error_html = f'<p class="error">{escape(error_message)}</p>' if error_message else ""
    return account_page("Goals", f"""
{onboarding_progress_html(state, "goals")}
<h1>Goals</h1>
<p>Goals may be directional, ongoing, or numeric. Dates and formal success metrics are not required.</p>
{error_html}<form method="post">{"".join(cards)}
<div class="actions"><button type="submit">Save and continue</button><a href="/onboarding/context">Back</a><a href="/account">Return to Account</a></div>
</form>""")


def integration_placeholder_page(session_data, current_key, title, explanation):
    user_id = session_data["user_id"]
    token = session_data["access_token"]
    profile = supabase_profile(user_id, token)
    training = coaching_profile(user_id, token)
    context = coaching_context(user_id, token)
    goals = coaching_goals(user_id, token)
    state = onboarding_state(profile, training, context, goals)

    return account_page(
        title,
        f"""
{onboarding_progress_html(state, current_key)}
<h1>{escape(title)}</h1>
<p>{escape(explanation)}</p>
<p>
  Your completed profile, training preferences, coaching context, and goals
  have been saved. This connection stage has not been implemented yet.
</p>
<div class="actions">
  <a class="button" href="/account">Return to Account</a>
  <a href="/onboarding/goals">Edit goals</a>
</div>
""",
    )


@app.route("/onboarding/strava")
@require_account
def onboarding_strava(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    profile, training, context, goals, connection, _, _, _, state = account_onboarding_state(user_id, token)
    if not goals_step_complete(goals):
        return redirect("/onboarding/goals")

    if connection["connected"]:
        athlete = connection.get("athlete_name") or "your Strava account"
        status_html = f"""
<p class="success"><strong>Connected:</strong> {escape(athlete)}</p>
<p>Strava activity data can now be retrieved separately for this signed-in account.</p>
<div class="actions">
  <a class="button" href="/onboarding/withings">Continue to Withings</a>
  <a href="/account/connect/strava">Reconnect Strava</a>
  <a href="/account">Return to Account</a>
</div>
<form method="post" action="/account/disconnect/strava">
  <button class="secondary" type="submit">Disconnect Strava from this account</button>
</form>
"""
    else:
        status_html = """
<p>Connect Strava to import activities, heart-rate zones, power zones, and other training data.</p>
<p>This connection belongs only to the currently signed-in coaching account.</p>
<div class="actions">
  <a class="button" href="/account/connect/strava">Connect Strava</a>
  <a href="/account">Return to Account</a>
</div>
"""
    return account_page("Connect Strava", f"""
{onboarding_progress_html(state, "strava")}
<h1>Connect Strava</h1>
{status_html}
""")


@app.route("/account/connect/strava")
@require_account
def account_connect_strava(session_data):
    state = create_oauth_state(session_data["user_id"], "strava", flow="account")
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


@app.route("/account/disconnect/strava", methods=["POST"])
@require_account
def account_disconnect_strava(session_data):
    delete_service_tokens("strava", session_data["user_id"])
    return redirect("/onboarding/strava")


@app.route("/onboarding/withings")
@require_account
def onboarding_withings(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    (
        profile, training, context, goals,
        strava_status, connection, skipped, _, state,
    ) = account_onboarding_state(user_id, token)

    if not strava_status["connected"]:
        return redirect("/onboarding/strava")

    if connection["connected"]:
        status_html = """
<p class="success"><strong>Withings connected.</strong></p>
<p>Body measurements can now supplement the coaching summary for this account.</p>
<div class="actions">
  <a class="button" href="/onboarding/integrations">Continue</a>
  <a href="/account/connect/withings">Reconnect Withings</a>
  <a href="/account">Return to Account</a>
</div>
<form method="post" action="/account/disconnect/withings">
  <button class="secondary" type="submit">Disconnect Withings from this account</button>
</form>
"""
    elif skipped:
        status_html = """
<p><strong>Withings is currently skipped.</strong></p>
<p>This does not block onboarding or Strava-based coaching. You can connect it now or later.</p>
<div class="actions">
  <a class="button" href="/onboarding/integrations">Continue</a>
  <a href="/account/connect/withings">Connect Withings</a>
  <a href="/account">Return to Account</a>
</div>
"""
    else:
        status_html = """
<p>Withings is optional. Connecting it adds weight and body-composition trends to coaching.</p>
<div class="actions">
  <a class="button" href="/account/connect/withings">Connect Withings</a>
  <a href="/account">Return to Account</a>
</div>
<form method="post" action="/account/skip/withings">
  <button class="secondary" type="submit">Skip Withings for now</button>
</form>
"""

    return account_page("Connect Withings", f"""
{onboarding_progress_html(state, "withings")}
<h1>Connect Withings</h1>
{status_html}
""")


@app.route("/account/connect/withings")
@require_account
def account_connect_withings(session_data):
    state = create_oauth_state(
        session_data["user_id"],
        "withings",
        flow="account",
    )
    auth_url = (
        "https://account.withings.com/oauth2_user/authorize2"
        "?response_type=code"
        f"&client_id={WITHINGS_CLIENT_ID}"
        f"&redirect_uri={WITHINGS_REDIRECT_URI}"
        "&scope=user.info,user.metrics"
        f"&state={state}"
    )
    return redirect(auth_url)


@app.route("/account/skip/withings", methods=["POST"])
@require_account
def account_skip_withings(session_data):
    _, error = update_supabase_profile(
        session_data["user_id"],
        session_data["access_token"],
        {"withings_onboarding_status": "skipped"},
    )
    if error:
        return account_page(
            "Withings error",
            f'<h1>Could not skip Withings</h1><p class="error">{escape(error)}</p>',
        ), 500
    return redirect("/onboarding/integrations")


@app.route("/account/disconnect/withings", methods=["POST"])
@require_account
def account_disconnect_withings(session_data):
    delete_service_tokens("withings", session_data["user_id"])
    update_supabase_profile(
        session_data["user_id"],
        session_data["access_token"],
        {"withings_onboarding_status": "skipped"},
    )
    return redirect("/onboarding/withings")


@app.route("/onboarding/integrations")
@require_account
def onboarding_integrations(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    (
        profile, training, context, goals,
        strava_status, withings_status, withings_skipped, integration, state,
    ) = account_onboarding_state(user_id, token)

    if not state["completion"].get("withings"):
        return redirect("/onboarding/withings")

    finalized = finalize_onboarding_if_complete(user_id, token, state)
    if finalized:
        profile = {**(profile or {}), "onboarding_completed": True}

    generated_key = request.args.get("generated_key")
    generated_html = ""
    if generated_key:
        generated_html = f"""
<div class="success">
<strong>Copy this API key now.</strong> It will not be displayed again.
<p><code style="word-break:break-all">{escape(generated_key)}</code></p>
</div>
"""

    providers = (integration or {}).get("providers") or []
    provider_options = [
        ("chatgpt", "ChatGPT / custom GPT"),
        ("claude", "Claude"),
        ("other", "Another AI client"),
    ]
    provider_html = "".join(
        f'<label><input type="checkbox" name="providers" value="{value}"'
        f'{" checked" if value in providers else ""}> {escape(label)}</label>'
        for value, label in provider_options
    )

    if integration and integration.get("enabled"):
        key_status = (
            f'<p class="success"><strong>Active API key:</strong> '
            f'{escape(integration.get("key_prefix") or "fitness_")}…</p>'
        )
        key_actions = """
<form method="post" action="/account/integrations/generate-key">
  <button type="submit">Replace API key</button>
</form>
<form method="post" action="/account/integrations/revoke-key">
  <button class="secondary" type="submit">Revoke API key</button>
</form>
"""
    else:
        key_status = (
            "<p>No active AI access key exists for this account.</p>"
        )
        key_actions = """
<form method="post" action="/account/integrations/generate-key">
  <button type="submit">Generate API key</button>
</form>
"""

    chatgpt_instructions = ""
    if "chatgpt" in providers:
        chatgpt_instructions = f"""
<h2>ChatGPT custom GPT setup</h2>
<ol>
  <li>In ChatGPT, create or edit a custom GPT.</li>
  <li>Open its Actions configuration and import this OpenAPI schema:</li>
</ol>
<p><code style="word-break:break-all">{escape(request.url_root.rstrip("/") + "/openapi.json")}</code></p>
<ol start="3">
  <li>Choose API-key authentication using a bearer token.</li>
  <li>Paste the full fitness API key generated above.</li>
  <li>Add the coaching instructions below to the GPT instructions.</li>
  <li>Test <code>getCurrentFitnessAccount</code>, then <code>getCoachingContext</code> and <code>getFitnessSummary</code>.</li>
</ol>
<h3>Coaching instructions</h3>
<pre style="white-space:pre-wrap">Before giving individualized training advice:

1. Call getCurrentFitnessAccount to verify which account is connected.
2. Call getCoachingContext to load the user's profile, goals, preferences, constraints, equipment, and persistent coaching instructions.
3. Call getFitnessSummary to load recent training, intensity, readiness, and available body-composition data.
4. Call getRecentWorkouts or a specific activity endpoint when more detail is needed.
5. Treat the coaching context as persistent user instructions. Do not invent missing measurements or claim unavailable data is current.
6. When Withings is unavailable or intentionally skipped, use Strava and stored coaching context and clearly identify the limitation.
7. Give practical recommendations that account for available time, preferred activities, equipment, weather strategy, and stated goals.</pre>
<p class="muted">Creating or editing a custom GPT requires a ChatGPT plan that supports GPT creation. The fitness API key authenticates only to this coaching backend; it is not an OpenAI credential.</p>
"""

    claude_instructions = ""
    if "claude" in providers:
        claude_instructions = f"""
<h2>Claude connector setup</h2>
<p>Claude uses a remote MCP connector with OAuth. Add the connector URL below; Claude will open this site so you can sign in with the same account credentials used for onboarding and approve read-only access.</p>
<p><code style="word-break:break-all">{escape((os.getenv("MCP_PUBLIC_BASE_URL") or "MCP_PUBLIC_BASE_URL_NOT_CONFIGURED").rstrip("/") + "/mcp")}</code></p>
<ol>
  <li>In Claude, open <strong>Settings → Connectors</strong>.</li>
  <li>Select <strong>Add custom connector</strong>.</li>
  <li>Name it <strong>Fitness Coach</strong> and paste the connector URL above.</li>
  <li>When prompted, sign in to this fitness account and approve access.</li>
  <li>Enable the connector in the conversation’s Search and tools menu.</li>
</ol>
<h3>Suggested Claude project instructions</h3>
<pre style="white-space:pre-wrap">For every request involving current fitness, workouts, readiness, body composition, training plans, or individualized coaching:

1. Use get_current_fitness_account to verify the connected account.
2. Use get_coaching_context and get_fitness_summary before answering.
3. Do not claim the data is unavailable until you have attempted the relevant connector tools.
4. Use get_recent_workouts, get_activity_detail, or get_activity_zones when the summary is insufficient.
5. Treat stored coaching context as persistent user instructions, including goals, constraints, preferred activities, equipment, available time, and weather strategy.
6. When Withings is unavailable or intentionally skipped, rely on Strava and stored coaching context and clearly identify that limitation.
7. Do not invent missing measurements or describe unretrieved information as current.
8. Give practical recommendations and clearly distinguish retrieved data, reasonable inference, and general guidance.</pre>
<p class="muted">OAuth tokens are user-specific and short-lived. The connector URL itself is not a secret.</p>
"""

    other_instructions = ""
    if "other" in providers:
        other_instructions = f"""
<h2>Other AI client setup</h2>
<p>Use the client’s supported integration method:</p>
<ul>
  <li>For an OpenAPI-compatible client, import <code style="word-break:break-all">{escape(request.url_root.rstrip("/") + "/openapi.json")}</code> and authenticate with the generated fitness API key as a bearer token.</li>
  <li>For an MCP-compatible client, use the MCP connector URL format shown for supported remote connectors and treat the complete URL as a password.</li>
</ul>
<p class="muted">Exact menus and authentication options vary by client.</p>
"""

    selected_instructions = chatgpt_instructions + claude_instructions + other_instructions
    if not selected_instructions:
        selected_instructions = """
<p class="muted">Select one or more AI clients above and save the integrations to display setup instructions.</p>
"""

    return account_page("AI integrations", f"""
{onboarding_progress_html(state, "integrations")}
<h1>AI integrations</h1>
<p>Generate an account-specific key that an AI assistant can use to request this account’s coaching data. The key grants access to the fitness API; it does not contain or replace an OpenAI or Anthropic account credential.</p>
{generated_html}
{key_status}
<form method="post" action="/account/integrations/providers">
<fieldset>
<legend>Where will you use the coaching API?</legend>
<div class="check-grid">{provider_html}</div>
</fieldset>
<div class="actions">
  <button type="submit">Save integrations</button>
  <a href="/account">Return to Account</a>
</div>
</form>
<div class="actions">{key_actions}</div>
{selected_instructions}
<p class="muted">Replacing or revoking the key immediately disables the previous key.</p>
<p>Review the <a href="/privacy">Privacy Policy</a> for details about connected data, storage, AI clients, and account deletion.</p>
""")



@app.route("/account/integrations/providers", methods=["POST"])
@require_account
def account_integration_providers(session_data):
    allowed = {"chatgpt", "claude", "other"}
    providers = [
        value for value in request.form.getlist("providers")
        if value in allowed
    ]
    _, error = upsert_ai_integration(
        session_data["user_id"],
        session_data["access_token"],
        {"providers": providers},
    )
    if error:
        return account_page(
            "Integration error",
            f'<h1>Could not save integrations</h1><p class="error">{escape(error)}</p>',
        ), 500
    return redirect("/onboarding/integrations")


@app.route("/account/integrations/generate-key", methods=["POST"])
@require_account
def account_generate_integration_key(session_data):
    api_key = "fitness_" + secrets.token_urlsafe(32)
    _, error = upsert_ai_integration(
        session_data["user_id"],
        session_data["access_token"],
        {
            "api_key_hash": api_key_digest(api_key),
            "key_prefix": api_key[:16],
            "enabled": True,
        },
    )
    if error:
        return account_page(
            "Integration error",
            f'<h1>Could not generate API key</h1><p class="error">{escape(error)}</p>',
        ), 500

    (
        _profile, _training, _context, _goals,
        _strava, _withings, _skipped, _integration, state,
    ) = account_onboarding_state(
        session_data["user_id"],
        session_data["access_token"],
    )
    finalize_onboarding_if_complete(
        session_data["user_id"],
        session_data["access_token"],
        state,
    )

    return redirect(
        "/onboarding/integrations?generated_key=" + requests.utils.quote(api_key)
    )


@app.route("/account/integrations/revoke-key", methods=["POST"])
@require_account
def account_revoke_integration_key(session_data):
    _, error = upsert_ai_integration(
        session_data["user_id"],
        session_data["access_token"],
        {
            "api_key_hash": None,
            "key_prefix": None,
            "enabled": False,
        },
    )
    if error:
        return account_page(
            "Integration error",
            f'<h1>Could not revoke API key</h1><p class="error">{escape(error)}</p>',
        ), 500
    return redirect("/onboarding/integrations")



# ===========================================================================
# OAuth authorization server for remote MCP clients
# ===========================================================================

OAUTH_CODE_SECONDS = 5 * 60
OAUTH_ACCESS_TOKEN_SECONDS = 60 * 60
OAUTH_REFRESH_TOKEN_SECONDS = 60 * 60 * 24 * 30
OAUTH_SCOPE = "fitness.read"


def public_app_base_url():
    return os.getenv("PUBLIC_APP_BASE_URL", request.url_root.rstrip("/")).rstrip("/")


def public_mcp_base_url():
    value = os.getenv("MCP_PUBLIC_BASE_URL", "").rstrip("/")
    if not value:
        raise RuntimeError("MCP_PUBLIC_BASE_URL is not configured")
    return value


def oauth_json_error(error, description, status=400):
    response = jsonify({"error": error, "error_description": description})
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def oauth_client(client_id):
    rows = service_rows(
        "oauth_clients",
        {"select": "*", "client_id": f"eq.{client_id}", "limit": "1"},
    )
    return rows[0] if rows else None


def valid_redirect_uri(client, redirect_uri):
    return bool(client and redirect_uri in (client.get("redirect_uris") or []))


def normalize_scope(scope):
    requested = [item for item in (scope or OAUTH_SCOPE).split() if item]
    if not requested or any(item != OAUTH_SCOPE for item in requested):
        return None
    return " ".join(dict.fromkeys(requested))


def oauth_authorize_parameters(values):
    return {
        "response_type": values.get("response_type", ""),
        "client_id": values.get("client_id", ""),
        "redirect_uri": values.get("redirect_uri", ""),
        "scope": values.get("scope", OAUTH_SCOPE),
        "state": values.get("state", ""),
        "code_challenge": values.get("code_challenge", ""),
        "code_challenge_method": values.get("code_challenge_method", ""),
        "resource": values.get("resource", ""),
    }


def validate_authorize_parameters(params):
    client = oauth_client(params["client_id"])
    if params["response_type"] != "code":
        return None, "unsupported_response_type", "Only authorization_code is supported."
    if not client:
        return None, "invalid_request", "Unknown OAuth client."
    if not valid_redirect_uri(client, params["redirect_uri"]):
        return None, "invalid_request", "The redirect URI is not registered for this client."
    if params["code_challenge_method"] != "S256" or not params["code_challenge"]:
        return None, "invalid_request", "PKCE using S256 is required."
    if normalize_scope(params["scope"]) is None:
        return None, "invalid_scope", "Only fitness.read is supported."
    expected_resource = public_mcp_base_url()
    if params["resource"] and params["resource"].rstrip("/") != expected_resource:
        return None, "invalid_target", "The requested resource is not this MCP server."
    params["resource"] = expected_resource
    params["scope"] = normalize_scope(params["scope"])
    return client, None, None


def oauth_redirect_error(redirect_uri, state, error, description):
    query = {"error": error, "error_description": description}
    if state:
        query["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(redirect_uri + separator + urlencode(query))


@app.route("/.well-known/oauth-authorization-server")
def oauth_authorization_server_metadata():
    base = public_app_base_url()
    return jsonify({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [OAUTH_SCOPE],
    })


@app.route("/oauth/register", methods=["POST"])
def oauth_register_client():
    payload = request.get_json(silent=True) or {}
    redirect_uris = payload.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return oauth_json_error("invalid_client_metadata", "At least one redirect_uri is required.")
    if any(not isinstance(uri, str) or not uri.startswith(("https://", "http://localhost", "http://127.0.0.1")) for uri in redirect_uris):
        return oauth_json_error("invalid_redirect_uri", "Redirect URIs must use HTTPS, localhost, or 127.0.0.1.")
    if payload.get("token_endpoint_auth_method", "none") != "none":
        return oauth_json_error("invalid_client_metadata", "Only public clients using token_endpoint_auth_method=none are supported.")

    client_id = "mcp_" + secrets.token_urlsafe(24)
    client = {
        "client_id": client_id,
        "client_name": str(payload.get("client_name") or "MCP client")[:200],
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    _, error = service_insert("oauth_clients", client)
    if error:
        return oauth_json_error("server_error", error, 500)
    response = jsonify(client)
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    params = oauth_authorize_parameters(request.values)
    client, error, description = validate_authorize_parameters(params)
    if error:
        if client and valid_redirect_uri(client, params["redirect_uri"]):
            return oauth_redirect_error(params["redirect_uri"], params["state"], error, description)
        return account_page("Authorization error", f'<h1>Authorization could not begin</h1><p class="error">{escape(description)}</p>'), 400

    _, session_data = current_account_session()
    if not session_data:
        next_path = "/oauth/authorize?" + urlencode(params)
        return redirect("/login?" + urlencode({"next": next_path}))

    if request.method == "GET":
        hidden = "".join(
            f'<input type="hidden" name="{escape(key)}" value="{escape(value)}">'
            for key, value in params.items()
        )
        client_name = escape(client.get("client_name") or "Claude")
        return account_page("Authorize fitness access", f"""
<h1>Allow {client_name} to access your fitness coaching data?</h1>
<p>This grants read-only access to your account profile, coaching context, goals, recent workouts, activity details, zones, and available body-composition summaries.</p>
<p><strong>Signed in as:</strong> {escape(session_data.get("email") or session_data["user_id"])}</p>
<form method="post" action="/oauth/authorize">{hidden}
<div class="actions"><button type="submit" name="decision" value="approve">Allow access</button>
<button class="secondary" type="submit" name="decision" value="deny">Cancel</button></div></form>
<p class="muted">The client cannot change your fitness data. You can revoke access later by disconnecting the connector or revoking its token.</p>
""")

    if request.form.get("decision") != "approve":
        return oauth_redirect_error(params["redirect_uri"], params["state"], "access_denied", "The user declined access.")

    raw_code = secrets.token_urlsafe(32)
    payload = {
        "code_hash": oauth_token_digest(raw_code),
        "user_id": session_data["user_id"],
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "resource": params["resource"],
        "code_challenge": params["code_challenge"],
        "expires_at": datetime.fromtimestamp(time.time() + OAUTH_CODE_SECONDS, timezone.utc).isoformat(),
    }
    _, insert_error = service_insert("oauth_authorization_codes", payload)
    if insert_error:
        return account_page("Authorization error", f'<h1>Could not authorize access</h1><p class="error">{escape(insert_error)}</p>'), 500

    query = {"code": raw_code}
    if params["state"]:
        query["state"] = params["state"]
    separator = "&" if "?" in params["redirect_uri"] else "?"
    return redirect(params["redirect_uri"] + separator + urlencode(query))


def pkce_s256(value):
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def issue_oauth_tokens(user_id, client_id, scope, resource):
    access_token = "mcp_at_" + secrets.token_urlsafe(32)
    refresh_token = "mcp_rt_" + secrets.token_urlsafe(40)
    now = time.time()
    access_payload = {
        "token_hash": oauth_token_digest(access_token),
        "user_id": user_id,
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
        "expires_at": datetime.fromtimestamp(now + OAUTH_ACCESS_TOKEN_SECONDS, timezone.utc).isoformat(),
    }
    refresh_payload = {
        "token_hash": oauth_token_digest(refresh_token),
        "user_id": user_id,
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
        "expires_at": datetime.fromtimestamp(now + OAUTH_REFRESH_TOKEN_SECONDS, timezone.utc).isoformat(),
    }
    _, access_error = service_insert("oauth_access_tokens", access_payload)
    if access_error:
        return None, None, access_error
    _, refresh_error = service_insert("oauth_refresh_tokens", refresh_payload)
    if refresh_error:
        return None, None, refresh_error
    return access_token, refresh_token, None


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type", "")
    client_id = request.form.get("client_id", "")
    client = oauth_client(client_id)
    if not client:
        return oauth_json_error("invalid_client", "Unknown OAuth client.", 401)

    if grant_type == "authorization_code":
        code = request.form.get("code", "")
        redirect_uri = request.form.get("redirect_uri", "")
        verifier = request.form.get("code_verifier", "")
        rows = service_rows(
            "oauth_authorization_codes",
            {
                "select": "*",
                "code_hash": f"eq.{oauth_token_digest(code)}",
                "client_id": f"eq.{client_id}",
                "used_at": "is.null",
                "expires_at": f"gt.{datetime.now(timezone.utc).isoformat()}",
                "limit": "1",
            },
        )
        record = rows[0] if rows else None
        if not record or redirect_uri != record.get("redirect_uri"):
            return oauth_json_error("invalid_grant", "The authorization code is invalid or expired.")
        if not verifier or not hmac.compare_digest(pkce_s256(verifier), record.get("code_challenge") or ""):
            return oauth_json_error("invalid_grant", "PKCE verification failed.")
        _, update_error = service_update(
            "oauth_authorization_codes",
            {"code_hash": f"eq.{oauth_token_digest(code)}", "used_at": "is.null"},
            {"used_at": datetime.now(timezone.utc).isoformat()},
        )
        if update_error:
            return oauth_json_error("server_error", update_error, 500)
        access_token, refresh_token, issue_error = issue_oauth_tokens(
            record["user_id"], client_id, record["scope"], record["resource"]
        )
        if issue_error:
            return oauth_json_error("server_error", issue_error, 500)

    elif grant_type == "refresh_token":
        supplied_refresh = request.form.get("refresh_token", "")
        rows = service_rows(
            "oauth_refresh_tokens",
            {
                "select": "*",
                "token_hash": f"eq.{oauth_token_digest(supplied_refresh)}",
                "client_id": f"eq.{client_id}",
                "revoked_at": "is.null",
                "expires_at": f"gt.{datetime.now(timezone.utc).isoformat()}",
                "limit": "1",
            },
        )
        record = rows[0] if rows else None
        if not record:
            return oauth_json_error("invalid_grant", "The refresh token is invalid or expired.")
        service_update(
            "oauth_refresh_tokens",
            {"token_hash": f"eq.{oauth_token_digest(supplied_refresh)}", "revoked_at": "is.null"},
            {"revoked_at": datetime.now(timezone.utc).isoformat()},
        )
        access_token, refresh_token, issue_error = issue_oauth_tokens(
            record["user_id"], client_id, record["scope"], record["resource"]
        )
        if issue_error:
            return oauth_json_error("server_error", issue_error, 500)
    else:
        return oauth_json_error("unsupported_grant_type", "Only authorization_code and refresh_token are supported.")

    response = jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": OAUTH_ACCESS_TOKEN_SECONDS,
        "refresh_token": refresh_token,
        "scope": record["scope"],
    })
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/oauth/introspect", methods=["POST"])
def oauth_introspect():
    expected = os.getenv("MCP_OAUTH_INTROSPECTION_SECRET", "")
    supplied = request.headers.get("Authorization", "")
    if not expected or not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:].strip(), expected):
        return oauth_json_error("invalid_client", "Introspection authentication failed.", 401)
    record = oauth_user_for_access_token(request.form.get("token", ""))
    if not record:
        return jsonify({"active": False})
    return jsonify({
        "active": True,
        "sub": record["user_id"],
        "client_id": record["client_id"],
        "scope": record["scope"],
        "aud": record["resource"],
        "exp": int(datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")).timestamp()),
    })


@app.route("/account")
@require_account
def account(session_data):
    user_id, token = session_data["user_id"], session_data["access_token"]
    try:
        (
            profile,
            training,
            context,
            goals,
            strava_status,
            withings_status,
            withings_skipped,
            ai_status,
            state,
        ) = account_onboarding_state(user_id, token)
    except Exception:
        app.logger.exception("Failed to build account onboarding state")
        return account_page(
            "Account error",
            '<h1>Account unavailable</h1>'
            '<p class="error">The account page could not load its current status. '
            'The error has been written to the server log.</p>'
            '<div class="actions"><a class="button subtle" href="/">Return home</a></div>',
        ), 500

    if not isinstance(profile, dict):
        return account_page("Account error", '<h1>Account unavailable</h1>'), 500

    goals = goals if isinstance(goals, list) else []
    strava_status = strava_status if isinstance(strava_status, dict) else {}
    withings_status = withings_status if isinstance(withings_status, dict) else {}
    next_step = state["next_step"]
    next_html = (
        f'<p><strong>Next step:</strong> {escape(next_step["label"])}</p>'
        f'<p><a class="button" href="{escape(next_step["path"])}">Continue onboarding</a></p>'
        if next_step else '<p class="success">Onboarding complete.</p>'
    )
    links = "".join([
        '<a class="button subtle" href="/onboarding/profile">Edit personal profile</a>',
        '<a class="button subtle" href="/onboarding/training">Edit training profile</a>',
        '<a class="button subtle" href="/onboarding/context">Edit coaching context</a>',
        '<a class="button subtle" href="/onboarding/goals">Edit goals</a>',
        '<a class="button subtle" href="/onboarding/strava">Strava connection</a>',
        '<a class="button subtle" href="/onboarding/withings">Withings connection</a>',
        '<a class="button subtle" href="/onboarding/integrations">AI integrations</a>',
        '<a class="button subtle" href="/privacy">Privacy policy</a>',
    ])
    return account_page("Account", f"""
<h1>{escape(profile.get("display_name") or profile.get("username") or profile.get("email") or "Account")}</h1>
<dl>
<dt>Location</dt><dd>{escape(profile.get("weather_location") or "")}</dd>
<dt>Time zone</dt><dd>{escape(profile.get("timezone") or "")}</dd>
<dt>Training profile</dt><dd>{"Configured" if training_step_complete(training) else "Not configured"}</dd>
<dt>Coaching context</dt><dd>{"Configured" if context_step_complete(context) else "Not configured"}</dd>
<dt>Goals</dt><dd>{len(goals)} configured</dd>
<dt>Strava</dt><dd>{"Connected" if strava_status.get("connected") else "Not connected"}</dd>
<dt>Withings</dt><dd>{"Connected" if withings_status.get("connected") else ("Skipped" if withings_skipped else "Not configured")}</dd>
<dt>AI access</dt><dd>{"Active" if ai_status and ai_status.get("enabled") else "Not configured"}</dd>
<dt>Onboarding</dt><dd>{"Complete" if state["complete"] else "In progress"}</dd>
</dl>{next_html}
<div class="actions account-actions">{links}</div>
{"<div class='success'><strong>Onboarding complete.</strong> Your account is ready for an AI coaching client.</div>" if state.get("complete") else ""}
<h2>Set up your AI coach</h2>
<p>Use the AI Integrations page to configure ChatGPT or Claude, generate or replace an integration key, and copy the current setup instructions.</p>
<ol>
  <li>Create or edit your custom GPT.</li>
  <li>Import the OpenAPI schema shown on the AI Integrations page.</li>
  <li>Configure bearer authentication with the generated fitness API key.</li>
  <li>Add the supplied coaching instructions to the GPT instructions.</li>
  <li>Test <code>/whoami</code>, then <code>/coaching-context</code> and <code>/summary</code>.</li>
</ol>
<p class="muted">Creating or editing a custom GPT requires a ChatGPT plan that supports GPT creation. Your fitness account does not store OpenAI credentials.</p>
<div class="actions">
  <a class="button" href="/onboarding/integrations">Open AI Integrations</a>
</div>
<form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form>""")


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

@app.route("/privacy")
def privacy_policy():
    operator_name = os.getenv("PRIVACY_OPERATOR_NAME", "Fitness Coaching")
    contact_email = os.getenv("PRIVACY_CONTACT_EMAIL", "").strip()
    contact_html = (
        f'<a href="mailto:{escape(contact_email)}">{escape(contact_email)}</a>'
        if contact_email
        else "the service operator using the contact information supplied with your account"
    )
    effective_date = "July 27, 2026"

    return account_page("Privacy Policy", f"""
<h1>Privacy Policy</h1>
<p><strong>Effective date:</strong> {effective_date}</p>
<p>This policy explains how {escape(operator_name)} (“the service,” “we,” or “us”) collects, uses, stores, and shares information when you create an account, connect fitness services, and use an AI coaching client with this service.</p>

<h2>1. What the service does</h2>
<p>The service retrieves fitness and wellness information that you authorize, combines it with goals and coaching preferences you provide, and makes that information available to an AI coaching client you choose, such as ChatGPT or Claude. The service is intended for general fitness coaching and planning. It is not medical care, diagnosis, or treatment.</p>

<h2>2. Information we collect</h2>
<ul>
  <li><strong>Account information:</strong> email address, username, display name, authentication identifiers, time zone, units, and account status.</li>
  <li><strong>Profile and coaching information:</strong> date of birth, height, optional biological sex, location used for weather-aware coaching, heart-rate or FTP overrides, goals, preferred activities, available training time, equipment, constraints, coaching preferences, and other context you submit.</li>
  <li><strong>Strava information:</strong> account connection status and authorized activity data, which may include activity names, sport types, dates, durations, distances, elevation, heart rate, power, pace, zones, streams, and related athlete information permitted by the scopes you approve.</li>
  <li><strong>Withings information:</strong> when connected, authorized measurements and summaries such as weight and body-composition information. Withings is optional.</li>
  <li><strong>Integration information:</strong> enabled AI providers, hashed integration credentials, credential prefixes, OAuth connection metadata, and requests made through the coaching API or MCP connector.</li>
  <li><strong>Technical information:</strong> server logs and security information such as timestamps, request paths, error details, IP-derived network information, and user-agent information generated by hosting and infrastructure providers.</li>
</ul>

<h2>3. How we use information</h2>
<p>We use information to authenticate accounts; connect and refresh authorized data sources; retrieve and summarize fitness data; provide account-specific context to authorized AI coaching clients; maintain preferences and goals; troubleshoot errors; protect the service; and improve reliability and functionality.</p>
<p>We do not sell personal information or use connected fitness information for advertising.</p>

<h2>4. AI coaching clients</h2>
<p>When you enable ChatGPT, Claude, or another supported client, that client may request information from the service to answer your prompts. The service returns only information associated with the authenticated account and the requested coaching function. The AI provider separately processes prompts, tool requests, and returned data under its own terms and privacy policy. Do not connect an AI provider unless you are comfortable with that provider processing the information returned to it.</p>

<h2>5. Authorization credentials</h2>
<p>Strava and Withings access and refresh tokens are stored so the service can retrieve information you authorized without requiring you to reconnect for every request. AI integration keys are stored as cryptographic hashes rather than plaintext. During the current Claude connector implementation, the full connector URL contains a secret credential and should be treated like a password. Replacing or revoking the credential invalidates the previous connector URL.</p>

<h2>6. Service providers and disclosures</h2>
<p>Information may be processed by service providers necessary to operate the service, including hosting, database, authentication, logging, and connected-platform providers. Current infrastructure may include Render and Supabase, while connected data and AI requests may involve Strava, Withings, OpenAI, or Anthropic depending on what you enable.</p>
<p>We may also disclose information when reasonably necessary to comply with law, protect users or the service, investigate abuse or security incidents, or complete a business transfer. We do not authorize service providers to use account information for their own advertising.</p>

<h2>7. Retention and deletion</h2>
<p>We retain account, coaching, connection, and integration information while your account remains active or as reasonably necessary to provide and secure the service. Operational logs may be retained for a shorter period determined by infrastructure settings. Disconnecting Strava or Withings stops future retrieval but may not automatically delete previously stored profile or summary information.</p>
<p>You may request account deletion and deletion of associated stored data by contacting {contact_html}. Some limited records may be retained when required for security, legal compliance, fraud prevention, or backup integrity.</p>

<h2>8. Your choices</h2>
<ul>
  <li>You may leave Withings disconnected or mark it as skipped.</li>
  <li>You may disconnect Strava or Withings and revoke access through the connected platform.</li>
  <li>You may replace or revoke AI integration credentials from the AI Integrations page.</li>
  <li>You may edit coaching context, profile information, goals, and activity preferences through your account.</li>
  <li>You may request access, correction, export, or deletion of stored information by contacting {contact_html}.</li>
</ul>

<h2>9. Security</h2>
<p>We use measures intended to reduce unauthorized access, including encrypted HTTPS connections, account authentication, scoped platform authorization, server-side credential storage, hashed AI integration keys, and account-level authorization checks. No system can guarantee absolute security. You are responsible for protecting your password, integration keys, and Claude connector URL.</p>

<h2>10. Health and fitness disclaimer</h2>
<p>Fitness, wellness, and body-composition information can be sensitive. This service is not represented as a healthcare provider or HIPAA-compliant service, and it should not be used to store or transmit information requiring a HIPAA-regulated environment. Coaching output may be incomplete or incorrect and should not replace professional medical advice, diagnosis, or treatment.</p>

<h2>11. Children</h2>
<p>The service is not intended for children under 13, and we do not knowingly collect personal information directly from children under 13. Do not create an account for a child or connect a child’s fitness data without confirming that doing so is lawful and appropriate.</p>

<h2>12. Changes to this policy</h2>
<p>We may update this policy as the service, integrations, or legal requirements change. The revised policy will be posted here with a new effective date. Material changes may also be communicated through the account interface when practical.</p>

<h2>13. Contact</h2>
<p>Questions, privacy requests, and deletion requests may be directed to {contact_html}.</p>
<div class="actions"><a class="button subtle" href="/">Return home</a><a class="button subtle" href="/account">Account</a></div>
""")

@app.route("/")
def home():
    return account_page("Fitness Coaching", """
<h1>Fitness Coaching</h1>
<p>Connect your fitness accounts and provide individualized coaching context for use with supported AI coaching clients.</p>
<div class="actions">
  <a class="button" href="/account">Account login and profile</a>
  <a class="button subtle" href="/privacy">Privacy policy</a>
</div>
<p class="muted">Fitness data endpoints require an authenticated AI integration. The legacy setup route remains available for compatibility but is no longer linked from this directory.</p>
""")


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
    authorization_error = request.args.get("error")
    payload = read_oauth_state_payload(request.args.get("state"), "strava")

    if not payload:
        return "Invalid or expired OAuth state", 400

    user_id = payload["user_id"]
    flow = payload.get("flow", "legacy")

    if authorization_error:
        if flow == "account":
            return redirect("/onboarding/strava?error=authorization_denied")
        return f"Authorization failed: {authorization_error}", 400

    if not code:
        return "Missing authorization code", 400

    token_data, exchange_error = exchange_strava_code(code, user_id=user_id)
    if exchange_error:
        message, status = exchange_error
        return f"Token exchange failed: {message}", status

    if flow == "account":
        _, current_session = current_account_session()
        if not current_session or current_session.get("user_id") != user_id:
            return redirect("/login")
        return redirect("/onboarding/strava?connected=1")

    athlete = token_data.get("athlete", {})
    athlete_name = " ".join(
        part for part in [athlete.get("firstname"), athlete.get("lastname")] if part
    ) or "the selected account"
    return setup_dashboard(user_id, f"Strava connected successfully for {athlete_name}.")



@app.route("/whoami")
@require_api_user
def api_whoami(user_id):
    profile = service_single_row(
        "profiles",
        user_id,
        id_column="id",
        select="id,username,display_name,timezone,units,onboarding_completed",
    ) or {}

    return jsonify({
        "authentication": getattr(g, "api_authentication", "internal"),
        "user_id": user_id,
        "username": profile.get("username"),
        "display_name": profile.get("display_name"),
        "timezone": profile.get("timezone"),
        "units": profile.get("units"),
        "onboarding_completed": bool(profile.get("onboarding_completed")),
    })


@app.route("/coaching-context")
@require_api_user
def api_context(user_id):
    payload = api_coaching_context(user_id)
    payload["user_id"] = user_id
    payload["debug_version"] = "multiuser-step19a-coaching-api"
    return jsonify(payload)


@app.route("/openapi.json")
def openapi_schema():
    server_url = request.url_root.rstrip("/")
    return jsonify({
        "openapi": "3.1.0",
        "info": {
            "title": "Fitness Coaching API",
            "version": "1.0.0",
            "description": (
                "Account-scoped fitness and coaching context for an AI coaching client."
            ),
        },
        "servers": [{"url": server_url}],
        "components": {
            "schemas": {
                "WhoAmIResponse": {
                    "type": "object",
                    "properties": {
                        "authentication": {"type": "string"},
                        "user_id": {"type": "string"},
                        "username": {"type": ["string", "null"]},
                        "display_name": {"type": ["string", "null"]},
                        "timezone": {"type": ["string", "null"]},
                        "units": {"type": ["string", "null"]},
                        "onboarding_completed": {"type": "boolean"},
                    },
                },
                "CoachingContextResponse": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "debug_version": {"type": "string"},
                        "profile": {
                            "type": "object",
                            "additionalProperties": True,
                            "properties": {
                                "id": {"type": ["string", "null"]},
                                "display_name": {"type": ["string", "null"]},
                                "timezone": {"type": ["string", "null"]},
                                "units": {"type": ["string", "null"]},
                            },
                        },
                        "training_profile": {
                            "type": "object",
                            "additionalProperties": True,
                            "properties": {
                                "primary_focus": {"type": ["string", "null"]},
                                "activity_preferences": {
                                    "type": ["array", "object", "null"]
                                },
                                "weekday_minutes": {"type": ["integer", "null"]},
                                "weekend_minutes": {"type": ["integer", "null"]},
                            },
                        },
                        "coaching_context": {
                            "type": "object",
                            "additionalProperties": True,
                            "properties": {
                                "coaching_preferences": {
                                    "type": ["string", "null"]
                                },
                                "training_philosophy": {
                                    "type": ["string", "null"]
                                },
                                "lifestyle_constraints": {
                                    "type": ["string", "null"]
                                },
                                "additional_context": {
                                    "type": ["string", "null"]
                                },
                            },
                        },
                        "goals": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True,
                                "properties": {
                                    "id": {"type": ["integer", "string"]},
                                    "title": {"type": ["string", "null"]},
                                    "status": {"type": ["string", "null"]},
                                    "priority": {"type": ["integer", "null"]},
                                    "description": {"type": ["string", "null"]},
                                },
                            },
                        },
                    },
                },
                "GenericFitnessResponse": {
                    "type": "object",
                    "additionalProperties": True,
                    "properties": {
                        "debug_version": {"type": ["string", "null"]},
                        "user_id": {"type": ["string", "null"]},
                        "error": {"type": ["string", "null"]},
                    },
                },
                "WorkoutsResponse": {
                    "type": "object",
                    "additionalProperties": True,
                    "properties": {
                        "workouts": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": True,
                                "properties": {
                                    "id": {"type": ["integer", "string"]},
                                    "name": {"type": ["string", "null"]},
                                    "sport_type": {"type": ["string", "null"]},
                                    "start_date": {"type": ["string", "null"]},
                                },
                            },
                        },
                        "error": {"type": ["string", "null"]},
                    },
                },
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API key",
                }
            }
        },
        "security": [{"bearerAuth": []}],
        "paths": {
            "/whoami": {
                "get": {
                    "operationId": "getCurrentFitnessAccount",
                    "summary": "Identify the connected fitness account",
                    "responses": {
                        "200": {
                            "description": "Connected account identity",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/WhoAmIResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/coaching-context": {
                "get": {
                    "operationId": "getCoachingContext",
                    "summary": "Get profile, preferences, constraints, and goals",
                    "responses": {
                        "200": {
                            "description": "Coaching context",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CoachingContextResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/summary": {
                "get": {
                    "operationId": "getFitnessSummary",
                    "summary": "Get the current 14-day fitness and readiness summary",
                    "responses": {
                        "200": {
                            "description": "Fitness summary",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/GenericFitnessResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/workouts": {
                "get": {
                    "operationId": "getRecentWorkouts",
                    "summary": "Get recent workouts with available zone data",
                    "responses": {
                        "200": {
                            "description": "Recent workouts",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/WorkoutsResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/activity/{activity_id}": {
                "get": {
                    "operationId": "getActivityDetail",
                    "summary": "Get detail for one activity",
                    "parameters": [{
                        "name": "activity_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }],
                    "responses": {
                        "200": {
                            "description": "Activity detail",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/GenericFitnessResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/activity/{activity_id}/zones": {
                "get": {
                    "operationId": "getActivityZones",
                    "summary": "Get zone data for one activity",
                    "parameters": [{
                        "name": "activity_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }],
                    "responses": {
                        "200": {
                            "description": "Activity zones",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/GenericFitnessResponse"}
                                }
                            },
                        }
                    },
                }
            },
        },
    })

def strava_source_athlete_id(user_id, payload=None):
    """Return the linked Strava athlete ID without conflating it with our user UUID."""
    if isinstance(payload, dict):
        athlete = payload.get("athlete")
        if isinstance(athlete, dict) and athlete.get("id") is not None:
            return athlete.get("id")
        for key in ("source_athlete_id", "athlete_id", "strava_athlete_id"):
            if payload.get(key) is not None:
                return payload.get(key)

    connection = strava_connection(user_id)
    if isinstance(connection, dict):
        athlete = connection.get("athlete")
        if isinstance(athlete, dict) and athlete.get("id") is not None:
            return athlete.get("id")
        for key in ("athlete_id", "strava_athlete_id", "source_athlete_id"):
            if connection.get(key) is not None:
                return connection.get(key)
    return None


def add_activity_identity(payload, user_id):
    """Add backend/source identity fields while preserving the native Strava payload."""
    if not isinstance(payload, dict):
        return payload
    result = dict(payload)
    result["user_id"] = user_id
    result["source"] = "strava"
    result["source_athlete_id"] = strava_source_athlete_id(user_id, result)
    return result


@app.route("/activity/<int:activity_id>")
@require_api_user
def activity_detail(user_id, activity_id):
    detail, error = get_activity_detail(activity_id, user_id=user_id)
    if error:
        message, status = error
        return jsonify({"error": message}), status
    return jsonify(add_activity_identity(detail, user_id))

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
    authorization_error = request.args.get("error")
    payload = read_oauth_state_payload(request.args.get("state"), "withings")

    if not payload:
        return "Invalid or expired OAuth state", 400

    user_id = payload["user_id"]
    flow = payload.get("flow", "legacy")

    if authorization_error:
        if flow == "account":
            return redirect("/onboarding/withings?error=authorization_denied")
        return f"Withings authorization failed: {authorization_error}", 400

    if not code:
        return "Missing Withings authorization code", 400

    token_data, token_error = exchange_withings_code(code, user_id=user_id)
    if token_error:
        message, status = token_error
        return jsonify({
            "error": "Withings token exchange failed",
            "details": message,
        }), status

    if flow == "account":
        _, current_session = current_account_session()
        if not current_session or current_session.get("user_id") != user_id:
            return redirect("/login")
        update_supabase_profile(
            user_id,
            current_session["access_token"],
            {"withings_onboarding_status": "connected"},
        )
        return redirect("/onboarding/withings?connected=1")

    return setup_dashboard(user_id, "Withings connected successfully.")


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



def mcp_jsonrpc_result(request_id, result, status=200):
    response = jsonify({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    })
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["MCP-Protocol-Version"] = request.headers.get(
        "MCP-Protocol-Version",
        "2025-06-18",
    )
    return response


def mcp_jsonrpc_error(request_id, code, message, status=200):
    response = jsonify({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    })
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["MCP-Protocol-Version"] = request.headers.get(
        "MCP-Protocol-Version",
        "2025-06-18",
    )
    return response


def mcp_tool_result(payload, is_error=False):
    return {
        "content": [{
            "type": "text",
            "text": json.dumps(payload, ensure_ascii=False, default=str),
        }],
        "structuredContent": payload if isinstance(payload, dict) else {"result": payload},
        "isError": bool(is_error),
    }


def response_payload(response_value):
    status = 200
    value = response_value

    if isinstance(response_value, tuple):
        value = response_value[0]
        if len(response_value) > 1:
            status = response_value[1]

    if hasattr(value, "status_code"):
        status = value.status_code

    if hasattr(value, "get_json"):
        payload = value.get_json(silent=True)
        if payload is None:
            payload = {"result": value.get_data(as_text=True)}
    elif isinstance(value, dict):
        payload = value
    else:
        payload = {"result": str(value)}

    return payload, status


MCP_TOOLS = [
    {
        "name": "get_current_fitness_account",
        "title": "Current Fitness Account",
        "description": "Verify the connected fitness account before giving personalized coaching.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_coaching_context",
        "title": "Coaching Context",
        "description": "Load the user's profile, goals, preferences, constraints, equipment, and persistent coaching context.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_fitness_summary",
        "title": "Fitness Summary",
        "description": "Load the recent 14-day fitness summary, intensity, readiness, and available Withings data.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "get_recent_workouts",
        "title": "Recent Workouts",
        "description": "Load recent workouts when the summary is not detailed enough.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "get_activity_detail",
        "title": "Activity Detail",
        "description": "Load detailed information for one Strava activity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "activity_id": {
                    "type": "integer",
                    "description": "The Strava activity ID.",
                }
            },
            "required": ["activity_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "get_activity_zones",
        "title": "Activity Zones",
        "description": "Load heart-rate, power, or pace zones for one Strava activity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "activity_id": {
                    "type": "integer",
                    "description": "The Strava activity ID.",
                }
            },
            "required": ["activity_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
]


def call_mcp_tool(user_id, tool_name, arguments):
    arguments = arguments or {}

    if tool_name == "get_current_fitness_account":
        return response_payload(api_whoami.__wrapped__(user_id))

    if tool_name == "get_coaching_context":
        return response_payload(api_context.__wrapped__(user_id))

    if tool_name == "get_fitness_summary":
        return response_payload(summary.__wrapped__(user_id))

    if tool_name == "get_recent_workouts":
        return response_payload(workouts.__wrapped__(user_id))

    if tool_name == "get_activity_detail":
        activity_id = arguments.get("activity_id")
        if not isinstance(activity_id, int):
            return {"error": "activity_id must be an integer"}, 400
        return response_payload(activity_detail.__wrapped__(user_id, activity_id))

    if tool_name == "get_activity_zones":
        activity_id = arguments.get("activity_id")
        if not isinstance(activity_id, int):
            return {"error": "activity_id must be an integer"}, 400
        return response_payload(activity_zones.__wrapped__(user_id, activity_id))

    return {"error": f"Unknown tool: {tool_name}"}, 404



@app.route("/mcp-check/<api_key>", methods=["GET"])
def claude_mcp_check(api_key):
    try:
        user_id = user_id_for_api_key(api_key)
        if not user_id:
            return jsonify({
                "ok": False,
                "error": "Invalid or revoked connector key",
            }), 401

        return jsonify({
            "ok": True,
            "user_id": user_id,
            "protocol_versions": [
                "2024-11-05",
                "2025-03-26",
                "2025-06-18",
                "2025-11-25",
            ],
            "tool_count": len(MCP_TOOLS),
            "tools": [tool["name"] for tool in MCP_TOOLS],
        })
    except Exception as exc:
        error_id = secrets.token_hex(4)
        app.logger.exception("MCP diagnostic failed [%s]", error_id)
        return jsonify({
            "ok": False,
            "error": "MCP diagnostic failed",
            "error_id": error_id,
            "exception_type": type(exc).__name__,
            "detail": str(exc),
        }), 500

@app.route("/mcp/<api_key>", methods=["GET", "POST"])
def claude_mcp(api_key):
    user_id = user_id_for_api_key(api_key)
    if not user_id:
        return mcp_jsonrpc_error(None, -32001, "Invalid or revoked connector key", 401)

    origin = (request.headers.get("Origin") or "").lower()
    blocked_origin_tokens = (
        "://localhost",
        "://127.0.0.1",
        "://[::1]",
    )
    if origin and any(token in origin for token in blocked_origin_tokens):
        return mcp_jsonrpc_error(None, -32002, "Origin not allowed", 403)

    if request.method == "GET":
        return Response(status=405, headers={
            "Allow": "POST",
            "Cache-Control": "no-store",
            "MCP-Protocol-Version": request.headers.get(
                "MCP-Protocol-Version",
                "2025-06-18",
            ),
        })

    message = request.get_json(silent=True)
    if isinstance(message, list):
        if not message:
            return mcp_jsonrpc_error(None, -32600, "Empty JSON-RPC batch", 400)

        batch_results = []
        for item in message:
            if not isinstance(item, dict):
                batch_results.append({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"},
                })
                continue

            item_id = item.get("id")
            item_method = item.get("method")
            item_params = item.get("params") or {}

            if item_method == "tools/list":
                batch_results.append({
                    "jsonrpc": "2.0",
                    "id": item_id,
                    "result": {"tools": MCP_TOOLS},
                })
            elif item_method == "ping":
                batch_results.append({
                    "jsonrpc": "2.0",
                    "id": item_id,
                    "result": {},
                })
            elif item_method == "notifications/initialized":
                continue
            else:
                batch_results.append({
                    "jsonrpc": "2.0",
                    "id": item_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {item_method}",
                    },
                })

        response = jsonify(batch_results)
        response.headers["Cache-Control"] = "no-store"
        response.headers["MCP-Protocol-Version"] = request.headers.get(
            "MCP-Protocol-Version",
            "2025-06-18",
        )
        return response

    if not isinstance(message, dict):
        return mcp_jsonrpc_error(None, -32700, "Invalid JSON", 400)

    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        requested_version = params.get("protocolVersion")
        supported_versions = {
            "2024-11-05",
            "2025-03-26",
            "2025-06-18",
            "2025-11-25",
        }
        protocol_version = (
            requested_version if requested_version in supported_versions
            else "2025-06-18"
        )
        return mcp_jsonrpc_result(request_id, {
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": False,
                }
            },
            "serverInfo": {
                "name": "Fitness Coaching Connector",
                "version": "18.0",
            },
            "instructions": (
                "Verify the account, then load coaching context and fitness "
                "summary before giving individualized training advice."
            ),
        })

    if method == "notifications/initialized":
        return Response(status=202, headers={
            "Cache-Control": "no-store",
            "MCP-Protocol-Version": request.headers.get(
                "MCP-Protocol-Version",
                "2025-06-18",
            ),
        })

    if method == "ping":
        return mcp_jsonrpc_result(request_id, {})

    if method == "tools/list":
        return mcp_jsonrpc_result(request_id, {"tools": MCP_TOOLS})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool_name, str):
            return mcp_jsonrpc_error(request_id, -32602, "Tool name is required")

        payload, status = call_mcp_tool(user_id, tool_name, arguments)
        if status == 404 and payload.get("error", "").startswith("Unknown tool"):
            return mcp_jsonrpc_error(request_id, -32602, payload["error"])

        return mcp_jsonrpc_result(
            request_id,
            mcp_tool_result(payload, is_error=status >= 400),
        )

    return mcp_jsonrpc_error(
        request_id,
        -32601,
        f"Method not found: {method}",
    )

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
        "debug_version": "multiuser-step17-11-training-state-machine",
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
    return jsonify(add_activity_identity(zones, user_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)