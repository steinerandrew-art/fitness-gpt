"""OAuth-protected remote MCP adapter for the Fitness Coaching API.

The Flask application is the OAuth authorization server and owns user identity.
This service is the MCP resource server: it validates Claude's bearer token by
calling the Flask app's introspection endpoint, then forwards that same token to
the existing read-only fitness API endpoints.

Set MCP_OAUTH_ENABLED=false temporarily to retain the previously validated
single-account FITNESS_API_KEY behavior during deployment testing.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx
from pydantic import AnyHttpUrl
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP


API_BASE_URL = os.getenv(
    "FITNESS_API_BASE_URL",
    "https://fitness-gpt-zr6n.onrender.com",
).rstrip("/")
MCP_PUBLIC_BASE_URL = os.getenv("MCP_PUBLIC_BASE_URL", "").rstrip("/")
LEGACY_API_KEY = os.getenv("FITNESS_API_KEY", "").strip()
INTROSPECTION_SECRET = os.getenv("MCP_OAUTH_INTROSPECTION_SECRET", "").strip()
OAUTH_ENABLED = os.getenv("MCP_OAUTH_ENABLED", "true").strip().lower() not in {
    "0", "false", "no", "off"
}
REQUEST_TIMEOUT_SECONDS = float(os.getenv("FITNESS_API_TIMEOUT_SECONDS", "120"))
PORT = int(os.getenv("PORT", "8000"))
REQUIRED_SCOPE = "fitness.read"


class FitnessTokenVerifier(TokenVerifier):
    """Validate opaque access tokens with the Flask authorization server."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or not INTROSPECTION_SECRET:
            return None

        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    f"{API_BASE_URL}/oauth/introspect",
                    headers={
                        "Authorization": f"Bearer {INTROSPECTION_SECRET}",
                        "Accept": "application/json",
                        "User-Agent": "fitness-coaching-mcp/2.0",
                    },
                    data={"token": token},
                )
        except httpx.RequestError:
            return None

        if response.status_code != 200:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict) or not payload.get("active"):
            return None

        scopes = str(payload.get("scope") or "").split()
        if REQUIRED_SCOPE not in scopes:
            return None
        if MCP_PUBLIC_BASE_URL and str(payload.get("aud") or "").rstrip("/") != MCP_PUBLIC_BASE_URL:
            return None

        return AccessToken(
            token=token,
            client_id=str(payload.get("client_id") or "unknown-client"),
            scopes=scopes,
            expires_at=int(payload["exp"]) if payload.get("exp") else None,
            resource=MCP_PUBLIC_BASE_URL or None,
        )


def _fastmcp_arguments() -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "name": "Fitness Coaching Connector",
        "instructions": (
            "Before giving individualized fitness or training advice, call "
            "get_current_fitness_account, get_coaching_context, and "
            "get_fitness_summary. Use recent workouts or activity-specific tools "
            "when more detail is needed. Treat the returned goals, preferences, "
            "constraints, equipment, availability, and coaching context as the "
            "user's current persistent instructions. Do not invent missing data."
        ),
        "host": "0.0.0.0",
        "port": PORT,
        "stateless_http": True,
        "json_response": True,
    }
    if OAUTH_ENABLED:
        if not MCP_PUBLIC_BASE_URL:
            raise RuntimeError("MCP_PUBLIC_BASE_URL is required when MCP_OAUTH_ENABLED=true")
        arguments.update({
            "token_verifier": FitnessTokenVerifier(),
            "auth": AuthSettings(
                issuer_url=AnyHttpUrl(API_BASE_URL),
                resource_server_url=AnyHttpUrl(MCP_PUBLIC_BASE_URL),
                required_scopes=[REQUIRED_SCOPE],
            ),
        })
    return arguments


mcp = FastMCP(**_fastmcp_arguments())


def _active_credential() -> str:
    if OAUTH_ENABLED:
        access_token = get_access_token()
        if not access_token or not access_token.token:
            raise RuntimeError("No authenticated OAuth access token is available.")
        return access_token.token
    if not LEGACY_API_KEY:
        raise RuntimeError(
            "FITNESS_API_KEY is required while MCP_OAUTH_ENABLED=false."
        )
    return LEGACY_API_KEY


def _api_get(path: str) -> dict[str, Any] | list[Any]:
    """Fetch one authenticated JSON response from the Flask fitness API."""
    url = f"{API_BASE_URL}/{path.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {_active_credential()}",
        "Accept": "application/json",
        "User-Agent": "fitness-coaching-mcp/2.0",
    }

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            response = client.get(url, headers=headers)
    except httpx.TimeoutException as exc:
        raise RuntimeError(
            f"The fitness API timed out while requesting {path}."
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(
            f"The fitness API could not be reached while requesting {path}: "
            f"{exc.__class__.__name__}."
        ) from exc

    try:
        payload: Any = response.json()
    except ValueError as exc:
        preview = response.text[:300].strip()
        raise RuntimeError(
            f"The fitness API returned non-JSON content for {path} "
            f"(HTTP {response.status_code}): {preview or 'empty response'}"
        ) from exc

    if response.is_error:
        if isinstance(payload, dict):
            detail = payload.get("error") or payload.get("message") or payload
        else:
            detail = payload
        raise RuntimeError(
            f"The fitness API request for {path} failed "
            f"(HTTP {response.status_code}): {detail}"
        )

    if not isinstance(payload, (dict, list)):
        raise RuntimeError(
            f"The fitness API returned an unexpected JSON type for {path}."
        )
    return payload


def _positive_activity_id(activity_id: int) -> int:
    if isinstance(activity_id, bool) or not isinstance(activity_id, int):
        raise ValueError("activity_id must be an integer.")
    if activity_id <= 0:
        raise ValueError("activity_id must be greater than zero.")
    return activity_id


@mcp.tool()
def health_check() -> dict[str, Any]:
    """Verify that this MCP server can reach and authenticate to the fitness API."""
    account = _api_get("/whoami")
    if not isinstance(account, dict):
        raise RuntimeError("The fitness API returned an unexpected account payload.")
    return {
        "status": "ok",
        "backend": API_BASE_URL,
        "authentication": "oauth" if OAUTH_ENABLED else "temporary_api_key",
        "authenticated": True,
        "user_id": account.get("user_id"),
    }


@mcp.tool()
def get_current_fitness_account() -> dict[str, Any] | list[Any]:
    """Verify which account is connected, including identity and onboarding status."""
    return _api_get("/whoami")


@mcp.tool()
def get_coaching_context() -> dict[str, Any] | list[Any]:
    """Load the current profile, training preferences, goals, and persistent coaching context."""
    return _api_get("/coaching-context")


@mcp.tool()
def get_fitness_summary() -> dict[str, Any] | list[Any]:
    """Load the current 14-day fitness, intensity, readiness, and body-data summary."""
    return _api_get("/summary")


@mcp.tool()
def get_recent_workouts() -> dict[str, Any] | list[Any]:
    """Load recent workouts with available heart-rate, power, pace, and zone data."""
    return _api_get("/workouts")


@mcp.tool()
def get_activity_detail(activity_id: int) -> dict[str, Any] | list[Any]:
    """Load detailed information for one Strava activity by activity ID."""
    validated_id = _positive_activity_id(activity_id)
    return _api_get(f"/activity/{validated_id}")


@mcp.tool()
def get_activity_zones(activity_id: int) -> dict[str, Any] | list[Any]:
    """Load heart-rate, power, pace, or other zone data for one Strava activity."""
    validated_id = _positive_activity_id(activity_id)
    return _api_get(f"/activity/{validated_id}/zones")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
