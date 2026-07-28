"""Remote MCP adapter for the Fitness Coaching API.

Claude connects to this server over Streamable HTTP. The server authenticates to
an existing Flask fitness API with one account-specific bearer token and exposes
the same read-only coaching data available to the ChatGPT Action integration.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


API_BASE_URL = os.getenv(
    "FITNESS_API_BASE_URL",
    "https://fitness-gpt-zr6n.onrender.com",
).rstrip("/")
API_KEY = os.getenv("FITNESS_API_KEY", "").strip()
REQUEST_TIMEOUT_SECONDS = float(os.getenv("FITNESS_API_TIMEOUT_SECONDS", "120"))
PORT = int(os.getenv("PORT", "8000"))


mcp = FastMCP(
    name="Fitness Coaching Connector",
    instructions=(
        "Before giving individualized fitness or training advice, call "
        "get_current_fitness_account, get_coaching_context, and "
        "get_fitness_summary. Use recent workouts or activity-specific tools "
        "when more detail is needed. Treat the returned goals, preferences, "
        "constraints, equipment, availability, and coaching context as the "
        "user's current persistent instructions. Do not invent missing data."
    ),
    host="0.0.0.0",
    port=PORT,
    stateless_http=True,
    json_response=True,
)


def _require_configuration() -> None:
    if not API_KEY:
        raise RuntimeError(
            "FITNESS_API_KEY is not configured on the MCP service. "
            "Set it to the account-specific fitness API key."
        )


def _api_get(path: str) -> dict[str, Any] | list[Any]:
    """Fetch one authenticated JSON response from the Flask fitness API."""
    _require_configuration()

    url = f"{API_BASE_URL}/{path.lstrip('/')}"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Accept": "application/json",
        "User-Agent": "fitness-coaching-mcp/1.0",
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
def health_check() -> dict[str, Any] | list[Any]:
    """Verify that this MCP server can authenticate to the fitness API."""
    return _api_get("/whoami")


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
