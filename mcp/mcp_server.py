import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


FITNESS_API_BASE_URL = os.getenv(
    "FITNESS_API_BASE_URL",
    "https://fitness-gpt-zr6n.onrender.com",
).rstrip("/")

PORT = int(os.getenv("PORT", "8000"))

mcp = FastMCP(
    "Fitness Coach",
    instructions=(
        "Retrieve current workout and health data from the Fitness GPT backend. "
        "Use get_summary for an aggregated training overview and get_workouts "
        "for recent individual activities."
    ),
    host="0.0.0.0",
    port=PORT,
    stateless_http=True,
    json_response=True,
)


async def fetch_backend(
    endpoint: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """Call the existing Fitness GPT Flask backend."""

    url = f"{FITNESS_API_BASE_URL}/{endpoint.lstrip('/')}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            follow_redirects=True,
        ) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            return response.json()

    except httpx.TimeoutException as exc:
        raise RuntimeError(
            f"The fitness backend timed out while requesting {endpoint}."
        ) from exc

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        detail = exc.response.text[:500]

        raise RuntimeError(
            f"The fitness backend returned HTTP {status} for {endpoint}: "
            f"{detail}"
        ) from exc

    except httpx.RequestError as exc:
        raise RuntimeError(
            f"Could not connect to the fitness backend for {endpoint}: {exc}"
        ) from exc

    except ValueError as exc:
        raise RuntimeError(
            f"The fitness backend returned invalid JSON for {endpoint}."
        ) from exc


@mcp.tool()
async def health_check() -> dict[str, str]:
    """Confirm that the MCP server is running and identify its data source."""

    return {
        "status": "ok",
        "backend": FITNESS_API_BASE_URL,
    }


@mcp.tool()
async def get_summary(
    user_id: str = "primary",
) -> Any:
    """
    Retrieve the current aggregated fitness summary for a user.

    The summary may include recent training volume, activity totals,
    intensity distribution, Strava information, Withings measurements,
    trends, and readiness-related data available from the backend.

    Args:
        user_id: Fitness GPT user identifier. Defaults to "primary".
    """

    return await fetch_backend(
        "/summary",
        params={"user_id": user_id},
    )


@mcp.tool()
async def get_workouts(
    user_id: str = "primary",
) -> Any:
    """
    Retrieve recent individual workouts for a user.

    Use this when activity-level detail is needed, including workout type,
    date, duration, distance, elevation, heart rate, power, pace, zones,
    or intensity information made available by the backend.

    Args:
        user_id: Fitness GPT user identifier. Defaults to "primary".
    """

    return await fetch_backend(
        "/workouts",
        params={"user_id": user_id},
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http")