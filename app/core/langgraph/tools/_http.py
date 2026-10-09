"""Shared async HTTP helpers for Threavix threat-intelligence tools.

All outbound threat-intel requests flow through here so that timeouts,
User-Agent, and error handling stay consistent across tools. Tools are designed
to degrade gracefully and never raise raw exceptions back into the agent loop.
"""

from typing import Any, Dict, Optional, Tuple

import httpx

from app.core.config import settings
from app.core.logging import logger


def default_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Build the default request headers, optionally merged with extras."""
    headers = {
        "User-Agent": settings.THREAT_INTEL_USER_AGENT,
        "Accept": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers


async def get_json(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> Tuple[bool, Any]:
    """Perform an async GET request and return parsed JSON.

    Args:
        url: The absolute URL to request.
        params: Optional query string parameters.
        headers: Optional additional headers.
        timeout: Optional timeout override in seconds.

    Returns:
        Tuple[bool, Any]: ``(True, payload)`` on success, otherwise
        ``(False, error_message)``.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout or settings.THREAT_INTEL_TIMEOUT) as client:
            response = await client.get(url, params=params, headers=default_headers(headers))
            response.raise_for_status()
            return True, response.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("threat_intel_http_status_error", url=url, status=exc.response.status_code)
        return False, f"upstream returned HTTP {exc.response.status_code} for {url}"
    except httpx.HTTPError as exc:
        logger.warning("threat_intel_http_error", url=url, error=str(exc))
        return False, f"network error contacting {url}: {exc}"
    except ValueError as exc:
        logger.warning("threat_intel_json_error", url=url, error=str(exc))
        return False, f"invalid JSON returned by {url}: {exc}"


async def post_json(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> Tuple[bool, Any]:
    """Perform an async POST request and return parsed JSON."""
    try:
        async with httpx.AsyncClient(timeout=timeout or settings.THREAT_INTEL_TIMEOUT) as client:
            response = await client.post(url, data=data, headers=default_headers(headers))
            response.raise_for_status()
            return True, response.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("threat_intel_http_status_error", url=url, status=exc.response.status_code)
        return False, f"upstream returned HTTP {exc.response.status_code} for {url}"
    except httpx.HTTPError as exc:
        logger.warning("threat_intel_http_error", url=url, error=str(exc))
        return False, f"network error contacting {url}: {exc}"
    except ValueError as exc:
        logger.warning("threat_intel_json_error", url=url, error=str(exc))
        return False, f"invalid JSON returned by {url}: {exc}"
