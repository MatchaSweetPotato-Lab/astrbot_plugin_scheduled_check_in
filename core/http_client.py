"""Shared HTTP client configuration for check-in plugin requests."""

from collections.abc import Mapping
from typing import Any

import aiohttp


DEFAULT_TIMEOUT_SECONDS = 15.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 300.0


def _get_timeout_seconds(settings: Mapping[str, Any]) -> float:
    """Read and clamp the configured request timeout."""
    try:
        timeout = float(settings.get("http_timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(timeout, MAX_TIMEOUT_SECONDS))


def create_client_session(settings: Mapping[str, Any] | None = None) -> aiohttp.ClientSession:
    """Create an HTTP session from the shared plugin request settings."""
    settings = settings or {}
    ssl_verify = settings.get("http_ssl_verify", False) is True
    timeout_seconds = _get_timeout_seconds(settings)
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=ssl_verify),
        trust_env=True,
        timeout=aiohttp.ClientTimeout(total=timeout_seconds),
    )
