"""Shared HTTP client configuration for check-in plugin requests."""

from collections.abc import Mapping
from typing import Any

from curl_cffi.requests import AsyncSession, BrowserType


DEFAULT_TIMEOUT_SECONDS = 15.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 300.0
DEFAULT_IMPERSONATE = "chrome131"


def _get_timeout_seconds(settings: Mapping[str, Any]) -> float:
    """Read and clamp the configured request timeout."""
    try:
        timeout = float(settings.get("http_timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(timeout, MAX_TIMEOUT_SECONDS))


def get_impersonate_options() -> list[str]:
    """Return the browser fingerprints exposed by the installed curl_cffi build."""
    return [browser.value for browser in BrowserType]


def normalize_impersonate(value: Any) -> str:
    """Validate a configured fingerprint and fall back to chrome131."""
    if isinstance(value, str) and value in get_impersonate_options():
        return value
    return DEFAULT_IMPERSONATE


def create_client_session(settings: Mapping[str, Any] | None = None) -> AsyncSession:
    """Create a curl_cffi session with the plugin's shared request settings."""
    settings = settings or {}
    # Verify TLS certificates by default; callers must explicitly opt out.
    ssl_verify = settings.get("http_ssl_verify", True) is True
    timeout_seconds = _get_timeout_seconds(settings)
    return AsyncSession(
        impersonate=normalize_impersonate(settings.get("http_impersonate")),
        verify=ssl_verify,
        trust_env=True,
        timeout=timeout_seconds,
    )
