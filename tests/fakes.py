"""Shared fake curl_cffi session used by adapter and OAuth tests."""

from __future__ import annotations

from typing import Any


class FakeResponse:
    """Minimal stand-in for a curl_cffi response."""

    def __init__(
        self,
        status: int = 200,
        text: str = "",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status
        self.text = text
        self.cookies = cookies or {}
        self.headers = headers or {}


class FakeSession:
    """Routes requests by ``(METHOD, url)`` and records every call.

    A route may map to a single response or to a list consumed in order, which
    is how "balance before and after check-in" scenarios are expressed.
    """

    impersonate = "chrome131"

    def __init__(self, routes: dict[Any, Any], default: FakeResponse | None = None) -> None:
        self.routes = routes
        self.default = default or FakeResponse(404, '{"success":false,"message":"not found"}')
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.routes.get((method.upper(), url))
        if response is None:
            response = self.routes.get(url, self.default)
        if isinstance(response, list):
            response = response.pop(0) if response else self.default
        return response

    # ------------------------------------------------------------------
    # Assertions helpers
    # ------------------------------------------------------------------
    def urls(self) -> list[str]:
        """Return every requested URL in order."""
        return [call["url"] for call in self.calls]

    def calls_to(self, suffix: str) -> list[dict[str, Any]]:
        """Return the calls whose URL ends with ``suffix``."""
        return [call for call in self.calls if call["url"].endswith(suffix)]

    def count_to(self, suffix: str) -> int:
        """Return how many calls targeted a URL ending with ``suffix``."""
        return len(self.calls_to(suffix))
