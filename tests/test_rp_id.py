"""Unit tests for WebAuthn RP ID derivation.

The RP ID must match the host the browser is actually on. A reverse proxy makes
the plugin's own ``Host`` header the upstream address, so deriving it from that
alone yields something like ``127.0.0.1`` while the page is on the public
domain, and every registration is rejected. These tests pin the precedence:
the page's own report first, then forwarding headers, then ``Host``.
"""

from __future__ import annotations

import pathlib
import unittest

import tests  # noqa: F401

_MAIN = pathlib.Path(__file__).resolve().parent.parent / "main.py"


def _load_rp_id_helpers():
    """Extract the RP ID helpers from main.py without importing the plugin.

    main.py imports the AstrBot runtime at module scope, which is not available
    to the test process, so the two static helpers are compiled on their own
    against a fake request object.
    """
    source = _MAIN.read_text(encoding="utf-8")
    start = source.index("    @staticmethod\n    def _host_to_rp_id")
    end = source.index("    async def api_get_slots")
    headers: dict[str, str] = {}

    class FakeRequest:
        @property
        def headers(self) -> dict[str, str]:
            return headers

    # One namespace for globals and locals, so `request` resolves at call time.
    namespace: dict[str, object] = {"request": FakeRequest(), "Any": object}
    exec("class Host:\n" + source[start:end], namespace, namespace)  # noqa: S102
    return namespace["Host"], headers


HostHelpers, FAKE_HEADERS = _load_rp_id_helpers()


class HostToRpIdTests(unittest.TestCase):
    def test_a_bare_domain_passes_through(self) -> None:
        self.assertEqual(HostHelpers._host_to_rp_id("astrbot.example.com"), "astrbot.example.com")

    def test_the_port_is_stripped(self) -> None:
        self.assertEqual(HostHelpers._host_to_rp_id("astrbot.example.com:443"), "astrbot.example.com")

    def test_a_scheme_and_path_are_stripped(self) -> None:
        self.assertEqual(
            HostHelpers._host_to_rp_id("https://astrbot.example.com/passkey"),
            "astrbot.example.com",
        )

    def test_a_forwarding_chain_takes_the_first_entry(self) -> None:
        self.assertEqual(
            HostHelpers._host_to_rp_id("astrbot.example.com, 127.0.0.1"),
            "astrbot.example.com",
        )

    def test_an_ipv6_literal_keeps_its_address(self) -> None:
        self.assertEqual(HostHelpers._host_to_rp_id("[::1]:6185"), "::1")

    def test_the_result_is_lowercased_and_trimmed(self) -> None:
        self.assertEqual(HostHelpers._host_to_rp_id("  UPPER.Example.COM  "), "upper.example.com")

    def test_blank_input_yields_nothing(self) -> None:
        for value in ("", "   ", None):
            self.assertEqual(HostHelpers._host_to_rp_id(value), "")


class CurrentRpIdTests(unittest.TestCase):
    def setUp(self) -> None:
        FAKE_HEADERS.clear()

    def _headers(self, **values: str) -> None:
        FAKE_HEADERS.clear()
        FAKE_HEADERS.update(values)

    def test_the_page_report_is_authoritative(self) -> None:
        """The browser knows which RP ID it will accept; headers can be wrong."""
        self._headers(host="127.0.0.1:6185")
        FAKE_HEADERS["x-forwarded-host"] = "stale.example.com"
        self.assertEqual(
            HostHelpers._current_rp_id("astrbot.example.com"),
            "astrbot.example.com",
        )

    def test_x_forwarded_host_is_used_without_a_report(self) -> None:
        self._headers(host="127.0.0.1:6185")
        FAKE_HEADERS["x-forwarded-host"] = "astrbot.example.com"
        self.assertEqual(HostHelpers._current_rp_id(None), "astrbot.example.com")

    def test_the_rfc7239_forwarded_header_is_parsed(self) -> None:
        self._headers(
            host="127.0.0.1:6185",
            forwarded='for=1.2.3.4;host="astrbot.example.com";proto=https',
        )
        self.assertEqual(HostHelpers._current_rp_id(None), "astrbot.example.com")

    def test_a_forwarded_chain_takes_the_outermost_host(self) -> None:
        self._headers(host="127.0.0.1")
        FAKE_HEADERS["x-forwarded-host"] = "astrbot.example.com, inner.proxy"
        self.assertEqual(HostHelpers._current_rp_id(None), "astrbot.example.com")

    def test_direct_access_falls_back_to_host(self) -> None:
        self._headers(host="localhost:6185")
        self.assertEqual(HostHelpers._current_rp_id(None), "localhost")

    def test_a_blank_report_does_not_shadow_the_headers(self) -> None:
        self._headers(host="localhost:6185")
        self.assertEqual(HostHelpers._current_rp_id("   "), "localhost")

    def test_nothing_available_yields_nothing(self) -> None:
        self._headers()
        self.assertEqual(HostHelpers._current_rp_id(None), "")

    def test_a_proxied_deployment_never_reports_the_upstream_address(self) -> None:
        """Regression: the reported failure was an RP ID of 127.0.0.1 while the
        page was served from a public domain."""
        self._headers(host="127.0.0.1:6185")
        FAKE_HEADERS["x-forwarded-host"] = "astrbot.example.com"
        for reported in ("astrbot.example.com", None):
            self.assertNotIn("127.0.0.1", HostHelpers._current_rp_id(reported))


if __name__ == "__main__":
    unittest.main()
