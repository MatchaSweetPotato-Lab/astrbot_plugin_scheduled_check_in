"""Tests for Cloudflare challenge detection and browser fallback settings."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

import tests  # noqa: F401
from core.adapters import create_adapter
from core.cloudflare import (
    CloudflareContext,
    CloudflareOptions,
    is_response_challenge,
    normalize_cloudflare_settings,
)
from core.http_client import RequestOptions
from core.oauth import LINUXDO_OAUTH, OAuthLoginClient
from core.scheduler import CheckInScheduler
from tests.fakes import FakeResponse, FakeSession, carries_mldsa

BASE = "https://relay.example.com"
AUTHORIZE = "https://connect.linux.do/oauth2/authorize"
MLDSA = RequestOptions(tls_mldsa=True)
CHALLENGE_BODY = (
    "<html><head><title>Just a moment...</title></head><body>"
    "<script>window._cf_chl_opt = {cType: 'managed'};</script></body></html>"
)


def challenge() -> FakeResponse:
    return FakeResponse(403, CHALLENGE_BODY, headers={"cf-mitigated": "challenge"})


def context(**options: Any) -> CloudflareContext:
    return CloudflareContext(CloudflareOptions(**options))


class Trace:
    """Collects what the context records, in the shape it calls."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def __call__(self, step: str, method: str, url: str, **fields: Any) -> None:
        self.entries.append({"step": step, "method": method, "url": url, **fields})


# ----------------------------------------------------------------------
# Detection and settings
# ----------------------------------------------------------------------
class DetectionTests(unittest.TestCase):
    def test_response_detection_reads_status_body_and_header(self) -> None:
        self.assertTrue(is_response_challenge(challenge()))
        self.assertTrue(is_response_challenge(FakeResponse(403, "x", headers={"cf-mitigated": "challenge"})))
        self.assertFalse(is_response_challenge(FakeResponse(200, CHALLENGE_BODY)))
        self.assertFalse(is_response_challenge(FakeResponse(403, "forbidden")))


class OptionTests(unittest.TestCase):
    def test_the_browser_fallback_is_on_by_default(self) -> None:
        self.assertTrue(CloudflareOptions.from_settings({}).browser_fallback)
        self.assertTrue(CloudflareOptions.from_settings(None).browser_fallback)

    def test_the_retired_fingerprint_flag_is_ignored(self) -> None:
        for value in (True, False, "on", "0"):
            with self.subTest(value=value):
                self.assertEqual(
                    CloudflareOptions.from_settings({"cf_fingerprint_fallback": value}),
                    CloudflareOptions(),
                )

    def test_normalization_removes_the_retired_setting_in_place(self) -> None:
        settings = {"cf_fingerprint_fallback": True}
        normalize_cloudflare_settings(settings)
        self.assertNotIn("cf_fingerprint_fallback", settings)
        self.assertIs(settings["cf_browser_fallback"], True)

    def test_storage_defaults_do_not_carry_the_retired_option(self) -> None:
        from core.storage import DEFAULT_SETTINGS

        self.assertNotIn("cf_fingerprint_fallback", DEFAULT_SETTINGS)


# ----------------------------------------------------------------------
# Handling without a configured browser
# ----------------------------------------------------------------------
class ResolveTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_normal_response_passes_untouched(self) -> None:
        trace = Trace()
        ok = FakeResponse(200, "fine")
        resolution = await context().resolve(response=ok, record=trace)
        self.assertIs(resolution.response, ok)
        self.assertEqual((resolution.detail, trace.entries), ("", []))

    async def test_a_disabled_browser_says_so(self) -> None:
        resolution = await context(browser_fallback=False).resolve(response=challenge())
        self.assertEqual(resolution.response.status_code, 403)
        self.assertIn("关闭", resolution.detail)

    async def test_a_missing_browser_reports_why_the_challenge_remains(self) -> None:
        trace = Trace()
        original = challenge()
        resolution = await context().resolve(response=original, record=trace)
        self.assertIs(resolution.response, original)
        self.assertIn("无头浏览器不可用", resolution.detail)
        self.assertEqual(trace.entries, [])


# ----------------------------------------------------------------------
# Adapters and OAuth
# ----------------------------------------------------------------------
def make_site(**overrides: Any) -> dict:
    site = {
        "id": "s1",
        "name": "Relay",
        "type": "new-api",
        "base_url": BASE,
        "proxy": "",
        "credentials": [{"id": "c1", "type": "token", "value": "sk-a"}],
        "checkin": {},
        "balance": {},
        "enabled": True,
    }
    site.update(overrides)
    return site


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_surviving_challenge_is_not_an_expired_credential(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context(browser_fallback=False))
        result = await adapter.check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("Cloudflare", result.message)
        self.assertIn("并非凭据失效", result.message)
        self.assertIn("关闭", result.message)

    async def test_without_a_context_a_challenge_is_still_reported_as_one(self) -> None:
        session = FakeSession({}, default=challenge())
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.expired)
        self.assertIn("Cloudflare", result.message)
        self.assertNotIn("凭据已失效", result.message)

    async def test_a_connection_test_behind_a_challenge_is_not_expired(self) -> None:
        session = FakeSession({}, default=challenge())
        result = await create_adapter(make_site(), session).test_connection()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)

    async def test_generic_sites_do_not_blame_the_credential_either(self) -> None:
        session = FakeSession({}, default=challenge())
        site = make_site(type="generic_rest", checkin={"path": "/sign", "protocol": "post"})
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("Cloudflare", result.message)

    async def test_a_challenge_does_not_trigger_an_oauth_relogin(self) -> None:
        """A 403 challenge says nothing about the stored session."""
        site = make_site(
            credentials=[{"id": "o1", "type": "linuxdo_oauth", "value": "_t=a; _forum_session=b",
                          "session_cookie": "session=stored"}],
            balance={"protocol": "get"},
        )
        session = FakeSession({}, default=challenge())
        await create_adapter(site, session).query_balance()
        self.assertEqual(session.count_to("/api/status"), 0)

    async def test_a_challenge_never_retries_other_curl_fingerprints(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context())
        await adapter.query_balance()
        await adapter.query_balance()
        self.assertEqual(
            [call["impersonate"] for call in session.calls],
            ["chrome131", "chrome131"],
        )

    async def test_the_initial_request_keeps_the_ml_dsa_option(self) -> None:
        session = FakeSession({}, default=challenge())
        await create_adapter(make_site(), session, None, context(), MLDSA).query_balance()
        self.assertEqual(
            [(call["impersonate"], carries_mldsa(call)) for call in session.calls],
            [("chrome131", True)],
        )

    async def test_a_challenge_without_ml_dsa_points_at_the_option(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context())
        _quota, error = await adapter.query_balance()
        self.assertIn("未携带 ML-DSA", error)
        self.assertIn("全局设置", error)
        self.assertIn("TLS 携带 ML-DSA", error)

    async def test_no_ml_dsa_hint_once_it_was_sent(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context(), MLDSA)
        _quota, error = await adapter.query_balance()
        self.assertIn("Cloudflare", error)
        self.assertNotIn("未携带 ML-DSA", error)


class OAuthTests(unittest.IsolatedAsyncioTestCase):
    def _routes(self, authorize: Any, status: Any = None) -> dict:
        return {
            ("GET", f"{BASE}/api/status"): status or FakeResponse(
                200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}'
            ),
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"st"}'),
            ("GET", AUTHORIZE): authorize,
            ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(200, "{}", cookies={"session": "fresh"}),
        }

    async def test_a_challenged_authorize_leg_is_not_retried_by_curl(self) -> None:
        redirect = FakeResponse(302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})
        session = FakeSession(self._routes([challenge(), redirect]))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertFalse(result.success)
        self.assertIn("无头浏览器不可用", result.message)
        self.assertEqual(
            [call["impersonate"] for call in session.calls_to("/oauth2/authorize")],
            ["chrome131"],
        )

    async def test_the_initial_request_keeps_the_provider_cookie_and_query(self) -> None:
        redirect = FakeResponse(302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})
        session = FakeSession(self._routes([challenge(), redirect]))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        initial = session.calls_to("/oauth2/authorize")[0]
        self.assertEqual(initial["headers"]["Cookie"], "_t=a; _forum_session=b")
        self.assertEqual(initial["params"]["client_id"], "cid")

    async def test_a_challenged_status_leg_names_cloudflare(self) -> None:
        session = FakeSession(self._routes(FakeResponse(302, ""), status=challenge()))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertFalse(result.success)
        self.assertIn("Cloudflare", result.message)
        self.assertIn("无头浏览器不可用", result.message)
        self.assertIn("未携带 ML-DSA", result.message)


class SchedulerHookTests(unittest.TestCase):
    def test_a_plugin_without_the_hook_gets_none(self) -> None:
        self.assertIsNone(CheckInScheduler(SimpleNamespace())._cloudflare_context({}))

    def test_the_plugins_factory_is_used(self) -> None:
        marker = object()
        plugin = SimpleNamespace(cloudflare_context=lambda settings: marker)
        self.assertIs(CheckInScheduler(plugin)._cloudflare_context({}), marker)

    def test_a_failing_factory_costs_only_the_handling(self) -> None:
        def broken(settings: dict) -> Any:
            raise OSError("disk full")

        plugin = SimpleNamespace(cloudflare_context=broken)
        with self.assertLogs("astrbot", level="WARNING"):
            self.assertIsNone(CheckInScheduler(plugin)._cloudflare_context({}))


if __name__ == "__main__":
    unittest.main()
