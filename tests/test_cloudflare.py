"""Tests for Cloudflare challenge detection and the fingerprint fallback."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock

import tests  # noqa: F401
from core import cloudflare
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


def self_payload(quota: float) -> str:
    return json.dumps({"success": True, "data": {"id": 7, "quota": quota}})


def context(**options: Any) -> CloudflareContext:
    return CloudflareContext(CloudflareOptions(**options), pacing=0)


class Trace:
    """Collects what the context records, in the shape it calls."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def __call__(self, step: str, method: str, url: str, **fields: Any) -> None:
        self.entries.append({"step": step, "method": method, "url": url, **fields})

    def steps(self) -> list[str]:
        return [entry["step"] for entry in self.entries]


class Sender:
    """Re-issues "the original request", answering per fingerprint."""

    def __init__(self, answers: dict[str, FakeResponse] | None = None, default: FakeResponse | None = None) -> None:
        self.answers = answers or {}
        self.default = default or FakeResponse(200, "ok")
        self.profiles: list[str] = []

    async def __call__(self, profile: str) -> FakeResponse:
        self.profiles.append(profile)
        return self.answers.get(profile, self.default)


async def resolve(ctx: CloudflareContext, send: Sender, trace: Trace | None = None, *,
                  url: str = AUTHORIZE, response: Any = None, impersonate: str = "chrome131",
                  mldsa: bool = False) -> Any:
    return await ctx.resolve(
        method="GET",
        url=url,
        response=response if response is not None else challenge(),
        impersonate=impersonate,
        send=send,
        record=trace,
        mldsa=mldsa,
    )


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
    def test_the_fallback_is_on_by_default(self) -> None:
        self.assertTrue(CloudflareOptions.from_settings({}).fingerprint_fallback)
        self.assertTrue(CloudflareOptions.from_settings(None).fingerprint_fallback)

    def test_string_flags_are_understood(self) -> None:
        self.assertFalse(CloudflareOptions.from_settings({"cf_fingerprint_fallback": "0"}).fingerprint_fallback)
        self.assertTrue(CloudflareOptions.from_settings({"cf_fingerprint_fallback": "on"}).fingerprint_fallback)

    def test_normalization_rewrites_the_settings_in_place(self) -> None:
        settings = {"cf_fingerprint_fallback": "false"}
        normalize_cloudflare_settings(settings)
        self.assertIs(settings["cf_fingerprint_fallback"], False)

    def test_storage_defaults_carry_the_option(self) -> None:
        from core.storage import DEFAULT_SETTINGS

        self.assertIs(DEFAULT_SETTINGS["cf_fingerprint_fallback"], True)


# ----------------------------------------------------------------------
# The fingerprint ladder
# ----------------------------------------------------------------------
class ResolveTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_normal_response_passes_untouched(self) -> None:
        send, trace = Sender(), Trace()
        ok = FakeResponse(200, "fine")
        resolution = await resolve(context(), send, trace, response=ok)
        self.assertIs(resolution.response, ok)
        self.assertEqual((send.profiles, trace.entries), ([], []))

    async def test_a_disabled_fallback_says_so(self) -> None:
        send = Sender()
        resolution = await resolve(context(fingerprint_fallback=False), send)
        self.assertEqual(resolution.response.status_code, 403)
        self.assertIn("关闭", resolution.detail)
        self.assertEqual(send.profiles, [])

    async def test_screening_finds_a_fingerprint_and_remembers_it(self) -> None:
        send = Sender({"chrome150": challenge()}, default=FakeResponse(200, "through"))
        trace = Trace()
        ctx = context()
        resolution = await resolve(ctx, send, trace)
        self.assertEqual(resolution.response.text, "through")
        self.assertEqual(send.profiles, ["chrome150", "firefox133"])
        self.assertEqual(ctx.impersonate_for(f"{AUTHORIZE}?x=1", "chrome131"), "firefox133")
        self.assertEqual(ctx.impersonate_for(f"{BASE}/api/status", "chrome131"), "chrome131")
        self.assertEqual(trace.steps(), ["Cloudflare 指纹轮换"])
        self.assertTrue(trace.entries[0]["success"])
        self.assertEqual(trace.entries[0]["status"], 200)

    async def test_the_trace_starts_with_the_challenged_request(self) -> None:
        trace = Trace()
        await resolve(context(), Sender(), trace)
        message = trace.entries[0]["message"]
        self.assertTrue(message.startswith("chrome131 收到人机验证页 (HTTP 403)"), message)
        self.assertIn("chrome150 通过 (HTTP 200)", message)

    async def test_the_trace_names_an_added_ml_dsa(self) -> None:
        """What went out was chrome131 plus ML-DSA; the trace must not say chrome131."""
        trace = Trace()
        await resolve(context(), Sender({"chrome150": challenge()}), trace, mldsa=True)
        message = trace.entries[0]["message"]
        self.assertIn("chrome131+ML-DSA 收到人机验证页", message)
        # chrome150 carries ML-DSA itself and Firefox never gets it.
        self.assertIn("chrome150 仍被拦截", message)
        self.assertIn("firefox133 通过", message)

    async def test_screening_never_retries_the_fingerprint_that_was_challenged(self) -> None:
        send = Sender({}, default=challenge())
        await resolve(context(), send, impersonate="firefox133")
        self.assertNotIn("firefox133", send.profiles)
        self.assertEqual(len(send.profiles), cloudflare.MAX_FALLBACK_ATTEMPTS)

    async def test_the_ladder_leads_with_the_ml_dsa_fingerprint(self) -> None:
        with mock.patch.object(cloudflare, "get_impersonate_options",
                               return_value=["chrome131", *cloudflare.FALLBACK_FINGERPRINTS]):
            self.assertEqual(cloudflare.fallback_fingerprints("chrome131")[0], "chrome150")

    async def test_the_ladder_only_offers_installed_profiles(self) -> None:
        with mock.patch.object(cloudflare, "get_impersonate_options", return_value=["chrome131", "safari2601"]):
            self.assertEqual(cloudflare.fallback_fingerprints("chrome131"), ["safari2601"])

    async def test_everything_failing_lists_what_was_tried(self) -> None:
        send = Sender({}, default=challenge())
        trace = Trace()
        resolution = await resolve(context(), send, trace)
        self.assertEqual(resolution.response.status_code, 403)
        self.assertTrue(resolution.detail.startswith("已自动尝试："))
        self.assertIn("指纹轮换", resolution.detail)
        self.assertIn("firefox133", resolution.detail)
        self.assertFalse(trace.entries[0].get("success"))

    async def test_a_lost_host_is_not_screened_again_in_the_same_run(self) -> None:
        """A second site behind the same SSO must not repeat the whole ladder."""
        ctx = context()
        await resolve(ctx, Sender({}, default=challenge()))
        second = Sender({}, default=challenge())
        resolution = await resolve(ctx, second)
        self.assertEqual(second.profiles, [])
        self.assertIn("跳过", resolution.detail)

    async def test_a_failing_retry_moves_on_to_the_next_fingerprint(self) -> None:
        class Flaky(Sender):
            async def __call__(self, profile: str) -> FakeResponse:
                if profile == "chrome150":
                    self.profiles.append(profile)
                    raise OSError("connection reset")
                return await super().__call__(profile)

        trace = Trace()
        resolution = await resolve(context(), Flaky(), trace)
        self.assertEqual(resolution.response.status_code, 200)
        self.assertIn("chrome150 请求异常", trace.entries[0]["message"])


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
        adapter = create_adapter(make_site(), session, None, context(fingerprint_fallback=False))
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

    async def test_a_fingerprint_that_got_through_is_reused(self) -> None:
        session = FakeSession({
            ("GET", f"{BASE}/api/user/self"): [
                challenge(),  # the configured fingerprint
                challenge(),  # chrome150
                FakeResponse(200, self_payload(500000)),  # firefox133
                FakeResponse(200, self_payload(500000)),  # the next read
            ],
        })
        adapter = create_adapter(make_site(), session, None, context())
        await adapter.query_balance()
        await adapter.query_balance()
        self.assertEqual(
            [call["impersonate"] for call in session.calls],
            ["chrome131", "chrome150", "firefox133", "firefox133"],
        )
        self.assertIn("Cloudflare 指纹轮换", [attempt["step"] for attempt in adapter.attempts])

    async def test_the_ladder_keeps_the_ml_dsa_option(self) -> None:
        """A retry is the same request under another fingerprint, not a different one."""
        session = FakeSession({
            ("GET", f"{BASE}/api/user/self"): [
                challenge(),  # chrome131 + ML-DSA
                challenge(),  # chrome150, which carries it natively
                challenge(),  # firefox133, which never gets it
                challenge(),  # safari184
                FakeResponse(200, self_payload(500000)),  # safari2601
            ],
        })
        await create_adapter(make_site(), session, None, context(), MLDSA).query_balance()
        self.assertEqual(
            [(call["impersonate"], carries_mldsa(call)) for call in session.calls],
            [("chrome131", True), ("chrome150", False), ("firefox133", False),
             ("safari184", False), ("safari2601", False)],
        )

    async def test_a_challenge_without_ml_dsa_points_at_the_option(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context(fingerprint_fallback=False))
        _quota, error = await adapter.query_balance()
        self.assertIn("未携带 ML-DSA", error)
        self.assertIn("全局设置", error)
        self.assertIn("TLS 携带 ML-DSA", error)

    async def test_no_ml_dsa_hint_once_it_was_sent(self) -> None:
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(make_site(), session, None, context(fingerprint_fallback=False), MLDSA)
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

    async def test_a_re_fingerprinted_authorize_leg_completes_the_login(self) -> None:
        redirect = FakeResponse(302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})
        session = FakeSession(self._routes([challenge(), redirect]))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.session_cookie, "session=fresh")
        self.assertEqual(
            [call["impersonate"] for call in session.calls_to("/oauth2/authorize")],
            ["chrome131", "chrome150"],
        )

    async def test_the_retry_keeps_the_provider_cookie_and_query(self) -> None:
        redirect = FakeResponse(302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})
        session = FakeSession(self._routes([challenge(), redirect]))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        retry = session.calls_to("/oauth2/authorize")[-1]
        self.assertEqual(retry["headers"]["Cookie"], "_t=a; _forum_session=b")
        self.assertEqual(retry["params"]["client_id"], "cid")

    async def test_a_challenged_status_leg_names_cloudflare(self) -> None:
        session = FakeSession(self._routes(FakeResponse(302, ""), status=challenge()))
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context())
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertFalse(result.success)
        self.assertIn("Cloudflare", result.message)
        self.assertIn("已自动尝试", result.message)
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
