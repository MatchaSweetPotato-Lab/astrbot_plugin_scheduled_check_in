"""Unit tests for the relay-station OAuth login flow."""

from __future__ import annotations

import unittest

import tests  # noqa: F401
from core.oauth import (
    GITHUB_OAUTH,
    LINUXDO_OAUTH,
    PROVIDERS,
    OAuthLoginClient,
    _extract_flow_token,
    _safe_location,
    get_provider,
)
from tests.fakes import FakeResponse, FakeSession

BASE = "https://relay.example.com"
GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
LINUXDO_AUTHORIZE = "https://connect.linux.do/oauth2/authorize"


def github_routes(overrides: dict | None = None) -> dict:
    """Build a happy-path Github route table."""
    routes = {
        ("GET", f"{BASE}/api/status"): FakeResponse(
            200, '{"data":{"github_oauth":true,"github_client_id":"cid-1"}}'
        ),
        ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"flow-1"}}'),
        ("GET", GITHUB_AUTHORIZE): FakeResponse(
            302, "", headers={"location": f"{BASE}/oauth/github?code=CODE-1&state=flow-1"}
        ),
        ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
            200, "{}", cookies={"session": "sess-1", "extra": "e"}
        ),
    }
    routes.update(overrides or {})
    return routes


def make_client(session: FakeSession, proxy: str | None = None) -> OAuthLoginClient:
    return OAuthLoginClient(session, BASE, "chrome131", proxy)


class ProviderTests(unittest.TestCase):
    def test_lookup_by_credential_type(self) -> None:
        self.assertEqual(get_provider(GITHUB_OAUTH).slug, "github")
        self.assertEqual(get_provider(LINUXDO_OAUTH).slug, "linuxdo")

    def test_unknown_type_returns_none(self) -> None:
        self.assertIsNone(get_provider("gitlab"))
        self.assertIsNone(get_provider(""))

    def test_only_linuxdo_sends_a_redirect_uri(self) -> None:
        """Github infers its callback from the registered application."""
        self.assertFalse(PROVIDERS[GITHUB_OAUTH].send_redirect_uri)
        self.assertTrue(PROVIDERS[LINUXDO_OAUTH].send_redirect_uri)

    def test_cookie_hints_name_the_provider_cookie(self) -> None:
        self.assertEqual(PROVIDERS[GITHUB_OAUTH].cookie_hint, "user_session")
        self.assertEqual(PROVIDERS[LINUXDO_OAUTH].cookie_hint, "_t")


class SuccessfulLoginTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_the_station_session_cookie(self) -> None:
        session = FakeSession(github_routes())
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        self.assertEqual(result.session_cookie, "session=sess-1; extra=e")

    async def test_walks_all_four_legs_in_order(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertEqual(
            session.urls(),
            [
                f"{BASE}/api/status",
                f"{BASE}/api/oauth/state",
                GITHUB_AUTHORIZE,
                f"{BASE}/api/oauth/github",
            ],
        )

    async def test_sends_the_third_party_cookie_to_the_provider(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["headers"]["Cookie"], "user_session=abc")

    async def test_does_not_follow_the_provider_redirect(self) -> None:
        """The authorization code lives in the Location header, not the target."""
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertFalse(authorize["allow_redirects"])

    async def test_forwards_the_flow_token_as_state(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["params"]["state"], "flow-1")
        self.assertEqual(authorize["params"]["client_id"], "cid-1")

    async def test_exchanges_the_code_it_extracted(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        exchange = session.calls_to("/api/oauth/github")[0]
        self.assertEqual(exchange["params"], {"code": "CODE-1", "state": "flow-1"})

    async def test_state_request_declares_a_login_intent(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        state_call = session.calls_to("/api/oauth/state")[0]
        self.assertEqual(state_call["json"], {"provider": "github", "intent": "login"})

    async def test_the_proxy_applies_to_every_leg(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session, "http://127.0.0.1:7890").login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(all(call["proxy"] == "http://127.0.0.1:7890" for call in session.calls))

    async def test_the_impersonation_applies_to_every_leg(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(all(call["impersonate"] == "chrome131" for call in session.calls))

    async def test_pasted_newlines_are_stripped_from_the_cookie(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, " user_session=abc\n")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["headers"]["Cookie"], "user_session=abc")

    async def test_linuxdo_sends_its_callback_and_response_type(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid-2"}}'
                ),
                ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
                ("GET", LINUXDO_AUTHORIZE): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/linuxdo?code=C&state=f"}
                ),
                ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                    200, "{}", cookies={"session": "s"}
                ),
            }
        )
        result = await make_client(session).login(LINUXDO_OAUTH, "_t=abc")
        self.assertTrue(result.success)
        authorize = session.calls_to("/oauth2/authorize")[0]
        self.assertEqual(authorize["params"]["redirect_uri"], f"{BASE}/api/oauth/linuxdo")
        self.assertEqual(authorize["params"]["response_type"], "code")


class FailedLoginTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_credential_type(self) -> None:
        result = await make_client(FakeSession({})).login("gitlab_oauth", "c")
        self.assertFalse(result.success)
        self.assertIn("不支持", result.message)

    async def test_empty_cookie_names_the_expected_cookie(self) -> None:
        result = await make_client(FakeSession({})).login(GITHUB_OAUTH, "  ")
        self.assertFalse(result.success)
        self.assertIn("user_session", result.message)

    async def test_provider_disabled_on_the_station(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", f"{BASE}/api/status"): FakeResponse(
                        200, '{"data":{"github_oauth":false}}'
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("未启用", result.message)

    async def test_missing_client_id(self) -> None:
        session = FakeSession(
            github_routes(
                {("GET", f"{BASE}/api/status"): FakeResponse(200, '{"data":{"github_oauth":true}}')}
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("client_id", result.message)

    async def test_status_endpoint_returning_html(self) -> None:
        session = FakeSession(
            github_routes({("GET", f"{BASE}/api/status"): FakeResponse(200, "<html></html>")})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("JSON", result.message)

    async def test_status_endpoint_without_a_data_field(self) -> None:
        session = FakeSession(
            github_routes({("GET", f"{BASE}/api/status"): FakeResponse(200, '{"success":true}')})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("data", result.message)

    async def test_missing_flow_token_surfaces_the_station_message(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("POST", f"{BASE}/api/oauth/state"): FakeResponse(
                        200, '{"success":false,"message":"频率过高"}'
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("频率过高", result.message)

    async def test_expired_cookie_redirecting_to_login(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", GITHUB_AUTHORIZE): FakeResponse(
                        302, "", headers={"location": "https://github.com/login?return_to=x"}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=stale")
        self.assertFalse(result.success)
        self.assertIn("user_session", result.message)

    async def test_unauthorized_authorize_response(self) -> None:
        session = FakeSession(
            github_routes({("GET", GITHUB_AUTHORIZE): FakeResponse(401, "unauthorized")})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=stale")
        self.assertFalse(result.success)
        self.assertIn("失效", result.message)

    async def test_consent_page_instead_of_a_redirect(self) -> None:
        """The user has to approve the OAuth app in a browser once."""
        session = FakeSession(
            github_routes(
                {("GET", GITHUB_AUTHORIZE): FakeResponse(200, "<html>Authorize app?</html>")}
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("浏览器", result.message)

    async def test_provider_reported_error_is_surfaced(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", GITHUB_AUTHORIZE): FakeResponse(
                        302, "", headers={"location": f"{BASE}/cb?error=access_denied"}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("access_denied", result.message)

    async def test_callback_without_a_session_cookie(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                        403, '{"success":false,"message":"该账号未绑定"}', cookies={}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("未绑定", result.message)

    async def test_transport_errors_are_wrapped(self) -> None:
        class BoomSession(FakeSession):
            async def request(self, method, url, **kwargs):
                raise ConnectionError("dns failure")

        result = await make_client(BoomSession({})).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("dns failure", result.message)


class FlowTokenShapeTests(unittest.TestCase):
    """Forks disagree on where the OAuth state token lives."""

    def test_nested_flow_token(self) -> None:
        self.assertEqual(_extract_flow_token({"data": {"flow_token": "T"}}), "T")

    def test_nested_aliases(self) -> None:
        for key in ("state", "token", "oauth_state", "flowToken"):
            self.assertEqual(_extract_flow_token({"data": {key: "T"}}), "T", key)

    def test_data_as_a_plain_string(self) -> None:
        self.assertEqual(_extract_flow_token({"success": True, "data": "T"}), "T")

    def test_top_level_keys(self) -> None:
        self.assertEqual(_extract_flow_token({"flow_token": "T"}), "T")
        self.assertEqual(_extract_flow_token({"state": "T"}), "T")

    def test_bare_string_response(self) -> None:
        self.assertEqual(_extract_flow_token("T"), "T")

    def test_unrecognised_shapes_yield_nothing(self) -> None:
        for payload in ({}, {"data": None}, {"data": {}}, {"data": {"foo": "bar"}}, None, 5, []):
            self.assertEqual(_extract_flow_token(payload), "", repr(payload))

    def test_blank_values_are_ignored(self) -> None:
        self.assertEqual(_extract_flow_token({"data": {"flow_token": "   "}}), "")


class SafeLocationTests(unittest.TestCase):
    def test_code_and_state_are_redacted(self) -> None:
        """A redirect carries the authorization code; it must not be logged."""
        safe = _safe_location("https://x.test/cb?code=SECRET&state=ALSOSECRET&keep=1")
        self.assertNotIn("SECRET", safe)
        self.assertNotIn("ALSOSECRET", safe)
        self.assertIn("code=***", safe)
        self.assertIn("state=***", safe)
        self.assertIn("keep=1", safe)

    def test_plain_url_is_preserved(self) -> None:
        self.assertEqual(_safe_location("https://x.test/login"), "https://x.test/login")

    def test_empty_input(self) -> None:
        self.assertEqual(_safe_location(""), "")


class FlowTokenFallbackTests(unittest.IsolatedAsyncioTestCase):
    """Diagnostics and tolerance around the /api/oauth/state endpoint."""

    def _client(self, state_response, trace=None):
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): state_response,
            ("GET", GITHUB_AUTHORIZE): FakeResponse(
                302, "", headers={"location": f"{BASE}/api/oauth/github?code=C&state=S"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "live"}
            ),
        }
        session = FakeSession(routes)
        recorder = (lambda **kw: trace.append(kw)) if trace is not None else None
        return session, OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=recorder)

    async def test_a_string_data_field_still_logs_in(self) -> None:
        _, client = self._client(FakeResponse(200, '{"success":true,"data":"ABC"}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertTrue(result.success)

    async def test_a_missing_state_endpoint_falls_back_to_a_local_state(self) -> None:
        """Older stations have no state endpoint and accept a client-chosen one."""
        for status in (404, 405):
            session, client = self._client(FakeResponse(status, "not found"))
            result = await client.login(GITHUB_OAUTH, "user_session=x")
            self.assertTrue(result.success, status)
            authorize = session.calls_to("/login/oauth/authorize")[0]
            self.assertTrue(authorize["params"]["state"])

    async def test_an_unknown_shape_reports_the_body(self) -> None:
        """The station's own response is the only clue, so surface it."""
        _, client = self._client(FakeResponse(200, '{"success":true,"data":{"foo":"bar"}}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertFalse(result.success)
        self.assertIn("flow_token", result.message)
        self.assertIn('"foo"', result.message)

    async def test_a_station_message_is_preferred_over_the_body(self) -> None:
        _, client = self._client(FakeResponse(200, '{"success":false,"message":"请求过于频繁"}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertIn("请求过于频繁", result.message)

    async def test_every_leg_is_traced_on_success(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"flow_token":"T"}}'), trace)
        await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertEqual(
            [item["step"] for item in trace],
            ["探测 OAuth 配置", "获取 OAuth state", "Github OAuth 授权", "OAuth 回调"],
        )
        self.assertTrue(all(item["success"] for item in trace))

    async def test_the_failing_leg_is_traced(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"foo":"bar"}}'), trace)
        await client.login(GITHUB_OAUTH, "user_session=x")
        failed = [item for item in trace if item.get("error")]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["step"], "获取 OAuth state")
        self.assertEqual(failed[0]["status"], 200)
        self.assertIn('"foo"', failed[0]["response_text"])

    async def test_the_traced_authorize_leg_hides_the_code(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"flow_token":"T"}}'), trace)
        await client.login(GITHUB_OAUTH, "user_session=x")
        joined = " ".join(str(item) for item in trace)
        self.assertNotIn("code=C&", joined)

    async def test_tracing_failures_do_not_break_the_login(self) -> None:
        def boom(**_kwargs):
            raise RuntimeError("recorder exploded")

        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
                ),
                ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"T"}}'),
                ("GET", GITHUB_AUTHORIZE): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/github?code=C&state=T"}
                ),
                ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                    200, "{}", cookies={"session": "live"}
                ),
            }
        )
        client = OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=boom)
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
