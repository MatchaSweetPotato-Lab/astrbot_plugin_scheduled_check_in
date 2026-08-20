"""Unit tests for the relay-station OAuth login flow."""

from __future__ import annotations

import unittest

import tests  # noqa: F401
from core.oauth import (
    GITHUB_OAUTH,
    LINUXDO_OAUTH,
    PROVIDERS,
    OAuthLoginClient,
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


if __name__ == "__main__":
    unittest.main()
