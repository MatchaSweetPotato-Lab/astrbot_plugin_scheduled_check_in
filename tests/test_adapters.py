"""Unit tests for the credential- and action-driven check-in adapters."""

from __future__ import annotations

import json
import unittest

import tests  # noqa: F401
from core.adapters import (
    MAX_ATTEMPTS_PER_RUN,
    QUOTA_CONVERSION_FACTOR,
    BaseCheckInAdapter,
    GenericRestAdapter,
    NewApiAdapter,
    SiteWriteback,
    create_adapter,
    persist_writeback,
)
from core.site_schema import ACTION_BALANCE, ACTION_CHECKIN, NEW_API_USER_HEADER, find_header
from tests.fakes import FakeResponse, FakeSession

BASE = "https://relay.example.com"


def self_payload(quota: float, user_id: int = 7) -> str:
    """Render a New-API ``/api/user/self`` body."""
    return json.dumps({"success": True, "data": {"id": user_id, "quota": quota}})


def make_site(**overrides) -> dict:
    """Build a site config with the new credential/action shape."""
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


class CredentialHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def _auth_headers(self, credential: dict, balance: dict | None = None) -> dict:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(credentials=[credential], balance=balance or {"protocol": "get"})
        await create_adapter(site, session).query_balance()
        return session.calls[0]["headers"]

    async def test_token_gets_a_bearer_prefix(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": "sk-plain"})
        self.assertEqual(headers["Authorization"], "Bearer sk-plain")

    async def test_existing_bearer_prefix_is_not_doubled(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": "Bearer sk-plain"})
        self.assertEqual(headers["Authorization"], "Bearer sk-plain")

    async def test_auto_bearer_off_sends_the_value_verbatim(self) -> None:
        headers = await self._auth_headers(
            {"id": "c", "type": "token", "value": "Basic abc", "auto_bearer": False}
        )
        self.assertEqual(headers["Authorization"], "Basic abc")

    async def test_cookie_credential_becomes_a_cookie_header(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "cookie", "value": "session=abc"})
        self.assertEqual(headers["Cookie"], "session=abc")
        self.assertNotIn("Authorization", headers)

    async def test_pasted_newlines_are_stripped(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": " sk-a\n"})
        self.assertEqual(headers["Authorization"], "Bearer sk-a")

    async def test_custom_headers_override_the_credential(self) -> None:
        headers = await self._auth_headers(
            {"id": "c", "type": "token", "value": "sk-a"},
            balance={
                "protocol": "get",
                "headers": [
                    {"key": "Authorization", "value": "Bearer override"},
                    {"key": "X-Custom", "value": "1"},
                ],
            },
        )
        self.assertEqual(headers["Authorization"], "Bearer override")
        self.assertEqual(headers["X-Custom"], "1")

    async def test_missing_credential_fails_before_any_request(self) -> None:
        session = FakeSession({})
        result = await create_adapter(make_site(credentials=[]), session).check_in()
        self.assertFalse(result.success)
        self.assertIn("凭据", result.message)
        self.assertEqual(session.calls, [])

    async def test_blank_credential_value_is_reported(self) -> None:
        session = FakeSession({})
        site = make_site(credentials=[{"id": "c", "type": "token", "value": ""}])
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertIn("未填写", result.message)

    async def test_token_is_preferred_over_cookie(self) -> None:
        headers = await self._auth_headers({"id": "tk", "type": "token", "value": "sk-tok"})
        self.assertIn("Authorization", headers)

    async def test_explicit_credential_id_wins(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(
            credentials=[
                {"id": "ck", "type": "cookie", "value": "session=ck"},
                {"id": "tk", "type": "token", "value": "sk-tok"},
            ],
            balance={"protocol": "get", "credential_id": "ck"},
        )
        await create_adapter(site, session).query_balance()
        headers = session.calls[0]["headers"]
        self.assertEqual(headers["Cookie"], "session=ck")
        self.assertNotIn("Authorization", headers)


class BalanceQueryTests(unittest.IsolatedAsyncioTestCase):
    async def _quota(self, body: str, site_overrides: dict | None = None) -> tuple[float, str]:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, body),
                ("GET", f"{BASE}/me"): FakeResponse(200, body),
            }
        )
        site = make_site(**(site_overrides or {}))
        return await create_adapter(site, session).query_balance()

    async def test_raw_quota_is_converted_to_currency(self) -> None:
        quota, error = await self._quota(self_payload(QUOTA_CONVERSION_FACTOR))
        self.assertEqual((quota, error), (1.0, ""))

    async def test_currency_fields_are_used_as_is(self) -> None:
        quota, _ = await self._quota(
            '{"data":{"balance":12.5}}',
            {"type": "generic_rest", "balance": {"path": "/me", "protocol": "get"}},
        )
        self.assertEqual(quota, 12.5)

    async def test_top_level_quota_is_accepted(self) -> None:
        quota, _ = await self._quota('{"quota":250000}')
        self.assertEqual(quota, 0.5)

    async def test_booleans_are_not_treated_as_amounts(self) -> None:
        _, error = await self._quota('{"data":{"quota":true}}')
        self.assertIn("未找到额度", error)

    async def test_missing_amount_is_reported(self) -> None:
        _, error = await self._quota('{"data":{"username":"x"}}')
        self.assertIn("未找到额度", error)

    async def test_non_json_is_reported(self) -> None:
        _, error = await self._quota("not json at all")
        self.assertIn("非 JSON", error)

    async def test_html_body_is_reported_as_a_page(self) -> None:
        _, error = await self._quota("<html><body>login</body></html>")
        self.assertIn("HTML", error)

    async def test_unadapted_framework_skips_the_query(self) -> None:
        """A generic site with no balance path must not guess an endpoint."""
        session = FakeSession({})
        site = make_site(type="generic_rest")
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual((quota, error), (0.0, ""))
        self.assertEqual(session.calls, [])

    async def test_absolute_custom_path_is_used_verbatim(self) -> None:
        session = FakeSession(
            {("GET", "https://other.test/api/me"): FakeResponse(200, '{"balance":3}')}
        )
        site = make_site(balance={"path": "https://other.test/api/me", "protocol": "get"})
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual((quota, error), (3.0, ""))


class NewApiCheckInTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_failed_final_read_keeps_the_known_balance(self) -> None:
        """A confirmed balance must not be overwritten with zero.

        The opening read succeeded, so the closing failure means "unknown", not
        "empty" — reporting 0 would blank a correct last_quota and its calendar
        cell.
        """
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(5_000_000)),
                    FakeResponse(503, "service unavailable"),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()

        self.assertTrue(result.success)
        self.assertFalse(result.expired)
        self.assertEqual(result.total_quota, 10.0)
        self.assertEqual(result.gained_quota, 0.0)
        self.assertIn("查询最终余额", result.error_detail)

    async def test_the_two_balance_reads_are_traced_separately(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertEqual(
            [attempt["step"] for attempt in result.attempts],
            ["查询余额", "签到", "查询最终余额"],
        )

    async def test_a_failed_opening_read_leaves_the_balance_unknown(self) -> None:
        """With no confirmed opening value there is nothing to fall back to."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(503, "unavailable"),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertEqual(result.total_quota, 0.0)

    async def test_framework_check_in_and_quota_delta(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(500000, 42)),
                    FakeResponse(200, self_payload(1500000, 42)),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        adapter = create_adapter(make_site(credentials=[{"id": "c", "type": "cookie", "value": "s=1"}]), session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 3.0)
        self.assertEqual(result.gained_quota, 2.0)

    async def test_new_api_user_is_probed_and_written_back(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        adapter = create_adapter(make_site(), session)
        await adapter.check_in()

        self.assertEqual(find_header(adapter.writeback.checkin_headers, NEW_API_USER_HEADER), "42")
        checkin_calls = session.calls_to("/api/user/checkin")
        self.assertEqual(checkin_calls[0]["headers"][NEW_API_USER_HEADER], "42")

    async def test_the_user_id_is_harvested_without_an_extra_request(self) -> None:
        """The balance response already carries the id, so no probe is needed."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        await create_adapter(make_site(), session).check_in()
        # Exactly two: the opening and closing balance reads.
        self.assertEqual(session.count_to("/api/user/self"), 2)

    async def test_explicit_protocol_skips_the_probe(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true}'),
            }
        )
        adapter = create_adapter(make_site(checkin={"path": "/sign", "protocol": "post"}), session)
        await adapter.check_in()
        self.assertIsNone(adapter.writeback.checkin_headers)

    async def test_405_falls_back_to_the_other_verb(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(500000)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(405, "method not allowed"),
                ("GET", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true,"message":"ok"}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertTrue(any(c["method"] == "GET" for c in session.calls_to("/api/user/checkin")))

    async def test_404_moves_on_to_the_next_candidate(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(404, "nope"),
                ("GET", f"{BASE}/api/user/checkin"): FakeResponse(404, "nope"),
                ("POST", f"{BASE}/api/user/pay/checkin"): FakeResponse(
                    200, '{"success":true,"message":"ok"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)

    async def test_already_signed_in_counts_as_success(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":false,"message":"今日已签到"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("已签到", result.message)

    async def test_401_marks_the_credential_expired(self) -> None:
        session = FakeSession({}, default=FakeResponse(401, '{"success":false,"message":"unauthorized"}'))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)

    async def test_custom_path_is_the_only_candidate(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/custom/sign"): FakeResponse(200, '{"success":true,"message":"ok"}'),
            }
        )
        site = make_site(checkin={"path": "/custom/sign", "protocol": "post"})
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/user/checkin"), 0)


class NewApiTestConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reports_the_balance_on_success(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(500000))}
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 1.0)

    async def test_never_performs_a_check_in(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))}
        )
        await create_adapter(make_site(), session).test_connection()
        self.assertEqual(session.count_to("/api/user/checkin"), 0)

    async def test_falls_back_to_the_models_endpoint(self) -> None:
        """A blocked management API is still distinguishable from a dead key."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(403, "denied"),
                ("GET", f"{BASE}/v1/models"): FakeResponse(200, '{"data":[{"id":"model-x"}]}'),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertFalse(result.success)
        self.assertIn("模型接口可用", result.message)

    async def test_a_waf_block_is_not_reported_as_an_expired_key(self) -> None:
        """The key works, so flagging it expired would send the user to
        regenerate a perfectly good credential."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, "<html>WAF challenge</html>"),
                ("GET", f"{BASE}/v1/models"): FakeResponse(200, '{"data":[{"model":"gpt-test"}]}'),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()

        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("API Key 有效", result.message)
        self.assertIn("API 接口兜底探测", result.error_detail)

    async def test_a_dead_key_is_still_reported_as_expired(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(401, '{"success":false}'),
                ("GET", f"{BASE}/v1/models"): FakeResponse(401, "unauthorized"),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)


class GenericRestTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_path_gets_the_base_url(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":true,"message":"ok"}')})
        site = make_site(type="generic_rest", credentials=[{"id": "c", "type": "cookie", "value": "s=1"}])
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.calls[0]["url"], BASE)
        self.assertEqual(session.calls[0]["method"], "GET")

    async def test_custom_path_and_balance(self) -> None:
        session = FakeSession(
            {
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true,"message":"done"}'),
                ("GET", f"{BASE}/me"): FakeResponse(200, '{"data":{"balance":12.5}}'),
            }
        )
        site = make_site(
            type="generic_rest",
            checkin={"path": "sign", "protocol": "post"},
            balance={"path": "/me", "protocol": "get"},
        )
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 12.5)

    async def test_a_success_body_cannot_rescue_a_failed_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(401, '{"success":"true"}')})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)

    async def test_a_failure_body_overrides_a_2xx_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":false}')})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertFalse(result.success)

    async def test_non_json_body_follows_the_http_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, "plain ok")})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("plain ok", result.message)

    async def test_test_connection_does_not_hit_the_checkin_path(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/me"): FakeResponse(200, '{"data":{"balance":3}}'),
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true}'),
            }
        )
        site = make_site(
            type="generic_rest",
            checkin={"path": "/sign", "protocol": "post"},
            balance={"path": "/me", "protocol": "get"},
        )
        result = await create_adapter(site, session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/sign"), 0)

    async def test_test_connection_probes_the_base_url_without_a_balance_path(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":true}')})
        site = make_site(type="generic_rest", checkin={"path": "/sign", "protocol": "post"})
        result = await create_adapter(site, session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(session.urls(), [BASE])


class OAuthCheckInTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _github_routes(extra: dict | None = None) -> dict:
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"flow-1"}}'),
            ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                302, "", headers={"location": f"{BASE}/oauth/github?code=CODE1&state=flow-1"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "fresh-session"}
            ),
            ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true,"message":"ok"}'),
        }
        routes.update(extra or {})
        return routes

    async def test_logs_in_when_no_session_is_stored(self) -> None:
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh-session")

    async def test_a_stale_session_triggers_exactly_one_relogin(self) -> None:
        session = FakeSession(
            self._github_routes(
                {
                    ("GET", f"{BASE}/api/user/self"): [
                        FakeResponse(401, '{"success":false}'),
                        FakeResponse(200, self_payload(1000000)),
                        FakeResponse(200, self_payload(1000000)),
                    ]
                }
            )
        )
        site = make_site(
            proxy="http://127.0.0.1:7890",
            credentials=[
                {
                    "id": "gh",
                    "type": "github_oauth",
                    "value": "user_session=gh",
                    "session_cookie": "session=stale",
                }
            ],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh-session")
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_refreshed_session_reaches_the_check_in_request(self) -> None:
        session = FakeSession(
            self._github_routes(
                {
                    ("GET", f"{BASE}/api/user/self"): [
                        FakeResponse(401, '{"success":false}'),
                        FakeResponse(200, self_payload(0)),
                        FakeResponse(200, self_payload(0)),
                    ]
                }
            )
        )
        site = make_site(
            credentials=[
                {
                    "id": "gh",
                    "type": "github_oauth",
                    "value": "user_session=gh",
                    "session_cookie": "session=stale",
                }
            ],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        checkin_calls = session.calls_to("/api/user/checkin")
        self.assertEqual(checkin_calls[0]["headers"]["Cookie"], "session=fresh-session")

    async def test_the_site_proxy_covers_the_third_party_leg(self) -> None:
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            proxy="http://127.0.0.1:7890",
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        github_calls = [c for c in session.calls if "github.com" in c["url"]]
        self.assertTrue(github_calls)
        self.assertTrue(all(c["proxy"] == "http://127.0.0.1:7890" for c in session.calls))

    async def test_an_expired_third_party_cookie_is_reported(self) -> None:
        routes = self._github_routes(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                    302, "", headers={"location": "https://github.com/login"}
                ),
            }
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=dead"}],
            checkin={"protocol": "oauth"},
        )
        result = await create_adapter(site, FakeSession(routes)).check_in()
        self.assertFalse(result.success)
        self.assertIn("Cookie", result.message)

    async def test_oauth_protocol_without_an_oauth_credential_fails(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(checkin={"protocol": "oauth"})
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertIn("OAuth", result.message)

    async def test_linuxdo_sends_a_redirect_uri(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}'
                ),
                ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
                ("GET", "https://connect.linux.do/oauth2/authorize"): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/linuxdo?code=C&state=f"}
                ),
                ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                    200, "{}", cookies={"session": "new-sess"}
                ),
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        site = make_site(
            credentials=[{"id": "ld", "type": "linuxdo_oauth", "value": "_t=ld"}],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        await adapter.check_in()

        authorize = [c for c in session.calls if "connect.linux.do" in c["url"]][0]
        self.assertEqual(authorize["params"]["redirect_uri"], f"{BASE}/api/oauth/linuxdo")
        self.assertEqual(adapter.writeback.oauth_sessions["ld"], "session=new-sess")

    async def test_github_does_not_send_a_redirect_uri(self) -> None:
        """Github rejects any redirect_uri that does not match the registration."""
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        authorize = [c for c in session.calls if "github.com" in c["url"]][0]
        self.assertNotIn("redirect_uri", authorize["params"])


class LoginAsCheckInTests(unittest.IsolatedAsyncioTestCase):
    """Stations that disabled their check-in endpoint credit the bonus on login.

    For these the OAuth login *is* the signing action, so it has to run on every
    check-in — reusing a stored session would silently do nothing while still
    reporting success.
    """

    @staticmethod
    def _routes(self_responses, checkin_status: int = 404) -> dict:
        return {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
            ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                302, "", headers={"location": f"{BASE}/cb?code=C&state=f"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "fresh"}
            ),
            ("GET", f"{BASE}/api/user/self"): self_responses,
            # The disabled endpoint, for both verbs the adapter may try.
            ("POST", f"{BASE}/api/user/checkin"): FakeResponse(checkin_status, "not found"),
            ("GET", f"{BASE}/api/user/checkin"): FakeResponse(checkin_status, "not found"),
            ("POST", f"{BASE}/api/user/pay/checkin"): FakeResponse(checkin_status, "not found"),
            ("GET", f"{BASE}/api/user/pay/checkin"): FakeResponse(checkin_status, "not found"),
        }

    @staticmethod
    def _site(**overrides) -> dict:
        credential = {
            "id": "gh",
            "type": "github_oauth",
            "value": "user_session=gh",
            "session_cookie": "session=yesterday",
        }
        credential.update(overrides.pop("credential", {}))
        return make_site(credentials=[credential], checkin={"protocol": "oauth"}, **overrides)

    async def test_a_stored_session_does_not_skip_the_login(self) -> None:
        """The whole point: yesterday's cookie must not stand in for today's login."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(500000))])
        )
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_login_counts_as_the_check_in(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("登录即打卡", result.message)

    async def test_a_bonus_credited_on_login_is_reported(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(12500000))])
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.gained_quota, 25.0)
        self.assertIn("25.0", result.message)

    async def test_the_opening_balance_read_does_not_log_in(self) -> None:
        """The opening read reuses the old cookie; only the check-in signs in."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        await create_adapter(self._site(), session).check_in()
        opening_read = session.calls_to("/api/user/self")[0]
        self.assertEqual(opening_read["headers"]["Cookie"], "session=yesterday")
        # No login had happened by the time that read was issued.
        self.assertEqual(session.urls().index(f"{BASE}/api/user/self"), 0)

    async def test_an_expired_stored_cookie_still_logs_in_only_once(self) -> None:
        """A 401 on the opening read refreshes the session; the check-in reuses it."""
        session = FakeSession(
            self._routes(
                [
                    FakeResponse(401, '{"success":false}'),  # yesterday's cookie is dead
                    FakeResponse(200, self_payload(0)),      # retried after the login
                    FakeResponse(200, self_payload(500000)),  # closing read
                ]
            )
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_exactly_one_login_per_run(self) -> None:
        """Two balance reads bracket the check-in; neither may re-login."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        await create_adapter(self._site(), session).check_in()
        self.assertEqual(session.count_to("/api/status"), 1)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_fresh_session_is_written_back(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh")

    async def test_a_failed_login_is_not_reported_as_a_check_in(self) -> None:
        routes = self._routes([FakeResponse(200, self_payload(0))])
        routes[("GET", "https://github.com/login/oauth/authorize")] = FakeResponse(
            302, "", headers={"location": "https://github.com/login"}
        )
        result = await create_adapter(self._site(), FakeSession(routes)).check_in()
        self.assertFalse(result.success)
        self.assertNotIn("登录即打卡", result.message)

    async def test_a_working_endpoint_is_still_used_after_the_login(self) -> None:
        """Stations that kept the endpoint get both the login and the request."""
        session = FakeSession(
            self._routes(
                [FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))],
            )
        )
        session.routes[("POST", f"{BASE}/api/user/checkin")] = FakeResponse(
            200, '{"success":true,"message":"签到成功"}'
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.message, "签到成功")
        self.assertEqual(session.count_to("/api/oauth/github"), 1)
        checkin_call = session.calls_to("/api/user/checkin")[0]
        self.assertEqual(checkin_call["headers"]["Cookie"], "session=fresh")

    async def test_balance_reads_alone_reuse_the_stored_session(self) -> None:
        """Only the check-in forces a login; a plain balance read must not."""
        session = FakeSession(self._routes(FakeResponse(200, self_payload(0))))
        quota, error = await create_adapter(self._site(), session).query_balance()
        self.assertEqual((quota, error), (0.0, ""))
        self.assertEqual(session.count_to("/api/oauth/github"), 0)
        self.assertEqual(session.calls_to("/api/user/self")[0]["headers"]["Cookie"], "session=yesterday")

    async def test_test_connection_does_not_log_in(self) -> None:
        """Testing a site must never consume the day's sign-in."""
        session = FakeSession(self._routes(FakeResponse(200, self_payload(0))))
        await create_adapter(self._site(), session).test_connection()
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_a_first_run_with_no_stored_session_still_works(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        site = self._site(credential={"session_cookie": ""})
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_generic_sites_also_treat_the_login_as_the_check_in(self) -> None:
        routes = self._routes(FakeResponse(404, "nope"))
        routes[("GET", BASE)] = FakeResponse(404, "not found")
        site = self._site(type="generic_rest")
        result = await create_adapter(site, FakeSession(routes)).check_in()
        self.assertTrue(result.success)
        self.assertIn("登录即打卡", result.message)


class AdapterFactoryTests(unittest.TestCase):
    def test_new_api_types_select_the_new_api_adapter(self) -> None:
        for site_type in ("new-api", "one-api", "", None, "mystery"):
            adapter = create_adapter(make_site(type=site_type), FakeSession({}))
            self.assertIsInstance(adapter, NewApiAdapter, msg=site_type)

    def test_generic_types_select_the_generic_adapter(self) -> None:
        for site_type in ("generic_rest", "generic", "custom"):
            adapter = create_adapter(make_site(type=site_type), FakeSession({}))
            self.assertIsInstance(adapter, GenericRestAdapter, msg=site_type)

    def test_trailing_slash_is_trimmed_from_the_base_url(self) -> None:
        adapter = create_adapter(make_site(base_url=f"{BASE}/"), FakeSession({}))
        self.assertEqual(adapter.base_url, BASE)


class WritebackTests(unittest.TestCase):
    class _FakeDb:
        def __init__(self) -> None:
            self.headers: list[tuple] = []
            self.sessions: list[tuple] = []

        def update_action_headers(self, site_id, action, headers):
            self.headers.append((site_id, action, headers))
            return True

        def update_credential_session(self, site_id, credential_id, cookie):
            self.sessions.append((site_id, credential_id, cookie))
            return True

    def test_empty_writeback_is_a_no_op(self) -> None:
        db = self._FakeDb()
        persist_writeback(db, "s", SiteWriteback())
        persist_writeback(db, "s", None)
        self.assertEqual((db.headers, db.sessions), ([], []))

    def test_writes_both_actions_and_sessions(self) -> None:
        db = self._FakeDb()
        writeback = SiteWriteback(
            checkin_headers=[{"key": NEW_API_USER_HEADER, "value": "9"}],
            balance_headers=[],
            oauth_sessions={"gh": "session=a"},
        )
        persist_writeback(db, "s", writeback)
        self.assertEqual([entry[1] for entry in db.headers], [ACTION_CHECKIN, ACTION_BALANCE])
        self.assertEqual(db.sessions, [("s", "gh", "session=a")])

    def test_storage_errors_do_not_escape(self) -> None:
        """A locked vault must not turn a successful check-in into a crash."""

        class BrokenDb:
            def update_action_headers(self, *_):
                raise RuntimeError("locked")

            def update_credential_session(self, *_):
                raise RuntimeError("locked")

        writeback = SiteWriteback(checkin_headers=[], oauth_sessions={"gh": "s"})
        with self.assertLogs("astrbot", level="WARNING"):
            persist_writeback(BrokenDb(), "s", writeback)


class RequestTraceTests(unittest.IsolatedAsyncioTestCase):
    """The per-run request trace that makes a failure diagnosable."""

    async def test_a_successful_run_records_each_step(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(500000)),
                    FakeResponse(200, self_payload(1500000)),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        steps = [attempt["step"] for attempt in result.attempts]
        self.assertIn("查询余额", steps)
        self.assertIn("签到", steps)
        self.assertTrue(all(attempt["status"] == 200 for attempt in result.attempts))

    async def test_success_leaves_error_detail_empty(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.error_detail, "")

    async def test_failure_fills_a_readable_error_detail(self) -> None:
        session = FakeSession({}, default=FakeResponse(401, '{"message":"unauthorized"}'))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertIn("HTTP 401", result.error_detail)
        self.assertIn("查询余额", result.error_detail)

    async def test_the_trace_travels_in_to_dict(self) -> None:
        """History stores the dict form, so the trace has to survive it."""
        session = FakeSession({}, default=FakeResponse(500, "boom"))
        result = await create_adapter(make_site(), session).check_in()
        payload = result.to_dict()
        self.assertIn("attempts", payload)
        self.assertIn("error_detail", payload)
        self.assertTrue(payload["attempts"])

    async def test_query_strings_are_stripped_from_traced_urls(self) -> None:
        """A URL could carry a token, so only scheme/host/path is recorded."""
        session = FakeSession(
            {("GET", f"{BASE}/me"): FakeResponse(200, '{"balance":1}')}
        )
        site = make_site(balance={"path": "/me?token=secret", "protocol": "get"})
        adapter = create_adapter(site, session)
        await adapter.query_balance()
        self.assertTrue(adapter.attempts)
        self.assertNotIn("secret", adapter.attempts[0]["url"])

    async def test_long_responses_are_truncated(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(500, "x" * 9000)})
        adapter = create_adapter(make_site(balance={"protocol": "get"}), session)
        await adapter.query_balance()
        attempt = adapter.attempts[0]
        self.assertIn("已截断", attempt["response"])
        self.assertEqual(attempt["response_length"], 9000)

    async def test_the_trace_is_bounded(self) -> None:
        adapter = create_adapter(make_site(), FakeSession({}))
        for _ in range(MAX_ATTEMPTS_PER_RUN + 10):
            adapter._record_attempt(step="s", method="GET", endpoint=f"{BASE}/x", status=200)
        self.assertEqual(len(adapter.attempts), MAX_ATTEMPTS_PER_RUN + 1)
        self.assertEqual(sum(1 for a in adapter.attempts if a.get("truncated")), 1)

    async def test_a_transport_error_is_traced(self) -> None:
        class BoomSession(FakeSession):
            async def request(self, method, url, **kwargs):
                raise ConnectionError("dns failure")

        adapter = create_adapter(make_site(balance={"protocol": "get"}), BoomSession({}))
        quota, error = await adapter.query_balance()
        self.assertEqual(quota, 0.0)
        self.assertIn("dns failure", error)
        self.assertIn("dns failure", adapter.attempts[0]["error"])


class CheckInMessageTests(unittest.TestCase):
    """Recognizing station messages without broad false positives."""

    def test_accepts_explicit_success(self) -> None:
        for message in ("签到成功", "今日已签到", "已经签到过了", "重复签到"):
            self.assertTrue(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_rejects_explicit_failure(self) -> None:
        for message in ("签到失败", "未签到", "未成功", "未触发签到"):
            self.assertFalse(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_rejects_unrelated_text(self) -> None:
        for message in ("", "ok", "quota updated"):
            self.assertFalse(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_extracts_a_message_from_json(self) -> None:
        self.assertEqual(
            BaseCheckInAdapter._response_message(None, '{"message":"额度不足"}'), "额度不足"
        )
        self.assertEqual(
            BaseCheckInAdapter._response_message({"msg": "ok"}), "ok"
        )
        self.assertEqual(
            BaseCheckInAdapter._response_message({"error": {"message": "bad token"}}), "bad token"
        )
        self.assertEqual(BaseCheckInAdapter._response_message(None, "plain text"), "")


if __name__ == "__main__":
    unittest.main()
