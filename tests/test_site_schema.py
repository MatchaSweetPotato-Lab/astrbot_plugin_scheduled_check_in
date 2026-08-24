"""Unit tests for site configuration normalization and credential resolution."""

from __future__ import annotations

import unittest

import tests  # noqa: F401
from core.site_schema import (
    CRED_COOKIE,
    CRED_GITHUB_OAUTH,
    CRED_LINUXDO_OAUTH,
    CRED_TOKEN,
    NEW_API_USER_HEADER,
    PROTOCOL_AUTO,
    PROTOCOL_GET,
    PROTOCOL_OAUTH,
    PROTOCOL_POST,
    SITE_TYPE_GENERIC,
    SITE_TYPE_NEW_API,
    credential_label,
    find_credential,
    find_header,
    headers_to_mapping,
    normalize_action,
    normalize_credential,
    normalize_credential_type,
    normalize_credentials,
    normalize_headers,
    normalize_path,
    normalize_protocol,
    normalize_site_type,
    parse_header_text,
    resolve_action_credential,
    resolve_credential,
    upsert_header,
    wants_new_api_user_probe,
)


class HeaderNormalizationTests(unittest.TestCase):
    def test_parses_legacy_colon_text(self) -> None:
        self.assertEqual(
            parse_header_text("User-Agent: test\n\nX-A: 1"),
            [{"key": "User-Agent", "value": "test"}, {"key": "X-A", "value": "1"}],
        )

    def test_accepts_list_of_pairs(self) -> None:
        self.assertEqual(
            normalize_headers([{"key": " X-A ", "value": 1}]),
            [{"key": "X-A", "value": "1"}],
        )

    def test_accepts_a_mapping(self) -> None:
        self.assertEqual(normalize_headers({"X-A": "1"}), [{"key": "X-A", "value": "1"}])

    def test_accepts_tuples(self) -> None:
        self.assertEqual(normalize_headers([("X-A", "1")]), [{"key": "X-A", "value": "1"}])

    def test_drops_entries_without_a_key(self) -> None:
        self.assertEqual(normalize_headers([{"key": "  ", "value": "x"}, "junk", 5]), [])

    def test_empty_inputs_normalize_to_empty(self) -> None:
        for empty in (None, "", [], {}, 42):
            self.assertEqual(normalize_headers(empty), [])

    def test_mapping_lets_later_entries_win(self) -> None:
        pairs = [{"key": "X-A", "value": "1"}, {"key": "X-A", "value": "2"}]
        self.assertEqual(headers_to_mapping(pairs), {"X-A": "2"})

    def test_find_header_is_case_insensitive(self) -> None:
        pairs = [{"key": "New-API-User", "value": "7"}]
        self.assertEqual(find_header(pairs, "new-api-user"), "7")
        self.assertEqual(find_header(pairs, "missing"), "")

    def test_upsert_replaces_case_insensitively(self) -> None:
        pairs = [{"key": "New-API-User", "value": "7"}]
        self.assertEqual(
            upsert_header(pairs, "new-api-user", "9"),
            [{"key": "New-API-User", "value": "9"}],
        )

    def test_upsert_appends_a_missing_header(self) -> None:
        self.assertEqual(
            upsert_header([], NEW_API_USER_HEADER, "9"),
            [{"key": NEW_API_USER_HEADER, "value": "9"}],
        )

    def test_upsert_ignores_a_blank_key(self) -> None:
        self.assertEqual(upsert_header([{"key": "X", "value": "1"}], "  ", "9"),
                         [{"key": "X", "value": "1"}])


class CredentialNormalizationTests(unittest.TestCase):
    def test_maps_type_aliases(self) -> None:
        self.assertEqual(normalize_credential_type("bearer_token"), CRED_TOKEN)
        self.assertEqual(normalize_credential_type("github"), CRED_GITHUB_OAUTH)
        self.assertEqual(normalize_credential_type("linux-do"), CRED_LINUXDO_OAUTH)
        self.assertEqual(normalize_credential_type("Cookie"), CRED_COOKIE)

    def test_unknown_type_falls_back_to_token(self) -> None:
        self.assertEqual(normalize_credential_type("mystery"), CRED_TOKEN)
        self.assertEqual(normalize_credential_type(None), CRED_TOKEN)

    def test_token_defaults_to_auto_bearer(self) -> None:
        """Users paste raw tokens far more often than 'Bearer <token>'."""
        credential = normalize_credential({"type": "token", "value": "sk-a"})
        self.assertTrue(credential["auto_bearer"])

    def test_auto_bearer_can_be_turned_off(self) -> None:
        credential = normalize_credential({"type": "token", "value": "x", "auto_bearer": False})
        self.assertFalse(credential["auto_bearer"])

    def test_oauth_credentials_carry_session_fields(self) -> None:
        credential = normalize_credential({"type": "github_oauth", "value": "c"})
        self.assertEqual(credential["session_cookie"], "")
        self.assertEqual(credential["session_updated_at"], "")

    def test_cookie_credentials_have_no_bearer_flag(self) -> None:
        self.assertNotIn("auto_bearer", normalize_credential({"type": "cookie"}))

    def test_missing_id_is_synthesized_from_position(self) -> None:
        self.assertEqual(normalize_credential({}, 2)["id"], "cred_3")

    def test_duplicate_ids_are_disambiguated(self) -> None:
        credentials = normalize_credentials([{"id": "a"}, {"id": "a"}])
        self.assertNotEqual(credentials[0]["id"], credentials[1]["id"])

    def test_non_list_input_normalizes_to_empty(self) -> None:
        self.assertEqual(normalize_credentials({"id": "a"}), [])

    def test_find_credential_by_id(self) -> None:
        credentials = normalize_credentials([{"id": "a"}, {"id": "b"}])
        self.assertEqual(find_credential(credentials, "b")["id"], "b")
        self.assertIsNone(find_credential(credentials, "missing"))
        self.assertIsNone(find_credential(credentials, ""))

    def test_label_falls_back_to_the_type_name(self) -> None:
        self.assertEqual(credential_label({"type": CRED_TOKEN}), "Authorization Token")
        self.assertEqual(credential_label({"type": CRED_TOKEN, "label": "主号"}), "主号")


class CredentialResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = {"id": "tk", "type": CRED_TOKEN, "value": "sk"}
        self.cookie = {"id": "ck", "type": CRED_COOKIE, "value": "s=1"}
        self.github = {"id": "gh", "type": CRED_GITHUB_OAUTH, "value": "gh"}
        self.linuxdo = {"id": "ld", "type": CRED_LINUXDO_OAUTH, "value": "ld"}

    def test_token_wins_over_cookie(self) -> None:
        plan = resolve_credential([self.cookie, self.token], PROTOCOL_AUTO)
        self.assertEqual(plan.mode, "request")
        self.assertEqual(plan.credential["id"], "tk")

    def test_cookie_is_used_when_no_token_exists(self) -> None:
        plan = resolve_credential([self.cookie], PROTOCOL_GET)
        self.assertEqual(plan.credential["id"], "ck")

    def test_github_wins_over_linuxdo_for_oauth(self) -> None:
        plan = resolve_credential([self.linuxdo, self.github], PROTOCOL_OAUTH)
        self.assertEqual(plan.mode, "oauth")
        self.assertEqual(plan.credential["id"], "gh")

    def test_oauth_protocol_without_an_oauth_credential_fails(self) -> None:
        plan = resolve_credential([self.token], PROTOCOL_OAUTH)
        self.assertIsNone(plan.credential)
        self.assertIn("OAuth", plan.reason)

    def test_request_protocol_falls_back_to_oauth(self) -> None:
        """An OAuth login is the only remaining way to authenticate."""
        plan = resolve_credential([self.github], PROTOCOL_POST)
        self.assertEqual(plan.mode, "oauth")
        self.assertEqual(plan.credential["id"], "gh")

    def test_no_credentials_reports_a_reason(self) -> None:
        plan = resolve_credential([], PROTOCOL_AUTO)
        self.assertIsNone(plan.credential)
        self.assertTrue(plan.reason)

    def test_explicit_selection_overrides_priority(self) -> None:
        action = {"protocol": PROTOCOL_AUTO, "credential_id": "ck"}
        plan = resolve_action_credential([self.token, self.cookie], action)
        self.assertEqual(plan.credential["id"], "ck")

    def test_explicit_oauth_selection_switches_mode(self) -> None:
        action = {"protocol": PROTOCOL_GET, "credential_id": "gh"}
        plan = resolve_action_credential([self.token, self.github], action)
        self.assertEqual(plan.mode, "oauth")

    def test_unknown_explicit_id_falls_back_to_priority(self) -> None:
        action = {"protocol": PROTOCOL_AUTO, "credential_id": "gone"}
        plan = resolve_action_credential([self.token], action)
        self.assertEqual(plan.credential["id"], "tk")


class ActionNormalizationTests(unittest.TestCase):
    def test_blank_protocol_means_follow_the_framework(self) -> None:
        for value in ("", None, "follow", "framework", "nonsense"):
            self.assertEqual(normalize_protocol(value, allow_oauth=True), PROTOCOL_AUTO)

    def test_oauth_is_rejected_for_balance_actions(self) -> None:
        self.assertEqual(normalize_protocol(PROTOCOL_OAUTH, allow_oauth=False), PROTOCOL_AUTO)
        self.assertEqual(normalize_protocol(PROTOCOL_OAUTH, allow_oauth=True), PROTOCOL_OAUTH)

    def test_path_gets_a_leading_slash(self) -> None:
        self.assertEqual(normalize_path("api/user/checkin"), "/api/user/checkin")

    def test_absolute_urls_are_left_alone(self) -> None:
        self.assertEqual(normalize_path("https://other.test/x"), "https://other.test/x")

    def test_blank_path_stays_blank(self) -> None:
        self.assertEqual(normalize_path("   "), "")
        self.assertEqual(normalize_path(None), "")

    def test_action_defaults(self) -> None:
        action = normalize_action(None, allow_oauth=True)
        self.assertEqual(
            action,
            {
                "path": "",
                "protocol": PROTOCOL_AUTO,
                "credential_id": "",
                "headers": [],
                "solve_acw_sc_v2": False,
            },
        )

    def test_action_normalizes_every_field(self) -> None:
        action = normalize_action(
            {
                "path": "sign",
                "protocol": "POST",
                "credential_id": " tk ",
                "headers": "X-A: 1",
                "solve_acw_sc_v2": 1,
            },
            allow_oauth=True,
        )
        self.assertEqual(action["path"], "/sign")
        self.assertEqual(action["protocol"], PROTOCOL_POST)
        self.assertEqual(action["credential_id"], "tk")
        self.assertEqual(action["headers"], [{"key": "X-A", "value": "1"}])
        self.assertTrue(action["solve_acw_sc_v2"])


class SiteTypeTests(unittest.TestCase):
    def test_known_types_pass_through(self) -> None:
        self.assertEqual(normalize_site_type("new-api"), SITE_TYPE_NEW_API)
        self.assertEqual(normalize_site_type("generic_rest"), SITE_TYPE_GENERIC)

    def test_legacy_aliases_keep_their_adapter(self) -> None:
        self.assertEqual(normalize_site_type("one-api"), SITE_TYPE_NEW_API)
        self.assertEqual(normalize_site_type("generic"), SITE_TYPE_GENERIC)
        self.assertEqual(normalize_site_type("custom"), SITE_TYPE_GENERIC)

    def test_unknown_type_defaults_to_new_api(self) -> None:
        self.assertEqual(normalize_site_type("mystery"), SITE_TYPE_NEW_API)
        self.assertEqual(normalize_site_type(None), SITE_TYPE_NEW_API)


class NewApiUserProbeTests(unittest.TestCase):
    def test_probes_new_api_sites_following_the_framework(self) -> None:
        site = {"type": "new-api"}
        self.assertTrue(wants_new_api_user_probe(site, {"protocol": PROTOCOL_AUTO}))

    def test_skips_generic_sites(self) -> None:
        self.assertFalse(
            wants_new_api_user_probe({"type": "generic_rest"}, {"protocol": PROTOCOL_AUTO})
        )

    def test_skips_explicit_protocols(self) -> None:
        site = {"type": "new-api"}
        self.assertFalse(wants_new_api_user_probe(site, {"protocol": PROTOCOL_GET}))

    def test_skips_when_the_header_is_already_set(self) -> None:
        site = {"type": "new-api"}
        action = {"protocol": PROTOCOL_AUTO, "headers": [{"key": NEW_API_USER_HEADER, "value": "7"}]}
        self.assertFalse(wants_new_api_user_probe(site, action))

    def test_probes_when_the_header_is_blank(self) -> None:
        site = {"type": "new-api"}
        action = {"protocol": PROTOCOL_AUTO, "headers": [{"key": NEW_API_USER_HEADER, "value": " "}]}
        self.assertTrue(wants_new_api_user_probe(site, action))

    def test_rejects_malformed_input(self) -> None:
        self.assertFalse(wants_new_api_user_probe(None, {}))
        self.assertFalse(wants_new_api_user_probe({"type": "new-api"}, None))


if __name__ == "__main__":
    unittest.main()
