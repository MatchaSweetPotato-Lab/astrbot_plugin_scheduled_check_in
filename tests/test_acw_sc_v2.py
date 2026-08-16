"""Regression tests for the pure-Python acw_sc__v2 challenge flow."""

from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import tests  # noqa: F401
from core.acw_sc_v2 import (
    AcwScV2Error,
    AcwScV2SolverCache,
    is_acw_sc_v2_challenge,
    translate_acw_sc_v2,
)
from core.adapters import GenericRestAdapter

ARG1 = "E516FCBA86E9AA50575BDFB0211588E628A0053F"
PERMUTATION = (
    15, 35, 29, 24, 33, 16, 1, 38, 10, 9,
    19, 31, 40, 27, 22, 23, 25, 13, 6, 11,
    39, 18, 20, 8, 14, 21, 32, 26, 2, 30,
    7, 4, 17, 5, 3, 28, 34, 37, 12, 36,
)
ENCODED_XOR_KEY = "mZaWmde3nJaWmdG1nJaWnJa2mtuWmtuZmZaWmZy5mdaYnZGWmdm3nq"
EXPECTED_COOKIE = "6a80378568db91fd2cdb36e99d6231b6789583e5"
STANDARD_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
CUSTOM_BASE64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="


def encode_custom_base64(value: str) -> str:
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.translate(str.maketrans(STANDARD_BASE64, CUSTOM_BASE64)).rstrip("=")


def make_challenge(
    arg1: str = ARG1,
    encoded_key: str = ENCODED_XOR_KEY,
    include_decoys: bool = False,
) -> str:
    permutation = ",".join(hex(value) for value in PERMUTATION)
    decoys = ""
    if include_decoys:
        decoy_permutation = ",".join(str(value) for value in range(40, 0, -1))
        decoys = f"""
var decoyPermutation=[{decoy_permutation}];
var decoyKey='1111111111111111111111111111111111111111';
"""
    return f"""<html><script>
var arg1='{arg1}';
{decoys}
function decodeKey(value) {{
  var alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
  return value;
}}
var permutation=[{permutation}];
var xorKey=decodeKey('{encoded_key}');
var reordered=[];
var joined='';
var cookieValue='';
for(var sourceIndex=0;sourceIndex<arg1.length;sourceIndex++){{
  var character=arg1[sourceIndex];
  for(var slot=0;slot<permutation.length;slot++){{
    permutation[slot]===sourceIndex+1&&(reordered[slot]=character);
  }}
}}
joined=reordered.join('');
for(var index=0;index<joined.length&&index<xorKey.length;index+=2){{
  var byte=(parseInt(joined.slice(index,index+2),16)^parseInt(xorKey.slice(index,index+2),16)).toString(16);
  if(byte.length===1) byte='0'+byte;
  cookieValue+=byte;
}}
document.cookie='acw_sc__v2='+cookieValue;
</script></html>"""


class AcwScV2TranslationTests(unittest.TestCase):
    def test_translates_obfuscated_key_and_solves_expected_cookie(self) -> None:
        challenge = make_challenge()
        self.assertTrue(is_acw_sc_v2_challenge(challenge))

        arg1, algorithm, source = translate_acw_sc_v2(challenge)
        self.assertEqual(arg1, ARG1)
        self.assertEqual(algorithm.permutation, PERMUTATION)
        self.assertEqual(algorithm.xor_key, "3000176000856006061501533003690027800375")
        self.assertIn("def solve_acw_sc_v2(arg1):", source)

        solution = AcwScV2SolverCache().solve(challenge)
        self.assertEqual(solution.cookie_value, EXPECTED_COOKIE)

    def test_rejects_an_unknown_algorithm_shape(self) -> None:
        challenge = make_challenge().replace("parseInt", "Number")
        with self.assertRaises(AcwScV2Error):
            translate_acw_sc_v2(challenge)

    def test_uses_only_constants_linked_to_the_cookie_dataflow(self) -> None:
        challenge = make_challenge(include_decoys=True)

        _, algorithm, _ = translate_acw_sc_v2(challenge)
        solution = AcwScV2SolverCache().solve(challenge)

        self.assertEqual(algorithm.permutation, PERMUTATION)
        self.assertEqual(algorithm.xor_key, "3000176000856006061501533003690027800375")
        self.assertEqual(solution.cookie_value, EXPECTED_COOKIE)

    def test_rejects_constants_without_a_verified_cookie_dataflow(self) -> None:
        permutation = ",".join(hex(value) for value in PERMUTATION)
        challenge = f"""<html><script>
var arg1='{ARG1}';
var permutation=[{permutation}];
var xorKey='{ENCODED_XOR_KEY}';
var result=(parseInt(arg1.slice(0,2),16)^parseInt(xorKey.slice(0,2),16));
document.cookie='acw_sc__v2='+result;
</script></html>"""

        with self.assertRaises(AcwScV2Error):
            translate_acw_sc_v2(challenge)

    def test_persistent_cache_is_not_rewritten_for_same_algorithm(self) -> None:
        with TemporaryDirectory() as temp_dir:
            cache_file = Path(temp_dir) / "acw_sc_v2_cache.json"
            first = AcwScV2SolverCache(cache_file).solve(make_challenge())
            first_bytes = cache_file.read_bytes()

            second_arg1 = "0123456789ABCDEF0123456789ABCDEF01234567"
            second = AcwScV2SolverCache(cache_file).solve(make_challenge(second_arg1))

            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(first.algorithm_fingerprint, second.algorithm_fingerprint)
            self.assertEqual(cache_file.read_bytes(), first_bytes)
            cache_data = json.loads(first_bytes)
            self.assertEqual(len(cache_data["algorithms"]), 1)

    def test_algorithm_change_creates_a_new_cached_translation(self) -> None:
        changed_key = "1000176000856006061501533003690027800375"
        changed_challenge = make_challenge(encoded_key=encode_custom_base64(changed_key))

        with TemporaryDirectory() as temp_dir:
            cache_file = Path(temp_dir) / "acw_sc_v2_cache.json"
            first = AcwScV2SolverCache(cache_file).solve(make_challenge())
            second = AcwScV2SolverCache(cache_file).solve(changed_challenge)
            cache_data = json.loads(cache_file.read_text(encoding="utf-8"))

            self.assertNotEqual(first.algorithm_fingerprint, second.algorithm_fingerprint)
            self.assertFalse(second.cache_hit)
            self.assertEqual(len(cache_data["algorithms"]), 2)


class _FakeResponse:
    def __init__(self, status: int, text: str, cookies: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.text = text
        self.cookies = cookies or {}


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[dict[str, object]] = []
        self.impersonate = "chrome131"

    async def request(self, method: str, url: str, **kwargs) -> _FakeResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


class ChallengeAwareRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_preserves_auth_cookie_and_retries_with_solved_waf_cookies(self) -> None:
        session = _FakeSession(
            [
                _FakeResponse(
                    200,
                    make_challenge(),
                    {"acw_tc": "tc-value", "cdn_sec_tc": "sec-value"},
                ),
                _FakeResponse(401, '{"success":false,"message":"unauthorized"}'),
            ]
        )
        config = {
            "id": "site-1",
            "name": "Example",
            "type": "generic",
            "base_url": "https://example.test",
            "checkin_endpoint": "/api/user/sign_in",
            "method": "GET",
            "auth_type": "cookie",
            "auth_value": "session=auth-value",
            "custom_headers": {"cookie": "custom=header-value"},
            "proxy": "",
            "solve_acw_sc_v2": True,
            "enabled": True,
        }

        with TemporaryDirectory() as temp_dir:
            adapter = GenericRestAdapter(
                config,
                session,  # type: ignore[arg-type]
                Path(temp_dir) / "cache.json",
            )
            result = await adapter.test_connection()

        self.assertFalse(result.success)
        self.assertEqual(result.message, 'HTTP 401: {"success":false,"message":"unauthorized"}')
        self.assertEqual(len(session.requests), 2)
        self.assertTrue(
            all(request["impersonate"] == "chrome131" for request in session.requests)
        )
        retry_headers = session.requests[1]["headers"]
        self.assertIsInstance(retry_headers, dict)
        cookie_headers = {
            str(name): str(value)
            for name, value in retry_headers.items()  # type: ignore[union-attr]
            if str(name).lower() == "cookie"
        }
        self.assertEqual(len(cookie_headers), 1)
        retry_cookie = next(iter(cookie_headers.values()))
        self.assertIn("session=auth-value", retry_cookie)
        self.assertIn("custom=header-value", retry_cookie)
        self.assertIn("acw_tc=tc-value", retry_cookie)
        self.assertIn("cdn_sec_tc=sec-value", retry_cookie)
        self.assertIn(f"acw_sc__v2={EXPECTED_COOKIE}", retry_cookie)

    async def test_string_success_cannot_override_failed_http_status(self) -> None:
        session = _FakeSession(
            [_FakeResponse(401, '{"success":"false","message":"unauthorized"}')]
        )
        config = {
            "id": "site-2",
            "name": "Example",
            "type": "generic",
            "base_url": "https://example.test",
            "checkin_endpoint": "/api/user/sign_in",
            "method": "GET",
            "auth_type": "bearer_token",
            "auth_value": "invalid-token",
            "custom_headers": "",
            "proxy": "",
            "solve_acw_sc_v2": False,
            "enabled": True,
        }
        adapter = GenericRestAdapter(config, session)  # type: ignore[arg-type]

        result = await adapter.test_connection()

        self.assertFalse(result.success)
        self.assertTrue(result.expired)


if __name__ == "__main__":
    unittest.main()
