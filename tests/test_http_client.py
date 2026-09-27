"""Regression tests for the shared curl_cffi HTTP session configuration."""

from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

import tests  # noqa: F401
from curl_cffi import requests as curl_requests

from core import http_client
from core.http_client import (
    DEFAULT_IMPERSONATE,
    MLDSA_ADDED,
    MLDSA_NATIVE,
    MLDSA_NOT_CHROMIUM,
    MLDSA_OLD_BUILD,
    MLDSA_SIGNATURE_ALGORITHMS,
    create_client_session,
    fingerprint_label,
    get_impersonate_options,
    mldsa_extra_fp,
    mldsa_support,
)

CHROMIUM_ALGORITHMS = list(http_client._CHROMIUM_SIGNATURE_ALGORITHMS)
MLDSA = list(MLDSA_SIGNATURE_ALGORITHMS)


class HttpClientConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_chrome150_and_shared_transport_settings(self) -> None:
        session = create_client_session(
            {
                "http_ssl_verify": False,
                "http_timeout_seconds": 999,
            }
        )
        try:
            self.assertEqual(DEFAULT_IMPERSONATE, "chrome150")
            self.assertEqual(session.impersonate, DEFAULT_IMPERSONATE)
            self.assertFalse(session.verify)
            self.assertEqual(session.timeout, 300.0)
            self.assertTrue(session.trust_env)
        finally:
            await session.close()

    async def test_uses_configured_fingerprint_from_curl_cffi_options(self) -> None:
        options = get_impersonate_options()
        self.assertIn(DEFAULT_IMPERSONATE, options)
        self.assertEqual(options[0], DEFAULT_IMPERSONATE)

        session = create_client_session({"http_impersonate": "chrome120"})
        try:
            self.assertEqual(session.impersonate, "chrome120")
        finally:
            await session.close()

    async def test_invalid_fingerprint_falls_back_to_default(self) -> None:
        session = create_client_session({"http_impersonate": "not-a-browser"})
        try:
            self.assertEqual(session.impersonate, DEFAULT_IMPERSONATE)
        finally:
            await session.close()

    async def test_normalizes_fingerprint_case_and_whitespace(self) -> None:
        session = create_client_session({"http_impersonate": "  CHROME120  "})
        try:
            self.assertEqual(session.impersonate, "chrome120")
        finally:
            await session.close()

    async def test_tls_verification_fails_closed_for_non_boolean_values(self) -> None:
        for value in ("true", 1):
            session = create_client_session({"http_ssl_verify": value})
            try:
                self.assertTrue(session.verify)
            finally:
                await session.close()


class MldsaOptionTests(unittest.TestCase):
    """Which fingerprints the ML-DSA option touches, and how."""

    def test_chrome_before_150_gets_it_added(self) -> None:
        for profile in ("chrome131", "chrome146", "chrome133a", "chrome131_android", "edge101"):
            self.assertEqual(mldsa_support(profile), MLDSA_ADDED, profile)

    def test_chrome_150_already_carries_it(self) -> None:
        self.assertEqual(mldsa_support("chrome150"), MLDSA_NATIVE)

    def test_other_browsers_are_left_alone(self) -> None:
        """Real Firefox and Safari send no ML-DSA; adding it would match no browser."""
        for profile in ("firefox133", "safari2601", "safari18_0", "tor145", ""):
            self.assertEqual(mldsa_support(profile), MLDSA_NOT_CHROMIUM, profile)

    def test_the_override_puts_ml_dsa_in_front_of_chromes_own_list(self) -> None:
        extra_fp = mldsa_extra_fp("chrome131", True)
        self.assertEqual(extra_fp, {"tls_signature_algorithms": MLDSA + CHROMIUM_ALGORITHMS})

    def test_nothing_changes_unless_asked_and_applicable(self) -> None:
        self.assertIsNone(mldsa_extra_fp("chrome131", False))
        self.assertIsNone(mldsa_extra_fp("chrome150", True))
        self.assertIsNone(mldsa_extra_fp("firefox133", True))

    def test_builds_that_reject_the_names_never_get_them(self) -> None:
        """curl_cffi 0.15 fails the whole request on an unknown algorithm name."""
        with mock.patch.object(http_client, "_MLDSA_BUILD", False):
            self.assertEqual(mldsa_support("chrome131"), MLDSA_OLD_BUILD)
            self.assertIsNone(mldsa_extra_fp("chrome131", True))

    def test_the_label_marks_only_an_added_ml_dsa(self) -> None:
        self.assertEqual(fingerprint_label("chrome131", True), "chrome131+ML-DSA")
        self.assertEqual(fingerprint_label("chrome131", False), "chrome131")
        self.assertEqual(fingerprint_label("chrome150", True), "chrome150")
        self.assertEqual(fingerprint_label("safari184", True), "safari184")


# ----------------------------------------------------------------------
# What actually goes on the wire
# ----------------------------------------------------------------------
_SIGNATURE_ALGORITHM_NAMES = {
    0x0403: "ecdsa_secp256r1_sha256",
    0x0804: "rsa_pss_rsae_sha256",
    0x0401: "rsa_pkcs1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0805: "rsa_pss_rsae_sha384",
    0x0501: "rsa_pkcs1_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0601: "rsa_pkcs1_sha512",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
}
_SIGNATURE_ALGORITHMS_EXTENSION = 13


def _read_exact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise AssertionError("the client hung up before sending a whole ClientHello")
        data += chunk
    return data


def _client_hello(impersonate: str, extra_fp: dict | None = None) -> bytes:
    """Capture the ClientHello curl_cffi sends, over loopback.

    Nothing answers it: the listener reads the first TLS record and hangs up,
    and the request fails, as intended.
    """
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        url = f"https://127.0.0.1:{server.getsockname()[1]}/"

        def attempt() -> None:
            try:
                # An empty proxy keeps curl off any proxy set in the environment.
                curl_requests.get(url, impersonate=impersonate, extra_fp=extra_fp,
                                  proxies={"all": ""}, verify=False, timeout=10)
            except Exception:
                pass

        client = threading.Thread(target=attempt, daemon=True)
        client.start()
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(10)
                header = _read_exact(conn, 5)
                return _read_exact(conn, int.from_bytes(header[3:5], "big"))
        finally:
            client.join(10)


def _extensions(hello: bytes) -> tuple[list[int], dict[int, bytes]]:
    """Split a ClientHello handshake message into cipher suites and extensions."""
    position = 4 + 2 + 32  # handshake header, legacy version, random
    position += 1 + hello[position]  # session id
    suites_length = int.from_bytes(hello[position:position + 2], "big")
    suites = [int.from_bytes(hello[position + 2 + i:position + 4 + i], "big")
              for i in range(0, suites_length, 2)]
    position += 2 + suites_length
    position += 1 + hello[position]  # compression methods
    end = position + 2 + int.from_bytes(hello[position:position + 2], "big")
    position += 2
    extensions: dict[int, bytes] = {}
    while position < end:
        kind = int.from_bytes(hello[position:position + 2], "big")
        length = int.from_bytes(hello[position + 2:position + 4], "big")
        extensions[kind] = hello[position + 4:position + 4 + length]
        position += 4 + length
    return suites, extensions


def _signature_algorithms(hello: bytes) -> list[str]:
    body = _extensions(hello)[1][_SIGNATURE_ALGORITHMS_EXTENSION][2:]
    codes = (int.from_bytes(body[i:i + 2], "big") for i in range(0, len(body), 2))
    return [_SIGNATURE_ALGORITHM_NAMES.get(code, hex(code)) for code in codes]


def _without_grease(values: list[int] | set[int]) -> set[int]:
    return {value for value in values if (value & 0x0F0F) != 0x0A0A}


class ClientHelloTests(unittest.TestCase):
    """The override against the ClientHellos the installed curl_cffi sends.

    It replaces the whole signature-algorithm list, so the list it rebuilds has
    to be exactly what the Chrome profiles send — this is where a curl_cffi
    upgrade that changes them would show.
    """

    def test_every_chromium_profile_sends_the_list_the_override_rebuilds(self) -> None:
        chromium = [option for option in get_impersonate_options()
                    if mldsa_support(option) in (MLDSA_ADDED, MLDSA_NATIVE)]
        self.assertIn("chrome131", chromium)
        for profile in chromium:
            expected = CHROMIUM_ALGORITHMS
            if mldsa_support(profile) == MLDSA_NATIVE:
                expected = MLDSA + CHROMIUM_ALGORITHMS
            with self.subTest(profile=profile):
                self.assertEqual(_signature_algorithms(_client_hello(profile)), expected)

    def test_the_option_puts_ml_dsa_on_the_wire(self) -> None:
        hello = _client_hello("chrome131", mldsa_extra_fp("chrome131", True))
        self.assertEqual(_signature_algorithms(hello), MLDSA + CHROMIUM_ALGORITHMS)

    def test_the_rest_of_the_handshake_is_left_alone(self) -> None:
        plain_suites, plain = _extensions(_client_hello("chrome131"))
        suites, altered = _extensions(_client_hello("chrome131", mldsa_extra_fp("chrome131", True)))
        self.assertEqual(_without_grease(suites), _without_grease(plain_suites))
        self.assertEqual(_without_grease(set(altered)), _without_grease(set(plain)))


if __name__ == "__main__":
    unittest.main()
