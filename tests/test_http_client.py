"""Regression tests for the shared curl_cffi HTTP session configuration."""

from __future__ import annotations

import unittest

import tests  # noqa: F401
from core.http_client import (
    DEFAULT_IMPERSONATE,
    create_client_session,
    get_impersonate_options,
)


class HttpClientConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_chrome131_and_shared_transport_settings(self) -> None:
        session = create_client_session(
            {
                "http_ssl_verify": False,
                "http_timeout_seconds": 999,
            }
        )
        try:
            self.assertEqual(DEFAULT_IMPERSONATE, "chrome131")
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

if __name__ == "__main__":
    unittest.main()
