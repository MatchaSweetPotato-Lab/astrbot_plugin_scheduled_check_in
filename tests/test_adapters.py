"""Regression tests for balance-aware check-in adapters."""

from __future__ import annotations

import json
import unittest

import tests  # noqa: F401
from core.adapters import (
    MAX_ATTEMPT_SUMMARY_CHARS,
    MAX_ATTEMPTS_PER_RUN,
    NewApiAdapter,
    _TextResponse,
)


class _FakeSession:
    impersonate = "chrome131"


class AdapterBalanceTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _make_adapter() -> NewApiAdapter:
        return NewApiAdapter(
            {
                "id": "site-1",
                "name": "Test site",
                "base_url": "https://site.test",
                "auth_type": "bearer_token",
                "auth_value": "token",
                "proxy": "",
                "solve_acw_sc_v2": False,
                "custom_headers": "",
                "checkin_endpoint": "/api/user/checkin",
            },
            _FakeSession(),
        )

    async def test_final_balance_failure_keeps_known_initial_balance(self) -> None:
        """Do not overwrite a confirmed balance with zero after a failed recheck."""
        adapter = self._make_adapter()
        responses = iter(
            [
                _TextResponse(
                    status=200,
                    text=json.dumps({"success": True, "data": {"quota": 5_000_000}}),
                ),
                _TextResponse(
                    status=200,
                    text=json.dumps({"success": True, "message": "签到成功"}),
                ),
                _TextResponse(status=503, text="service unavailable"),
            ]
        )

        async def fake_request_text(method: str, url: str, headers: dict[str, str]) -> _TextResponse:
            del method, url, headers
            return next(responses)

        adapter._request_text = fake_request_text  # type: ignore[method-assign]

        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertFalse(result.expired)
        self.assertEqual(result.total_quota, 10.0)
        self.assertEqual(result.gained_quota, 0.0)
        self.assertIn("查询最终余额", result.error_detail)

    async def test_attempt_trace_is_bounded(self) -> None:
        """Keep repeated endpoint failures from growing one history record forever."""
        adapter = self._make_adapter()
        attempts: list[dict[str, object]] = []

        for index in range(MAX_ATTEMPTS_PER_RUN * 2):
            adapter._record_attempt(
                attempts,
                step=f"attempt-{index}",
                method="GET",
                endpoint="https://site.test/api/user/checkin",
                message="x" * 1000,
                response_text="y" * 10000,
            )

        self.assertEqual(len(attempts), MAX_ATTEMPTS_PER_RUN)
        self.assertTrue(attempts[-1].get("truncated"))
        self.assertLessEqual(
            len(adapter._format_attempts(attempts)),
            MAX_ATTEMPT_SUMMARY_CHARS,
        )


if __name__ == "__main__":
    unittest.main()
