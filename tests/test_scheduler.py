"""Regression tests for scheduler result persistence."""

from __future__ import annotations

import copy
import unittest
from datetime import datetime
from typing import Any

import tests  # noqa: F401
from core.adapters import CheckInResult
from core.scheduler import CheckInScheduler


class _FakePlugin:
    def __init__(self, sites: list[dict[str, Any]]) -> None:
        self.sites = copy.deepcopy(sites)
        self.saved_sites: list[dict[str, Any]] | None = None
        self.history: list[tuple[list[CheckInResult], str]] = []

    def get_sites(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.sites)

    def save_sites(self, sites: list[dict[str, Any]]) -> None:
        self.saved_sites = copy.deepcopy(sites)
        self.sites = copy.deepcopy(sites)

    def record_history(self, results: list[CheckInResult], log_type: str) -> None:
        self.history.append((results, log_type))


class _PluginWithDirectUpdate:
    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []
        self.history: list[tuple[list[CheckInResult], str]] = []

    def update_site_checkin_state(
        self,
        site_id: str,
        last_checkin_date: str,
        last_checkin_time: str,
        last_checkin_success: bool,
        last_quota: float | None = None,
    ) -> None:
        self.updates.append({
            "site_id": site_id,
            "last_checkin_date": last_checkin_date,
            "last_checkin_time": last_checkin_time,
            "last_checkin_success": last_checkin_success,
            "last_quota": last_quota,
        })

    def record_history(self, results: list[CheckInResult], log_type: str) -> None:
        self.history.append((results, log_type))


class SchedulerPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_update_site_checkin_state_called(self) -> None:
        plugin = _PluginWithDirectUpdate()
        scheduler = CheckInScheduler(plugin)
        result = CheckInResult("site-123", "Site 123", True, "ok", total_quota=88.8)
        checked_at = datetime(2026, 8, 16, 15, 30, 0)

        await scheduler._persist_checkin_results(
            [result],
            True,
            [result],
            checked_at,
        )

        self.assertEqual(len(plugin.updates), 1)
        self.assertEqual(plugin.updates[0]["site_id"], "site-123")
        self.assertEqual(plugin.updates[0]["last_checkin_date"], "2026-08-16")
        self.assertEqual(plugin.updates[0]["last_checkin_time"], "15:30:00")
        self.assertEqual(plugin.updates[0]["last_checkin_success"], True)
        self.assertEqual(plugin.updates[0]["last_quota"], 88.8)
        self.assertEqual(len(plugin.history), 1)

    async def test_merges_result_into_latest_site_configuration(self) -> None:
        plugin = _FakePlugin(
            [
                {
                    "id": "site-1",
                    "name": "edited while checking in",
                    "type": "new-api",
                    "base_url": "https://site-1.test",
                    "auth_type": "bearer_token",
                    "auth_value": "token-1",
                    "checkin_endpoint": "",
                    "proxy": "",
                    "custom_headers": "",
                    "enabled": True,
                    "solve_acw_sc_v2": False,
                },
                {
                    "id": "site-2",
                    "name": "untouched",
                    "type": "new-api",
                    "base_url": "https://site-2.test",
                    "auth_type": "bearer_token",
                    "auth_value": "token-2",
                    "checkin_endpoint": "",
                    "proxy": "",
                    "custom_headers": "",
                    "enabled": True,
                    "solve_acw_sc_v2": False,
                },
            ]
        )
        scheduler = CheckInScheduler(plugin)
        result = CheckInResult("site-1", "site-1", True, "ok", total_quota=12.5)
        checked_at = datetime(2026, 8, 16, 12, 34, 56)

        await scheduler._persist_checkin_results(
            [result],
            True,
            [result],
            checked_at,
        )

        self.assertIsNotNone(plugin.saved_sites)
        self.assertEqual(plugin.saved_sites[0]["name"], "edited while checking in")
        self.assertEqual(plugin.saved_sites[0]["last_checkin_date"], "2026-08-16")
        self.assertEqual(plugin.saved_sites[0]["last_checkin_time"], "12:34:56")
        self.assertEqual(plugin.saved_sites[0]["last_quota"], 12.5)
        self.assertNotIn("last_checkin_date", plugin.saved_sites[1])

    async def test_skips_sites_and_results_without_ids(self) -> None:
        plugin = _FakePlugin(
            [
                {
                    "name": "site",
                    "enabled": True,
                },
                {
                    "id": "site-1",
                    "name": "valid site",
                },
            ]
        )
        scheduler = CheckInScheduler(plugin)
        result = CheckInResult("", "unknown site", True, "ok")

        with self.assertLogs("astrbot", level="WARNING") as logs:
            await scheduler._persist_checkin_results(
                [result], True, [result], datetime(2026, 8, 16, 12, 34, 56)
            )

        self.assertIsNone(plugin.saved_sites)
        self.assertTrue(any("without an ID" in message for message in logs.output))

if __name__ == "__main__":
    unittest.main()
