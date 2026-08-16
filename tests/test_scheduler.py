"""Regression tests for scheduler result persistence."""

from __future__ import annotations

import copy
import unittest
from datetime import datetime
from typing import Any

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


class SchedulerPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_merges_result_into_latest_site_configuration(self) -> None:
        plugin = _FakePlugin(
            [
                {"id": "site-1", "name": "edited while checking in"},
                {"id": "site-2", "name": "untouched"},
            ]
        )
        scheduler = CheckInScheduler(plugin)
        result = CheckInResult("site-1", "site-1", True, "ok", total_quota=12.5)
        checked_at = datetime(2026, 8, 16, 12, 34, 56)

        await scheduler._persist_checkin_results(
            [result], True, [result], checked_at
        )

        assert plugin.saved_sites is not None
        self.assertEqual(plugin.saved_sites[0]["name"], "edited while checking in")
        self.assertEqual(plugin.saved_sites[0]["last_checkin_date"], "2026-08-16")
        self.assertEqual(plugin.saved_sites[0]["last_checkin_time"], "12:34:56")
        self.assertEqual(plugin.saved_sites[0]["last_quota"], 12.5)
        self.assertNotIn("last_checkin_date", plugin.saved_sites[1])

    async def test_persists_checked_in_site_without_an_id(self) -> None:
        plugin = _FakePlugin([{"name": "legacy site"}])
        scheduler = CheckInScheduler(plugin)
        result = CheckInResult("", "legacy site", False, "failed")
        checked_at = datetime(2026, 8, 16, 13, 0, 0)

        await scheduler._persist_checkin_results(
            [result], False, [result], checked_at
        )

        assert plugin.saved_sites is not None
        self.assertEqual(plugin.saved_sites[0]["last_checkin_date"], "2026-08-16")
        self.assertEqual(plugin.saved_sites[0]["last_checkin_time"], "13:00:00")
        self.assertFalse(plugin.saved_sites[0]["last_checkin_success"])


if __name__ == "__main__":
    unittest.main()
