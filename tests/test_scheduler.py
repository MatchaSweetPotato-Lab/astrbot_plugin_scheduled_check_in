"""Regression tests for scheduler result persistence."""

from __future__ import annotations

import copy
import unittest
from datetime import datetime
from typing import Any

import tests  # noqa: F401
from core.adapters import CheckInResult, SiteWriteback
from core.scheduler import LOCKED_MESSAGE, CheckInScheduler


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
                    "proxy": "",
                    "credentials": [{"id": "c1", "type": "token", "value": "token-1"}],
                    "checkin": {},
                    "balance": {},
                    "enabled": True,
                },
                {
                    "id": "site-2",
                    "name": "untouched",
                    "type": "new-api",
                    "base_url": "https://site-2.test",
                    "proxy": "",
                    "credentials": [{"id": "c1", "type": "token", "value": "token-2"}],
                    "checkin": {},
                    "balance": {},
                    "enabled": True,
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


class _LockedPlugin:
    """Plugin whose configuration is encrypted and still locked."""

    def __init__(self, sites: list[dict[str, Any]] | None = None) -> None:
        self.sites = copy.deepcopy(sites or [])
        self.history: list[tuple[list[CheckInResult], str]] = []

    def get_sites(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.sites)

    def get_settings(self) -> dict[str, Any]:
        return {}

    def record_history(self, results: list[CheckInResult], log_type: str) -> None:
        self.history.append((results, log_type))

    def is_config_locked(self) -> bool:
        return True


class LockedVaultTests(unittest.IsolatedAsyncioTestCase):
    async def test_scheduled_run_skips_every_site(self) -> None:
        """The task still fires so the skip is visible, but nothing is requested."""
        plugin = _LockedPlugin([{"id": "s1", "name": "Site", "enabled": True}])
        scheduler = CheckInScheduler(plugin)

        with self.assertLogs("astrbot", level="WARNING"):
            results = await scheduler.run_check_in_all(manual=False)

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].success)
        self.assertEqual(results[0].message, LOCKED_MESSAGE)

    async def test_skipped_run_is_recorded_in_history(self) -> None:
        plugin = _LockedPlugin()
        scheduler = CheckInScheduler(plugin)

        with self.assertLogs("astrbot", level="WARNING"):
            await scheduler.run_check_in_all(manual=False)

        self.assertEqual(len(plugin.history), 1)
        self.assertEqual(plugin.history[0][1], "scheduled")

    async def test_manual_run_is_tagged_as_manual(self) -> None:
        plugin = _LockedPlugin()
        scheduler = CheckInScheduler(plugin)

        with self.assertLogs("astrbot", level="WARNING"):
            await scheduler.run_check_in_all(manual=True)

        self.assertEqual(plugin.history[0][1], "manual")

    async def test_single_site_run_reports_the_lock(self) -> None:
        plugin = _LockedPlugin([{"id": "s1", "name": "Site", "enabled": True}])
        scheduler = CheckInScheduler(plugin)
        result = await scheduler.run_check_in_site("s1")
        self.assertIsNotNone(result)
        self.assertFalse(result.success)
        self.assertEqual(result.message, LOCKED_MESSAGE)

    async def test_report_names_the_lock(self) -> None:
        plugin = _LockedPlugin()
        scheduler = CheckInScheduler(plugin)
        with self.assertLogs("astrbot", level="WARNING"):
            results = await scheduler.run_check_in_all()
        self.assertIn(LOCKED_MESSAGE, CheckInScheduler.format_report(results))

    async def test_a_plugin_without_the_hook_is_treated_as_unlocked(self) -> None:
        """Older plugin objects must not be blocked by a missing method."""
        plugin = _FakePlugin([])
        scheduler = CheckInScheduler(plugin)
        self.assertFalse(scheduler._is_locked())


class WritebackPersistenceTests(unittest.TestCase):
    class _Db:
        def __init__(self) -> None:
            self.headers: list[tuple] = []
            self.sessions: list[tuple] = []

        def update_action_headers(self, site_id, action, headers):
            self.headers.append((site_id, action, headers))
            return True

        def update_credential_session(self, site_id, credential_id, cookie):
            self.sessions.append((site_id, credential_id, cookie))
            return True

    class _Adapter:
        def __init__(self, writeback) -> None:
            self.writeback = writeback

    def test_persists_discovered_config(self) -> None:
        plugin = _FakePlugin([])
        plugin.db = self._Db()
        scheduler = CheckInScheduler(plugin)
        writeback = SiteWriteback(
            checkin_headers=[{"key": "new-api-user", "value": "7"}],
            oauth_sessions={"gh": "session=a"},
        )
        scheduler._persist_site_writeback("s1", self._Adapter(writeback))
        self.assertEqual(plugin.db.headers, [("s1", "checkin", [{"key": "new-api-user", "value": "7"}])])
        self.assertEqual(plugin.db.sessions, [("s1", "gh", "session=a")])

    def test_skips_a_blank_site_id(self) -> None:
        plugin = _FakePlugin([])
        plugin.db = self._Db()
        scheduler = CheckInScheduler(plugin)
        scheduler._persist_site_writeback("", self._Adapter(SiteWriteback(checkin_headers=[])))
        self.assertEqual(plugin.db.headers, [])

    def test_tolerates_a_plugin_without_a_database(self) -> None:
        scheduler = CheckInScheduler(_FakePlugin([]))
        scheduler._persist_site_writeback("s1", self._Adapter(SiteWriteback(checkin_headers=[])))


if __name__ == "__main__":
    unittest.main()
