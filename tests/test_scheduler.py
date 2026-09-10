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
    def __init__(self, sites: list[dict[str, Any]], settings: dict[str, Any] | None = None) -> None:
        self.sites = copy.deepcopy(sites)
        self.settings = copy.deepcopy(settings) if settings is not None else {}
        self.saved_sites: list[dict[str, Any]] | None = None
        self.history: list[tuple[list[CheckInResult], str]] = []
        self.notifications: list[tuple[str, str | None]] = []

    def get_sites(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self.sites)

    def get_settings(self) -> dict[str, Any]:
        return copy.deepcopy(self.settings)

    def save_sites(self, sites: list[dict[str, Any]]) -> None:
        self.saved_sites = copy.deepcopy(sites)
        self.sites = copy.deepcopy(sites)

    def record_history(self, results: list[CheckInResult], log_type: str) -> None:
        self.history.append((results, log_type))

    async def send_notification(self, text: str, session: str | None = None) -> None:
        self.notifications.append((text, session))


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


class HistoryEntryTests(unittest.TestCase):
    """A batch run is stored as one entry per site, not one aggregate entry."""

    TS = "2026-08-20 08:31:20"

    @staticmethod
    def _results() -> list[CheckInResult]:
        return [
            CheckInResult("s1", "站点 A", True, "额度增加 +$ 1.0", total_quota=12.5, gained_quota=1.0),
            CheckInResult("s2", "站点 B", False, "凭据已失效", expired=True),
            CheckInResult("s3", "站点 C", False, "请求超时"),
        ]

    def test_one_entry_per_site(self) -> None:
        entries = CheckInScheduler.build_history_entries(self._results(), "scheduled", self.TS)
        self.assertEqual(len(entries), 3)
        for entry in entries:
            self.assertEqual(len(entry["details"]), 1)

    def test_each_entry_holds_only_its_own_site(self) -> None:
        entries = CheckInScheduler.build_history_entries(self._results(), "scheduled", self.TS)
        ids = [entry["details"][0]["site_id"] for entry in entries]
        self.assertEqual(sorted(ids), ["s1", "s2", "s3"])
        for entry in entries:
            detail = entry["details"][0]
            self.assertIn(detail["site_name"], entry["report"])
            # No other site may leak into this entry's stored report.
            others = {"站点 A", "站点 B", "站点 C"} - {detail["site_name"]}
            for name in others:
                self.assertNotIn(name, entry["report"])

    def test_success_is_per_site_not_aggregated(self) -> None:
        entries = CheckInScheduler.build_history_entries(self._results(), "scheduled", self.TS)
        by_site = {e["details"][0]["site_id"]: e["success"] for e in entries}
        self.assertEqual(by_site, {"s1": True, "s2": False, "s3": False})

    def test_every_entry_shares_the_run_timestamp(self) -> None:
        entries = CheckInScheduler.build_history_entries(self._results(), "manual", self.TS)
        self.assertEqual({e["timestamp"] for e in entries}, {self.TS})

    def test_manual_flag_follows_the_log_type(self) -> None:
        for log_type, expected in (("manual", True), ("scheduled", False), ("test", False)):
            entries = CheckInScheduler.build_history_entries(self._results(), log_type, self.TS)
            self.assertTrue(all(e["manual"] is expected for e in entries), log_type)
            self.assertTrue(all(e["type"] == log_type for e in entries))

    def test_sites_read_in_check_order(self) -> None:
        """Rows share a timestamp and the drawer is newest-first, so they are
        stored reversed to read top-down in check order."""
        entries = CheckInScheduler.build_history_entries(self._results(), "scheduled", self.TS)
        self.assertEqual([e["details"][0]["site_id"] for e in entries], ["s3", "s2", "s1"])

    def test_no_results_yields_no_entries(self) -> None:
        self.assertEqual(CheckInScheduler.build_history_entries([], "scheduled", self.TS), [])

    def test_report_line_marks_each_outcome(self) -> None:
        ok, expired, failed = self._results()
        self.assertIn("[成功]", CheckInScheduler.format_result_line(ok))
        self.assertIn("+$1.00", CheckInScheduler.format_result_line(ok))
        self.assertIn("(余额: $12.50)", CheckInScheduler.format_result_line(ok))
        self.assertIn("[Token失效]", CheckInScheduler.format_result_line(expired))
        self.assertIn("[失败]", CheckInScheduler.format_result_line(failed))
        self.assertIn("请求超时", CheckInScheduler.format_result_line(failed))

    def test_report_line_omits_a_zero_balance(self) -> None:
        line = CheckInScheduler.format_result_line(self._results()[2])
        self.assertNotIn("余额", line)

    def test_report_line_cleans_raw_json_dumps(self) -> None:
        raw_json = 'HTTP 200: {"added":140,"balance":3520,"daily_checkin":{"enabled":true}}'
        res = CheckInResult("s_raw", "wisart", True, raw_json, total_quota=0.0, gained_quota=0.0)
        line = CheckInScheduler.format_result_line(res)
        self.assertEqual(line, "[成功] wisart | 签到成功")
        self.assertNotIn("HTTP 200", line)
        self.assertNotIn("daily_checkin", line)

    def test_clean_result_message_json_extracted_truncation(self) -> None:
        long_err = "A" * 100
        raw = json.dumps({"error": {"message": long_err}})
        cleaned = CheckInScheduler._clean_result_message(raw, success=False)
        self.assertTrue(cleaned.endswith("..."))
        self.assertEqual(len(cleaned), 80)
        self.assertEqual(cleaned, "A" * 77 + "...")

    def test_clean_result_message_plain_long_error_truncation(self) -> None:
        long_err = "Error: " + "X" * 100
        cleaned = CheckInScheduler._clean_result_message(long_err, success=False)
        self.assertTrue(cleaned.endswith("..."))
        self.assertEqual(len(cleaned), 80)

    def test_clean_result_message_html_failure(self) -> None:
        html = "<html><head><title>502 Bad Gateway</title></head><body><h1>502</h1></body></html>"
        cleaned = CheckInScheduler._clean_result_message(html, success=False)
        self.assertEqual(cleaned, "服务器返回异常网页内容")

    def test_clean_result_message_html_success(self) -> None:
        html = "<html><body>Welcome</body></html>"
        cleaned = CheckInScheduler._clean_result_message(html, success=True)
        self.assertEqual(cleaned, "签到成功")

    def test_the_broadcast_report_still_combines_every_site(self) -> None:
        """Splitting storage must not change the chat briefing."""
        report = CheckInScheduler.format_report(self._results())
        for name in ("站点 A", "站点 B", "站点 C"):
            self.assertIn(name, report)
        self.assertIn("完成统计: 1/3", report)
        self.assertIn("总余额估算: $12.50", report)

    def test_the_report_reuses_the_single_line_format(self) -> None:
        results = self._results()
        report = CheckInScheduler.format_report(results)
        for result in results:
            self.assertIn(CheckInScheduler.format_result_line(result), report)

    def test_format_report_failure_only_all_success(self) -> None:
        success_results = [
            CheckInResult("s1", "站点 A", True, "ok", total_quota=10.0, gained_quota=0.5),
            CheckInResult("s2", "站点 B", True, "ok", total_quota=5.0),
        ]
        report = CheckInScheduler.format_report(success_results, report_level="failure_only")
        self.assertEqual(report, "")

    def test_format_report_failure_only_with_failures(self) -> None:
        results = self._results()
        report = CheckInScheduler.format_report(results, report_level="failure_only")
        self.assertIn("异常提醒", report)
        self.assertIn("站点 B", report)
        self.assertIn("站点 C", report)
        self.assertNotIn("站点 A", report)
        self.assertIn("2 个签到失败", report)


class SchedulerNotificationDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_scheduled_dispatch_all_level(self) -> None:
        plugin = _FakePlugin(
            [],
            settings={"lock_notify_session": "test:FriendMessage:123", "report_level": "all"},
        )
        scheduler = CheckInScheduler(plugin)
        sample_results = [
            CheckInResult("s1", "站点 A", True, "ok", total_quota=10.0, gained_quota=0.5)
        ]
        async def _fake_run_check_in_all(manual: bool = False) -> list[CheckInResult]:
            return sample_results

        scheduler.run_check_in_all = _fake_run_check_in_all  # type: ignore[method-assign]

        # Simulate scheduled trigger logic
        results = await scheduler.run_check_in_all()
        settings = plugin.get_settings()
        report_level = settings.get("report_level", "all")
        report_session = str(settings.get("lock_notify_session") or "").strip()
        report_text = scheduler.format_report(results, report_level=report_level)
        if report_text:
            await plugin.send_notification(report_text, session=report_session)

        self.assertEqual(len(plugin.notifications), 1)
        self.assertEqual(plugin.notifications[0][1], "test:FriendMessage:123")
        self.assertIn("站点 A", plugin.notifications[0][0])

    async def test_scheduled_dispatch_failure_only_skips_success(self) -> None:
        plugin = _FakePlugin(
            [],
            settings={"lock_notify_session": "test:FriendMessage:123", "report_level": "failure_only"},
        )
        scheduler = CheckInScheduler(plugin)
        sample_results = [
            CheckInResult("s1", "站点 A", True, "ok", total_quota=10.0, gained_quota=0.5)
        ]
        async def _fake_run_check_in_all(manual: bool = False) -> list[CheckInResult]:
            return sample_results

        scheduler.run_check_in_all = _fake_run_check_in_all  # type: ignore[method-assign]

        results = await scheduler.run_check_in_all()
        settings = plugin.get_settings()
        report_level = settings.get("report_level", "all")
        report_session = str(settings.get("lock_notify_session") or "").strip()
        report_text = scheduler.format_report(results, report_level=report_level)
        if report_text:
            await plugin.send_notification(report_text, session=report_session)

        self.assertEqual(len(plugin.notifications), 0)


if __name__ == "__main__":
    unittest.main()
