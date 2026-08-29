"""Tests for the one-shot alert sent when the credential vault is locked."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tests  # noqa: F401
from core.lock_notifier import LOCK_ALERT_TEXT, LockNotifier
from core.scheduler import CheckInScheduler
from core.storage import LOCK_NOTIFY_SENT_KEY, DatabaseManager


class _FakeHost:
    """Stands in for the plugin, recording every push the notifier makes."""

    def __init__(self, *, locked: bool = True, target: str = "test:FriendMessage:1") -> None:
        self.locked = locked
        self.target = target
        self.sent_flag = False
        self.pushes: list[tuple[str, str]] = []
        # Delivery outcomes to hand back, one per push; the last value repeats.
        self.results: list[bool | Exception] = [True]
        # Persistence outcomes to hand back, one per state write; the last
        # value repeats.
        self.mark_results: list[bool | Exception] = [True]

    def build(self) -> LockNotifier:
        return LockNotifier(
            is_locked=lambda: self.locked,
            get_target=lambda: self.target,
            was_sent=lambda: self.sent_flag,
            mark_sent=self._mark_sent,
            send=self._send,
        )

    def _mark_sent(self, sent: bool) -> bool:
        outcome = (
            self.mark_results[0]
            if len(self.mark_results) == 1
            else self.mark_results.pop(0)
        )
        if isinstance(outcome, Exception):
            raise outcome
        if outcome:
            self.sent_flag = sent
        return outcome

    async def _send(self, session: str, text: str) -> bool:
        self.pushes.append((session, text))
        outcome = self.results[0] if len(self.results) == 1 else self.results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class LockNotifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_once_while_locked(self) -> None:
        """A locked vault produces exactly one push, however often we poll."""
        host = _FakeHost()
        notifier = host.build()

        for _ in range(5):
            await notifier.poll()

        self.assertEqual(len(host.pushes), 1)
        self.assertEqual(host.pushes[0], ("test:FriendMessage:1", LOCK_ALERT_TEXT))
        self.assertTrue(host.sent_flag)

    async def test_unlock_rearms_alert_for_the_next_lock(self) -> None:
        """Unlocking clears the flag so a later re-lock alerts again."""
        host = _FakeHost()
        notifier = host.build()

        await notifier.poll()
        host.locked = False
        await notifier.poll()
        self.assertFalse(host.sent_flag)

        host.locked = True
        await notifier.poll()

        self.assertEqual(len(host.pushes), 2)

    async def test_preset_flag_suppresses_alert_after_restart(self) -> None:
        """A flag persisted from a previous process is honoured."""
        host = _FakeHost()
        host.sent_flag = True
        notifier = host.build()

        await notifier.poll()

        self.assertEqual(host.pushes, [])

    async def test_empty_target_disables_alert(self) -> None:
        """No configured session means the feature is off."""
        host = _FakeHost(target="   ")
        notifier = host.build()

        await notifier.poll()

        self.assertEqual(host.pushes, [])
        self.assertFalse(host.sent_flag)

    async def test_target_is_trimmed(self) -> None:
        """A pasted session with stray whitespace still resolves."""
        host = _FakeHost(target="  test:FriendMessage:1\n")
        notifier = host.build()

        await notifier.poll()

        self.assertEqual(host.pushes[0][0], "test:FriendMessage:1")

    async def test_unlocked_vault_never_alerts(self) -> None:
        host = _FakeHost(locked=False)
        notifier = host.build()

        await notifier.poll()

        self.assertEqual(host.pushes, [])
        self.assertFalse(host.sent_flag)

    async def test_undelivered_push_is_retried(self) -> None:
        """A push no platform accepted does not consume the one allowance."""
        host = _FakeHost()
        host.results = [False, True]
        notifier = host.build()

        await notifier.poll()
        self.assertFalse(host.sent_flag)

        await notifier.poll()

        self.assertEqual(len(host.pushes), 2)
        self.assertTrue(host.sent_flag)

    async def test_send_exception_is_contained_and_retried(self) -> None:
        """An adapter blowing up is logged, not raised, and retried."""
        host = _FakeHost()
        host.results = [ValueError("不合法的 session 字符串"), True]
        notifier = host.build()

        await notifier.poll()
        self.assertFalse(host.sent_flag)

        await notifier.poll()

        self.assertEqual(len(host.pushes), 2)
        self.assertTrue(host.sent_flag)

    async def test_persistence_failure_does_not_repeat_delivery(self) -> None:
        """A delivered alert is not sent twice while its flag write retries."""
        host = _FakeHost()
        host.mark_results = [False, True]
        notifier = host.build()

        await notifier.poll()
        self.assertEqual(len(host.pushes), 1)
        self.assertFalse(host.sent_flag)

        await notifier.poll()
        self.assertEqual(len(host.pushes), 1)
        self.assertTrue(host.sent_flag)

        await notifier.poll()
        self.assertEqual(len(host.pushes), 1)

    async def test_target_change_rearms_current_process(self) -> None:
        """A committed target change allows a new target to alert immediately."""
        host = _FakeHost(target="test:FriendMessage:old")
        notifier = host.build()

        await notifier.poll()
        host.target = "test:FriendMessage:new"
        host.sent_flag = False  # The host transaction cleared the durable flag.
        notifier.rearm_after_target_change()

        await notifier.poll()

        self.assertEqual(
            [session for session, _ in host.pushes],
            ["test:FriendMessage:old", "test:FriendMessage:new"],
        )
        self.assertTrue(host.sent_flag)


class LockNotifyStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            # Windows keeps WAL sidecar files briefly locked; the test is done.
            pass

    def test_target_setting_defaults_to_disabled(self) -> None:
        self.assertEqual(self.db.get_settings()["lock_notify_session"], "")

    def test_report_settings_defaults(self) -> None:
        settings = self.db.get_settings()
        self.assertEqual(settings["lock_notify_session"], "")
        self.assertEqual(settings["report_level"], "all")

    def test_sent_flag_round_trips_across_instances(self) -> None:
        """The flag must survive a restart, or "once" becomes "once per boot"."""
        self.assertFalse(self.db.get_lock_notify_sent())

        self.db.set_lock_notify_sent(True)

        self.assertTrue(DatabaseManager(self.db_path).get_lock_notify_sent())

    def test_sent_flag_is_hidden_from_the_settings_dictionary(self) -> None:
        """The dashboard round-trip must not be able to clobber the flag."""
        self.db.set_lock_notify_sent(True)

        settings = self.db.get_settings()
        self.assertNotIn(LOCK_NOTIFY_SENT_KEY, settings)

        settings[LOCK_NOTIFY_SENT_KEY] = False
        self.db.save_settings(settings)

        self.assertTrue(self.db.get_lock_notify_sent())

    def test_target_change_resets_sent_flag_in_same_transaction(self) -> None:
        """A committed target change re-arms the durable alert state."""
        self.db.set_lock_notify_sent(True)

        self.db.save_settings(
            {"lock_notify_session": "test:FriendMessage:new"},
            rearm_lock_alert=True,
        )

        self.assertEqual(
            self.db.get_settings()["lock_notify_session"],
            "test:FriendMessage:new",
        )
        self.assertFalse(self.db.get_lock_notify_sent())

    def test_target_change_rolls_back_with_sent_flag_on_failure(self) -> None:
        """A failed target write cannot leave the old target re-armed."""
        self.db.save_settings({"lock_notify_session": "test:FriendMessage:old"})
        self.db.set_lock_notify_sent(True)
        original_save_records = self.db._save_settings_records

        def fail_when_rearming(conn: object, settings_data: dict[str, object]) -> None:
            if settings_data == {LOCK_NOTIFY_SENT_KEY: False}:
                raise RuntimeError("simulated flag write failure")
            original_save_records(conn, settings_data)

        with mock.patch.object(
            self.db,
            "_save_settings_records",
            side_effect=fail_when_rearming,
        ):
            with self.assertRaises(RuntimeError):
                self.db.save_settings(
                    {"lock_notify_session": "test:FriendMessage:new"},
                    rearm_lock_alert=True,
                )

        self.assertEqual(
            self.db.get_settings()["lock_notify_session"],
            "test:FriendMessage:old",
        )
        self.assertTrue(self.db.get_lock_notify_sent())


class SchedulerLockAlertHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_hook_is_called_when_present(self) -> None:
        class _Plugin:
            def __init__(self) -> None:
                self.calls = 0

            async def poll_lock_alert(self) -> None:
                self.calls += 1

        plugin = _Plugin()
        await CheckInScheduler(plugin)._poll_lock_alert()

        self.assertEqual(plugin.calls, 1)

    async def test_missing_hook_is_ignored(self) -> None:
        """Plugins without the hook keep working."""
        await CheckInScheduler(object())._poll_lock_alert()

    async def test_failing_hook_does_not_break_the_loop(self) -> None:
        class _Plugin:
            async def poll_lock_alert(self) -> None:
                raise RuntimeError("boom")

        await CheckInScheduler(_Plugin())._poll_lock_alert()
