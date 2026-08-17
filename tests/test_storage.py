"""Unit tests for SQLite database storage and migration."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

from core.storage import DEFAULT_SETTINGS, DatabaseManager

import tests  # noqa: F401


class DatabaseManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_database_initialization(self) -> None:
        """Test database tables and WAL mode are initialized properly."""
        self.assertTrue(self.db_path.exists())
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("sites", tables)
            self.assertIn("settings", tables)
            self.assertIn("history_logs", tables)

    def test_sites_crud_and_ordering(self) -> None:
        """Test saving, retrieving in order, and updating site check-in status."""
        sites = [
            {
                "id": "site_1",
                "name": "Site One",
                "type": "new-api",
                "base_url": "https://site1.example.com",
                "auth_type": "bearer_token",
                "auth_value": "token_123",
                "solve_acw_sc_v2": False,
                "checkin_endpoint": "",
                "proxy": "",
                "custom_headers": "User-Agent: test",
                "enabled": True,
            },
            {
                "id": "site_2",
                "name": "Site Two",
                "type": "one-api",
                "base_url": "https://site2.example.com",
                "auth_type": "cookie",
                "auth_value": "session=abc",
                "solve_acw_sc_v2": True,
                "checkin_endpoint": "/api/user/sign_in",
                "proxy": "http://127.0.0.1:7890",
                "custom_headers": "",
                "enabled": False,
            },
        ]
        self.db.save_sites(sites)
        loaded = self.db.get_sites()
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0]["id"], "site_1")
        self.assertEqual(loaded[0]["name"], "Site One")
        self.assertEqual(loaded[0]["enabled"], True)
        self.assertEqual(loaded[1]["id"], "site_2")
        self.assertEqual(loaded[1]["solve_acw_sc_v2"], True)
        self.assertEqual(loaded[1]["enabled"], False)

        # Update check-in state
        self.db.update_site_checkin_state(
            "site_1",
            last_checkin_date="2026-08-16",
            last_checkin_time="12:00:00",
            last_checkin_success=True,
            last_quota=100.5,
        )
        updated = self.db.get_sites()
        self.assertEqual(updated[0]["last_checkin_date"], "2026-08-16")
        self.assertEqual(updated[0]["last_checkin_time"], "12:00:00")
        self.assertEqual(updated[0]["last_checkin_success"], True)
        self.assertEqual(updated[0]["last_quota"], 100.5)

        # Verify created_at preservation across save_sites
        orig_created_at_1 = updated[0]["created_at"]
        orig_created_at_2 = updated[1]["created_at"]
        self.assertTrue(bool(orig_created_at_1))
        self.assertTrue(bool(orig_created_at_2))

        # Re-save with modifications and a new site
        modified_sites = list(updated)
        modified_sites[0]["name"] = "Site One Renamed"
        modified_sites.append({
            "id": "site_3",
            "name": "Site Three",
            "type": "new-api",
            "base_url": "https://site3.example.com",
            "auth_type": "bearer_token",
            "auth_value": "token_3",
            "enabled": True,
        })
        self.db.save_sites(modified_sites)
        reloaded = self.db.get_sites()
        self.assertEqual(len(reloaded), 3)
        self.assertEqual(reloaded[0]["name"], "Site One Renamed")
        self.assertEqual(reloaded[0]["created_at"], orig_created_at_1)
        self.assertEqual(reloaded[1]["created_at"], orig_created_at_2)
        self.assertTrue(bool(reloaded[2]["created_at"]))

    def test_settings_crud_and_defaults(self) -> None:
        """Test reading default settings and saving updated settings."""
        settings = self.db.get_settings()
        self.assertEqual(settings["enabled"], DEFAULT_SETTINGS["enabled"])
        self.assertEqual(settings["start_time"], "08:00")
        self.assertEqual(settings["auto_cleanup_logs"], True)
        self.assertEqual(settings["history_retention_days"], 0)
        self.assertEqual(settings["max_history_records"], 0)

        # Save customized settings
        new_settings = dict(settings)
        new_settings["start_time"] = "09:00"
        new_settings["end_time"] = "11:00"
        new_settings["http_timeout_seconds"] = 30
        new_settings["auto_cleanup_logs"] = False
        new_settings["history_retention_days"] = 30
        new_settings["max_history_records"] = 500
        self.db.save_settings(new_settings)

        reloaded = self.db.get_settings()
        self.assertEqual(reloaded["start_time"], "09:00")
        self.assertEqual(reloaded["end_time"], "11:00")
        self.assertEqual(reloaded["http_timeout_seconds"], 30)
        self.assertEqual(reloaded["auto_cleanup_logs"], False)
        self.assertEqual(reloaded["history_retention_days"], 30)
        self.assertEqual(reloaded["max_history_records"], 500)

    def test_history_logs_and_pruning(self) -> None:
        """Test recording, pagination, count, and configurable pruning of logs."""
        # 1. Default max_history_records = 0 (unlimited: no pruning)
        for i in range(15):
            self.db.record_history({
                "timestamp": f"2026-08-16 10:{i:02d}:00",
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": f"Report {i}",
                "details": [{"site_id": f"site_{i}", "success": True}],
            })

        self.assertEqual(self.db.count_history_logs(), 15)
        all_logs = self.db.read_history_logs(limit=100)
        self.assertEqual(len(all_logs), 15)
        self.assertEqual(all_logs[0]["report"], "Report 14")
        self.assertEqual(all_logs[-1]["report"], "Report 0")

        filtered_logs = self.db.read_history_logs(
            limit=100,
            start_date="2026-08-16",
            end_date="2026-08-16",
        )
        self.assertEqual(len(filtered_logs), 15)
        self.assertEqual(
            self.db.count_history_logs(start_date="2026-08-16", end_date="2026-08-16"),
            15,
        )
        self.assertEqual(
            len(self.db.read_history_logs(
                limit=None,
                start_date="2026-08-16",
                end_date="2026-08-16",
            )),
            15,
        )

        # 2. Test pagination with before_id
        page1 = self.db.read_history_logs(limit=5)
        self.assertEqual(len(page1), 5)
        self.assertEqual(page1[0]["report"], "Report 14")
        self.assertEqual(page1[-1]["report"], "Report 10")

        next_cursor = page1[-1]["id"]
        page2 = self.db.read_history_logs(limit=5, before_id=next_cursor)
        self.assertEqual(len(page2), 5)
        self.assertEqual(page2[0]["report"], "Report 9")
        self.assertEqual(page2[-1]["report"], "Report 5")

        next_cursor2 = page2[-1]["id"]
        page3 = self.db.read_history_logs(limit=5, before_id=next_cursor2)
        self.assertEqual(len(page3), 5)
        self.assertEqual(page3[0]["report"], "Report 4")
        self.assertEqual(page3[-1]["report"], "Report 0")

        # 3. Test explicit max_records pruning
        self.db.record_history(
            {
                "timestamp": "2026-08-16 11:00:00",
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": "Report 15",
                "details": [],
            },
            max_records=10,
        )
        self.assertEqual(self.db.count_history_logs(), 10)
        pruned_logs = self.db.read_history_logs(limit=100)
        self.assertEqual(len(pruned_logs), 10)
        self.assertEqual(pruned_logs[0]["report"], "Report 15")
        self.assertEqual(pruned_logs[-1]["report"], "Report 6")

        # 4. Test settings-driven max_history_records pruning
        settings = self.db.get_settings()
        settings["auto_cleanup_logs"] = True
        settings["max_history_records"] = 5
        self.db.save_settings(settings)

        self.db.record_history({
            "timestamp": "2026-08-16 11:05:00",
            "type": "scheduled",
            "manual": False,
            "success": True,
            "report": "Report 16",
            "details": [],
        })
        self.assertEqual(self.db.count_history_logs(), 5)
        pruned_logs_5 = self.db.read_history_logs(limit=100)
        self.assertEqual(len(pruned_logs_5), 5)
        self.assertEqual(pruned_logs_5[0]["report"], "Report 16")
        self.assertEqual(pruned_logs_5[-1]["report"], "Report 12")

        # 5. Disable automatic cleanup; max_history_records should no longer prune.
        settings["auto_cleanup_logs"] = False
        settings["max_history_records"] = 1
        self.db.save_settings(settings)
        self.db.record_history({
            "timestamp": "2026-08-16 11:06:00",
            "type": "scheduled",
            "manual": False,
            "success": True,
            "report": "Report 17",
            "details": [],
        })
        self.assertEqual(self.db.count_history_logs(), 6)

        # 6. Age-based cleanup works independently and ignores the row limit.
        self.db.clear_history_logs()
        settings["auto_cleanup_logs"] = True
        settings["history_retention_days"] = 2
        settings["max_history_records"] = 0
        self.db.save_settings(settings)
        now = datetime.now()
        for label, timestamp in (
            ("Too Old", now - timedelta(days=3)),
            ("Recent 1", now - timedelta(hours=2)),
            ("Recent 2", now - timedelta(hours=1)),
            ("Recent 3", now),
        ):
            self.db.record_history({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": label,
                "details": [],
            })
        self.assertEqual(self.db.count_history_logs(), 3)
        age_only_logs = self.db.read_history_logs(limit=100)
        self.assertNotIn("Too Old", [log["report"] for log in age_only_logs])

        # 7. Row-count cleanup works independently and ignores the age limit.
        self.db.clear_history_logs()
        settings["history_retention_days"] = 0
        settings["max_history_records"] = 2
        self.db.save_settings(settings)
        for label, timestamp in (
            ("Recent 1", now - timedelta(hours=2)),
            ("Recent 2", now - timedelta(hours=1)),
            ("Old But Within Row Limit", datetime(2020, 1, 1)),
        ):
            self.db.record_history({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": label,
                "details": [],
            })
        self.assertEqual(self.db.count_history_logs(), 2)
        count_only_logs = self.db.read_history_logs(limit=100)
        self.assertEqual(
            {log["report"] for log in count_only_logs},
            {"Recent 2", "Old But Within Row Limit"},
        )

        # 8. Apply both age-based and row-count cleanup together.
        self.db.clear_history_logs()
        settings["history_retention_days"] = 2
        settings["max_history_records"] = 2
        self.db.save_settings(settings)
        now = datetime.now()
        for label, timestamp in (
            ("Too Old", now - timedelta(days=3)),
            ("Recent 1", now - timedelta(hours=2)),
            ("Recent 2", now - timedelta(hours=1)),
            ("Recent 3", now),
        ):
            self.db.record_history({
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": label,
                "details": [],
            })
        self.assertEqual(self.db.count_history_logs(), 2)
        combined_pruned_logs = self.db.read_history_logs(limit=100)
        self.assertEqual(combined_pruned_logs[0]["report"], "Recent 3")
        self.assertEqual(combined_pruned_logs[-1]["report"], "Recent 2")

        # 9. Clear logs
        self.db.clear_history_logs()
        self.assertEqual(self.db.count_history_logs(), 0)
        self.assertEqual(len(self.db.read_history_logs()), 0)

    def test_legacy_json_migration(self) -> None:
        """Test automated migration from legacy sites.json, settings.json, and history.json."""
        migration_dir = self.data_dir / "legacy"
        migration_dir.mkdir()

        legacy_sites = [
            {
                "id": "migrated_site_1",
                "name": "Legacy Site",
                "type": "new-api",
                "base_url": "https://legacy.example.com",
                "auth_type": "bearer_token",
                "auth_value": "tok_leg",
                "solve_acw_sc_v2": False,
                "checkin_endpoint": "",
                "proxy": "",
                "custom_headers": "",
                "enabled": True,
                "last_checkin_date": "2026-08-15",
                "last_checkin_time": "08:30:00",
                "last_checkin_success": True,
                "last_quota": 50.0,
            }
        ]
        legacy_settings = {
            "enabled": True,
            "random_enabled": False,
            "checkin_time": "07:45",
            "http_timeout_seconds": 20,
        }
        legacy_history = [
            {
                "timestamp": "2026-08-15 08:30:00",
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": "Legacy report 1",
                "details": [{"site_id": "migrated_site_1", "success": True}],
            },
            {
                "timestamp": "2026-08-15 08:20:00",
                "type": "manual",
                "manual": True,
                "success": False,
                "report": "Legacy report 2",
                "details": [{"site_id": "migrated_site_1", "success": False}],
            },
        ]

        sites_file = migration_dir / "sites.json"
        settings_file = migration_dir / "settings.json"
        history_file = migration_dir / "history.json"

        with open(sites_file, "w", encoding="utf-8") as f:
            json.dump(legacy_sites, f)
        with open(settings_file, "w", encoding="utf-8") as f:
            json.dump(legacy_settings, f)
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(legacy_history, f)

        # Initialize DatabaseManager with legacy directory
        migrated_db_path = migration_dir / "data.db"
        mgr = DatabaseManager(migrated_db_path, legacy_data_dir=migration_dir)

        # Verify data in DB
        sites = mgr.get_sites()
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["id"], "migrated_site_1")
        self.assertEqual(sites[0]["last_quota"], 50.0)

        settings = mgr.get_settings()
        self.assertEqual(settings["random_enabled"], False)
        self.assertEqual(settings["checkin_time"], "07:45")
        self.assertEqual(settings["http_timeout_seconds"], 20)

        logs = mgr.read_history_logs()
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["report"], "Legacy report 1")
        self.assertEqual(logs[1]["report"], "Legacy report 2")

        # Verify JSON files were renamed to .bak
        self.assertFalse(sites_file.exists())
        self.assertTrue(sites_file.with_suffix(".json.bak").exists())
        self.assertFalse(settings_file.exists())
        self.assertTrue(settings_file.with_suffix(".json.bak").exists())
        self.assertFalse(history_file.exists())
        self.assertTrue(history_file.with_suffix(".json.bak").exists())

    def test_string_auto_cleanup_setting_is_normalized(self) -> None:
        """Normalize string values when enabling or disabling automatic cleanup."""
        self.db.clear_history_logs()
        settings = self.db.get_settings()
        settings["auto_cleanup_logs"] = "false"
        settings["history_retention_days"] = 0
        settings["max_history_records"] = 1
        self.db.save_settings(settings)

        for index in range(2):
            self.db.record_history({
                "timestamp": f"2026-08-16 12:0{index}:00",
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": f"Disabled {index}",
                "details": [],
            })
        self.assertEqual(self.db.count_history_logs(), 2)

        # The global switch remains authoritative even when a caller supplies
        # explicit numeric cleanup values.
        self.db.record_history({
            "timestamp": "2020-01-01 00:00:00",
            "type": "scheduled",
            "manual": False,
            "success": True,
            "report": "Explicit values ignored",
            "details": [],
        }, max_records=1, retention_days=1)
        self.assertEqual(self.db.count_history_logs(), 3)

        settings["auto_cleanup_logs"] = "yes"
        self.db.save_settings(settings)
        self.db.record_history({
            "timestamp": "2026-08-16 12:02:00",
            "type": "scheduled",
            "manual": False,
            "success": True,
            "report": "Enabled",
            "details": [],
        })
        self.assertEqual(self.db.count_history_logs(), 1)
        self.assertEqual(self.db.read_history_logs()[0]["report"], "Enabled")


if __name__ == "__main__":
    unittest.main()
