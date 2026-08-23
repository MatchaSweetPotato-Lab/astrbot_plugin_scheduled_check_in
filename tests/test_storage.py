"""Unit tests for SQLite database storage, migration, and the config vault."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401
from core.crypto import (
    CIPHER_PREFIX,
    LOCKED_PLACEHOLDER,
    InvalidVaultKeyError,
    VaultLockedError,
    encode_bytes,
)
from core.storage import (
    DEFAULT_SETTINGS,
    SLOT_USER_KEY,
    SLOT_WEBAUTHN,
    USER_KEY_SLOT_ID,
    DatabaseManager,
)


def read_raw(db_path: Path, column: str, site_id: str = "site_1") -> str:
    """Read one column straight from disk, bypassing the vault."""
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(f"SELECT {column} FROM sites WHERE id = ?", (site_id,)).fetchone()
    finally:
        conn.close()
    return "" if row is None else str(row[0] or "")


def make_site(**overrides) -> dict:
    """Build a site in the current credential/action shape."""
    site = {
        "id": "site_1",
        "name": "Site One",
        "type": "new-api",
        "base_url": "https://site1.example.com",
        "proxy": "http://127.0.0.1:7890",
        "credentials": [
            {"id": "c1", "type": "token", "value": "sk-secret", "auto_bearer": True},
            {
                "id": "gh",
                "type": "github_oauth",
                "value": "user_session=gh",
                "session_cookie": "session=live",
            },
        ],
        "checkin": {
            "path": "/api/user/checkin",
            "protocol": "post",
            "credential_id": "c1",
            "headers": [{"key": "X-A", "value": "1"}],
            "solve_acw_sc_v2": True,
        },
        "balance": {"path": "", "protocol": "auto", "credential_id": "", "headers": [], "solve_acw_sc_v2": False},
        "enabled": True,
    }
    site.update(overrides)
    return site


class DatabaseManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            # Windows keeps WAL sidecar files briefly locked; the test is done.
            pass

    def test_database_initialization(self) -> None:
        """Test database tables and WAL mode are initialized properly."""
        self.assertTrue(self.db_path.exists())
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            self.assertEqual(cursor.fetchone()[0].lower(), "wal")

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("sites", tables)
            self.assertIn("settings", tables)
            self.assertIn("history_logs", tables)
        finally:
            conn.close()

    def test_sites_round_trip_the_full_shape(self) -> None:
        self.db.save_sites([make_site()])
        loaded = self.db.get_sites()
        self.assertEqual(len(loaded), 1)
        site = loaded[0]
        self.assertEqual(site["name"], "Site One")
        self.assertEqual(site["proxy"], "http://127.0.0.1:7890")
        self.assertEqual(site["credentials"][0]["value"], "sk-secret")
        self.assertTrue(site["credentials"][0]["auto_bearer"])
        self.assertEqual(site["credentials"][1]["session_cookie"], "session=live")
        self.assertEqual(site["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(site["checkin"]["protocol"], "post")
        self.assertEqual(site["checkin"]["credential_id"], "c1")
        self.assertEqual(site["checkin"]["headers"], [{"key": "X-A", "value": "1"}])
        self.assertTrue(site["checkin"]["solve_acw_sc_v2"])
        self.assertEqual(site["balance"]["protocol"], "auto")
        self.assertFalse(site["locked"])

    def test_sites_are_normalized_on_read(self) -> None:
        """A hand-written row still comes back in canonical form."""
        self.db.save_sites([
            {
                "id": "site_1",
                "name": "Loose",
                "type": "one-api",
                "base_url": "https://x.test",
                "credentials": [{"type": "bearer_token", "value": "sk"}],
                "checkin": {"path": "sign", "protocol": "POST", "headers": "X-A: 1"},
                "enabled": True,
            }
        ])
        site = self.db.get_sites()[0]
        self.assertEqual(site["credentials"][0]["type"], "token")
        self.assertEqual(site["credentials"][0]["id"], "cred_1")
        self.assertEqual(site["checkin"]["path"], "/sign")
        self.assertEqual(site["checkin"]["protocol"], "post")
        self.assertEqual(site["checkin"]["headers"], [{"key": "X-A", "value": "1"}])

    def test_display_order_is_preserved(self) -> None:
        self.db.save_sites([
            make_site(id="site_1", name="One"),
            make_site(id="site_2", name="Two", enabled=False),
        ])
        loaded = self.db.get_sites()
        self.assertEqual([s["id"] for s in loaded], ["site_1", "site_2"])
        self.assertTrue(loaded[0]["enabled"])
        self.assertFalse(loaded[1]["enabled"])

    def test_update_site_checkin_state(self) -> None:
        self.db.save_sites([make_site()])
        self.db.update_site_checkin_state(
            "site_1",
            last_checkin_date="2026-08-16",
            last_checkin_time="12:00:00",
            last_checkin_success=True,
            last_quota=100.5,
        )
        site = self.db.get_sites()[0]
        self.assertEqual(site["last_checkin_date"], "2026-08-16")
        self.assertEqual(site["last_checkin_time"], "12:00:00")
        self.assertTrue(site["last_checkin_success"])
        self.assertEqual(site["last_quota"], 100.5)

    def test_created_at_survives_a_resave(self) -> None:
        self.db.save_sites([make_site()])
        original = self.db.get_sites()[0]["created_at"]
        self.assertTrue(original)

        edited = self.db.get_sites()
        edited[0]["name"] = "Renamed"
        edited.append(make_site(id="site_2", name="New Site"))
        self.db.save_sites(edited)

        reloaded = self.db.get_sites()
        self.assertEqual(len(reloaded), 2)
        self.assertEqual(reloaded[0]["name"], "Renamed")
        self.assertEqual(reloaded[0]["created_at"], original)
        self.assertTrue(reloaded[1]["created_at"])

    def test_display_view_withholds_oauth_sessions(self) -> None:
        """The browser must never receive a live station session cookie."""
        self.db.save_sites([make_site()])
        display = self.db.get_sites_for_display()[0]
        oauth = display["credentials"][1]
        self.assertEqual(oauth["session_cookie"], "")
        self.assertTrue(oauth["has_session"])

    def test_dashboard_round_trip_keeps_the_oauth_session(self) -> None:
        self.db.save_sites([make_site()])
        display = self.db.get_sites_for_display()
        display[0]["name"] = "Renamed"
        self.db.save_sites(display)
        self.assertEqual(
            self.db.get_sites()[0]["credentials"][1]["session_cookie"], "session=live"
        )

    def test_update_credential_session(self) -> None:
        self.db.save_sites([make_site()])
        self.assertTrue(self.db.update_credential_session("site_1", "gh", "session=rotated"))
        credential = self.db.get_sites()[0]["credentials"][1]
        self.assertEqual(credential["session_cookie"], "session=rotated")
        self.assertTrue(credential["session_updated_at"])

    def test_update_credential_session_ignores_unknown_ids(self) -> None:
        self.db.save_sites([make_site()])
        self.assertFalse(self.db.update_credential_session("site_1", "nope", "s"))
        self.assertFalse(self.db.update_credential_session("nope", "gh", "s"))

    def test_update_action_headers(self) -> None:
        self.db.save_sites([make_site()])
        headers = [{"key": "new-api-user", "value": "7"}]
        self.assertTrue(self.db.update_action_headers("site_1", "balance", headers))
        self.assertEqual(self.db.get_sites()[0]["balance"]["headers"], headers)

    def test_update_action_headers_rejects_an_unknown_action(self) -> None:
        self.db.save_sites([make_site()])
        with self.assertRaises(ValueError):
            self.db.update_action_headers("site_1", "bogus", [])

    def test_settings_crud_and_defaults(self) -> None:
        settings = self.db.get_settings()
        self.assertEqual(settings["enabled"], DEFAULT_SETTINGS["enabled"])
        self.assertEqual(settings["start_time"], "08:00")
        self.assertEqual(settings["max_history_records"], 0)

        new_settings = dict(settings)
        new_settings["start_time"] = "09:00"
        new_settings["end_time"] = "11:00"
        new_settings["http_timeout_seconds"] = 30
        new_settings["max_history_records"] = 500
        self.db.save_settings(new_settings)

        reloaded = self.db.get_settings()
        self.assertEqual(reloaded["start_time"], "09:00")
        self.assertEqual(reloaded["end_time"], "11:00")
        self.assertEqual(reloaded["http_timeout_seconds"], 30)
        self.assertEqual(reloaded["max_history_records"], 500)

    def test_history_logs_and_pruning(self) -> None:
        """Test recording, pagination, count, and configurable pruning of logs."""
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

        page1 = self.db.read_history_logs(limit=5)
        self.assertEqual(page1[0]["report"], "Report 14")
        self.assertEqual(page1[-1]["report"], "Report 10")

        page2 = self.db.read_history_logs(limit=5, before_id=page1[-1]["id"])
        self.assertEqual(page2[0]["report"], "Report 9")
        self.assertEqual(page2[-1]["report"], "Report 5")

        page3 = self.db.read_history_logs(limit=5, before_id=page2[-1]["id"])
        self.assertEqual(page3[0]["report"], "Report 4")
        self.assertEqual(page3[-1]["report"], "Report 0")

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
        self.assertEqual(self.db.read_history_logs(limit=100)[-1]["report"], "Report 6")

        settings = self.db.get_settings()
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
        self.assertEqual(self.db.read_history_logs(limit=100)[0]["report"], "Report 16")

        self.db.clear_history_logs()
        self.assertEqual(self.db.count_history_logs(), 0)


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def test_legacy_json_migration(self) -> None:
        """Test automated migration from legacy sites.json, settings.json, and history.json."""
        legacy_sites = [
            {
                "id": "migrated_site_1",
                "name": "Legacy Site",
                "type": "new-api",
                "base_url": "https://legacy.example.com",
                "auth_type": "bearer_token",
                "auth_value": "tok_leg",
                "solve_acw_sc_v2": True,
                "checkin_endpoint": "/api/user/checkin",
                "proxy": "http://127.0.0.1:1080",
                "custom_headers": "User-Agent: legacy",
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

        sites_file = self.data_dir / "sites.json"
        settings_file = self.data_dir / "settings.json"
        history_file = self.data_dir / "history.json"
        sites_file.write_text(json.dumps(legacy_sites), encoding="utf-8")
        settings_file.write_text(json.dumps(legacy_settings), encoding="utf-8")
        history_file.write_text(json.dumps(legacy_history), encoding="utf-8")

        mgr = DatabaseManager(self.data_dir / "data.db", legacy_data_dir=self.data_dir)

        sites = mgr.get_sites()
        self.assertEqual(len(sites), 1)
        site = sites[0]
        self.assertEqual(site["id"], "migrated_site_1")
        self.assertEqual(site["last_quota"], 50.0)
        self.assertEqual(site["proxy"], "http://127.0.0.1:1080")

        # auth_type/auth_value became one credential
        self.assertEqual(len(site["credentials"]), 1)
        self.assertEqual(site["credentials"][0]["type"], "token")
        self.assertEqual(site["credentials"][0]["value"], "tok_leg")
        self.assertTrue(site["credentials"][0]["auto_bearer"])

        # checkin_endpoint became the check-in path
        self.assertEqual(site["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(site["balance"]["path"], "")

        # custom_headers and the solver flag apply to both actions
        expected_headers = [{"key": "User-Agent", "value": "legacy"}]
        self.assertEqual(site["checkin"]["headers"], expected_headers)
        self.assertEqual(site["balance"]["headers"], expected_headers)
        self.assertTrue(site["checkin"]["solve_acw_sc_v2"])
        self.assertTrue(site["balance"]["solve_acw_sc_v2"])

        settings = mgr.get_settings()
        self.assertEqual(settings["random_enabled"], False)
        self.assertEqual(settings["checkin_time"], "07:45")
        self.assertEqual(settings["http_timeout_seconds"], 20)

        logs = mgr.read_history_logs()
        self.assertEqual([log["report"] for log in logs], ["Legacy report 1", "Legacy report 2"])

        self.assertFalse(sites_file.exists())
        self.assertTrue(sites_file.with_suffix(".json.bak").exists())
        self.assertFalse(settings_file.exists())
        self.assertTrue(settings_file.with_suffix(".json.bak").exists())
        self.assertFalse(history_file.exists())
        self.assertTrue(history_file.with_suffix(".json.bak").exists())

    def test_cookie_credential_migration(self) -> None:
        legacy = [
            {
                "id": "s",
                "name": "Legacy Cookie Site",
                "type": "generic_rest",
                "base_url": "https://legacy.test",
                "auth_type": "cookie",
                "auth_value": "session=abc",
                "enabled": True,
            }
        ]
        (self.data_dir / "sites.json").write_text(json.dumps(legacy), encoding="utf-8")
        mgr = DatabaseManager(self.data_dir / "data.db", legacy_data_dir=self.data_dir)
        credential = mgr.get_sites()[0]["credentials"][0]
        self.assertEqual(credential["type"], "cookie")
        self.assertEqual(credential["value"], "session=abc")
        self.assertNotIn("auto_bearer", credential)

    def test_legacy_sqlite_schema_is_upgraded_in_place(self) -> None:
        """An existing database from the previous release keeps its data."""
        db_path = self.data_dir / "data.db"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(
                """
                CREATE TABLE sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    auth_value TEXT NOT NULL,
                    checkin_endpoint TEXT NOT NULL DEFAULT '',
                    proxy TEXT NOT NULL DEFAULT '',
                    custom_headers TEXT NOT NULL DEFAULT '',
                    solve_acw_sc_v2 INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_checkin_date TEXT,
                    last_checkin_time TEXT,
                    last_checkin_success INTEGER,
                    last_quota REAL,
                    display_order INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO sites VALUES (
                    'old_1', 'Old Site', 'new-api', 'https://old.test',
                    'bearer_token', 'sk-old', '/api/user/checkin',
                    'http://127.0.0.1:7890', 'X-Old: 1', 1, 1,
                    '2026-08-01', '09:00:00', 1, 7.5, 0,
                    '2026-07-01 00:00:00', '2026-08-01 09:00:00'
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

        mgr = DatabaseManager(db_path)
        sites = mgr.get_sites()
        self.assertEqual(len(sites), 1)
        site = sites[0]
        self.assertEqual(site["name"], "Old Site")
        self.assertEqual(site["credentials"][0]["value"], "sk-old")
        self.assertEqual(site["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(site["checkin"]["headers"], [{"key": "X-Old", "value": "1"}])
        self.assertTrue(site["checkin"]["solve_acw_sc_v2"])
        self.assertEqual(site["proxy"], "http://127.0.0.1:7890")
        self.assertEqual(site["last_quota"], 7.5)
        self.assertEqual(site["created_at"], "2026-07-01 00:00:00")


class VaultStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.db = DatabaseManager(self.db_path)
        self.db.save_sites([make_site()])

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def test_starts_disabled(self) -> None:
        status = self.db.vault_status()
        self.assertFalse(status["enabled"])
        self.assertFalse(status["unlocked"])
        self.assertFalse(status["locked"])
        self.assertEqual(status["slot_count"], 0)
        self.assertFalse(status["has_passkey"])
        self.assertFalse(self.db.is_encryption_enabled())

    def test_enable_seals_existing_rows(self) -> None:
        self.db.enable_encryption()
        for column in ("credentials", "checkin_headers", "proxy"):
            self.assertTrue(read_raw(self.db_path, column).startswith(CIPHER_PREFIX), column)

    def test_action_config_stays_readable_while_sealed(self) -> None:
        """Path and protocol are not secrets, so the list stays informative."""
        self.db.enable_encryption()
        raw = read_raw(self.db_path, "checkin_config")
        self.assertFalse(raw.startswith(CIPHER_PREFIX))
        self.assertIn("/api/user/checkin", raw)

    def test_enable_returns_a_usable_key(self) -> None:
        key = self.db.enable_encryption()
        self.assertEqual(len(base64.b64decode(key)), 32)
        self.assertTrue(self.db.vault_status()["unlocked"])

    def test_enabling_twice_is_rejected(self) -> None:
        self.db.enable_encryption()
        with self.assertRaises(RuntimeError):
            self.db.enable_encryption()

    def test_secrets_are_readable_while_unlocked(self) -> None:
        self.db.enable_encryption()
        site = self.db.get_sites()[0]
        self.assertEqual(site["credentials"][0]["value"], "sk-secret")
        self.assertEqual(site["proxy"], "http://127.0.0.1:7890")
        self.assertFalse(site["locked"])

    def test_locked_sites_are_listed_but_withheld(self) -> None:
        self.db.enable_encryption()
        self.db.lock_encryption()
        site = self.db.get_sites_for_display()[0]
        self.assertTrue(site["locked"])
        self.assertEqual(site["name"], "Site One")
        self.assertEqual(site["base_url"], "https://site1.example.com")
        self.assertEqual(site["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(site["credentials"], [])
        self.assertEqual(site["checkin"]["headers"], [])
        self.assertEqual(site["proxy"], LOCKED_PLACEHOLDER)

    def test_unlock_requires_the_right_key(self) -> None:
        self.db.enable_encryption()
        self.db.lock_encryption()
        with self.assertRaises(InvalidVaultKeyError):
            self.db.unlock_encryption("not-base64!!")
        wrong = base64.b64encode(os.urandom(32)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.db.unlock_encryption(wrong)
        self.assertTrue(self.db.vault_status()["locked"])

    def test_unlock_restores_access(self) -> None:
        key = self.db.enable_encryption()
        self.db.lock_encryption()
        self.db.unlock_encryption(key)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_unlock_without_encryption_is_rejected(self) -> None:
        with self.assertRaises(RuntimeError):
            self.db.unlock_encryption("anything")

    def test_saving_while_locked_preserves_every_secret(self) -> None:
        """Editing a name from the dashboard must not wipe unreadable fields."""
        key = self.db.enable_encryption()
        self.db.lock_encryption()

        edited = self.db.get_sites_for_display()
        edited[0]["name"] = "Renamed While Locked"
        self.db.save_sites(edited)

        self.db.unlock_encryption(key)
        site = self.db.get_sites()[0]
        self.assertEqual(site["name"], "Renamed While Locked")
        self.assertEqual(site["credentials"][0]["value"], "sk-secret")
        self.assertEqual(site["credentials"][1]["session_cookie"], "session=live")
        self.assertEqual(site["proxy"], "http://127.0.0.1:7890")
        self.assertEqual(site["checkin"]["headers"], [{"key": "X-A", "value": "1"}])

    def test_runtime_writeback_stays_encrypted(self) -> None:
        self.db.enable_encryption()
        self.db.update_credential_session("site_1", "gh", "session=rotated")
        self.db.update_action_headers("site_1", "balance", [{"key": "new-api-user", "value": "7"}])
        self.assertTrue(read_raw(self.db_path, "credentials").startswith(CIPHER_PREFIX))
        self.assertTrue(read_raw(self.db_path, "balance_headers").startswith(CIPHER_PREFIX))
        site = self.db.get_sites()[0]
        self.assertEqual(site["credentials"][1]["session_cookie"], "session=rotated")
        self.assertEqual(site["balance"]["headers"], [{"key": "new-api-user", "value": "7"}])

    def test_a_reload_starts_locked(self) -> None:
        """The key is never persisted, so a restart must require re-entry."""
        self.db.enable_encryption()
        reloaded = DatabaseManager(self.db_path)
        status = reloaded.vault_status()
        self.assertTrue(status["enabled"])
        self.assertFalse(status["unlocked"])
        self.assertTrue(status["locked"])
        self.assertEqual(len(reloaded.get_sites_for_display()), 1)

    def test_vault_bookkeeping_is_hidden_from_settings(self) -> None:
        self.db.enable_encryption()
        settings = self.db.get_settings()
        self.assertNotIn("vault_enabled", settings)
        self.assertNotIn("vault_verifier", settings)

    def test_saving_settings_cannot_clear_the_vault_flag(self) -> None:
        self.db.enable_encryption()
        self.db.save_settings({"vault_enabled": False, "start_time": "07:00"})
        self.assertTrue(self.db.is_encryption_enabled())
        self.assertEqual(self.db.get_settings()["start_time"], "07:00")

    def test_disable_rewrites_plaintext(self) -> None:
        self.db.enable_encryption()
        self.db.disable_encryption()
        self.assertFalse(self.db.vault_status()["enabled"])
        self.assertFalse(read_raw(self.db_path, "credentials").startswith(CIPHER_PREFIX))
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_disable_while_locked_is_refused(self) -> None:
        self.db.enable_encryption()
        self.db.lock_encryption()
        with self.assertRaises(Exception):
            self.db.disable_encryption()
        self.assertTrue(self.db.is_encryption_enabled())

    def test_disable_without_encryption_is_a_no_op(self) -> None:
        self.db.disable_encryption()
        self.assertFalse(self.db.vault_status()["enabled"])

    def test_reset_clears_secrets_but_keeps_the_site(self) -> None:
        self.db.enable_encryption()
        self.db.lock_encryption()
        self.assertEqual(self.db.reset_encryption(), 1)
        self.assertFalse(self.db.vault_status()["enabled"])

        site = self.db.get_sites()[0]
        self.assertEqual(site["name"], "Site One")
        self.assertEqual(site["base_url"], "https://site1.example.com")
        self.assertEqual(site["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(site["credentials"], [])
        self.assertEqual(site["proxy"], "")
        self.assertEqual(site["checkin"]["headers"], [])

    def test_reset_only_blanks_the_encrypted_columns(self) -> None:
        """Losing the key must cost the secrets, never the site configuration.

        Reset is the last resort after a lost key, so it has to leave everything
        that is not ciphertext intact — otherwise a user who forgets their key
        also loses the work of setting the sites up.
        """
        self.db.update_site_checkin_state(
            "site_1",
            last_checkin_date="2026-08-19",
            last_checkin_time="08:31:20",
            last_checkin_success=True,
            last_quota=12.5,
        )
        self.db.save_sites([
            self.db.get_sites()[0],
            make_site(id="site_2", name="Site Two", base_url="https://site2.test", enabled=False),
        ])
        created_at = self.db.get_sites()[0]["created_at"]

        self.db.enable_encryption()
        self.db.lock_encryption()
        self.assertEqual(self.db.reset_encryption(), 2)

        sites = self.db.get_sites()
        # No rows dropped, order and identity preserved.
        self.assertEqual([site["id"] for site in sites], ["site_1", "site_2"])

        first = sites[0]
        self.assertEqual(first["name"], "Site One")
        self.assertEqual(first["type"], "new-api")
        self.assertEqual(first["base_url"], "https://site1.example.com")
        self.assertTrue(first["enabled"])
        self.assertEqual(first["created_at"], created_at)

        # Non-secret action config survives, so the site still knows how to run.
        self.assertEqual(first["checkin"]["path"], "/api/user/checkin")
        self.assertEqual(first["checkin"]["protocol"], "post")
        self.assertEqual(first["checkin"]["credential_id"], "c1")
        self.assertTrue(first["checkin"]["solve_acw_sc_v2"])

        # Check-in history state survives.
        self.assertEqual(first["last_checkin_date"], "2026-08-19")
        self.assertEqual(first["last_checkin_time"], "08:31:20")
        self.assertTrue(first["last_checkin_success"])
        self.assertEqual(first["last_quota"], 12.5)

        # Only the four encrypted columns are blanked.
        self.assertEqual(first["credentials"], [])
        self.assertEqual(first["proxy"], "")
        self.assertEqual(first["checkin"]["headers"], [])
        self.assertEqual(first["balance"]["headers"], [])

        # A disabled second site keeps its own flags too.
        self.assertEqual(sites[1]["name"], "Site Two")
        self.assertEqual(sites[1]["base_url"], "https://site2.test")
        self.assertFalse(sites[1]["enabled"])

    def test_reset_keeps_global_settings(self) -> None:
        settings = self.db.get_settings()
        settings["start_time"] = "07:15"
        self.db.save_settings(settings)

        self.db.enable_encryption()
        self.db.lock_encryption()
        self.db.reset_encryption()

        self.assertEqual(self.db.get_settings()["start_time"], "07:15")

    def test_sites_are_usable_again_right_after_reset(self) -> None:
        """The user only needs to re-enter the secrets, not rebuild the site."""
        self.db.enable_encryption()
        self.db.lock_encryption()
        self.db.reset_encryption()

        site = self.db.get_sites()[0]
        site["credentials"] = [{"id": "c1", "type": "token", "value": "sk-fresh"}]
        site["proxy"] = "http://127.0.0.1:1080"
        self.db.save_sites([site])

        restored = self.db.get_sites()[0]
        self.assertEqual(restored["credentials"][0]["value"], "sk-fresh")
        self.assertEqual(restored["proxy"], "http://127.0.0.1:1080")
        self.assertEqual(restored["checkin"]["path"], "/api/user/checkin")
        self.assertFalse(restored["locked"])

    def test_reset_keeps_history(self) -> None:
        self.db.record_history({
            "timestamp": "2026-08-16 10:00:00",
            "type": "scheduled",
            "manual": False,
            "success": True,
            "report": "kept",
            "details": [],
        })
        self.db.enable_encryption()
        self.db.reset_encryption()
        self.assertEqual(self.db.count_history_logs(), 1)

    def test_re_enabling_issues_a_new_key(self) -> None:
        first = self.db.enable_encryption()
        self.db.disable_encryption()
        self.assertNotEqual(self.db.enable_encryption(), first)


class KeySlotStorageTests(unittest.TestCase):
    """Multi-slot wrapping: any one slot secret unlocks the same vault."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.db = DatabaseManager(self.db_path)
        self.db.save_sites([make_site()])
        self.key = self.db.enable_encryption()
        self.prf_salt = encode_bytes(os.urandom(32))
        self.prf_output = encode_bytes(os.urandom(32))

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def _add_passkey(self, **overrides) -> dict:
        params = {
            "credential_id": "Y3JlZC1hYmM",
            "prf_output": self.prf_output,
            "prf_salt": self.prf_salt,
            "rp_id": "localhost",
            "label": "Windows Hello",
            "transports": ["internal"],
        }
        params.update(overrides)
        return self.db.add_webauthn_slot(**params)

    # -- user key slot -------------------------------------------------
    def test_enabling_creates_a_user_key_slot(self) -> None:
        slots = self.db.list_slots()
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0]["type"], SLOT_USER_KEY)
        self.assertFalse(slots[0]["removable"])

    def test_slot_rows_never_expose_the_wrapped_key(self) -> None:
        self.assertNotIn("wrapped_dek", self.db.list_slots()[0])

    def test_the_user_key_slot_cannot_be_removed(self) -> None:
        with self.assertRaises(RuntimeError):
            self.db.remove_slot(USER_KEY_SLOT_ID)
        self.assertEqual(len(self.db.list_slots()), 1)

    def test_user_key_still_unlocks_after_enabling(self) -> None:
        self.db.lock_encryption()
        self.db.unlock_encryption(self.key)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_a_wrong_user_key_is_rejected(self) -> None:
        self.db.lock_encryption()
        wrong = base64.b64encode(os.urandom(32)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.db.unlock_encryption(wrong)
        self.assertTrue(self.db.vault_status()["locked"])

    # -- passkey slots -------------------------------------------------
    def test_registering_a_passkey_adds_a_slot(self) -> None:
        slot = self._add_passkey()
        self.assertEqual(slot["type"], SLOT_WEBAUTHN)
        self.assertEqual(slot["label"], "Windows Hello")
        self.assertEqual(slot["rp_id"], "localhost")
        self.assertEqual(slot["transports"], ["internal"])
        self.assertTrue(slot["removable"])
        self.assertEqual(len(self.db.list_slots()), 2)

    def test_the_passkey_slot_keeps_the_salt_for_unlocking(self) -> None:
        """The same salt must be replayed at unlock or the PRF output differs."""
        self.assertEqual(self._add_passkey()["prf_salt"], self.prf_salt)

    def test_a_passkey_unlocks_the_vault(self) -> None:
        self._add_passkey()
        self.db.lock_encryption()
        self.assertTrue(self.db.vault_status()["locked"])

        self.db.unlock_with_webauthn("Y3JlZC1hYmM", self.prf_output)
        self.assertTrue(self.db.vault_status()["unlocked"])
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_both_slot_kinds_recover_the_same_data(self) -> None:
        self._add_passkey()
        expected = self.db.get_sites()[0]["credentials"][0]["value"]

        self.db.lock_encryption()
        self.db.unlock_with_webauthn("Y3JlZC1hYmM", self.prf_output)
        via_passkey = self.db.get_sites()[0]["credentials"][0]["value"]

        self.db.lock_encryption()
        self.db.unlock_encryption(self.key)
        via_key = self.db.get_sites()[0]["credentials"][0]["value"]

        self.assertEqual(via_passkey, expected)
        self.assertEqual(via_key, expected)

    def test_a_wrong_prf_output_is_rejected(self) -> None:
        self._add_passkey()
        self.db.lock_encryption()
        with self.assertRaises(InvalidVaultKeyError):
            self.db.unlock_with_webauthn("Y3JlZC1hYmM", encode_bytes(os.urandom(32)))
        self.assertTrue(self.db.vault_status()["locked"])

    def test_an_unknown_credential_is_reported(self) -> None:
        self._add_passkey()
        self.db.lock_encryption()
        with self.assertRaises(RuntimeError):
            self.db.unlock_with_webauthn("bm90LXJlZ2lzdGVyZWQ", self.prf_output)

    def test_registering_requires_an_unlocked_vault(self) -> None:
        """Wrapping the vault key is impossible without holding it."""
        self.db.lock_encryption()
        with self.assertRaises(VaultLockedError):
            self._add_passkey()

    def test_registering_requires_encryption(self) -> None:
        self.db.disable_encryption()
        with self.assertRaises(RuntimeError):
            self._add_passkey()

    def test_the_same_credential_cannot_be_registered_twice(self) -> None:
        self._add_passkey()
        with self.assertRaises(RuntimeError):
            self._add_passkey()

    def test_the_same_credential_can_serve_two_hosts(self) -> None:
        """Credentials are bound to an RP ID, so each host needs its own slot."""
        self._add_passkey(rp_id="localhost")
        self._add_passkey(rp_id="nas.example.com", prf_output=encode_bytes(os.urandom(32)))
        self.assertEqual(len(self.db.list_slots()), 3)

    def test_a_malformed_prf_output_is_rejected(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            self._add_passkey(prf_output=encode_bytes(os.urandom(16)))
        with self.assertRaises(InvalidVaultKeyError):
            self._add_passkey(prf_output="!!! not base64 !!!")

    def test_a_missing_credential_id_is_rejected(self) -> None:
        with self.assertRaises(RuntimeError):
            self._add_passkey(credential_id="  ")

    # -- listing and filtering ----------------------------------------
    def test_slots_are_listed_while_locked(self) -> None:
        """The unlock page needs the slot list before any key is available."""
        self._add_passkey()
        self.db.lock_encryption()
        slots = self.db.list_slots()
        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[1]["credential_id"], "Y3JlZC1hYmM")

    def test_slots_are_filtered_by_rp_id(self) -> None:
        self._add_passkey(rp_id="localhost")
        self._add_passkey(
            credential_id="b3RoZXI",
            rp_id="nas.example.com",
            prf_output=encode_bytes(os.urandom(32)),
        )
        local = self.db.list_slots_for_rp("localhost")
        self.assertEqual([slot["credential_id"] for slot in local], ["Y3JlZC1hYmM"])
        self.assertEqual(len(self.db.list_slots_for_rp("nas.example.com")), 1)
        self.assertEqual(self.db.list_slots_for_rp("unknown.test"), [])

    def test_rp_filtering_ignores_case(self) -> None:
        self._add_passkey(rp_id="NAS.Example.com")
        self.assertEqual(len(self.db.list_slots_for_rp("nas.example.com")), 1)

    def test_rp_filtering_excludes_the_user_key_slot(self) -> None:
        self.assertEqual(self.db.list_slots_for_rp(""), [])

    def test_unlocking_stamps_last_used(self) -> None:
        self._add_passkey()
        self.assertIsNone(self.db.list_slots()[1]["last_used_at"])
        self.db.lock_encryption()
        self.db.unlock_with_webauthn("Y3JlZC1hYmM", self.prf_output)
        self.assertIsNotNone(self.db.list_slots()[1]["last_used_at"])

    def test_status_reports_the_slot_summary(self) -> None:
        self.assertFalse(self.db.vault_status()["has_passkey"])
        self._add_passkey()
        status = self.db.vault_status()
        self.assertEqual(status["slot_count"], 2)
        self.assertTrue(status["has_passkey"])

    # -- removal -------------------------------------------------------
    def test_removing_a_passkey_leaves_the_others_working(self) -> None:
        self._add_passkey(credential_id="Zmlyc3Q")
        second_prf = encode_bytes(os.urandom(32))
        self._add_passkey(credential_id="c2Vjb25k", prf_output=second_prf)

        # Select by credential id: two slots created in the same second sort by
        # their random ids, so an index would be non-deterministic.
        first = next(s for s in self.db.list_slots() if s["credential_id"] == "Zmlyc3Q")
        self.assertTrue(self.db.remove_slot(first["id"]))
        self.assertEqual(len(self.db.list_slots()), 2)

        self.db.lock_encryption()
        self.db.unlock_with_webauthn("c2Vjb25k", second_prf)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_a_removed_passkey_can_no_longer_unlock(self) -> None:
        slot = self._add_passkey()
        self.db.remove_slot(slot["id"])
        self.db.lock_encryption()
        with self.assertRaises(RuntimeError):
            self.db.unlock_with_webauthn("Y3JlZC1hYmM", self.prf_output)

    def test_removing_an_unknown_slot_returns_false(self) -> None:
        self.assertFalse(self.db.remove_slot("slot_missing"))

    def test_disabling_encryption_clears_the_slots(self) -> None:
        self._add_passkey()
        self.db.disable_encryption()
        self.assertEqual(self.db.list_slots(), [])

    def test_resetting_encryption_clears_the_slots(self) -> None:
        self._add_passkey()
        self.db.lock_encryption()
        self.db.reset_encryption()
        self.assertEqual(self.db.list_slots(), [])


class CredentialRotationTests(unittest.TestCase):
    """A provider cookie rotates underneath us; storage must keep the new one."""

    HELD = "user_session=OLD; _gh_sess=G1; logged_in=yes"
    ROTATED = "user_session=OLD; _gh_sess=G2; logged_in=yes"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data.db"
        self.db = DatabaseManager(self.db_path)
        self.db.save_sites([
            make_site(credentials=[
                {"id": "gh", "type": "github_oauth", "label": "Github",
                 "value": self.HELD, "session_cookie": "session=live"},
            ])
        ])

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def _credential(self) -> dict:
        return self.db.get_sites()[0]["credentials"][0]

    def test_a_rotated_value_is_stored(self) -> None:
        self.assertTrue(self.db.update_credential_value("site_1", "gh", self.ROTATED))
        self.assertEqual(self._credential()["value"], self.ROTATED)

    def test_the_rotation_is_timestamped(self) -> None:
        self.db.update_credential_value("site_1", "gh", self.ROTATED)
        self.assertTrue(self._credential()["value_updated_at"])

    def test_an_unchanged_value_is_not_rewritten(self) -> None:
        self.assertFalse(self.db.update_credential_value("site_1", "gh", self.HELD))

    def test_a_blank_value_cannot_wipe_the_credential(self) -> None:
        """A bad response must never destroy a working credential."""
        for blank in ("", "   ", None):
            self.assertFalse(self.db.update_credential_value("site_1", "gh", blank))
        self.assertEqual(self._credential()["value"], self.HELD)

    def test_an_unknown_credential_is_ignored(self) -> None:
        self.assertFalse(self.db.update_credential_value("site_1", "nope", self.ROTATED))
        self.assertFalse(self.db.update_credential_value("nope", "gh", self.ROTATED))

    def test_the_session_cookie_is_untouched(self) -> None:
        self.db.update_credential_value("site_1", "gh", self.ROTATED)
        self.assertEqual(self._credential()["session_cookie"], "session=live")

    def test_the_rotation_survives_encryption(self) -> None:
        key = self.db.enable_encryption()
        self.db.update_credential_value("site_1", "gh", self.ROTATED)
        self.db.lock_encryption()
        self.db.unlock_encryption(key)
        self.assertEqual(self._credential()["value"], self.ROTATED)

    def test_an_omitted_value_keeps_the_stored_one(self) -> None:
        """The dashboard omits an untouched OAuth cookie so that saving an
        unrelated edit cannot revert a rotation."""
        self.db.update_credential_value("site_1", "gh", self.ROTATED)
        payload = self.db.get_sites_for_display()
        del payload[0]["credentials"][0]["value"]
        payload[0]["name"] = "Renamed"
        self.db.save_sites(payload)
        self.assertEqual(self._credential()["value"], self.ROTATED)
        self.assertEqual(self.db.get_sites()[0]["name"], "Renamed")

    def test_a_supplied_value_still_wins(self) -> None:
        """Editing the cookie by hand must not be ignored."""
        payload = self.db.get_sites_for_display()
        payload[0]["credentials"][0]["value"] = "user_session=TYPED"
        self.db.save_sites(payload)
        self.assertEqual(self._credential()["value"], "user_session=TYPED")


class LegacyVaultUpgradeTests(unittest.TestCase):
    """A vault created before key slots must keep working untouched."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.key = self._build_legacy_vault()
        self.legacy_ciphertext = read_raw(self.db_path, "credentials")
        self.db = DatabaseManager(self.db_path)

    def _build_legacy_vault(self) -> str:
        """Recreate the pre-slot on-disk layout.

        In that layout the user's key *is* the vault key: fields were encrypted
        directly under it and there was no vault_slots table content.
        """
        db = DatabaseManager(self.db_path)
        db.save_sites([make_site()])
        key_text, verifier = db.vault.enable()

        columns = ("proxy", "credentials", "checkin_headers", "balance_headers")
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(f"SELECT id, {', '.join(columns)} FROM sites").fetchall()
            for row in rows:
                sealed = [db.vault.encrypt(str(row[column] or "")) for column in columns]
                assignments = ", ".join(f"{column} = ?" for column in columns)
                conn.execute(
                    f"UPDATE sites SET {assignments} WHERE id = ?", (*sealed, row["id"])
                )
            for key, value in (("vault_enabled", "true"), ("vault_verifier", verifier)):
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
            conn.commit()
        finally:
            conn.close()
        return key_text

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def test_a_legacy_vault_has_no_slots(self) -> None:
        self.assertEqual(self.db.list_slots(), [])
        self.assertTrue(self.db.vault_status()["locked"])

    def test_the_saved_key_still_unlocks(self) -> None:
        self.db.unlock_encryption(self.key)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_unlocking_upgrades_to_the_slot_layout(self) -> None:
        self.db.unlock_encryption(self.key)
        slots = self.db.list_slots()
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0]["type"], SLOT_USER_KEY)

    def test_the_upgrade_does_not_re_encrypt_anything(self) -> None:
        """Field ciphertext must be byte-identical — the safest migration."""
        self.db.unlock_encryption(self.key)
        self.assertEqual(read_raw(self.db_path, "credentials"), self.legacy_ciphertext)

    def test_the_key_keeps_working_after_the_upgrade(self) -> None:
        self.db.unlock_encryption(self.key)
        self.db.lock_encryption()
        self.db.unlock_encryption(self.key)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")

    def test_a_wrong_key_is_still_rejected(self) -> None:
        wrong = base64.b64encode(os.urandom(32)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.db.unlock_encryption(wrong)
        self.assertEqual(self.db.list_slots(), [])

    def test_a_passkey_can_be_added_after_the_upgrade(self) -> None:
        self.db.unlock_encryption(self.key)
        prf_output = encode_bytes(os.urandom(32))
        self.db.add_webauthn_slot(
            credential_id="dXBncmFkZWQ",
            prf_output=prf_output,
            prf_salt=encode_bytes(os.urandom(32)),
            rp_id="localhost",
            label="Touch ID",
        )
        self.db.lock_encryption()
        self.db.unlock_with_webauthn("dXBncmFkZWQ", prf_output)
        self.assertEqual(self.db.get_sites()[0]["credentials"][0]["value"], "sk-secret")


class HistoryFilteringTests(unittest.TestCase):
    """Date and per-site filtering used by the check-in calendar."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.db_path = self.data_dir / "data.db"
        self.db = DatabaseManager(self.db_path)
        for timestamp, site_ids in (
            ("2026-07-15 08:00:00", ["s1"]),
            ("2026-08-01 08:00:00", ["s1", "s2"]),
            ("2026-08-10 08:00:00", ["s1"]),
            ("2026-08-20 08:00:00", ["s2"]),
        ):
            self.db.record_history({
                "timestamp": timestamp,
                "type": "scheduled",
                "manual": False,
                "success": True,
                "report": timestamp,
                "details": [{"site_id": site_id, "success": True} for site_id in site_ids],
            })

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def test_filters_by_site(self) -> None:
        self.assertEqual(len(self.db.read_history_logs(site_id="s1")), 3)
        self.assertEqual(len(self.db.read_history_logs(site_id="s2")), 2)

    def test_unknown_site_matches_nothing(self) -> None:
        self.assertEqual(self.db.read_history_logs(site_id="missing"), [])

    def test_blank_site_id_is_ignored(self) -> None:
        self.assertEqual(len(self.db.read_history_logs(site_id="   ")), 4)

    def test_date_range_is_inclusive(self) -> None:
        logs = self.db.read_history_logs(start_date="2026-08-01", end_date="2026-08-10")
        self.assertEqual([log["report"] for log in logs],
                         ["2026-08-10 08:00:00", "2026-08-01 08:00:00"])

    def test_a_single_day_range_works(self) -> None:
        self.assertEqual(len(self.db.read_history_logs(start_date="2026-08-10", end_date="2026-08-10")), 1)

    def test_malformed_dates_are_ignored(self) -> None:
        """A bad filter must not silently return an empty calendar."""
        self.assertEqual(len(self.db.read_history_logs(start_date="08/2026")), 4)
        self.assertEqual(len(self.db.read_history_logs(end_date="")), 4)

    def test_site_and_date_combine(self) -> None:
        logs = self.db.read_history_logs(site_id="s1", start_date="2026-08-01")
        self.assertEqual(len(logs), 2)

    def test_limit_none_returns_everything(self) -> None:
        self.assertEqual(len(self.db.read_history_logs(limit=None)), 4)

    def test_count_respects_the_date_range(self) -> None:
        self.assertEqual(self.db.count_history_logs(), 4)
        self.assertEqual(self.db.count_history_logs(start_date="2026-08-01"), 3)
        self.assertEqual(self.db.count_history_logs(end_date="2026-07-31"), 1)

    def test_pagination_still_works_with_filters(self) -> None:
        page = self.db.read_history_logs(limit=1, site_id="s1")
        self.assertEqual(len(page), 1)
        rest = self.db.read_history_logs(limit=5, before_id=page[0]["id"], site_id="s1")
        self.assertEqual(len(rest), 2)

    def test_clearing_history_drops_the_index(self) -> None:
        self.db.clear_history_logs()
        self.assertEqual(self.db.read_history_logs(site_id="s1"), [])

    def test_the_index_is_backfilled_on_upgrade(self) -> None:
        """An existing database gets its site associations rebuilt on open."""
        self.db.clear_history_logs()
        details = [{"site_id": "existing_site", "success": True, "message": "签到成功"}]
        with self.db._connection() as conn:
            conn.execute(
                "DELETE FROM storage_metadata WHERE key = ?", ("history_site_index_version",)
            )
            conn.execute(
                """
                INSERT INTO history_logs (timestamp, type, manual, success, report, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-08-18 08:30:00", "scheduled", 0, 1, "Existing SQLite history",
                    json.dumps(details, ensure_ascii=False),
                ),
            )

        reopened = DatabaseManager(self.db_path)
        indexed = reopened.read_history_logs(site_id="existing_site")
        self.assertEqual(len(indexed), 1)
        self.assertEqual(indexed[0]["report"], "Existing SQLite history")

    def test_malformed_details_do_not_break_indexing(self) -> None:
        self.db.record_history({
            "timestamp": "2026-08-21 08:00:00", "type": "scheduled", "manual": False,
            "success": True, "report": "odd", "details": ["not-a-dict", {"no_site": 1}],
        })
        self.assertEqual(len(self.db.read_history_logs(limit=None)), 5)


class HistoryCleanupTests(unittest.TestCase):
    """The auto_cleanup_logs master switch and its two numeric rules."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.temp_dir.name) / "data.db")

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass

    def _log(self, report: str, timestamp: str = "2026-08-16 12:00:00", **kwargs) -> None:
        self.db.record_history({
            "timestamp": timestamp, "type": "scheduled", "manual": False,
            "success": True, "report": report, "details": [],
        }, **kwargs)

    def _set(self, **values) -> None:
        settings = self.db.get_settings()
        settings.update(values)
        self.db.save_settings(settings)

    def test_defaults(self) -> None:
        settings = self.db.get_settings()
        self.assertIs(settings["auto_cleanup_logs"], True)
        self.assertEqual(settings["history_retention_days"], 0)
        self.assertEqual(settings["max_history_records"], 0)

    def test_row_limit_prunes(self) -> None:
        self._set(max_history_records=2)
        for index in range(4):
            self._log(f"r{index}", f"2026-08-16 12:0{index}:00")
        self.assertEqual(self.db.count_history_logs(), 2)
        self.assertEqual(self.db.read_history_logs()[0]["report"], "r3")

    def test_retention_days_prunes_by_age(self) -> None:
        self._set(history_retention_days=30)
        self._log("old", "2020-01-01 00:00:00")
        self._log("new", "2026-08-20 08:00:00")
        self.assertEqual(self.db.count_history_logs(), 1)
        self.assertEqual(self.db.read_history_logs()[0]["report"], "new")

    def test_the_master_switch_suppresses_both_rules(self) -> None:
        self._set(auto_cleanup_logs=False, max_history_records=1, history_retention_days=1)
        self._log("a", "2020-01-01 00:00:00")
        self._log("b", "2026-08-16 12:01:00")
        self.assertEqual(self.db.count_history_logs(), 2)

    def test_the_master_switch_beats_per_call_values(self) -> None:
        """An explicit per-call limit must not re-enable disabled cleanup."""
        self._set(auto_cleanup_logs=False)
        self._log("a")
        self._log("b", max_records=1, retention_days=1)
        self.assertEqual(self.db.count_history_logs(), 2)

    def test_string_switch_values_are_normalized(self) -> None:
        self._set(auto_cleanup_logs="false", max_history_records=1)
        self._log("a")
        self._log("b")
        self.assertEqual(self.db.count_history_logs(), 2)

        self._set(auto_cleanup_logs="yes", max_history_records=1)
        self._log("c")
        self.assertEqual(self.db.count_history_logs(), 1)
        self.assertEqual(self.db.read_history_logs()[0]["report"], "c")

    def test_per_call_values_override_global_numbers(self) -> None:
        self._set(max_history_records=100)
        for index in range(3):
            self._log(f"r{index}", f"2026-08-16 12:0{index}:00")
        self._log("last", "2026-08-16 12:09:00", max_records=1)
        self.assertEqual(self.db.count_history_logs(), 1)

    def test_saving_settings_invalidates_the_cache(self) -> None:
        """The cleanup settings are cached, so a change must clear that cache."""
        self._log("a")
        self._log("b")
        self.assertEqual(self.db.count_history_logs(), 2)
        self._set(max_history_records=1)
        self._log("c")
        self.assertEqual(self.db.count_history_logs(), 1)

    def test_negative_and_junk_values_disable_cleanup(self) -> None:
        self._set(max_history_records=-5, history_retention_days="abc")
        self._log("a")
        self._log("b")
        self.assertEqual(self.db.count_history_logs(), 2)


if __name__ == "__main__":
    unittest.main()
