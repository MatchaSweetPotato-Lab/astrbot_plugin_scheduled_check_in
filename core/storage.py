"""SQLite data storage manager for AstrBot scheduled check-in plugin."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .http_client import DEFAULT_IMPERSONATE, normalize_impersonate

logger = logging.getLogger("astrbot")

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "random_enabled": True,
    "start_time": "08:00",
    "end_time": "10:30",
    "checkin_time": "08:30",
    "http_ssl_verify": True,
    "http_timeout_seconds": 15,
    "http_impersonate": DEFAULT_IMPERSONATE,
    "manual_target_time": "",
    "max_history_records": 0,
}


class DatabaseManager:
    """Manages SQLite database storage for sites, settings, and check-in history."""

    def __init__(self, db_path: Path | str, legacy_data_dir: Path | str | None = None) -> None:
        """Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
            legacy_data_dir: Optional directory to look for legacy JSON files to migrate.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        self._init_db()
        if legacy_data_dir:
            self._migrate_legacy_json(Path(legacy_data_dir))

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Create necessary database tables and indices if not already present."""
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    auth_value TEXT NOT NULL,
                    solve_acw_sc_v2 INTEGER NOT NULL DEFAULT 0,
                    checkin_endpoint TEXT NOT NULL DEFAULT '',
                    proxy TEXT NOT NULL DEFAULT '',
                    custom_headers TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_checkin_date TEXT,
                    last_checkin_time TEXT,
                    last_checkin_success INTEGER,
                    last_quota REAL,
                    display_order INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS history_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    manual INTEGER NOT NULL DEFAULT 0,
                    success INTEGER NOT NULL DEFAULT 0,
                    report TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_history_logs_id_desc ON history_logs(id DESC);
            """)

    def _migrate_legacy_json(self, legacy_dir: Path) -> None:
        """Migrate legacy JSON files into SQLite and rename them to .bak.

        Args:
            legacy_dir: Directory where legacy JSON files reside.
        """
        with self._lock, self._get_connection() as conn:
            # 1. Migrate sites.json
            sites_file = legacy_dir / "sites.json"
            if sites_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
                    if count == 0:
                        with open(sites_file, encoding="utf-8") as f:
                            sites_data = json.load(f)
                        if isinstance(sites_data, list):
                            self._insert_sites_records(conn, sites_data)
                            logger.info(f"Migrated {len(sites_data)} sites from sites.json to SQLite.")
                    self._backup_file(sites_file)
                except Exception as e:
                    logger.error(f"Failed to migrate sites.json: {e}", exc_info=True)

            # 2. Migrate settings.json
            settings_file = legacy_dir / "settings.json"
            if settings_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0]
                    if count == 0:
                        with open(settings_file, encoding="utf-8") as f:
                            settings_data = json.load(f)
                        if isinstance(settings_data, dict):
                            self._save_settings_records(conn, settings_data)
                            logger.info("Migrated settings from settings.json to SQLite.")
                    self._backup_file(settings_file)
                except Exception as e:
                    logger.error(f"Failed to migrate settings.json: {e}", exc_info=True)

            # 3. Migrate history.json
            history_file = legacy_dir / "history.json"
            if history_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM history_logs").fetchone()[0]
                    if count == 0:
                        with open(history_file, encoding="utf-8") as f:
                            history_data = json.load(f)
                        if isinstance(history_data, list):
                            # history_data is newest-first in JSON, insert in chronological order
                            for item in reversed(history_data):
                                if isinstance(item, dict):
                                    conn.execute(
                                        """
                                        INSERT INTO history_logs (timestamp, type, manual, success, report, details)
                                        VALUES (?, ?, ?, ?, ?, ?)
                                        """,
                                        (
                                            item.get("timestamp", ""),
                                            item.get("type", "scheduled"),
                                            1 if item.get("manual") else 0,
                                            1 if item.get("success") else 0,
                                            item.get("report", ""),
                                            json.dumps(item.get("details", []), ensure_ascii=False),
                                        ),
                                    )
                            logger.info(f"Migrated {len(history_data)} log entries from history.json to SQLite.")
                    self._backup_file(history_file)
                except Exception as e:
                    logger.error(f"Failed to migrate history.json: {e}", exc_info=True)

    @staticmethod
    def _backup_file(file_path: Path) -> None:
        """Rename an existing file to .bak to avoid re-migration."""
        try:
            bak_path = file_path.with_suffix(file_path.suffix + ".bak")
            if bak_path.exists():
                bak_path.unlink()
            file_path.rename(bak_path)
            logger.info(f"Renamed {file_path.name} to {bak_path.name}")
        except Exception as e:
            logger.warning(f"Could not backup {file_path.name}: {e}")

    # ------------------------------------------------------------------
    # Sites Operations
    # ------------------------------------------------------------------
    @staticmethod
    def _site_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a sites table SQLite Row to a dictionary."""
        site_dict = {
            "id": row["id"],
            "name": row["name"],
            "type": row["type"],
            "base_url": row["base_url"],
            "auth_type": row["auth_type"],
            "auth_value": row["auth_value"],
            "solve_acw_sc_v2": bool(row["solve_acw_sc_v2"]),
            "checkin_endpoint": row["checkin_endpoint"],
            "proxy": row["proxy"],
            "custom_headers": row["custom_headers"],
            "enabled": bool(row["enabled"]),
        }
        if row["last_checkin_date"] is not None:
            site_dict["last_checkin_date"] = row["last_checkin_date"]
        if row["last_checkin_time"] is not None:
            site_dict["last_checkin_time"] = row["last_checkin_time"]
        if row["last_checkin_success"] is not None:
            site_dict["last_checkin_success"] = bool(row["last_checkin_success"])
        if row["last_quota"] is not None:
            site_dict["last_quota"] = row["last_quota"]
        if "created_at" in row.keys() and row["created_at"]:
            site_dict["created_at"] = row["created_at"]
        if "updated_at" in row.keys() and row["updated_at"]:
            site_dict["updated_at"] = row["updated_at"]
        return site_dict

    def _insert_sites_records(
        self,
        conn: sqlite3.Connection,
        sites_data: list[dict[str, Any]],
        existing_created_at: dict[str, str] | None = None,
    ) -> None:
        """Insert or replace a list of site dicts into the database."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        existing_created_at = existing_created_at or {}
        for order, site in enumerate(sites_data):
            site_id = str(site.get("id") or f"site_{int(datetime.now().timestamp() * 1000)}_{order}").strip()
            name = str(site.get("name", "")).strip()
            stype = str(site.get("type", "new-api")).strip()
            base_url = str(site.get("base_url", "")).strip()
            auth_type = str(site.get("auth_type", "bearer_token")).strip()
            auth_value = str(site.get("auth_value", "")).strip()
            solve_acw = 1 if site.get("solve_acw_sc_v2") else 0
            endpoint = str(site.get("checkin_endpoint", "")).strip()
            proxy = str(site.get("proxy", "")).strip()
            headers = str(site.get("custom_headers", "")).strip()
            enabled = 1 if site.get("enabled", True) else 0
            last_date = site.get("last_checkin_date")
            last_time = site.get("last_checkin_time")
            last_success = None
            if "last_checkin_success" in site and site["last_checkin_success"] is not None:
                last_success = 1 if site["last_checkin_success"] else 0
            last_quota = site.get("last_quota")
            created_at = site.get("created_at") or existing_created_at.get(site_id) or now_str

            conn.execute(
                """
                INSERT INTO sites (
                    id, name, type, base_url, auth_type, auth_value, solve_acw_sc_v2,
                    checkin_endpoint, proxy, custom_headers, enabled,
                    last_checkin_date, last_checkin_time, last_checkin_success, last_quota,
                    display_order, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    type=excluded.type,
                    base_url=excluded.base_url,
                    auth_type=excluded.auth_type,
                    auth_value=excluded.auth_value,
                    solve_acw_sc_v2=excluded.solve_acw_sc_v2,
                    checkin_endpoint=excluded.checkin_endpoint,
                    proxy=excluded.proxy,
                    custom_headers=excluded.custom_headers,
                    enabled=excluded.enabled,
                    last_checkin_date=excluded.last_checkin_date,
                    last_checkin_time=excluded.last_checkin_time,
                    last_checkin_success=excluded.last_checkin_success,
                    last_quota=excluded.last_quota,
                    display_order=excluded.display_order,
                    updated_at=excluded.updated_at
                """,
                (
                    site_id, name, stype, base_url, auth_type, auth_value, solve_acw,
                    endpoint, proxy, headers, enabled,
                    last_date, last_time, last_success, last_quota,
                    order, created_at, now_str
                ),
            )

    def get_sites(self) -> list[dict[str, Any]]:
        """Get all configured sites ordered by display_order.

        Returns:
            List of site dictionaries.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM sites ORDER BY display_order ASC, created_at ASC")
            return [self._site_row_to_dict(row) for row in cursor.fetchall()]

    def save_sites(self, sites_data: list[dict[str, Any]]) -> None:
        """Replace the full sites configuration atomically while preserving created_at.

        Args:
            sites_data: New list of site dictionaries.
        """
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                cursor = conn.execute("SELECT id, created_at FROM sites")
                existing_created_at = {row["id"]: row["created_at"] for row in cursor.fetchall()}
                conn.execute("DELETE FROM sites")
                self._insert_sites_records(conn, sites_data, existing_created_at=existing_created_at)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def update_site_checkin_state(
        self,
        site_id: str,
        last_checkin_date: str,
        last_checkin_time: str,
        last_checkin_success: bool,
        last_quota: float | None = None,
    ) -> None:
        """Update check-in status and quota for a single site.

        Args:
            site_id: ID of the site to update.
            last_checkin_date: YYYY-MM-DD string.
            last_checkin_time: HH:MM:SS string.
            last_checkin_success: Success boolean flag.
            last_quota: Balance quota float.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE sites
                SET last_checkin_date = ?,
                    last_checkin_time = ?,
                    last_checkin_success = ?,
                    last_quota = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    last_checkin_date,
                    last_checkin_time,
                    1 if last_checkin_success else 0,
                    last_quota,
                    now_str,
                    site_id.strip(),
                ),
            )

    # ------------------------------------------------------------------
    # Settings Operations
    # ------------------------------------------------------------------
    def _save_settings_records(self, conn: sqlite3.Connection, settings_data: dict[str, Any]) -> None:
        """Internal helper to save settings key-values into database."""
        for key, value in settings_data.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value, ensure_ascii=False)),
            )

    def get_settings(self) -> dict[str, Any]:
        """Read plugin settings from SQLite.

        Returns:
            Settings dictionary merged with defaults.
        """
        settings = dict(DEFAULT_SETTINGS)
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("SELECT key, value FROM settings")
            for row in cursor.fetchall():
                try:
                    settings[row["key"]] = json.loads(row["value"])
                except Exception:
                    settings[row["key"]] = row["value"]

        settings["http_impersonate"] = normalize_impersonate(settings.get("http_impersonate"))
        return settings

    def save_settings(self, settings_data: dict[str, Any]) -> None:
        """Save settings dictionary to SQLite.

        Args:
            settings_data: Settings dictionary.
        """
        with self._lock, self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                self._save_settings_records(conn, settings_data)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ------------------------------------------------------------------
    # History Logs Operations
    # ------------------------------------------------------------------
    def record_history(
        self,
        entry: dict[str, Any],
        max_records: int | None = None,
    ) -> None:
        """Record a single check-in result history log and optionally prune old entries.

        Args:
            entry: Log dictionary with keys timestamp, type, manual, success, report, details.
            max_records: Maximum number of history records to retain. If None, read from
                settings ("max_history_records"). If <= 0, no pruning is performed (unlimited).
        """
        if max_records is None:
            settings = self.get_settings()
            try:
                max_records = int(settings.get("max_history_records", 0))
            except (ValueError, TypeError):
                max_records = 0

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO history_logs (timestamp, type, manual, success, report, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    entry.get("type", "scheduled"),
                    1 if entry.get("manual") else 0,
                    1 if entry.get("success") else 0,
                    entry.get("report", ""),
                    json.dumps(entry.get("details", []), ensure_ascii=False),
                ),
            )

            # Auto prune if max_records > 0
            if isinstance(max_records, int) and max_records > 0:
                conn.execute(
                    """
                    DELETE FROM history_logs
                    WHERE id NOT IN (
                        SELECT id FROM history_logs ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (max_records,),
                )

    def read_history_logs(
        self,
        limit: int = 100,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read recent history log records ordered from newest to oldest.

        Args:
            limit: Maximum number of logs to return.
            before_id: Optional log ID cursor for pagination. When provided, returns logs with id < before_id.

        Returns:
            List of history log dictionaries.
        """
        with self._lock, self._get_connection() as conn:
            if before_id is not None:
                cursor = conn.execute(
                    "SELECT * FROM history_logs WHERE id < ? ORDER BY id DESC LIMIT ?",
                    (before_id, limit),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM history_logs ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            logs = []
            for row in cursor.fetchall():
                try:
                    details = json.loads(row["details"])
                except Exception:
                    details = []

                logs.append({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "type": row["type"],
                    "manual": bool(row["manual"]),
                    "success": bool(row["success"]),
                    "report": row["report"],
                    "details": details,
                })
            return logs

    def count_history_logs(self) -> int:
        """Count the total number of history log records in SQLite.

        Returns:
            Total record count integer.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM history_logs")
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def clear_history_logs(self) -> None:
        """Clear all history log records from SQLite."""
        with self._lock, self._get_connection() as conn:
            conn.execute("DELETE FROM history_logs")
