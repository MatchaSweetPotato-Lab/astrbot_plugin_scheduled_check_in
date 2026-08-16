"""Main plugin entry point for AstrBot scheduled check-in plugin."""

import json
import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from pathlib import Path
from typing import Any

from astrbot.api.event import AstrMessageEvent, MessageEventResult, filter
from astrbot.api.star import Context, Star, register
from astrbot.api.web import error_response, json_response, request
from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

from .core.adapters import create_adapter
from .core.http_client import (
    DEFAULT_IMPERSONATE,
    create_client_session,
    get_impersonate_options,
    normalize_impersonate,
)
from .core.scheduler import CheckInScheduler
from .core.storage import DEFAULT_SETTINGS, DatabaseManager

logger = logging.getLogger("astrbot")


async def _read_json_body() -> tuple[bool, Any]:
    """Parse the current request body without leaking JSON decode failures."""
    try:
        payload = await request.json()
    except Exception:
        return False, None
    if payload is None:
        return False, None
    return True, payload


@register(
    "astrbot_plugin_scheduled_check_in",
    "Soulter",
    "LLM API 中转站自动签到插件，支持 Pages 可视化配置与定时广播简报",
    "1.0.0",
)
class ScheduledCheckInPlugin(Star):
    """Star plugin managing auto sign-ins for API relay stations."""

    def __init__(self, context: Context, config: dict[str, Any] | None = None) -> None:
        """Initialize plugin and storage paths.

        Args:
            context: AstrBot plugin Context object.
            config: Optional configuration dictionary.
        """
        super().__init__(context, config)
        self.data_dir: Path = Path(get_astrbot_plugin_data_path()) / "astrbot_plugin_scheduled_check_in"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(self.data_dir / "data.db", legacy_data_dir=self.data_dir)
        self.acw_cache_file: Path = self.data_dir / "acw_sc_v2_cache.json"

        self.scheduler = CheckInScheduler(self)
        self._register_routes()

    async def initialize(self) -> None:
        """Lifecycle method called after plugin initialization."""
        self.scheduler.start()
        logger.info("ScheduledCheckInPlugin initialized successfully.")

    async def terminate(self) -> None:
        """Lifecycle method called when plugin is stopping or unloading."""
        self.scheduler.stop()
        logger.info("ScheduledCheckInPlugin terminated successfully.")

    # ------------------------------------------------------------------
    # Data Storage Utilities
    # ------------------------------------------------------------------
    def get_sites(self) -> list[dict[str, Any]]:
        """Read configured sites from SQLite database.

        Returns:
            List of site configuration dictionaries.
        """
        try:
            return self.db.get_sites()
        except Exception as e:
            logger.error(f"Error reading sites from database: {e}", exc_info=True)
            return []

    def save_sites(self, sites_data: list[dict[str, Any]]) -> None:
        """Write site configurations to SQLite database.

        Args:
            sites_data: List of site dictionaries.
        """
        try:
            self.db.save_sites(sites_data)
        except Exception as e:
            logger.error(f"Error saving sites to database: {e}", exc_info=True)

    def update_site_checkin_state(
        self,
        site_id: str,
        last_checkin_date: str,
        last_checkin_time: str,
        last_checkin_success: bool,
        last_quota: float | None = None,
    ) -> None:
        """Update check-in status and quota for a single site in SQLite database.

        Args:
            site_id: ID of the site to update.
            last_checkin_date: YYYY-MM-DD string.
            last_checkin_time: HH:MM:SS string.
            last_checkin_success: Success boolean flag.
            last_quota: Balance quota float.
        """
        try:
            self.db.update_site_checkin_state(
                site_id=site_id,
                last_checkin_date=last_checkin_date,
                last_checkin_time=last_checkin_time,
                last_checkin_success=last_checkin_success,
                last_quota=last_quota,
            )
        except Exception as e:
            logger.error(f"Error updating site check-in state in database: {e}", exc_info=True)

    def get_settings(self) -> dict[str, Any]:
        """Read plugin settings from SQLite database.

        Returns:
            Settings dictionary.
        """
        try:
            return self.db.get_settings()
        except Exception as e:
            logger.error(f"Error reading settings from database: {e}", exc_info=True)
            return dict(DEFAULT_SETTINGS)

    def save_settings(self, settings_data: dict[str, Any]) -> None:
        """Write settings to SQLite database.

        Args:
            settings_data: Settings dictionary.
        """
        try:
            self.db.save_settings(settings_data)
        except Exception as e:
            logger.error(f"Error saving settings to database: {e}", exc_info=True)

    def record_history(self, results: list[Any], log_type: str = "scheduled") -> None:
        """Record check-in results into history SQLite table.

        Args:
            results: List of CheckInResult objects.
            log_type: Type of log entry ("scheduled", "manual", "test").
        """
        try:
            report_text = CheckInScheduler.format_report(results)
            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": log_type,
                "manual": log_type == "manual",
                "success": all(r.success for r in results) if results else False,
                "report": report_text,
                "details": [r.to_dict() for r in results],
            }
            self.db.record_history(entry)
        except Exception as e:
            logger.error(f"Error recording history to database: {e}", exc_info=True)

    def read_history_logs(
        self,
        limit: int = 100,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read history log entries from SQLite database.

        Args:
            limit: Maximum number of logs to return.
            before_id: Optional log ID cursor.

        Returns:
            List of history log entries.
        """
        try:
            return self.db.read_history_logs(limit=limit, before_id=before_id)
        except Exception as e:
            logger.error(f"Error reading history logs from database: {e}", exc_info=True)
            return []

    def count_history_logs(self) -> int:
        """Count total history log entries in SQLite database."""
        try:
            return self.db.count_history_logs()
        except Exception as e:
            logger.error(f"Error counting history logs from database: {e}", exc_info=True)
            return 0

    def clear_history_logs(self) -> None:
        """Clear all history log entries from SQLite database."""
        try:
            self.db.clear_history_logs()
        except Exception as e:
            logger.error(f"Error clearing history logs from database: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Web API Routes for Pages Dashboard
    # ------------------------------------------------------------------
    def _register_routes(self) -> None:
        """Register custom plugin REST API routes with AstrBot."""
        prefix = "/astrbot_plugin_scheduled_check_in"
        routes = [
            ("/api/sites", self.api_get_sites, ["GET"], "获取站点列表"),
            ("/api/sites", self.api_save_sites, ["POST"], "保存站点配置"),
            ("/api/sites/test", self.api_test_site, ["POST"], "测试站点连接"),
            ("/api/sites/recheckin", self.api_recheckin_site, ["POST"], "重新签到单个站点"),
            ("/api/checkin/run", self.api_run_checkin, ["POST"], "触发一键打卡"),
            ("/api/settings", self.api_get_settings, ["GET"], "获取设置"),
            ("/api/settings", self.api_save_settings, ["POST"], "保存设置"),
            ("/api/settings/target_time", self.api_save_custom_target_time, ["POST"], "设置自定义下次签到时间"),
            ("/api/logs", self.api_get_logs, ["GET"], "获取打卡日志"),
            ("/api/logs/clear", self.api_clear_logs, ["POST"], "清空打卡日志"),
        ]

        for path, handler, methods, desc in routes:
            self.context.register_web_api(
                route=f"{prefix}{path}",
                view_handler=handler,
                methods=methods,
                desc=desc,
            )
            self.context.register_web_api(
                route=path,
                view_handler=handler,
                methods=methods,
                desc=desc,
            )

    async def api_get_sites(self) -> Any:
        """Web API: Get sites.

        Returns:
            JSON response.
        """
        return json_response(self.get_sites())

    async def api_save_sites(self) -> Any:
        """Web API: Save sites.

        Returns:
            JSON response.
        """
        parsed, sites = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(sites, list) or not all(
            isinstance(site, dict) for site in sites
        ):
            return error_response("站点配置必须是对象数组")
        self.save_sites(sites)
        return json_response({"status": "ok", "message": "站点配置保存成功"})

    async def api_test_site(self) -> Any:
        """Web API: Test site connection.

        Returns:
            JSON response with connection test result.
        """
        parsed, site_config = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(site_config, dict):
            return error_response("站点配置必须是对象")
        async with create_client_session(self.get_settings()) as session:
            adapter = create_adapter(site_config, session, self.acw_cache_file)
            result = await adapter.test_connection()
            self.record_history([result], log_type="test")
            return json_response(result.to_dict())

    async def api_recheckin_site(self) -> Any:
        """Web API: Force a check-in for one configured site."""
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("重新签到请求必须是对象")
        site_id = str(body.get("site_id", "")).strip()
        if not site_id:
            return error_response("缺少站点 ID")

        result = await self.scheduler.run_check_in_site(site_id, manual=True)
        if result is None:
            return error_response("站点不存在")

        return json_response({"status": "ok", "result": result.to_dict()})

    async def api_run_checkin(self) -> Any:
        """Web API: Trigger instant check-in.

        Returns:
            JSON response with results.
        """
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("签到请求必须是对象")
        force = bool(body.get("force", False))
        results = await self.scheduler.run_check_in_all(manual=True, force=force)
        return json_response({"status": "ok", "results": [r.to_dict() for r in results]})

    async def api_get_settings(self) -> Any:
        """Web API: Get settings.

        Returns:
            JSON response.
        """
        settings = self.get_settings()
        target_info = self.scheduler.get_next_target_info()
        settings["target_info"] = target_info
        settings["today_target_time"] = target_info.get("display_text", "")
        settings["http_impersonate_options"] = get_impersonate_options()
        return json_response(settings)

    async def api_save_settings(self) -> Any:
        """Web API: Save settings.

        Returns:
            JSON response.
        """
        parsed, data = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(data, dict):
            return error_response("全局设置必须是对象")
        settings = self.get_settings()
        settings.update(data)
        if "max_history_records" in data:
            try:
                settings["max_history_records"] = max(0, int(data["max_history_records"]))
            except (ValueError, TypeError):
                settings["max_history_records"] = 0
        settings["http_impersonate"] = normalize_impersonate(
            settings.get("http_impersonate")
        )
        self.save_settings(settings)
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "全局设置已更新"})

    async def api_save_custom_target_time(self) -> Any:
        """Web API: Save custom manual next target check-in time.

        Returns:
            JSON response.
        """
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("签到时间配置必须是对象")
        target_time = str(body.get("target_time", "")).strip()
        settings = self.get_settings()
        settings["manual_target_time"] = target_time
        self.save_settings(settings)
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "下次签到时间已设置"})

    async def api_get_logs(self) -> Any:
        """Web API: Get history logs with pagination support.

        Returns:
            JSON response with items, total, has_more, and next_before_id.
        """
        limit = 20
        before_id = None
        try:
            if hasattr(request, "query") and request.query:
                q_limit = request.query.get("limit")
                if q_limit is not None and str(q_limit).strip():
                    limit = max(1, min(100, int(q_limit)))
                q_before_id = request.query.get("before_id")
                if q_before_id is not None and str(q_before_id).strip():
                    before_id = int(q_before_id)
        except Exception as e:
            logger.warning(f"Failed to parse query params for /api/logs: {e}")

        logs = self.read_history_logs(limit=limit, before_id=before_id)
        total = self.count_history_logs() if before_id is None else None
        has_more = len(logs) == limit
        next_before_id = logs[-1]["id"] if (has_more and logs) else None

        response_data: dict[str, Any] = {
            "items": logs,
            "has_more": has_more,
            "next_before_id": next_before_id,
        }
        if total is not None:
            response_data["total"] = total

        return json_response(response_data)

    async def api_clear_logs(self) -> Any:
        """Web API: Clear history logs.

        Returns:
            JSON response.
        """
        self.clear_history_logs()
        return json_response({"status": "ok", "message": "历史日志已清空"})

    # ------------------------------------------------------------------
    # Notification & Chat Commands
    # ------------------------------------------------------------------
    async def send_notification(self, text: str) -> None:
        """Log or dispatch notification text.

        Args:
            text: Markdown report text.
        """
        logger.info(f"CheckIn Notification:\n{text}")

    @filter.command("清空签到日志")
    async def cmd_clear_logs(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """清空历史签到日志记录"""
        self.clear_history_logs()
        yield event.plain_result("历史签到日志已成功清空！")

    @filter.command("签到")
    async def cmd_checkin(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """手动触发中转站签到打卡并回复简报结果"""
        yield event.plain_result("正在批量请求中转站签到，请稍候...")
        results = await self.scheduler.run_check_in_all(manual=True)
        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)
    @filter.command("签到状态")
    async def cmd_status(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """查看当前配置的所有中转站连接状态与余额明细"""
        sites = self.get_sites()
        if not sites:
            yield event.plain_result("当前未配置任何中转站，请前往 Pages 页面添加！")
            return

        yield event.plain_result("正在查询各中转站余额与连通性...")
        results = []
        async with create_client_session(self.get_settings()) as session:
            for site in sites:
                site_id = str(site.get("id", "")).strip()
                if not site_id:
                    logger.warning(
                        "Skipping status check for site without an ID: %s",
                        site.get("name", "<unnamed>"),
                    )
                    continue
                if site.get("enabled") is not True:
                    logger.info(
                        "Skipping status check for site %s because enabled is not true",
                        site_id,
                    )
                    continue
                adapter = create_adapter(site, session, self.acw_cache_file)
                res = await adapter.test_connection()
                results.append(res)

        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)
