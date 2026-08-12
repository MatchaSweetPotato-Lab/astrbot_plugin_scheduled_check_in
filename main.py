"""Main plugin entry point for AstrBot scheduled check-in plugin."""

from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any

import aiohttp

from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.api.web import json_response, request

from .core.adapters import create_adapter
from .core.scheduler import CheckInScheduler

from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

logger = logging.getLogger("astrbot")


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

        self.sites_file: Path = self.data_dir / "sites.json"
        self.settings_file: Path = self.data_dir / "settings.json"
        self.history_file: Path = self.data_dir / "history.json"

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
        """Read configured sites from JSON file.

        Returns:
            List of site configuration dictionaries.
        """
        if not self.sites_file.exists():
            return []
        try:
            with open(self.sites_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading sites.json: {e}")
            return []

    def save_sites(self, sites_data: list[dict[str, Any]]) -> None:
        """Write site configurations to JSON file.

        Args:
            sites_data: List of site dictionaries.
        """
        with open(self.sites_file, "w", encoding="utf-8") as f:
            json.dump(sites_data, f, ensure_ascii=False, indent=2)

    def get_settings(self) -> dict[str, Any]:
        """Read plugin settings from JSON file.

        Returns:
            Settings dictionary.
        """
        default_settings = {
            "enabled": True,
            "random_enabled": True,
            "start_time": "08:00",
            "end_time": "10:30",
            "checkin_time": "08:30",
        }
        if not self.settings_file.exists():
            return default_settings
        try:
            with open(self.settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                default_settings.update(data)
                return default_settings
        except Exception as e:
            logger.error(f"Error reading settings.json: {e}")
            return default_settings

    def save_settings(self, settings_data: dict[str, Any]) -> None:
        """Write settings to JSON file.

        Args:
            settings_data: Settings dictionary.
        """
        with open(self.settings_file, "w", encoding="utf-8") as f:
            json.dump(settings_data, f, ensure_ascii=False, indent=2)

    def record_history(self, results: list[Any], log_type: str = "scheduled") -> None:
        """Record check-in results into history JSON log.

        Args:
            results: List of CheckInResult objects.
            log_type: Type of log entry ("scheduled", "manual", "test").
        """
        logs = []
        if self.history_file.exists():
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except Exception:
                logs = []

        report_text = CheckInScheduler.format_report(results)
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": log_type,
            "manual": log_type == "manual",
            "success": all(r.success for r in results) if results else False,
            "report": report_text,
            "details": [r.to_dict() for r in results],
        }

        # Keep last 50 log entries
        logs.insert(0, entry)
        logs = logs[:50]

        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)

    def read_history_logs(self) -> list[dict[str, Any]]:
        """Read history log file.

        Returns:
            List of history log entries.
        """
        if not self.history_file.exists():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading history.json: {e}")
            return []

    def clear_history_logs(self) -> None:
        """Clear all history log entries."""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Error clearing history.json: {e}")

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
        sites = await request.json()
        self.save_sites(sites)
        return json_response({"status": "ok", "message": "站点配置保存成功"})

    async def api_test_site(self) -> Any:
        """Web API: Test site connection.

        Returns:
            JSON response with connection test result.
        """
        site_config = await request.json()
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
            adapter = create_adapter(site_config, session)
            result = await adapter.test_connection()
            self.record_history([result], log_type="test")
            return json_response(result.to_dict())

    async def api_run_checkin(self) -> Any:
        """Web API: Trigger instant check-in.

        Returns:
            JSON response with results.
        """
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass
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
        return json_response(settings)

    async def api_save_settings(self) -> Any:
        """Web API: Save settings.

        Returns:
            JSON response.
        """
        data = await request.json()
        self.save_settings(data)
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "全局设置已更新"})

    async def api_save_custom_target_time(self) -> Any:
        """Web API: Save custom manual next target check-in time.

        Returns:
            JSON response.
        """
        body = await request.json()
        target_time = str(body.get("target_time", "")).strip()
        settings = self.get_settings()
        settings["manual_target_time"] = target_time
        self.save_settings(settings)
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "下次签到时间已设置"})

    async def api_get_logs(self) -> Any:
        """Web API: Get history logs.

        Returns:
            JSON response.
        """
        return json_response(self.read_history_logs())

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
    async def cmd_clear_logs(self, event: AstrMessageEvent) -> None:
        """清空历史签到日志记录"""
        self.clear_history_logs()
        yield event.plain_result("历史签到日志已成功清空！")

    @filter.command("签到")
    async def cmd_checkin(self, event: AstrMessageEvent) -> None:
        """手动触发中转站签到打卡并回复简报结果"""
        yield event.plain_result("正在批量请求中转站签到，请稍候...")
        results = await self.scheduler.run_check_in_all(manual=True)
        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)

    @filter.command("签到状态")
    async def cmd_status(self, event: AstrMessageEvent) -> None:
        """查看当前配置的所有中转站连接状态与余额明细"""
        sites = self.get_sites()
        if not sites:
            yield event.plain_result("当前未配置任何中转站，请前往 Pages 页面添加！")
            return

        yield event.plain_result("正在查询各中转站余额与连通性...")
        results = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
            for site in sites:
                if site.get("enabled", True):
                    adapter = create_adapter(site, session)
                    res = await adapter.test_connection()
                    results.append(res)

        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)
