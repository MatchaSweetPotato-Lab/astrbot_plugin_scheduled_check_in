"""Scheduler module managing daily sign-in execution and report formatting."""

import asyncio
from datetime import datetime
import logging
import random
from typing import Any

from .adapters import CheckInResult, create_adapter
from .http_client import create_client_session

logger = logging.getLogger("astrbot")


class CheckInScheduler:
    """Manager for scheduled daily check-ins and notification dispatch."""

    def __init__(self, plugin_inst: Any) -> None:
        """Initialize scheduler instance.

        Args:
            plugin_inst: Reference to parent Star plugin instance.
        """
        self.plugin = plugin_inst
        self._task: asyncio.Task | None = None
        self._running: bool = False
        self._last_run_date: str = ""
        self._today_target_time: str = ""
        self._tomorrow_target_time: str = ""
        self._today_date_str: str = ""

    def reset_today_target_time(self) -> None:
        """Reset cached target time when settings are updated."""
        self._today_target_time = ""
        self._tomorrow_target_time = ""
        self._today_date_str = ""

    def get_next_target_info(self) -> dict[str, Any]:
        """Get next scheduled check-in time details.

        Returns:
            Dict containing enabled, is_manual, target_time, is_tomorrow, and display_text.
        """
        now = datetime.now()
        current_date = now.strftime("%Y-%m-%d")
        now_minutes = now.hour * 60 + now.minute

        settings = self.plugin.get_settings()
        enabled = settings.get("enabled", True)
        manual_time = settings.get("manual_target_time", "").strip()

        if not enabled:
            return {
                "enabled": False,
                "is_manual": False,
                "target_time": "--:--",
                "is_tomorrow": False,
                "display_text": "自动定时签到已禁用",
            }

        # Priority 1: Manual target time override (unrestricted by window config)
        if manual_time:
            try:
                mh, mm = map(int, manual_time.split(":"))
                target_mins = mh * 60 + mm
                is_tomorrow = (now_minutes > target_mins) or (self._last_run_date == current_date and now_minutes >= target_mins)
                day_prefix = "明日" if is_tomorrow else "今日"
                return {
                    "enabled": True,
                    "is_manual": True,
                    "target_time": f"{mh:02d}:{mm:02d}",
                    "is_tomorrow": is_tomorrow,
                    "display_text": f"下次预计签到: {day_prefix} {mh:02d}:{mm:02d} (手动)",
                }
            except Exception:
                pass

        # Priority 2: Automatic Random / Fixed calculation
        random_enabled = settings.get("random_enabled", True)
        start_time = settings.get("start_time", "08:00")
        end_time = settings.get("end_time", "10:30")
        fixed_time = settings.get("checkin_time", "08:30")

        if random_enabled:
            try:
                sh, sm = map(int, start_time.split(":"))
                eh, em = map(int, end_time.split(":"))
                start_mins = sh * 60 + sm
                end_mins = eh * 60 + em
                if end_mins <= start_mins:
                    end_mins = start_mins + 30
            except Exception:
                start_mins, end_mins = 8 * 60, 10 * 60 + 30

            # If today's window has already passed OR today has already run
            if now_minutes > end_mins or self._last_run_date == current_date:
                if not self._tomorrow_target_time or self._today_date_str != current_date:
                    target_mins = random.randint(start_mins, end_mins)
                    th = (target_mins // 60) % 24
                    tm = target_mins % 60
                    self._tomorrow_target_time = f"{th:02d}:{tm:02d}"
                    self._today_date_str = current_date
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": self._tomorrow_target_time,
                    "is_tomorrow": True,
                    "display_text": f"下次预计签到: 明日 {self._tomorrow_target_time}",
                }
            else:
                if self._today_date_str != current_date or not self._today_target_time:
                    pick_start = max(start_mins, now_minutes)
                    target_mins = random.randint(pick_start, end_mins)
                    th = (target_mins // 60) % 24
                    tm = target_mins % 60
                    self._today_target_time = f"{th:02d}:{tm:02d}"
                    self._today_date_str = current_date
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": self._today_target_time,
                    "is_tomorrow": False,
                    "display_text": f"下次预计签到: 今日 {self._today_target_time}",
                }
        else:
            try:
                fh, fm = map(int, fixed_time.split(":"))
                fixed_mins = fh * 60 + fm
            except Exception:
                fixed_mins = 8 * 60 + 30

            if now_minutes > fixed_mins or self._last_run_date == current_date:
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": fixed_time,
                    "is_tomorrow": True,
                    "display_text": f"下次预计签到: 明日 {fixed_time}",
                }
            else:
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": fixed_time,
                    "is_tomorrow": False,
                    "display_text": f"下次预计签到: 今日 {fixed_time}",
                }

    def start(self) -> None:
        """Start the background scheduler task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info("CheckInScheduler started background loop.")

    def stop(self) -> None:
        """Stop the background scheduler task."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("CheckInScheduler task cancelled.")

    @staticmethod
    def _update_site_checkin_state(
        site_config: dict[str, Any], result: CheckInResult, checked_at: datetime | None = None
    ) -> None:
        """Apply a check-in result to a site configuration in memory."""
        checked_at = checked_at or datetime.now()
        site_config["last_checkin_date"] = checked_at.strftime("%Y-%m-%d")
        site_config["last_checkin_time"] = checked_at.strftime("%H:%M:%S")
        site_config["last_checkin_success"] = result.success
        site_config["last_quota"] = result.total_quota

    def _record_checkin_history(self, results: list[CheckInResult], manual: bool) -> None:
        """Record check-in results using the same log type for all flows."""
        self.plugin.record_history(results, log_type="manual" if manual else "scheduled")

    def _persist_checkin_results(
        self,
        all_sites: list[dict[str, Any]],
        results: list[CheckInResult],
        manual: bool,
        persist_sites: bool = True,
    ) -> None:
        """Persist site changes and record a history entry for check-in results."""
        if persist_sites:
            self.plugin.save_sites(all_sites)
        self._record_checkin_history(results, manual)

    async def _scheduler_loop(self) -> None:
        """Internal background loop running check-ins at configured daily time window."""
        while self._running:
            try:
                info = self.get_next_target_info()
                if info.get("enabled") and not info.get("is_tomorrow"):
                    now = datetime.now()
                    current_date = now.strftime("%Y-%m-%d")
                    current_hhmm = now.strftime("%H:%M")
                    target_time = info.get("target_time")

                    if current_hhmm == target_time and self._last_run_date != current_date:
                        self._last_run_date = current_date
                        logger.info(f"Triggering scheduled daily check-in at target time ({target_time})...")
                        results = await self.run_check_in_all()
                        report_text = self.format_report(results)
                        await self.plugin.send_notification(report_text)

                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in CheckInScheduler loop: {e}", exc_info=True)
                await asyncio.sleep(60)

    async def run_check_in_all(self, manual: bool = False, force: bool = False) -> list[CheckInResult]:
        """Execute check-in for all enabled sites.

        Args:
            manual: Flag indicating if this was triggered manually.
            force: If True, execute check-in even if already signed in today.

        Returns:
            List of CheckInResult objects.
        """
        all_sites = self.plugin.get_sites()
        enabled_sites = [s for s in all_sites if s.get("enabled", True)]
        results: list[CheckInResult] = []

        if not enabled_sites:
            logger.info("No enabled check-in sites configured.")
            return results

        checked_at = datetime.now()
        today_str = checked_at.strftime("%Y-%m-%d")
        sites_updated = False

        async with create_client_session() as session:
            for idx, site_config in enumerate(enabled_sites):
                site_id = site_config.get("id", "")
                site_name = site_config.get("name", "Unknown Site")
                last_date = site_config.get("last_checkin_date", "")
                last_success = site_config.get("last_checkin_success", False)

                # Skip if already signed in today successfully
                if not force and last_date == today_str and last_success:
                    checkin_time = site_config.get("last_checkin_time", "")
                    msg = f"今日已完成签到 ({checkin_time})" if checkin_time else "今日已完成签到"
                    results.append(
                        CheckInResult(
                            site_id=site_id,
                            site_name=site_name,
                            success=True,
                            message=msg,
                            total_quota=site_config.get("last_quota", 0.0),
                        )
                    )
                    continue

                if idx > 0:
                    await asyncio.sleep(random.uniform(1.5, 3.5))

                adapter = create_adapter(site_config, session)
                result = await adapter.check_in()
                results.append(result)

                self._update_site_checkin_state(site_config, result, checked_at)
                sites_updated = True

        # Clear temporary manual_target_time override after check-in execution
        settings = self.plugin.get_settings()
        if settings.get("manual_target_time"):
            settings["manual_target_time"] = ""
            self.plugin.save_settings(settings)
            self.reset_today_target_time()

        self._persist_checkin_results(all_sites, results, manual, persist_sites=sites_updated)
        return results

    async def run_check_in_site(self, site_id: str, manual: bool = True) -> CheckInResult | None:
        """Force a check-in for one configured site, ignoring today's skip state.

        Args:
            site_id: ID of the configured site to check in.
            manual: Flag indicating whether this was triggered manually.

        Returns:
            The check-in result, or None if the site does not exist.
        """
        all_sites = self.plugin.get_sites()
        site_config = next((s for s in all_sites if str(s.get("id", "")) == site_id), None)
        if site_config is None:
            return None

        async with create_client_session() as session:
            adapter = create_adapter(site_config, session)
            result = await adapter.check_in()

        self._update_site_checkin_state(site_config, result)
        self._persist_checkin_results(all_sites, [result], manual)
        return result

    @staticmethod
    def format_report(results: list[CheckInResult]) -> str:
        """Format check-in results into a clean markdown report card.

        Args:
            results: List of CheckInResult objects.

        Returns:
            Formatted markdown string.
        """
        if not results:
            return "未配置有效的中转站签到目标。"

        lines = ["每日 API 中转站自动签到简报", "━━━━━━━━━━━━━━━━━━━━"]
        success_count = 0
        total_quota_sum = 0.0

        for r in results:
            if r.success:
                status_str = "[成功]"
                success_count += 1
            elif r.expired:
                status_str = "[Token失效]"
            else:
                status_str = "[失败]"

            line = f"{status_str} {r.site_name} | {r.message}"
            if r.total_quota > 0:
                line += f" (余额: ${r.total_quota:.2f})"
                total_quota_sum += r.total_quota
            lines.append(line)

        lines.append("━━━━━━━━━━━━━━━━━━━━")
        summary_line = f"完成统计: {success_count}/{len(results)}"
        if total_quota_sum > 0:
            summary_line += f" | 总余额估算: ${total_quota_sum:.2f}"
        lines.append(summary_line)

        return "\n".join(lines)
