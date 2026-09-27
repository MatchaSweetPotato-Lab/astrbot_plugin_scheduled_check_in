"""Running each site's scheduled tasks when they fall due.

One loop for all sites, ticking every few seconds. Each tick works out, for
every enabled task of every enabled site, when it runs next — keeping a time
already worked out unless its schedule changed — and runs those that are due,
one after another. Run times and outcomes live in the ``site_task_state``
table, so they survive a restart and show in the dashboard.

A run that fell due while AstrBot was stopped is not caught up: once more than
:data:`MISFIRE_GRACE_SECONDS` late it is skipped and the next one scheduled, so
a restart never sets off a burst of stale requests. Nothing runs while the
vault is locked, as with check-ins.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .adapters import CheckInResult, create_adapter, persist_writeback
from .http_client import RequestOptions, create_client_session
from .task_schema import (
    ScheduleError,
    next_run,
    schedule_key,
    task_label,
    validate_task,
)

logger = logging.getLogger("astrbot")

TICK_SECONDS = 15
MISFIRE_GRACE_SECONDS = 5 * 60
LOG_TYPE_TASK = "task"
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _format(moment: datetime | None) -> str | None:
    return moment.strftime(_TIME_FORMAT) if moment is not None else None


def _parse(text: Any) -> datetime | None:
    try:
        return datetime.strptime(str(text), _TIME_FORMAT)
    except (TypeError, ValueError):
        return None


@dataclass
class DueTask:
    """A task to run now, with the site it belongs to."""

    site: dict[str, Any]
    task: dict[str, Any]


class TaskScheduler:
    """Runs the scheduled tasks of every site."""

    def __init__(self, plugin: Any) -> None:
        """Initialize the scheduler.

        Args:
            plugin: The plugin, for its database, settings, sites, history and
                the Cloudflare context each run gets.
        """
        self.plugin = plugin
        self._task: asyncio.Task | None = None
        # Serialises runs, so a manual run never overlaps a scheduled one of
        # the same task and the state they write stays in order.
        self._run_lock = asyncio.Lock()

    def start(self) -> None:
        """Start the background loop."""
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._loop())

    def stop(self) -> None:
        """Stop the background loop."""
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Scheduled task loop failed: {exc}", exc_info=True)
            await asyncio.sleep(TICK_SECONDS)

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------
    def _locked(self) -> bool:
        try:
            return bool(self.plugin.is_config_locked())
        except Exception:
            return False

    def plan(self, now: datetime | None = None) -> list[DueTask]:
        """Bring every task's next run up to date, and return those due now.

        Cheap and without network access, so it also runs right after the
        sites are saved, and a changed schedule shows its next run at once.
        """
        if self._locked():
            return []
        now = now or datetime.now()
        db = self.plugin.db
        states = db.get_task_states()
        due: list[DueTask] = []
        for site in self.plugin.get_sites():
            site_id = str(site.get("id") or "").strip()
            if not site_id or site.get("enabled") is not True or site.get("locked"):
                continue
            for task in site.get("tasks") or []:
                if not task.get("enabled") or validate_task(task):
                    continue
                key = schedule_key(task)
                state = states.get((site_id, task["id"])) or {}
                scheduled = _parse(state.get("next_run_at"))
                if state.get("schedule_key") != key or scheduled is None:
                    self._schedule(site_id, task, key, now)
                    continue
                if scheduled > now:
                    continue
                if now - scheduled > timedelta(seconds=MISFIRE_GRACE_SECONDS):
                    logger.info(
                        "Skipping missed run of task %s (%s) due at %s",
                        task_label(task), site.get("name"), state.get("next_run_at"),
                    )
                    self._schedule(site_id, task, key, now)
                    continue
                due.append(DueTask(site, task))
        return due

    def _schedule(self, site_id: str, task: dict[str, Any], key: str, after: datetime) -> None:
        try:
            upcoming = next_run(task, after)
        except ScheduleError as exc:
            logger.warning(f"Cannot schedule task {task_label(task)}: {exc}")
            upcoming = None
        self.plugin.db.set_task_schedule(site_id, task["id"], key, _format(upcoming))

    async def tick(self, now: datetime | None = None) -> list[CheckInResult]:
        """Plan, then run whatever is due."""
        results = []
        for item in self.plan(now):
            results.append(await self.run(item.site, item.task, manual=False))
        return results

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------
    async def run(self, site: dict[str, Any], task: dict[str, Any], manual: bool) -> CheckInResult:
        """Run one task now and record how it went.

        A scheduled run also works out the next one, counted from now, so a
        slow request can never make the same slot fire twice. A manual run
        leaves the schedule alone.

        Args:
            site: The site, as stored or as the editor posted it.
            task: One of its tasks, normalized.
            manual: Started from the dashboard rather than by the schedule.
        """
        site_id = str(site.get("id") or "").strip()
        async with self._run_lock:
            started = datetime.now()
            if not manual:
                self._schedule(site_id, task, schedule_key(task), started)
            settings = self.plugin.get_settings()
            try:
                async with create_client_session(settings) as session:
                    adapter = create_adapter(
                        site,
                        session,
                        getattr(self.plugin, "acw_cache_file", None),
                        self.plugin.cloudflare_context(settings),
                        RequestOptions.from_settings(settings),
                    )
                    result = await adapter.run_task(task)
                    if site_id:
                        persist_writeback(self.plugin.db, site_id, adapter.writeback)
            except Exception as exc:
                logger.warning(f"Scheduled task {task_label(task)} failed: {exc}", exc_info=True)
                result = CheckInResult(
                    site_id=site_id,
                    site_name=f"{site.get('name') or ''} · {task_label(task)}",
                    success=False,
                    message=f"运行异常：{exc}",
                )
            if site_id:
                self.plugin.db.record_task_run(
                    site_id, task["id"], _format(started) or "", result.success, result.message
                )
        if manual or task.get("log_history", True):
            self.plugin.record_history([result], log_type=LOG_TYPE_TASK, manual=manual)
        logger.info(
            "Task %s of %s: %s",
            task_label(task),
            site.get("name"),
            result.message,
        )
        return result
