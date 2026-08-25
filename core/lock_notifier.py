"""One-shot alert telling the operator that the credential vault is locked.

A locked vault makes every scheduled check-in skip silently, which is
indistinguishable from a quiet day unless somebody opens the dashboard. This
module watches the vault state and pushes a single message to a configured
session when the vault closes, then stays quiet until it is opened again.

The decision logic is kept free of AstrBot types: the plugin injects the vault
state, the configured target, the persisted "already sent" flag and the actual
send call, so the once-per-lock contract can be tested on its own.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger("astrbot")

# Sent verbatim to the configured session. It names the panel to open, because
# the vault can only be unlocked from the web UI — never from a chat command.
LOCK_ALERT_TEXT = (
    "🔒 定时签到 | 凭据已锁定\n"
    "配置加密已启用但尚未解锁，自动签到将被跳过，站点凭据当前不可读。\n"
    "请前往 AstrBot Pages「定时自动签到」面板输入密钥，或使用通行密钥解锁。"
)


class LockNotifier:
    """Delivers :data:`LOCK_ALERT_TEXT` once per locked period.

    "Once" is anchored to a persisted flag rather than to process lifetime, so
    restarting AstrBot while the vault is still locked does not re-alert. The
    flag is cleared as soon as the vault is observed unlocked, which re-arms the
    alert for the next lock.
    """

    def __init__(
        self,
        *,
        is_locked: Callable[[], bool],
        get_target: Callable[[], str],
        was_sent: Callable[[], bool],
        mark_sent: Callable[[bool], None],
        send: Callable[[str, str], Awaitable[bool]],
    ) -> None:
        """Wire the notifier to its host plugin.

        Args:
            is_locked: Returns whether the vault is encrypted but keyless.
            get_target: Returns the configured session, empty when disabled.
            was_sent: Returns the persisted "already alerted" flag.
            mark_sent: Persists the "already alerted" flag.
            send: Delivers ``(target, text)`` and reports whether it landed.
        """
        self._is_locked = is_locked
        self._get_target = get_target
        self._was_sent = was_sent
        self._mark_sent = mark_sent
        self._send = send
        # Last delivery problem, so a misconfigured target is reported once
        # instead of on every poll.
        self._last_failure: str = ""

    async def poll(self) -> None:
        """Reconcile the alert with the current vault state.

        Safe to call on a short interval: at most one message is sent per locked
        period, and a failed send is retried on the next call rather than
        consuming the single allowance.
        """
        if not self._is_locked():
            self._rearm()
            return

        target = str(self._get_target() or "").strip()
        if not target:
            # Feature is off. Deliberately silent: the vault being locked is
            # already visible in the dashboard and the history log.
            return

        if self._was_sent():
            return

        await self._deliver(target)

    def _rearm(self) -> None:
        """Clear the sent flag so the next lock alerts again."""
        self._last_failure = ""
        if not self._was_sent():
            return
        self._mark_sent(False)
        logger.info("Vault is unlocked; the locked-vault alert is armed again.")

    async def _deliver(self, target: str) -> None:
        """Send the alert and record it, keeping failures retryable."""
        try:
            delivered = await self._send(target, LOCK_ALERT_TEXT)
        except Exception as exc:
            self._note_failure(f"发送失败: {exc}")
            return

        if not delivered:
            self._note_failure(f"没有平台匹配会话 {target}")
            return

        # Recorded only after a confirmed send, so an unreachable target keeps
        # being retried instead of silently burning the single allowance.
        self._mark_sent(True)
        self._last_failure = ""
        logger.info(f"Sent the locked-vault alert to {target}.")

    def _note_failure(self, reason: str) -> None:
        """Log a delivery failure once per distinct cause."""
        if reason == self._last_failure:
            logger.debug(f"Locked-vault alert still undelivered: {reason}")
            return
        self._last_failure = reason
        logger.warning(f"Could not deliver the locked-vault alert: {reason}")
