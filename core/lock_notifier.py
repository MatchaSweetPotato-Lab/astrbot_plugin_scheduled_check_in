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
        mark_sent: Callable[[bool], bool],
        send: Callable[[str, str], Awaitable[bool]],
    ) -> None:
        """Wire the notifier to its host plugin.

        Args:
            is_locked: Returns whether the vault is encrypted but keyless.
            get_target: Returns the configured session, empty when disabled.
            was_sent: Returns the persisted "already alerted" flag.
            mark_sent: Persists the "already alerted" flag and reports whether
                the write succeeded.
            send: Delivers ``(target, text)`` and reports whether it landed.
        """
        self._is_locked = is_locked
        self._get_target = get_target
        self._was_sent = was_sent
        self._mark_sent = mark_sent
        self._send = send
        # Delivery is authoritative for the current process even if the
        # durable flag cannot be written. A failed write is retried without
        # sending the alert again.
        self._sent_in_memory: bool | None = None
        self._persistence_pending = False
        self._last_persistence_failure: str = ""
        # Last delivery problem, so a misconfigured target is reported once
        # instead of on every poll.
        self._last_failure: str = ""

    def rearm_after_target_change(self) -> None:
        """Forget the current delivery after storage committed a new target.

        The caller must persist the new target and clear the durable sent flag
        before invoking this method. Keeping that ordering outside the
        notifier lets the host commit both settings atomically.
        """
        self._sent_in_memory = False
        self._persistence_pending = False
        self._last_failure = ""
        self._last_persistence_failure = ""

    async def poll(self) -> None:
        """Reconcile the alert with the current vault state.

        Safe to call on a short interval: at most one message is sent per locked
        period, and a failed send is retried on the next call rather than
        consuming the single allowance.
        """
        if not self._is_locked():
            self._rearm()
            return

        if self._sent_in_memory is not None:
            self._retry_persistence()
            if self._sent_in_memory:
                return

        target = str(self._get_target() or "").strip()
        if not target:
            # Feature is off. Deliberately silent: the vault being locked is
            # already visible in the dashboard and the history log.
            return

        if self._sent_in_memory is None and self._was_sent():
            return

        await self._deliver(target)

    def _rearm(self) -> None:
        """Clear the sent flag so the next lock alerts again."""
        self._last_failure = ""
        if self._sent_in_memory is False:
            self._retry_persistence()
            return

        if self._sent_in_memory is None and not self._was_sent():
            self._sent_in_memory = False
            return

        self._sent_in_memory = False
        self._persistence_pending = not self._persist_sent(False)
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
        self._sent_in_memory = True
        self._persistence_pending = not self._persist_sent(True)
        self._last_failure = ""
        logger.info(f"Sent the locked-vault alert to {target}.")

    def _retry_persistence(self) -> None:
        """Retry a durable state write without retrying an accepted message."""
        if self._sent_in_memory is None or not self._persistence_pending:
            return
        self._persistence_pending = not self._persist_sent(self._sent_in_memory)

    def _persist_sent(self, sent: bool) -> bool:
        """Persist the in-memory delivery state and report whether it stuck."""
        try:
            persisted = bool(self._mark_sent(sent))
        except Exception as exc:
            reason = f"保存发送状态失败: {exc}"
            self._note_persistence_failure(reason)
            return False

        if not persisted:
            self._note_persistence_failure(f"无法保存发送状态 sent={sent}")
            return False

        self._last_persistence_failure = ""
        return True

    def _note_persistence_failure(self, reason: str) -> None:
        """Log a persistence problem once per distinct cause."""
        if reason == self._last_persistence_failure:
            logger.debug(f"Locked-vault alert state still not persisted: {reason}")
            return
        self._last_persistence_failure = reason
        logger.warning(f"Could not persist the locked-vault alert state: {reason}")

    def _note_failure(self, reason: str) -> None:
        """Log a delivery failure once per distinct cause."""
        if reason == self._last_failure:
            logger.debug(f"Locked-vault alert still undelivered: {reason}")
            return
        self._last_failure = reason
        logger.warning(f"Could not deliver the locked-vault alert: {reason}")
