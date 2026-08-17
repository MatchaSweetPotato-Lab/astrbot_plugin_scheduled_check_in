"""Quota and check-in flows shared by New-API and One-API adapters."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .acw_sc_v2 import is_acw_sc_v2_challenge

if TYPE_CHECKING:
    from .adapters import BaseCheckInAdapter

logger = logging.getLogger("astrbot")

QUOTA_CONVERSION_FACTOR = 500000.0


@dataclass
class QuotaFetchResult:
    """Result of a quota query, including whether failure means auth expiry."""

    total_quota: float = 0.0
    expired: bool = False
    available: bool = False
    waf_intercepted: bool = False
    message: str = ""


@dataclass
class CheckInRequestResult:
    """Result of one check-in endpoint attempt."""

    success: bool = False
    signed: bool = False
    expired: bool = False
    message: str = ""


class NewApiQuotaService:
    """Own quota queries and final-balance reconciliation for a New-API run."""

    def __init__(
        self,
        adapter: BaseCheckInAdapter,
        headers: dict[str, str],
        attempts: list[dict[str, Any]],
    ) -> None:
        self.adapter = adapter
        self.headers = headers
        self.attempts = attempts

    async def fetch(self, step: str = "查询余额") -> QuotaFetchResult:
        """Fetch the current user quota and classify authentication failures."""
        adapter = self.adapter
        url = f"{adapter.base_url}/api/user/self"
        status_code: int | None = None
        try:
            response = await adapter._request_text("GET", url, self.headers)
            status_code = response.status
            text = response.text
            if response.status in (401, 403):
                message = "鉴权失败：Token 或 Cookie 无效 (401/403)"
                adapter._record_attempt(
                    self.attempts,
                    step=step,
                    method="GET",
                    endpoint=url,
                    status=response.status,
                    message=message,
                    response_text=text,
                )
                return QuotaFetchResult(expired=True, message=message)

            if "<html" in text.lower() or "acw_sc" in text.lower() or "denied by http_custom" in text.lower():
                logger.warning("WAF intercepted request to %s", url)
                message = adapter._waf_message(response)
                adapter._record_attempt(
                    self.attempts,
                    step=step,
                    method="GET",
                    endpoint=url,
                    status=response.status,
                    message=message,
                    response_text=text,
                )
                return QuotaFetchResult(waf_intercepted=True, message=message)

            data: Any = None
            if response.status == 200:
                try:
                    data = json.loads(text)
                except (TypeError, ValueError) as exc:
                    message = "响应内容格式非法 (非 JSON 格式)"
                    adapter._record_attempt(
                        self.attempts,
                        step=step,
                        method="GET",
                        endpoint=url,
                        status=response.status,
                        message=message,
                        response_text=text,
                        error=str(exc),
                    )
                    return QuotaFetchResult(message=message)

                if isinstance(data, dict) and (data.get("success") or "data" in data):
                    user_info = data.get("data", {})
                    if not isinstance(user_info, dict):
                        user_info = {}
                    try:
                        raw_quota = user_info.get("quota", 0)
                        total_quota = round(raw_quota / QUOTA_CONVERSION_FACTOR, 3)
                    except (TypeError, ValueError) as exc:
                        message = "响应内容中的余额格式非法"
                        adapter._record_attempt(
                            self.attempts,
                            step=step,
                            method="GET",
                            endpoint=url,
                            status=response.status,
                            message=message,
                            response_text=text,
                            error=str(exc),
                        )
                        return QuotaFetchResult(message=message)

                    adapter._record_attempt(
                        self.attempts,
                        step=step,
                        method="GET",
                        endpoint=url,
                        status=response.status,
                        success=True,
                        message="连接成功",
                        response_text=text,
                    )
                    return QuotaFetchResult(
                        total_quota=total_quota,
                        available=True,
                        message="连接成功",
                    )

            message = adapter._response_message(data, text) or f"HTTP {response.status}"
            adapter._record_attempt(
                self.attempts,
                step=step,
                method="GET",
                endpoint=url,
                status=response.status,
                message=message,
                response_text=text,
            )
            return QuotaFetchResult(message=message)
        except Exception as exc:
            logger.debug("Failed to fetch user quota from %s: %s", url, exc)
            message = f"请求异常: {str(exc)}"
            adapter._record_attempt(
                self.attempts,
                step=step,
                method="GET",
                endpoint=url,
                status=status_code,
                message=message,
                error=str(exc),
            )
            return QuotaFetchResult(message=message)

    @staticmethod
    def reconcile(
        initial_result: QuotaFetchResult,
        final_result: QuotaFetchResult,
        success: bool,
        expired: bool,
        last_message: str,
    ) -> tuple[float, float, bool, bool, str]:
        """Combine the final balance query with the check-in response."""
        initial_quota = initial_result.total_quota
        total_quota = final_result.total_quota if final_result.available else initial_quota
        gained = 0.0

        if not final_result.available:
            # Keep a known initial balance when the final query is transiently
            # unavailable instead of replacing it with a misleading zero.
            expired = expired or final_result.expired
            if not success:
                last_message = final_result.message
            elif final_result.message:
                last_message = f"{last_message}（签到后余额查询失败：{final_result.message}）"

        if initial_result.available and final_result.available and total_quota > initial_quota:
            success = True
            gained = round(total_quota - initial_quota, 3)
            last_message = f"登录成功，自动获赠额度 (+$ {gained})"

        return total_quota, gained, success, expired, last_message


class NewApiCheckInFlow:
    """Own endpoint fallback and response handling for a New-API check-in."""

    def __init__(
        self,
        adapter: BaseCheckInAdapter,
        headers: dict[str, str],
        attempts: list[dict[str, Any]],
    ) -> None:
        self.adapter = adapter
        self.headers = headers
        self.attempts = attempts

    def endpoints(self) -> list[str]:
        """Return configured check-in endpoints in fallback order."""
        custom_endpoint = self.adapter.config["checkin_endpoint"].strip()
        if custom_endpoint:
            return [f"{self.adapter.base_url}/{custom_endpoint.lstrip('/')}"]
        return [
            f"{self.adapter.base_url}/api/user/pay/checkin",
            f"{self.adapter.base_url}/api/user/checkin",
            f"{self.adapter.base_url}/api/user/sign_in",
            f"{self.adapter.base_url}/api/user/self",
        ]

    async def _get_fallback(self, endpoint: str) -> CheckInRequestResult:
        """Try GET when a check-in endpoint rejects POST."""
        adapter = self.adapter
        try:
            response = await adapter._request_text("GET", endpoint, self.headers)
            text = response.text
            message = ""
            data: Any = None

            if is_acw_sc_v2_challenge(text):
                message = adapter._waf_message(response)
            elif response.status == 200 and "<html" not in text.lower():
                try:
                    data = json.loads(text)
                except (TypeError, ValueError) as exc:
                    message = "响应内容格式非法 (非 JSON 格式)"
                    adapter._record_attempt(
                        self.attempts,
                        step="执行签到请求（GET 重试）",
                        method="GET",
                        endpoint=endpoint,
                        status=response.status,
                        message=message,
                        response_text=text,
                        error=str(exc),
                    )
                    return CheckInRequestResult(message=message)
            elif "<html" in text.lower():
                message = "返回 HTML 页面，可能被 WAF 或登录页拦截"
            else:
                try:
                    data = json.loads(text) if text.strip() else None
                except (TypeError, ValueError):
                    data = None

            success = False
            if isinstance(data, dict):
                success = bool(data.get("success", False))
                message = adapter._response_message(data, text) or message
            message = message or adapter._response_message(data, text) or f"HTTP {response.status}"
            signed = success or adapter._message_indicates_checkin(message)
            adapter._record_attempt(
                self.attempts,
                step="执行签到请求（GET 重试）",
                method="GET",
                endpoint=endpoint,
                status=response.status,
                success=signed,
                message=message,
                response_text=text,
            )
            return CheckInRequestResult(success=success, signed=signed, message=message)
        except Exception as exc:
            message = f"请求异常: {str(exc)}"
            adapter._record_attempt(
                self.attempts,
                step="执行签到请求（GET 重试）",
                method="GET",
                endpoint=endpoint,
                message=message,
                error=str(exc),
            )
            return CheckInRequestResult(message=message)

    async def execute(self, endpoint: str) -> CheckInRequestResult:
        """Execute one POST check-in request and its optional GET fallback."""
        adapter = self.adapter
        try:
            response = await adapter._request_text("POST", endpoint, self.headers)
            response_text = response.text
            if response.status in (401, 403):
                message = "Token 或 Cookie 已失效 (401/403)"
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    message=message,
                    response_text=response_text,
                )
                return CheckInRequestResult(expired=True, message=message)

            if response.status == 405:
                message = "POST 方法不允许，改用 GET 重试"
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    message=message,
                    response_text=response_text,
                )
                return await self._get_fallback(endpoint)

            if is_acw_sc_v2_challenge(response_text):
                message = adapter._waf_message(response)
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    message=message,
                    response_text=response_text,
                )
                return CheckInRequestResult(message=message)

            data: Any = None
            message = ""
            if response.status == 200 and "<html" not in response_text.lower():
                try:
                    data = json.loads(response_text)
                except (TypeError, ValueError) as exc:
                    message = "响应内容格式非法 (非 JSON 格式)"
                    adapter._record_attempt(
                        self.attempts,
                        step="执行签到请求",
                        method="POST",
                        endpoint=endpoint,
                        status=response.status,
                        message=message,
                        response_text=response_text,
                        error=str(exc),
                    )
                    return CheckInRequestResult(message=message)
            elif response.status == 200:
                message = "返回 HTML 页面，可能被 WAF 或登录页拦截"
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    message=message,
                    response_text=response_text,
                )
                return CheckInRequestResult(message=message)
            else:
                try:
                    data = json.loads(response_text) if response_text.strip() else None
                except (TypeError, ValueError):
                    data = None
                message = adapter._response_message(data, response_text) or f"HTTP {response.status}"

            if isinstance(data, dict):
                success = bool(data.get("success", False))
                message = adapter._response_message(data, response_text) or message
                message = message or f"HTTP {response.status}"
                signed = success or adapter._message_indicates_checkin(message)
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    success=signed,
                    message=message,
                    response_text=response_text,
                )
                return CheckInRequestResult(success=success, signed=signed, message=message)

            if response.status != 405:
                adapter._record_attempt(
                    self.attempts,
                    step="执行签到请求",
                    method="POST",
                    endpoint=endpoint,
                    status=response.status,
                    message=message,
                    response_text=response_text,
                )
            return CheckInRequestResult(message=message)
        except Exception as exc:
            message = f"请求异常: {str(exc)}"
            adapter._record_attempt(
                self.attempts,
                step="执行签到请求",
                method="POST",
                endpoint=endpoint,
                message=message,
                error=str(exc),
            )
            return CheckInRequestResult(message=message)
