"""Check-in adapter implementations for various LLM API relay stations."""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from curl_cffi.requests import AsyncSession

from .acw_sc_v2 import AcwScV2Error, AcwScV2SolverCache, is_acw_sc_v2_challenge
from .http_client import normalize_impersonate
from .new_api_flow import NewApiCheckInFlow, NewApiQuotaService

logger = logging.getLogger("astrbot")

MAX_RESPONSE_LOG_CHARS = 4000
MAX_ATTEMPTS_PER_RUN = 32
MAX_ATTEMPT_SUMMARY_CHARS = 12000


@dataclass
class CheckInResult:
    """Dataclass storing the result of a site check-in or status check."""

    site_id: str
    site_name: str
    success: bool
    message: str
    gained_quota: float = 0.0
    total_quota: float = 0.0
    expired: bool = False
    error_detail: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert dataclass instance to dictionary.

        Returns:
            Dictionary containing result fields.
        """
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "success": self.success,
            "message": self.message,
            "gained_quota": self.gained_quota,
            "total_quota": self.total_quota,
            "expired": self.expired,
            "error_detail": self.error_detail,
            "attempts": self.attempts,
        }


@dataclass
class _TextResponse:
    """Materialized HTTP response used by the challenge-aware request layer."""

    status: int
    text: str
    challenge_error: str = ""
    challenge_solved: bool = False


class BaseCheckInAdapter(ABC):
    """Abstract base class for all check-in site adapters."""

    def __init__(
        self,
        site_config: dict[str, Any],
        session: AsyncSession,
        acw_cache_file: Path | None = None,
    ) -> None:
        """Initialize site adapter.

        Args:
            site_config: Configuration dictionary for the target site.
            session: Active curl_cffi AsyncSession instance.
            acw_cache_file: Optional persistent translated-algorithm cache path.
        """
        self.config = site_config
        self.session = session
        self.impersonate = normalize_impersonate(session.impersonate)
        self.site_id: str = site_config["id"]
        self.site_name: str = site_config["name"]
        self.base_url: str = site_config["base_url"].rstrip("/")
        self.auth_type: str = site_config["auth_type"]
        self.auth_value: str = site_config["auth_value"]
        self.proxy: str | None = site_config["proxy"].strip() or None
        self.solve_acw_sc_v2: bool = site_config["solve_acw_sc_v2"]
        self._acw_solver = AcwScV2SolverCache(acw_cache_file)
        self._challenge_cookies: dict[str, str] = {}

    def _get_headers(self) -> dict[str, str]:
        """Build request headers according to authentication type.

        Returns:
            Header dictionary.
        """
        headers: dict[str, str] = {
            # Leave User-Agent generation to curl_cffi so it stays consistent with
            # the configured browser impersonation.
            "Content-Type": "application/json",
            "Referer": f"{self.base_url}/console/personal",
            "Accept": "application/json, text/plain, */*",
        }
        if self.auth_type == "bearer_token" and self.auth_value:
            val = self.auth_value.strip().replace("\n", "").replace("\r", "")
            if val.lower().startswith("bearer "):
                val = val[7:].strip()
            headers["Authorization"] = f"Bearer {val}"
        elif self.auth_type == "cookie" and self.auth_value:
            headers["Cookie"] = self.auth_value.strip().replace("\n", "").replace("\r", "")

        custom_headers = self.config["custom_headers"]
        if isinstance(custom_headers, str) and custom_headers.strip():
            for line in custom_headers.strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
        elif isinstance(custom_headers, dict):
            for k, v in custom_headers.items():
                if k and v:
                    headers[k.strip()] = str(v).strip()

        return headers

    def _merge_challenge_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        """Merge WAF cookies into a copy of the configured request headers."""
        merged_headers = dict(headers)
        if not self._challenge_cookies:
            return merged_headers

        cookies: dict[str, str] = {}
        cookie_header_values: list[str] = []
        for header_name in list(merged_headers):
            if header_name.lower() == "cookie":
                cookie_header_values.append(merged_headers.pop(header_name))
        for header_value in cookie_header_values:
            for part in header_value.split(";"):
                if "=" not in part:
                    continue
                name, value = part.strip().split("=", 1)
                if name:
                    cookies[name] = value
        cookies.update(self._challenge_cookies)
        merged_headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
        return merged_headers

    async def _request_text(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> _TextResponse:
        """Request text and optionally solve one inline ``acw_sc__v2`` challenge."""
        request_headers = self._merge_challenge_cookies(headers)
        response = await self.session.request(
            method,
            url,
            headers=request_headers,
            proxy=self.proxy,
            impersonate=self.impersonate,
        )
        status = response.status_code
        text = response.text
        response_cookies = {
            name: getattr(value, "value", str(value))
            for name, value in response.cookies.items()
        }

        if not self.solve_acw_sc_v2 or not is_acw_sc_v2_challenge(text):
            return _TextResponse(status=status, text=text)

        try:
            solution = self._acw_solver.solve(text)
        except AcwScV2Error as exc:
            logger.warning("Failed to solve acw_sc__v2 challenge from %s: %s", url, exc)
            return _TextResponse(status=status, text=text, challenge_error=str(exc))

        self._challenge_cookies.update(response_cookies)
        self._challenge_cookies["acw_sc__v2"] = solution.cookie_value
        retry_headers = self._merge_challenge_cookies(headers)
        logger.info(
            "Solved acw_sc__v2 challenge from %s with algorithm %s (%s)",
            url,
            solution.algorithm_fingerprint[:12],
            "cache hit" if solution.cache_hit else "translated",
        )

        retry_response = await self.session.request(
            method,
            url,
            headers=retry_headers,
            proxy=self.proxy,
            impersonate=self.impersonate,
        )
        retry_status = retry_response.status_code
        retry_text = retry_response.text
        for name, value in retry_response.cookies.items():
            self._challenge_cookies[name] = getattr(value, "value", str(value))

        if is_acw_sc_v2_challenge(retry_text):
            return _TextResponse(
                status=retry_status,
                text=retry_text,
                challenge_error="已生成 Cookie，但重试后仍收到 JS 挑战",
            )
        return _TextResponse(
            status=retry_status,
            text=retry_text,
            challenge_solved=True,
        )

    @staticmethod
    def _waf_message(response: _TextResponse) -> str:
        if response.challenge_error:
            return f"acw_sc__v2 解算失败: {response.challenge_error}"
        return "被站点 WAF 防火墙拦截 (Aliyun WAF JS Challenge)"

    @staticmethod
    def _safe_url(url: str) -> str:
        """Remove query strings and fragments before storing a URL in history."""
        try:
            parsed = urlsplit(url)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        except Exception:
            return url.split("?", 1)[0].split("#", 1)[0]

    @staticmethod
    def _response_preview(text: str) -> str:
        """Keep useful response text without allowing history to grow indefinitely."""
        preview = (text or "").strip()
        if len(preview) <= MAX_RESPONSE_LOG_CHARS:
            return preview
        return (
            f"{preview[:MAX_RESPONSE_LOG_CHARS]}\n"
            f"...（响应过长，已截断；原长度 {len(preview)} 字符）"
        )

    @staticmethod
    def _response_message(data: Any, text: str = "") -> str:
        """Extract a short human-readable message from a JSON response."""
        if not isinstance(data, dict) and text:
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                data = parsed
        if isinstance(data, dict):
            message = data.get("message") or data.get("msg") or data.get("detail")
            if message:
                return str(message)
            error = data.get("error")
            if isinstance(error, dict):
                error_message = error.get("message") or error.get("detail")
                if error_message:
                    return str(error_message)
            elif error:
                return str(error)
        return ""

    @staticmethod
    def _message_indicates_checkin(message: str) -> bool:
        """Recognize explicit check-in success messages without broad false positives."""
        normalized = message.strip()
        if any(marker in normalized for marker in ("签到失败", "未签到", "未成功", "未触发签到")):
            return False
        return any(marker in normalized for marker in ("签到成功", "已签到", "已经签到", "重复签到"))

    def _record_attempt(
        self,
        attempts: list[dict[str, Any]],
        *,
        step: str,
        method: str,
        endpoint: str,
        status: int | None = None,
        success: bool = False,
        message: str = "",
        response_text: str = "",
        error: str = "",
    ) -> None:
        """Append one request trace while deliberately excluding request headers."""
        item: dict[str, Any] = {
            "step": step,
            "method": method.upper(),
            "url": self._safe_url(endpoint),
            "status": status,
            "success": bool(success),
        }
        if message:
            item["message"] = str(message)
        response = self._response_preview(response_text)
        if response:
            item["response"] = response
            item["response_length"] = len((response_text or "").strip())
        if error:
            item["error"] = str(error)

        # Keep the attempt that reaches the cap. A marker is added only when a
        # later attempt is first omitted, so the trace has MAX_ATTEMPTS_PER_RUN
        # real attempts plus at most one bounded marker.
        if len(attempts) < MAX_ATTEMPTS_PER_RUN:
            attempts.append(item)
            return
        if attempts and attempts[-1].get("truncated"):
            return
        if len(attempts) >= MAX_ATTEMPTS_PER_RUN:
            attempts.append(
                {
                    "step": "请求追踪",
                    "method": method.upper(),
                    "url": self._safe_url(endpoint),
                    "status": status,
                    "success": False,
                    "message": (
                        f"已达到单次请求追踪上限（{MAX_ATTEMPTS_PER_RUN}），"
                        "后续尝试已省略"
                    ),
                    "truncated": True,
                }
            )

    @staticmethod
    def _format_attempts(attempts: list[dict[str, Any]]) -> str:
        """Build a compact readable summary for notifications and old clients."""
        lines: list[str] = []
        for attempt in attempts:
            if attempt.get("truncated"):
                lines.append(f"[请求追踪] {attempt.get('message', '后续尝试已省略')}")
                continue
            status = (
                f"HTTP {attempt['status']}"
                if attempt.get("status") is not None
                else "未收到 HTTP 响应"
            )
            outcome = "成功" if attempt.get("success") else "失败"
            line = (
                f"[{attempt.get('step', '请求')}] "
                f"{attempt.get('method', '')} {attempt.get('url', '')} -> "
                f"{status}（{outcome}）"
            )
            if attempt.get("message"):
                line += f"：{attempt['message']}"
            if attempt.get("error"):
                line += f"；异常：{attempt['error']}"
            lines.append(line)
        summary = "\n".join(lines)
        if len(summary) <= MAX_ATTEMPT_SUMMARY_CHARS:
            return summary
        suffix = f"\n...（追踪摘要过长，已截断；原长度 {len(summary)} 字符）"
        return summary[: MAX_ATTEMPT_SUMMARY_CHARS - len(suffix)] + suffix

    @abstractmethod
    async def check_in(self) -> CheckInResult:
        """Perform daily check-in action.

        Returns:
            CheckInResult object.
        """
        pass

    @abstractmethod
    async def test_connection(self) -> CheckInResult:
        """Test connection and check site balance/status without checking in.

        Returns:
            CheckInResult object.
        """
        pass






class NewApiAdapter(BaseCheckInAdapter):
    """Adapter for New-API / One-API relay station frameworks."""

    async def check_in(self) -> CheckInResult:
        """Perform check-in on New-API / One-API station.

        Supports standard check-in endpoints, custom configured endpoints, and
        login-triggered auto-checkin detection.

        Returns:
            CheckInResult containing execution status and balance.
        """
        headers = self._get_headers()
        attempts: list[dict[str, Any]] = []
        quota_service = NewApiQuotaService(self, headers, attempts)
        checkin_flow = NewApiCheckInFlow(self, headers, attempts)

        initial_result = await quota_service.fetch("查询初始余额")
        if initial_result.expired:
            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=initial_result.message,
                expired=True,
                error_detail=self._format_attempts(attempts),
                attempts=attempts,
            )

        last_message = ""
        success = False
        expired = False
        for endpoint in checkin_flow.endpoints():
            result = await checkin_flow.execute(endpoint)
            if result.message:
                last_message = result.message
            success = success or result.success
            expired = expired or result.expired
            if result.expired or result.signed:
                break

        final_result = await quota_service.fetch("查询最终余额")
        total_quota, gained, success, expired, last_message = NewApiQuotaService.reconcile(
            initial_result,
            final_result,
            success,
            expired,
            last_message,
        )
        is_signed = success or self._message_indicates_checkin(last_message)

        return CheckInResult(
            site_id=self.site_id,
            site_name=self.site_name,
            success=is_signed,
            message=last_message or ("签到成功" if is_signed else "未获得明确签到成功响应（请查看详情）"),
            gained_quota=gained,
            total_quota=total_quota,
            expired=expired,
            error_detail=self._format_attempts(attempts),
            attempts=attempts,
        )

    async def test_connection(self) -> CheckInResult:
        """Test authentication and query account quota.

        Returns:
            CheckInResult containing status and total quota.
        """
        headers = self._get_headers()
        attempts: list[dict[str, Any]] = []
        quota_service = NewApiQuotaService(self, headers, attempts)
        quota_result = await quota_service.fetch("测试鉴权/余额")
        if quota_result.expired or quota_result.waf_intercepted:
            # Probe /v1/models when auth or the management endpoint is blocked.
            models_url = f"{self.base_url}/v1/models"
            model_status: int | None = None
            fallback_message = quota_result.message
            try:
                models_response = await self._request_text("GET", models_url, headers)
                model_status = models_response.status
                m_text = models_response.text
                model_ok = (
                    models_response.status == 200
                    and "model" in m_text.lower()
                    and "<html" not in m_text.lower()
                )
                model_message = (
                    "API Key 有效(模型接口可用)，但管理接口(/api/user/self)已被 WAF 拦截"
                    if model_ok
                    else self._response_message(None, m_text) or f"HTTP {models_response.status}"
                )
                self._record_attempt(
                    attempts,
                    step="API 接口兜底探测",
                    method="GET",
                    endpoint=models_url,
                    status=models_response.status,
                    success=model_ok,
                    message=model_message,
                    response_text=m_text,
                )
                if model_ok:
                    fallback_message = model_message
            except Exception as exc:
                self._record_attempt(
                    attempts,
                    step="API 接口兜底探测",
                    method="GET",
                    endpoint=models_url,
                    status=model_status,
                    message=f"请求异常: {str(exc)}",
                    error=str(exc),
                )

            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=fallback_message,
                expired=quota_result.expired,
                error_detail=self._format_attempts(attempts),
                attempts=attempts,
            )

        if not quota_result.available:
            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=quota_result.message or "余额查询失败",
                expired=False,
                error_detail=self._format_attempts(attempts),
                attempts=attempts,
            )

        return CheckInResult(
            site_id=self.site_id,
            site_name=self.site_name,
            success=True,
            message="连接成功",
            total_quota=quota_result.total_quota,
            error_detail=self._format_attempts(attempts),
            attempts=attempts,
        )


class GenericRestAdapter(BaseCheckInAdapter):
    """Adapter for custom REST API check-in sites."""

    async def _execute_request(self) -> CheckInResult:
        """Execute request and return exact HTTP status code and raw response text."""
        headers = self._get_headers()
        endpoint = self.config["checkin_endpoint"].strip()
        if not endpoint:
            endpoint = "/api/user/checkin"
        url = f"{self.base_url}{endpoint}" if endpoint.startswith("/") else f"{self.base_url}/{endpoint}"
        method = self.config.get("method", "POST").upper()
        attempts: list[dict[str, Any]] = []
        status_code: int | None = None

        try:
            response = await self._request_text(method, url, headers)
            status_code = response.status
            text_clean = response.text.strip()
            payload: Any = None

            if is_acw_sc_v2_challenge(response.text):
                msg = self._waf_message(response)
                is_success = False
            else:
                msg = f"HTTP {status_code}: {text_clean}" if text_clean else f"HTTP {status_code}"
                is_success = 200 <= status_code < 300
                try:
                    payload = json.loads(response.text)
                    if isinstance(payload, dict) and "success" in payload:
                        success_value = payload["success"]
                        response_success: bool | None = None
                        if isinstance(success_value, bool):
                            response_success = success_value
                        elif isinstance(success_value, str):
                            normalized = success_value.strip().lower()
                            if normalized in {"true", "false"}:
                                response_success = normalized == "true"
                        if response_success is not None:
                            is_success = is_success and response_success
                except (TypeError, ValueError):
                    pass
            is_expired = status_code in (401, 403)
            attempt_message = (
                self._waf_message(response)
                if is_acw_sc_v2_challenge(response.text)
                else self._response_message(payload, text_clean) or f"HTTP {status_code}"
            )
            self._record_attempt(
                attempts,
                step="执行 REST 请求",
                method=method,
                endpoint=url,
                status=status_code,
                success=is_success,
                message=attempt_message,
                response_text=response.text,
            )

            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=is_success,
                message=msg,
                expired=is_expired,
                total_quota=0.0,
                error_detail=self._format_attempts(attempts),
                attempts=attempts,
            )
        except Exception as e:
            message = f"请求失败: {str(e)}"
            self._record_attempt(
                attempts,
                step="执行 REST 请求",
                method=method,
                endpoint=url,
                status=status_code,
                message=message,
                error=str(e),
            )
            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=message,
                total_quota=0.0,
                error_detail=self._format_attempts(attempts),
                attempts=attempts,
            )

    async def check_in(self) -> CheckInResult:
        """Execute check-in request against custom configured REST API.

        Returns:
            CheckInResult object.
        """
        return await self._execute_request()

    async def test_connection(self) -> CheckInResult:
        """Test custom REST site connection.

        Returns:
            CheckInResult object.
        """
        return await self._execute_request()


def create_adapter(
    site_config: dict[str, Any],
    session: AsyncSession,
    acw_cache_file: Path | None = None,
) -> BaseCheckInAdapter:
    """Factory function creating appropriate site adapter.

    Args:
        site_config: Site configuration.
        session: Active curl_cffi AsyncSession.
        acw_cache_file: Optional persistent translated-algorithm cache path.

    Returns:
        Subclass instance of BaseCheckInAdapter.
    """
    site_type = site_config["type"].lower()
    if site_type in ("new-api", "one-api"):
        return NewApiAdapter(site_config, session, acw_cache_file)
    return GenericRestAdapter(site_config, session, acw_cache_file)
