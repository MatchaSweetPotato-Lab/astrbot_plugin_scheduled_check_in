"""Check-in adapter implementations for various LLM API relay stations."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from curl_cffi.requests import AsyncSession

from .acw_sc_v2 import AcwScV2Error, AcwScV2SolverCache, is_acw_sc_v2_challenge
from .http_client import DEFAULT_IMPERSONATE, normalize_impersonate

logger = logging.getLogger("astrbot")

# Standard conversion: 1 USD = 500,000 raw quota points in One-API / New-API
QUOTA_CONVERSION_FACTOR = 500000.0


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
        self.impersonate = normalize_impersonate(
            getattr(session, "impersonate", DEFAULT_IMPERSONATE)
        )
        self.site_id: str = site_config.get("id", "")
        self.site_name: str = site_config.get("name", "Unknown Site")
        self.base_url: str = site_config.get("base_url", "").rstrip("/")
        self.auth_type: str = site_config.get("auth_type", "bearer_token")
        self.auth_value: str = site_config.get("auth_value", "")
        self.proxy: str | None = site_config.get("proxy", "").strip() or None
        self.solve_acw_sc_v2: bool = bool(site_config.get("solve_acw_sc_v2", False))
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

        custom_headers = self.config.get("custom_headers", "")
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
        timeout: int,
    ) -> _TextResponse:
        """Request text and optionally solve one inline ``acw_sc__v2`` challenge."""
        request_headers = self._merge_challenge_cookies(headers)
        response = await self.session.request(
            method,
            url,
            headers=request_headers,
            proxy=self.proxy,
            timeout=float(timeout),
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
            timeout=float(timeout),
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

    async def _fetch_user_quota(self, headers: dict[str, str]) -> tuple[float, bool, str]:
        """Fetch user profile and calculate remaining quota in USD.

        Args:
            headers: Prepared headers with authentication.

        Returns:
            Tuple of (total_quota_usd, is_expired, status_message).
        """
        url = f"{self.base_url}/api/user/self"
        try:
            response = await self._request_text("GET", url, headers, timeout=10)
            if response.status in (401, 403):
                return 0.0, True, "鉴权失败：Token 或 Cookie 无效 (401/403)"

            text = response.text
            if "<html" in text.lower() or "acw_sc" in text.lower() or "denied by http_custom" in text.lower():
                logger.warning(f"WAF intercepted request to {url}")
                return 0.0, True, self._waf_message(response)

            if response.status == 200:
                import json
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and (data.get("success") or "data" in data):
                        user_info = data.get("data", {})
                        raw_quota = user_info.get("quota", 0)
                        total_quota = round(raw_quota / QUOTA_CONVERSION_FACTOR, 3)
                        return total_quota, False, "连接成功"
                except Exception:
                    return 0.0, True, "响应内容格式非法 (非 JSON 格式)"
        except Exception as e:
            logger.debug(f"Failed to fetch user quota from {url}: {e}")
            return 0.0, True, f"请求异常: {str(e)}"
        return 0.0, True, "鉴权或响应格式异常"

    async def check_in(self) -> CheckInResult:
        """Perform check-in on New-API / One-API station.

        Supports standard check-in endpoints, custom configured endpoints, and
        login-triggered auto-checkin detection.

        Returns:
            CheckInResult containing execution status and balance.
        """
        headers = self._get_headers()

        # Step 1: Query initial quota
        initial_quota, initial_expired, init_msg = await self._fetch_user_quota(headers)
        if initial_expired:
            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=init_msg,
                expired=True,
            )

        # Step 2: Determine endpoints to attempt
        custom_endpoint = self.config.get("checkin_endpoint", "").strip()
        if custom_endpoint:
            endpoints = [f"{self.base_url}/{custom_endpoint.lstrip('/')}"]
        else:
            endpoints = [
                f"{self.base_url}/api/user/pay/checkin",
                f"{self.base_url}/api/user/checkin",
                f"{self.base_url}/api/user/sign_in",
                f"{self.base_url}/api/user/self",
            ]

        last_message = ""
        success = False
        expired = False

        for endpoint in endpoints:
            try:
                response = await self._request_text("POST", endpoint, headers, timeout=10)
                if response.status in (401, 403):
                    expired = True
                    last_message = "Token 或 Cookie 已失效 (401/403)"
                    break

                data = None
                if response.status == 405:
                    # Fall back to GET if POST is not allowed (e.g., /api/user/self)
                    get_response = await self._request_text("GET", endpoint, headers, timeout=10)
                    if is_acw_sc_v2_challenge(get_response.text):
                        last_message = self._waf_message(get_response)
                    elif get_response.status == 200 and "<html" not in get_response.text.lower():
                        import json
                        data = json.loads(get_response.text)
                elif is_acw_sc_v2_challenge(response.text):
                    last_message = self._waf_message(response)
                elif response.status == 200 and "<html" not in response.text.lower():
                    import json
                    data = json.loads(response.text)

                if isinstance(data, dict):
                    success = data.get("success", False)
                    msg = data.get("message") or data.get("msg") or ""
                    if msg:
                        last_message = str(msg)
                    if success or "重复" in last_message or "已签到" in last_message:
                        break
            except Exception as e:
                last_message = f"请求异常: {str(e)}"
                continue

        # Step 3: Query final quota
        total_quota, quota_expired, final_msg = await self._fetch_user_quota(headers)
        if quota_expired:
            expired = True
            last_message = final_msg

        # Step 4: Check for login-triggered quota increases
        if total_quota > initial_quota:
            success = True
            gained = round(total_quota - initial_quota, 3)
            last_message = f"登录成功，自动获赠额度 (+$ {gained})"

        is_signed = success or ("已签到" in last_message or "重复" in last_message or "成功" in last_message)

        return CheckInResult(
            site_id=self.site_id,
            site_name=self.site_name,
            success=is_signed,
            message=last_message or ("签到成功" if is_signed else "已尝试触发打卡/登录"),
            total_quota=total_quota,
            expired=expired,
        )

    async def test_connection(self) -> CheckInResult:
        """Test authentication and query account quota.

        Returns:
            CheckInResult containing status and total quota.
        """
        headers = self._get_headers()
        total_quota, expired, err_msg = await self._fetch_user_quota(headers)
        if expired:
            # Fallback probe on /v1/models to verify if API key works
            models_url = f"{self.base_url}/v1/models"
            try:
                models_response = await self._request_text("GET", models_url, headers, timeout=8)
                if models_response.status == 200:
                    m_text = models_response.text
                    if "model" in m_text.lower() and "<html" not in m_text.lower():
                        err_msg = "API Key 有效(模型接口可用)，但管理接口(/api/user/self)已被 WAF 拦截"
            except Exception:
                pass

            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=err_msg,
                expired=True,
            )

        return CheckInResult(
            site_id=self.site_id,
            site_name=self.site_name,
            success=True,
            message="连接成功",
            total_quota=total_quota,
        )


class GenericRestAdapter(BaseCheckInAdapter):
    """Adapter for custom REST API check-in sites."""

    async def _execute_request(self) -> CheckInResult:
        """Execute request and return exact HTTP status code and raw response text."""
        headers = self._get_headers()
        endpoint = self.config.get("checkin_endpoint", "").strip()
        if not endpoint:
            endpoint = "/api/user/checkin"
        url = f"{self.base_url}{endpoint}" if endpoint.startswith("/") else f"{self.base_url}/{endpoint}"
        method = self.config.get("method", "POST").upper()

        try:
            response = await self._request_text(method, url, headers, timeout=10)
            status_code = response.status
            text_clean = response.text.strip()

            if is_acw_sc_v2_challenge(response.text):
                msg = self._waf_message(response)
                is_success = False
            else:
                msg = f"HTTP {status_code}: {text_clean}" if text_clean else f"HTTP {status_code}"
                is_success = 200 <= status_code < 300
                try:
                    import json
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

            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=is_success,
                message=msg,
                expired=is_expired,
                total_quota=0.0,
            )
        except Exception as e:
            return CheckInResult(
                site_id=self.site_id,
                site_name=self.site_name,
                success=False,
                message=f"请求失败: {str(e)}",
                total_quota=0.0,
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
    site_type = site_config.get("type", "new-api").lower()
    if site_type in ("new-api", "one-api"):
        return NewApiAdapter(site_config, session, acw_cache_file)
    return GenericRestAdapter(site_config, session, acw_cache_file)
