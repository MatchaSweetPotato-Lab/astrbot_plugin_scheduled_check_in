"""Check-in adapter implementations for various LLM API relay stations.

Every request is driven by two things the user configures per site: a
**credential list** and an **action config** (one for check-in, one for balance).
An action names a path, a protocol, an optional credential, extra headers, and
whether to solve Aliyun's ``acw_sc__v2`` challenge. Leaving the path or protocol
empty falls back to what the site's framework is known to expose.

Runtime discoveries that belong in the config — a probed ``new-api-user`` id, a
session cookie won by an OAuth login — are collected in ``SiteWriteback`` and
persisted by the caller through :func:`persist_writeback`.
"""

from __future__ import annotations

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
from .oauth import OAuthLoginClient
from .site_schema import (
    ACTION_BALANCE,
    ACTION_CHECKIN,
    CRED_COOKIE,
    CRED_TOKEN,
    NEW_API_USER_HEADER,
    PROTOCOL_AUTO,
    PROTOCOL_GET,
    PROTOCOL_OAUTH,
    PROTOCOL_POST,
    SITE_TYPE_GENERIC,
    SITE_TYPE_NEW_API,
    credential_label,
    headers_to_mapping,
    normalize_action,
    normalize_credentials,
    normalize_site_type,
    resolve_action_credential,
    upsert_header,
    wants_new_api_user_probe,
)

logger = logging.getLogger("astrbot")

# Standard conversion: 1 USD = 500,000 raw quota points in One-API / New-API
QUOTA_CONVERSION_FACTOR = 500000.0

# Bounds on the per-run request trace. Traces are stored in history, so they
# must not be allowed to grow without limit.
MAX_RESPONSE_LOG_CHARS = 4000
MAX_ATTEMPTS_PER_RUN = 32
MAX_ATTEMPT_SUMMARY_CHARS = 12000

# Balance fields carrying raw quota points, which need the conversion above.
_RAW_QUOTA_KEYS = ("quota", "remain_quota", "remaining_quota")
# Balance fields already expressed in currency.
_CURRENCY_KEYS = ("balance", "money", "credit", "amount")

# Check-in endpoints New-API style stations are known to expose.
_NEW_API_CHECKIN_PATHS = ("/api/user/checkin", "/api/user/pay/checkin")
_NEW_API_SELF_PATH = "/api/user/self"


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
    # Per-request trace, surfaced in history so a failure can be diagnosed
    # without re-running the check-in.
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
class SiteWriteback:
    """Config updates discovered while running a site's actions."""

    checkin_headers: list[dict[str, str]] | None = None
    balance_headers: list[dict[str, str]] | None = None
    oauth_sessions: dict[str, str] = field(default_factory=dict)
    # Provider cookies the upstream rotated during a login, keyed by credential
    # id. Storing them keeps the next run from replaying a retired session.
    credential_values: dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """Return whether there is nothing to persist."""
        return (
            self.checkin_headers is None
            and self.balance_headers is None
            and not self.oauth_sessions
            and not self.credential_values
        )


def persist_writeback(db: Any, site_id: str, writeback: SiteWriteback | None) -> None:
    """Persist runtime-discovered config updates for one site.

    Args:
        db: Database manager exposing ``update_action_headers``,
            ``update_credential_session`` and ``update_credential_value``.
        site_id: Site the writeback belongs to.
        writeback: Collected updates; ignored when empty or None.
    """
    if writeback is None or writeback.is_empty():
        return
    try:
        if writeback.checkin_headers is not None:
            db.update_action_headers(site_id, ACTION_CHECKIN, writeback.checkin_headers)
        if writeback.balance_headers is not None:
            db.update_action_headers(site_id, ACTION_BALANCE, writeback.balance_headers)
        for credential_id, session_cookie in writeback.oauth_sessions.items():
            db.update_credential_session(site_id, credential_id, session_cookie)
        for credential_id, value in writeback.credential_values.items():
            db.update_credential_value(site_id, credential_id, value)
    except Exception as exc:
        logger.warning(f"Could not persist discovered config for site {site_id}: {exc}")


@dataclass
class _TextResponse:
    """Materialized HTTP response used by the challenge-aware request layer."""

    status: int
    text: str
    challenge_error: str = ""
    challenge_solved: bool = False


@dataclass
class _AuthContext:
    """Prepared authentication for one action."""

    headers: dict[str, str]
    error: str = ""
    credential: dict[str, Any] | None = None
    oauth: bool = False
    # True when an existing OAuth session cookie was reused rather than freshly
    # obtained, meaning a 401 is worth one re-login.
    reused_session: bool = False

    @property
    def ok(self) -> bool:
        """Whether the action can be attempted."""
        return not self.error


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
        self.impersonate = normalize_impersonate(getattr(session, "impersonate", None))
        self.site_id: str = str(site_config.get("id") or "")
        self.site_name: str = str(site_config.get("name") or "")
        self.site_type: str = normalize_site_type(site_config.get("type"))
        self.base_url: str = str(site_config.get("base_url") or "").strip().rstrip("/")
        self.credentials = normalize_credentials(site_config.get("credentials"))
        self.checkin = normalize_action(site_config.get("checkin"), allow_oauth=True)
        self.balance = normalize_action(site_config.get("balance"), allow_oauth=False)
        # The proxy is site-wide on purpose: it also covers the third-party
        # OAuth domains, which are often the ones that need it most.
        self.proxy: str | None = str(site_config.get("proxy") or "").strip() or None
        self.writeback = SiteWriteback()
        self._acw_solver = AcwScV2SolverCache(acw_cache_file)
        self._challenge_cookies: dict[str, str] = {}
        # Discovered once per run and shared by both actions.
        self._new_api_user_id: str = ""
        # Sessions won by a fresh login during this run, keyed by credential id.
        # A second login in the same run would be a duplicate sign-in attempt.
        self._fresh_sessions: dict[str, str] = {}
        # Request trace for the current run, attached to the result.
        self.attempts: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Request tracing
    # ------------------------------------------------------------------
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
        attempts = self.attempts
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
        attempts.append(
            {
                "step": "请求追踪",
                "method": method.upper(),
                "url": self._safe_url(endpoint),
                "status": status,
                "success": False,
                "message": (
                    f"已达到单次请求追踪上限（{MAX_ATTEMPTS_PER_RUN}），后续尝试已省略"
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

    # ------------------------------------------------------------------
    # Request assembly
    # ------------------------------------------------------------------
    def _base_headers(self) -> dict[str, str]:
        """Build the headers every request shares.

        User-Agent generation is left to curl_cffi so it stays consistent with
        the configured browser impersonation.
        """
        return {
            "Content-Type": "application/json",
            "Referer": f"{self.base_url}/console/personal",
            "Accept": "application/json, text/plain, */*",
        }

    @staticmethod
    def _clean_credential_value(value: Any) -> str:
        """Strip whitespace and newlines a pasted credential often carries."""
        return str(value or "").strip().replace("\n", "").replace("\r", "")

    def _credential_headers(self, credential: dict[str, Any]) -> dict[str, str]:
        """Build the auth headers for a direct-request credential."""
        headers: dict[str, str] = {}
        value = self._clean_credential_value(credential.get("value"))
        if not value:
            return headers
        if credential.get("type") == CRED_TOKEN:
            if credential.get("auto_bearer", True):
                if value.lower().startswith("bearer "):
                    value = value[7:].strip()
                headers["Authorization"] = f"Bearer {value}"
            else:
                headers["Authorization"] = value
        elif credential.get("type") == CRED_COOKIE:
            headers["Cookie"] = value
        return headers

    async def _oauth_login(self, credential: dict[str, Any]) -> tuple[str, str]:
        """Run an OAuth login and remember the resulting session cookie.

        Args:
            credential: OAuth credential holding the third-party cookie.

        Returns:
            Tuple of ``(session_cookie, error_message)``.
        """
        client = OAuthLoginClient(
            self.session,
            self.base_url,
            self.impersonate,
            self.proxy,
            # Record every leg, so a login failure is visible in the log detail
            # view instead of collapsing into a one-line message.
            on_attempt=self._record_attempt,
        )
        result = await client.login(str(credential.get("type") or ""), credential.get("value"))

        # Persist a rotated provider cookie whether or not the login succeeded:
        # the provider may have moved the session on before rejecting, and
        # replaying a value it has already retired guarantees the next failure.
        if result.rotated_provider_cookie:
            credential["value"] = result.rotated_provider_cookie
            rotated_id = str(credential.get("id") or "")
            if rotated_id:
                self.writeback.credential_values[rotated_id] = result.rotated_provider_cookie

        if not result.success:
            return "", result.message
        credential["session_cookie"] = result.session_cookie
        credential_id = str(credential.get("id") or "")
        if credential_id:
            self.writeback.oauth_sessions[credential_id] = result.session_cookie
            self._fresh_sessions[credential_id] = result.session_cookie
        return result.session_cookie, ""

    async def _authenticate(
        self,
        action: dict[str, Any],
        force_login: bool = False,
        allow_login: bool = True,
    ) -> _AuthContext:
        """Resolve and apply the credential one action should use.

        Custom headers are applied last so they can override anything the
        credential produced.

        Args:
            action: Action config naming the protocol, credential, and headers.
            force_login: Re-run the OAuth login instead of reusing a stored
                session. Required when the login itself is the signing action:
                some stations disable their check-in endpoint and grant the
                daily bonus only on a real login, so reusing a cookie would
                silently do nothing.
            allow_login: When False, refuse to log in rather than doing so.
                Used for the opening balance read of a login-style check-in, so
                that reading the balance cannot consume the day's sign-in.
        """
        plan = resolve_action_credential(self.credentials, action)
        headers = self._base_headers()

        if plan.credential is None:
            return _AuthContext(headers=headers, error=plan.reason or "未配置可用凭据")

        credential = plan.credential
        reused = False
        if plan.mode == "oauth":
            credential_id = str(credential.get("id") or "")
            session_cookie = self._clean_credential_value(credential.get("session_cookie"))
            # A login already performed in this run counts as fresh, so the two
            # balance reads around a check-in do not each trigger one.
            already_fresh = bool(credential_id) and credential_id in self._fresh_sessions
            if session_cookie and (already_fresh or not force_login):
                reused = not already_fresh
            elif not allow_login:
                return _AuthContext(
                    headers=headers,
                    error="尚无可用会话，需 OAuth 登录后才能查询",
                    credential=credential,
                    oauth=True,
                )
            else:
                session_cookie, error = await self._oauth_login(credential)
                if error:
                    return _AuthContext(headers=headers, error=error, credential=credential, oauth=True)
            headers["Cookie"] = session_cookie
        else:
            auth_headers = self._credential_headers(credential)
            if not auth_headers:
                label = credential_label(credential)
                return _AuthContext(headers=headers, error=f"凭据「{label}」未填写内容", credential=credential)
            headers.update(auth_headers)

        headers.update(headers_to_mapping(action.get("headers")))
        return _AuthContext(
            headers=headers,
            credential=credential,
            oauth=plan.mode == "oauth",
            reused_session=reused,
        )

    async def _refresh_oauth(self, auth: _AuthContext, action: dict[str, Any]) -> _AuthContext:
        """Re-run the OAuth login after a stored session cookie was rejected."""
        if auth.credential is None:
            return auth
        session_cookie, error = await self._oauth_login(auth.credential)
        if error:
            return _AuthContext(headers=auth.headers, error=error, credential=auth.credential, oauth=True)
        headers = self._base_headers()
        headers["Cookie"] = session_cookie
        headers.update(headers_to_mapping(action.get("headers")))
        return _AuthContext(headers=headers, credential=auth.credential, oauth=True)

    def _action_url(self, action: dict[str, Any], default_path: str = "") -> str:
        """Resolve an action's target URL, honouring an absolute custom path."""
        path = str(action.get("path") or "").strip() or default_path
        if not path:
            return self.base_url
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    @staticmethod
    def _action_method(action: dict[str, Any], default: str) -> str:
        """Map an action protocol onto an HTTP verb."""
        protocol = action.get("protocol")
        if protocol == PROTOCOL_GET:
            return "GET"
        if protocol == PROTOCOL_POST:
            return "POST"
        return default

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
        solve_challenge: bool = False,
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

        if not solve_challenge or not is_acw_sc_v2_challenge(text):
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

    async def _request_action(
        self,
        method: str,
        url: str,
        auth: _AuthContext,
        action: dict[str, Any],
        step: str = "请求",
    ) -> tuple[_TextResponse, _AuthContext]:
        """Perform an action request, re-logging in once if a session expired.

        Every attempt is recorded in the run's trace, so a caller never has to
        remember to log; ``step`` names the phase in that trace.

        Returns:
            Tuple of the response and the (possibly refreshed) auth context.
        """
        solve = action.get("solve_acw_sc_v2", False)
        response = await self._traced_request(method, url, auth.headers, solve, step)
        if response.status not in (401, 403) or not (auth.oauth and auth.reused_session):
            return response, auth

        logger.info("Stored OAuth session for %s expired; logging in again.", self.site_name)
        refreshed = await self._refresh_oauth(auth, action)
        if not refreshed.ok:
            return response, refreshed
        retried = await self._traced_request(
            method, url, refreshed.headers, solve, f"{step}（重新登录后）"
        )
        return retried, refreshed

    async def _traced_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        solve_challenge: bool,
        step: str,
    ) -> _TextResponse:
        """Issue one request and record it in the run's trace."""
        try:
            response = await self._request_text(method, url, headers, solve_challenge)
        except Exception as exc:
            self._record_attempt(
                step=step, method=method, endpoint=url, message=f"请求异常: {exc}", error=str(exc)
            )
            raise

        if is_acw_sc_v2_challenge(response.text):
            message = self._waf_message(response)
        elif response.status in (401, 403):
            message = "鉴权失败：凭据无效或已过期 (401/403)"
        else:
            message = self._response_message(None, response.text) or f"HTTP {response.status}"
        self._record_attempt(
            step=step,
            method=method,
            endpoint=url,
            status=response.status,
            success=200 <= response.status < 300 and not is_acw_sc_v2_challenge(response.text),
            message=message,
            response_text=response.text,
        )
        return response

    @staticmethod
    def _waf_message(response: _TextResponse) -> str:
        """Describe a WAF interception, including any solver failure."""
        if response.challenge_error:
            return f"acw_sc__v2 解算失败: {response.challenge_error}"
        return "被站点 WAF 防火墙拦截 (Aliyun WAF JS Challenge)"

    @staticmethod
    def _looks_like_html(text: str) -> bool:
        """Return whether a body is an HTML page rather than an API response."""
        lowered = text.lower()
        return "<html" in lowered or "denied by http_custom" in lowered

    def _parse_json(self, response: _TextResponse) -> tuple[dict[str, Any] | None, str]:
        """Parse a JSON body, returning a human-readable error instead of raising."""
        if is_acw_sc_v2_challenge(response.text):
            return None, self._waf_message(response)
        if response.status in (401, 403):
            return None, "鉴权失败：凭据无效或已过期 (401/403)"
        if self._looks_like_html(response.text):
            return None, "响应为 HTML 页面，可能被防火墙或登录页拦截"
        try:
            payload = json.loads(response.text)
        except (TypeError, ValueError):
            return None, f"响应内容非 JSON 格式 (HTTP {response.status})"
        if not isinstance(payload, dict):
            return None, f"响应结构非法 (HTTP {response.status})"
        return payload, ""

    # ------------------------------------------------------------------
    # new-api-user probing
    # ------------------------------------------------------------------
    async def _probe_new_api_user(
        self,
        action: dict[str, Any],
        action_name: str,
        auth: _AuthContext,
    ) -> None:
        """Fill in the ``new-api-user`` header by asking the station who we are.

        Only runs for New-API sites that follow the framework protocol and have
        no such header yet. OAuth actions are excluded: their session cookie
        already identifies the user. The id is probed at most once per run and
        then shared with the other action.
        """
        if auth.oauth or not wants_new_api_user_probe(self.config, action):
            return

        if not self._new_api_user_id:
            # An action already pointing at /api/user/self needs no probe: its
            # own response carries the id, and a probe would be the exact same
            # request. The caller harvests it instead.
            if self._action_url(action, self._default_balance_path()) == self._self_url():
                return
            try:
                response = await self._request_text(
                    "GET", self._self_url(), auth.headers, action.get("solve_acw_sc_v2", False)
                )
            except Exception as exc:
                logger.debug(f"Could not probe new-api-user for {self.site_name}: {exc}")
                return
            payload, error = self._parse_json(response)
            if error or payload is None:
                return
            self._remember_new_api_user(payload)
            if not self._new_api_user_id:
                return

        self._apply_new_api_user(action, action_name, auth)

    def _self_url(self) -> str:
        """Return the station's own ``/api/user/self`` URL."""
        return f"{self.base_url}{_NEW_API_SELF_PATH}"

    async def probe_new_api_user_id(self) -> tuple[str, str]:
        """Ask the station for the account id used by ``new-api-user``.

        Driven by the dashboard's fetch button, so it reports a reason rather
        than failing silently the way the automatic probe does.

        Returns:
            Tuple of ``(user_id, detail)``. The id is empty when unavailable, in
            which case the detail says why.
        """
        auth = await self._authenticate(self.balance, allow_login=False)
        if not auth.ok:
            return "", auth.error
        if auth.oauth:
            return "", "OAuth 凭据的会话本身已标识用户，无需 new-api-user"

        try:
            response, auth = await self._request_action(
                "GET",
                self._self_url(),
                auth,
                self.balance,
                step="探测 new-api-user",
            )
        except Exception as exc:
            return "", f"请求 {_NEW_API_SELF_PATH} 失败: {exc}"

        payload, error = self._parse_json(response)
        if error or payload is None:
            return "", error or "响应无法解析"

        self._remember_new_api_user(payload)
        if not self._new_api_user_id:
            return "", (
                f"{_NEW_API_SELF_PATH} 响应中没有 data.id 字段，"
                "该站点可能是 One-API（不需要 new-api-user）"
            )
        return self._new_api_user_id, ""

    def _remember_new_api_user(self, payload: dict[str, Any]) -> None:
        """Cache the station user id out of any ``/api/user/self`` style payload."""
        data = payload.get("data")
        user_id = data.get("id") if isinstance(data, dict) else payload.get("id")
        if user_id not in (None, ""):
            self._new_api_user_id = str(user_id)

    def _apply_new_api_user(
        self,
        action: dict[str, Any],
        action_name: str,
        auth: _AuthContext,
    ) -> None:
        """Write the cached user id into an action's headers and the writeback."""
        headers = upsert_header(action.get("headers"), NEW_API_USER_HEADER, self._new_api_user_id)
        action["headers"] = headers
        auth.headers[NEW_API_USER_HEADER] = self._new_api_user_id
        if action_name == ACTION_CHECKIN:
            self.writeback.checkin_headers = headers
        else:
            self.writeback.balance_headers = headers
        logger.info(
            "Using %s=%s for %s (%s)",
            NEW_API_USER_HEADER,
            self._new_api_user_id,
            self.site_name,
            action_name,
        )

    # ------------------------------------------------------------------
    # Balance
    # ------------------------------------------------------------------
    def _default_balance_path(self) -> str:
        """Return the framework's balance endpoint, or empty when unknown."""
        return _NEW_API_SELF_PATH if self.site_type == SITE_TYPE_NEW_API else ""

    @staticmethod
    def _extract_quota(payload: dict[str, Any]) -> float | None:
        """Pull a balance out of a station payload.

        Raw ``quota`` style fields are divided by the One-API conversion factor;
        currency-style fields are used as they are.
        """
        candidates: list[dict[str, Any]] = []
        data = payload.get("data")
        if isinstance(data, dict):
            candidates.append(data)
        candidates.append(payload)

        for source in candidates:
            for key in _RAW_QUOTA_KEYS:
                value = source.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return round(value / QUOTA_CONVERSION_FACTOR, 3)
            for key in _CURRENCY_KEYS:
                value = source.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return round(float(value), 3)
        return None

    async def query_balance(
        self,
        allow_login: bool = True,
        step: str = "查询余额",
    ) -> tuple[float, str]:
        """Query the account balance using the balance action config.

        Args:
            allow_login: When False, do not perform an OAuth login just to read
                the balance. Used for the opening read of a login-style
                check-in, where logging in would consume the day's sign-in.
            step: Name recorded in the request trace, so the opening and closing
                reads of a check-in can be told apart.

        Returns:
            Tuple of ``(quota, error_message)``. An empty error with a 0.0 quota
            means the site has no balance endpoint configured or adapted.
        """
        default_path = self._default_balance_path()
        if not str(self.balance.get("path") or "").strip() and not default_path:
            return 0.0, ""

        auth = await self._authenticate(self.balance, allow_login=allow_login)
        if not auth.ok:
            return 0.0, auth.error
        await self._probe_new_api_user(self.balance, ACTION_BALANCE, auth)

        url = self._action_url(self.balance, default_path)
        method = self._action_method(self.balance, "GET")
        try:
            response, auth = await self._request_action(
                method, url, auth, self.balance, step=step
            )
        except Exception as exc:
            logger.debug(f"Balance query failed for {self.site_name}: {exc}")
            return 0.0, f"余额查询请求异常: {exc}"

        payload, error = self._parse_json(response)
        if error:
            return 0.0, error
        assert payload is not None
        # The balance response usually carries the account id too; taking it
        # here saves a separate probe request.
        self._remember_new_api_user(payload)
        if (
            self._new_api_user_id
            and not auth.oauth
            and wants_new_api_user_probe(self.config, self.balance)
        ):
            self._apply_new_api_user(self.balance, ACTION_BALANCE, auth)

        quota = self._extract_quota(payload)
        if quota is None:
            return 0.0, "余额响应中未找到额度字段"
        return quota, ""

    @abstractmethod
    async def check_in(self) -> CheckInResult:
        """Perform daily check-in action.

        Returns:
            CheckInResult object.
        """

    @abstractmethod
    async def test_connection(self) -> CheckInResult:
        """Test connection and check site balance/status without checking in.

        Returns:
            CheckInResult object.
        """

    def _result(
        self,
        success: bool,
        message: str,
        total_quota: float = 0.0,
        gained_quota: float = 0.0,
        expired: bool = False,
        detail_on_success: bool = False,
    ) -> CheckInResult:
        """Build a CheckInResult for this site, attaching the request trace.

        Args:
            detail_on_success: Record the trace even though the run succeeded.
                Used when part of the run failed anyway — a stale balance after
                a successful check-in is otherwise unexplained.
        """
        include_detail = not success or detail_on_success
        return CheckInResult(
            site_id=self.site_id,
            site_name=self.site_name,
            success=success,
            message=message,
            gained_quota=gained_quota,
            total_quota=total_quota,
            expired=expired,
            error_detail=self._format_attempts(self.attempts) if include_detail else "",
            attempts=list(self.attempts),
        )


class NewApiAdapter(BaseCheckInAdapter):
    """Adapter for New-API / One-API relay station frameworks."""

    def _checkin_candidates(self) -> list[str]:
        """Return the check-in URLs to try, in order."""
        if str(self.checkin.get("path") or "").strip():
            return [self._action_url(self.checkin)]
        return [f"{self.base_url}{path}" for path in _NEW_API_CHECKIN_PATHS]

    async def _attempt_checkin(
        self,
        auth: _AuthContext,
    ) -> tuple[bool, str, bool, bool]:
        """Try the configured or framework check-in endpoints.

        Returns:
            Tuple of ``(success, message, expired, endpoint_missing)``.
        """
        follow_framework = self.checkin.get("protocol") in (PROTOCOL_AUTO, PROTOCOL_OAUTH)
        method = self._action_method(self.checkin, "POST")
        last_message = ""
        missing = True

        for url in self._checkin_candidates():
            try:
                response, auth = await self._request_action(
                    method, url, auth, self.checkin, step="签到"
                )
                if not auth.ok:
                    return False, auth.error, True, False

                # Some deployments only expose the verb the browser uses.
                if follow_framework and response.status in (404, 405):
                    fallback = "GET" if method == "POST" else "POST"
                    response, auth = await self._request_action(
                        fallback, url, auth, self.checkin, step="签到（换用 GET/POST）"
                    )

                if response.status == 404:
                    last_message = last_message or "签到接口不存在 (404)"
                    continue
                missing = False

                if response.status in (401, 403):
                    return False, "凭据已失效 (401/403)", True, False

                payload, error = self._parse_json(response)
                if error:
                    last_message = error
                    continue

                assert payload is not None
                message = str(payload.get("message") or payload.get("msg") or "").strip()
                if message:
                    last_message = message
                if payload.get("success") is True:
                    return True, message or "签到成功", False, False
                if self._message_indicates_checkin(message):
                    return True, message, False, False
            except Exception as exc:
                last_message = f"请求异常: {exc}"
                continue

        return False, last_message, False, missing

    async def check_in(self) -> CheckInResult:
        """Perform check-in on a New-API / One-API station.

        Runs the configured protocol (or the framework default), then compares
        the balance before and after so login-granted bonuses are still counted.

        With the OAuth protocol the login *is* the check-in: stations that have
        disabled their check-in endpoint grant the daily bonus only on a real
        login. So the session is re-established every run, and the opening
        balance read is not allowed to consume it.

        Returns:
            CheckInResult containing execution status and balance.
        """
        login_is_checkin = self.checkin.get("protocol") == PROTOCOL_OAUTH

        # The opening balance read comes first so a stale OAuth session is
        # already refreshed by the time the check-in request is authenticated.
        initial_quota, initial_error = await self.query_balance(allow_login=not login_is_checkin)

        auth = await self._authenticate(self.checkin, force_login=login_is_checkin)
        if not auth.ok:
            return self._result(False, auth.error, expired=True)
        logged_in = login_is_checkin and not auth.reused_session
        await self._probe_new_api_user(self.checkin, ACTION_CHECKIN, auth)

        # The opening balance was unreadable before the login; read it now that
        # a session exists, so the delta below still has a baseline.
        if login_is_checkin and initial_error:
            initial_quota, initial_error = await self.query_balance()

        if login_is_checkin:
            # The login *is* the sign-in on these stations, so stop here. Probing
            # the check-in endpoints afterwards only adds 404/401 noise, and the
            # station has already credited the day.
            return await self._finish_login_checkin(initial_quota, initial_error, logged_in)

        success, message, expired, endpoint_missing = await self._attempt_checkin(auth)
        total_quota, balance_error = await self.query_balance(step="查询最终余额")

        gained = 0.0
        if not initial_error and not balance_error and total_quota > initial_quota:
            gained = round(total_quota - initial_quota, 3)
            success = True
            message = f"额度增加 +$ {gained}" + (f"（{message}）" if message else "")

        if balance_error:
            expired = expired or "401" in balance_error
            message = message or balance_error
            # A failed re-read must not overwrite a balance we already confirmed
            # this run, or the dashboard and calendar would show a false zero.
            if not initial_error:
                total_quota = initial_quota

        return self._result(
            success=success,
            message=message or ("签到成功" if success else "签到失败：站点未返回可识别结果"),
            total_quota=total_quota,
            gained_quota=gained,
            expired=expired,
            # Surface the trace when the balance read failed even though the
            # check-in itself worked, so a stale figure has an explanation.
            detail_on_success=bool(balance_error),
        )

    async def _finish_login_checkin(
        self,
        initial_quota: float,
        initial_error: str,
        logged_in: bool,
    ) -> CheckInResult:
        """Complete an OAuth check-in, where logging in is the sign-in itself.

        The freshly issued session cookie is already written back to the
        credential, so the closing balance read reuses it rather than logging in
        again. No check-in endpoint is contacted at all.

        Args:
            initial_quota: Balance read before the login, if it was readable.
            initial_error: Why that read failed, if it did.
            logged_in: Whether a fresh login actually happened.

        Returns:
            The check-in result.
        """
        total_quota, balance_error = await self.query_balance(step="查询最终余额")

        gained = 0.0
        if not initial_error and not balance_error and total_quota > initial_quota:
            gained = round(total_quota - initial_quota, 3)

        if gained > 0:
            message = f"额度增加 +$ {gained}（OAuth 重新登录即签到）"
        elif logged_in:
            message = "OAuth 重新登录成功（登录即签到）"
        else:
            message = "OAuth 会话仍有效，未重新登录"

        if balance_error and not initial_error:
            # Keep the figure we already confirmed rather than reporting zero.
            total_quota = initial_quota

        return self._result(
            success=True,
            message=message,
            total_quota=total_quota,
            gained_quota=gained,
            expired=False,
            detail_on_success=bool(balance_error),
        )

    async def test_connection(self) -> CheckInResult:
        """Test authentication and query account quota.

        Returns:
            CheckInResult containing status and total quota.
        """
        total_quota, error = await self.query_balance(step="连通性测试")
        if not error:
            return self._result(True, "连接成功", total_quota=total_quota)

        # Fall back to /v1/models so a WAF-blocked management API is still
        # distinguishable from a dead credential.
        key_is_valid = False
        auth = await self._authenticate(self.balance)
        if auth.ok:
            try:
                models, auth = await self._request_action(
                    "GET",
                    f"{self.base_url}/v1/models",
                    auth,
                    self.balance,
                    step="API 接口兜底探测",
                )
                if (
                    models.status == 200
                    and "model" in models.text.lower()
                    and not self._looks_like_html(models.text)
                ):
                    key_is_valid = True
                    error = "API Key 有效(模型接口可用)，但管理接口(/api/user/self)不可用"
            except Exception as exc:
                logger.debug(f"Model endpoint probe failed for {self.site_name}: {exc}")

        # A working key behind a blocked management API is not an expired
        # credential; reporting it as one would send the user to regenerate a
        # perfectly good key.
        return self._result(False, error, expired=not key_is_valid, detail_on_success=False)


class GenericRestAdapter(BaseCheckInAdapter):
    """Adapter for custom REST API check-in sites."""

    async def check_in(self) -> CheckInResult:
        """Execute the configured check-in request.

        With no custom path the request is a plain GET against the Base URL,
        since no framework endpoint is known for this site type. With the OAuth
        protocol the login is re-run first, since on those stations the login
        itself is what credits the daily bonus.

        Returns:
            CheckInResult object.
        """
        login_is_checkin = self.checkin.get("protocol") == PROTOCOL_OAUTH
        auth = await self._authenticate(self.checkin, force_login=login_is_checkin)
        if not auth.ok:
            return self._result(False, auth.error, expired=True)
        logged_in = login_is_checkin and not auth.reused_session

        if login_is_checkin:
            # The login is the sign-in; requesting anything else afterwards
            # would only add noise, exactly as for New-API stations.
            total_quota, balance_error = await self.query_balance(step="查询最终余额")
            return self._result(
                success=True,
                message=("OAuth 重新登录成功（登录即签到）" if logged_in
                         else "OAuth 会话仍有效，未重新登录"),
                total_quota=total_quota,
                expired=False,
                detail_on_success=bool(balance_error),
            )

        url = self._action_url(self.checkin)
        method = self._action_method(self.checkin, "GET" if not self.checkin.get("path") else "POST")
        try:
            response, auth = await self._request_action(
                method, url, auth, self.checkin, step="签到"
            )
        except Exception as exc:
            return self._result(False, f"请求失败: {exc}")
        if not auth.ok:
            return self._result(False, auth.error, expired=True)

        success, message = _interpret_generic_response(response, self._waf_message)

        total_quota, balance_error = await self.query_balance()
        if balance_error:
            logger.debug(f"Balance query skipped for {self.site_name}: {balance_error}")

        return self._result(
            success=success,
            message=message,
            total_quota=total_quota,
            expired=response.status in (401, 403),
        )

    async def test_connection(self) -> CheckInResult:
        """Probe the site without triggering a check-in.

        With a balance path configured the balance query is the whole test.
        Otherwise the site is reachable-tested with a plain GET on the Base URL,
        which never triggers a check-in.

        Returns:
            CheckInResult object.
        """
        total_quota, balance_error = await self.query_balance()
        if not balance_error and str(self.balance.get("path") or "").strip():
            return self._result(True, "连接成功", total_quota=total_quota)

        auth = await self._authenticate(self.balance)
        if not auth.ok:
            return self._result(False, auth.error, expired=True)

        try:
            response = await self._request_text(
                "GET",
                self._action_url(self.balance),
                auth.headers,
                self.balance.get("solve_acw_sc_v2", False),
            )
        except Exception as exc:
            return self._result(False, f"请求失败: {exc}")

        success, message = _interpret_generic_response(
            response, self._waf_message, default_success="连接成功"
        )
        if balance_error and success:
            message = f"{message}（余额查询: {balance_error}）"
        return self._result(
            success=success,
            message=message,
            total_quota=total_quota,
            expired=response.status in (401, 403),
        )


def _interpret_generic_response(
    response: _TextResponse,
    waf_message: Any,
    default_success: str = "签到成功",
) -> tuple[bool, str]:
    """Judge a free-form REST response, honouring an explicit ``success`` or ``ok`` field."""
    if is_acw_sc_v2_challenge(response.text):
        return False, waf_message(response)

    text_clean = response.text.strip()
    success = 200 <= response.status < 300

    try:
        payload = json.loads(response.text)
    except (TypeError, ValueError):
        payload = None

    if isinstance(payload, dict):
        for ok_key in ("success", "ok"):
            if ok_key in payload:
                val = payload[ok_key]
                if isinstance(val, bool):
                    success = success and val if val is not None else success
                elif isinstance(val, str) and val.strip().lower() in {"true", "false"}:
                    success = success and (val.strip().lower() == "true")

        human_msg = BaseCheckInAdapter._response_message(payload, "")
        if human_msg:
            message = human_msg
        elif success:
            message = default_success
        else:
            message = f"HTTP {response.status}"
    else:
        if success:
            if text_clean and len(text_clean) <= 60 and not text_clean.startswith(("{", "[", "<")):
                message = text_clean
            else:
                message = default_success
        else:
            if text_clean and len(text_clean) <= 100 and not text_clean.startswith("<"):
                message = f"HTTP {response.status}: {text_clean}"
            else:
                message = f"HTTP {response.status}"

    return success, message


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
    if normalize_site_type(site_config.get("type")) == SITE_TYPE_GENERIC:
        return GenericRestAdapter(site_config, session, acw_cache_file)
    return NewApiAdapter(site_config, session, acw_cache_file)
