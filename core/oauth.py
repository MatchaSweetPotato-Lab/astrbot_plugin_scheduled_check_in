"""OAuth login flows used to refresh relay-station session cookies.

New-API style stations expose a standard three-legged flow:

1. ``GET  {base_url}/api/status``          reveals whether a provider is enabled
   and its ``client_id``.
2. ``POST {base_url}/api/oauth/state``     issues a short-lived ``flow_token``
   used as the OAuth ``state``.
3. ``GET  {authorize_url}``                is called with the user's *third
   party* session cookie (``user_session`` for Github, ``_t`` for LinuxDO) and
   redirects back with an authorization ``code``.
4. ``GET  {base_url}/api/oauth/{provider}`` exchanges the code and returns the
   station's own session cookie.

The third-party leg only redirects when the user has already approved the
station's OAuth application in a browser at least once; otherwise the provider
answers with a consent page, which is reported back as an actionable error.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from curl_cffi.requests import AsyncSession

logger = logging.getLogger("astrbot")

GITHUB_OAUTH = "github_oauth"
LINUXDO_OAUTH = "linuxdo_oauth"

# Ordered fallback used when a check-in config selects the OAuth protocol
# without naming a specific credential.
OAUTH_CREDENTIAL_PRIORITY: tuple[str, ...] = (GITHUB_OAUTH, LINUXDO_OAUTH)


class OAuthError(RuntimeError):
    """Raised when an OAuth login cannot be completed."""


@dataclass(frozen=True)
class OAuthProvider:
    """Static description of one upstream identity provider."""

    # Path segment used by ``/api/oauth/{provider}`` on the relay station.
    slug: str
    label: str
    authorize_url: str
    # Keys published by ``/api/status``.
    enabled_key: str
    client_id_key: str
    # Cookie the user copies out of their browser for the provider's domain.
    cookie_hint: str
    # Github infers the callback from the registered application, and rejects
    # any redirect_uri that does not match it exactly. LinuxDO derives the
    # callback from the request host and requires it to be sent.
    send_redirect_uri: bool = False
    extra_authorize_params: dict[str, str] = field(default_factory=dict)


PROVIDERS: dict[str, OAuthProvider] = {
    GITHUB_OAUTH: OAuthProvider(
        slug="github",
        label="Github OAuth",
        authorize_url="https://github.com/login/oauth/authorize",
        enabled_key="github_oauth",
        client_id_key="github_client_id",
        cookie_hint="user_session",
    ),
    LINUXDO_OAUTH: OAuthProvider(
        slug="linuxdo",
        label="LinuxDO OAuth",
        authorize_url="https://connect.linux.do/oauth2/authorize",
        enabled_key="linuxdo_oauth",
        client_id_key="linuxdo_client_id",
        cookie_hint="_t",
        send_redirect_uri=True,
        extra_authorize_params={"response_type": "code"},
    ),
}


@dataclass
class OAuthLoginResult:
    """Outcome of one OAuth login attempt."""

    success: bool
    message: str
    session_cookie: str = ""


def get_provider(credential_type: str) -> OAuthProvider | None:
    """Return the provider description for a credential type."""
    return PROVIDERS.get(str(credential_type or "").strip().lower())


def _cookie_string(cookies: Any) -> str:
    """Render a curl_cffi cookie jar as a ``Cookie`` header value."""
    parts = []
    for name, value in cookies.items():
        raw = getattr(value, "value", value)
        if name:
            parts.append(f"{name}={raw}")
    return "; ".join(parts)


def _extract_code(location: str) -> str:
    """Pull the authorization ``code`` out of a redirect target."""
    if not location:
        return ""
    query = parse_qs(urlparse(location).query)
    values = query.get("code") or []
    return str(values[0]).strip() if values else ""


def _extract_error(location: str) -> str:
    """Pull an OAuth error description out of a redirect target."""
    query = parse_qs(urlparse(location).query)
    for key in ("error_description", "error"):
        values = query.get(key) or []
        if values:
            return str(values[0]).strip()
    return ""


class OAuthLoginClient:
    """Runs the relay-station OAuth login flow for one site."""

    def __init__(
        self,
        session: AsyncSession,
        base_url: str,
        impersonate: str,
        proxy: str | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            session: Active curl_cffi session.
            base_url: Relay station root URL without a trailing slash.
            impersonate: Browser fingerprint to reuse for every leg.
            proxy: Site-wide proxy, applied to the third-party legs too.
        """
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.impersonate = impersonate
        self.proxy = proxy or None

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> Any:
        """Issue one request with the site's proxy and fingerprint applied."""
        return await self.session.request(
            method,
            url,
            headers=headers or {},
            json=json_body,
            params=params,
            proxy=self.proxy,
            impersonate=self.impersonate,
            allow_redirects=allow_redirects,
        )

    async def _fetch_client_id(self, provider: OAuthProvider) -> str:
        """Read the provider's ``client_id`` from ``/api/status``."""
        url = f"{self.base_url}/api/status"
        try:
            response = await self._request("GET", url)
        except Exception as exc:
            raise OAuthError(f"探测站点 OAuth 配置失败: {exc}") from exc

        try:
            payload = json.loads(response.text)
        except (TypeError, ValueError) as exc:
            raise OAuthError("站点 /api/status 未返回 JSON，无法探测 OAuth 配置") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise OAuthError("站点 /api/status 响应缺少 data 字段")

        if data.get(provider.enabled_key) is False:
            raise OAuthError(f"站点未启用 {provider.label}")

        client_id = str(data.get(provider.client_id_key) or "").strip()
        if not client_id:
            raise OAuthError(f"站点未配置 {provider.label} 的 client_id")
        return client_id

    async def _fetch_flow_token(self, provider: OAuthProvider) -> str:
        """Ask the station for a single-use OAuth ``state`` token."""
        url = f"{self.base_url}/api/oauth/state"
        try:
            response = await self._request(
                "POST",
                url,
                headers={"Content-Type": "application/json"},
                json_body={"provider": provider.slug, "intent": "login"},
            )
        except Exception as exc:
            raise OAuthError(f"获取 OAuth state 失败: {exc}") from exc

        try:
            payload = json.loads(response.text)
        except (TypeError, ValueError) as exc:
            raise OAuthError("OAuth state 接口未返回 JSON") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        flow_token = ""
        if isinstance(data, dict):
            flow_token = str(data.get("flow_token") or "").strip()
        if not flow_token:
            message = ""
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
            raise OAuthError(message or "OAuth state 接口未返回 flow_token")
        return flow_token

    async def _authorize(
        self,
        provider: OAuthProvider,
        client_id: str,
        state: str,
        third_party_cookie: str,
    ) -> str:
        """Exchange the third-party session cookie for an authorization code."""
        params = {"client_id": client_id, "state": state, **provider.extra_authorize_params}
        if provider.send_redirect_uri:
            params["redirect_uri"] = f"{self.base_url}/api/oauth/{provider.slug}"

        try:
            response = await self._request(
                "GET",
                provider.authorize_url,
                headers={
                    "Cookie": third_party_cookie,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                params=params,
                allow_redirects=False,
            )
        except Exception as exc:
            raise OAuthError(f"请求 {provider.label} 授权端点失败: {exc}") from exc

        location = str(response.headers.get("location") or "")
        code = _extract_code(location)
        if code:
            return code

        redirect_error = _extract_error(location)
        if redirect_error:
            raise OAuthError(f"{provider.label} 拒绝授权: {redirect_error}")

        if response.status_code in (401, 403) or (
            300 <= response.status_code < 400 and "login" in location.lower()
        ):
            raise OAuthError(
                f"{provider.label} 会话 Cookie 已失效，请重新从浏览器复制 {provider.cookie_hint}"
            )
        raise OAuthError(
            f"{provider.label} 未直接返回授权码 (HTTP {response.status_code})，"
            f"请先在浏览器登录该站点并完成一次 OAuth 授权"
        )

    async def _exchange(self, provider: OAuthProvider, code: str, state: str) -> str:
        """Trade the authorization code for the station's session cookie."""
        url = f"{self.base_url}/api/oauth/{provider.slug}"
        try:
            response = await self._request(
                "GET",
                url,
                params={"code": code, "state": state},
                allow_redirects=False,
            )
        except Exception as exc:
            raise OAuthError(f"回调站点 OAuth 接口失败: {exc}") from exc

        session_cookie = _cookie_string(response.cookies)
        if session_cookie:
            return session_cookie

        message = ""
        try:
            payload = json.loads(response.text)
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
        except (TypeError, ValueError):
            message = ""
        raise OAuthError(message or f"站点未在 OAuth 回调中下发会话 Cookie (HTTP {response.status_code})")

    async def login(self, credential_type: str, third_party_cookie: str) -> OAuthLoginResult:
        """Run the full flow and return the station's session cookie.

        Args:
            credential_type: ``github_oauth`` or ``linuxdo_oauth``.
            third_party_cookie: Provider-domain session cookie from the user.

        Returns:
            An ``OAuthLoginResult`` describing success or the failure reason.
        """
        provider = get_provider(credential_type)
        if provider is None:
            return OAuthLoginResult(False, f"不支持的 OAuth 凭据类型: {credential_type}")

        cookie = str(third_party_cookie or "").strip().replace("\n", "").replace("\r", "")
        if not cookie:
            return OAuthLoginResult(
                False,
                f"{provider.label} 凭据为空，请填入 {provider.cookie_hint} Cookie",
            )

        try:
            client_id = await self._fetch_client_id(provider)
            state = await self._fetch_flow_token(provider)
            code = await self._authorize(provider, client_id, state, cookie)
            session_cookie = await self._exchange(provider, code, state)
        except OAuthError as exc:
            logger.info("OAuth login failed for %s at %s: %s", provider.slug, self.base_url, exc)
            return OAuthLoginResult(False, str(exc))

        logger.info("OAuth login succeeded for %s at %s", provider.slug, self.base_url)
        return OAuthLoginResult(True, f"{provider.label} 登录成功", session_cookie)
