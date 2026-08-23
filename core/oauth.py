"""OAuth login flows used to refresh relay-station session cookies.

New-API style stations expose a standard four-legged flow:

1. ``GET  {base_url}/api/status``          reveals whether a provider is enabled
   and its ``client_id``.
2. ``GET  {base_url}/api/oauth/state``     issues a short-lived ``state``. Most
   builds also bind it to a *server-side session*, so the cookie that response
   sets has to be carried to leg 4 or the station rejects the callback with
   ``state is empty or not same``. Newer branches serve the same route over
   ``POST``; older ones have no such route at all.
3. ``GET  {authorize_url}``                is called with the user's *third
   party* session cookie (``user_session`` for Github, ``_t`` for LinuxDO) and
   redirects back with an authorization ``code``. The query string mirrors the
   station's own login page exactly — the callback is inferred from the
   registered application, so sending a guessed ``redirect_uri`` is refused.
4. ``GET  {base_url}/api/oauth/{provider}`` exchanges the code and returns the
   station's own session cookie.

The third-party leg only redirects when the user has already approved the
station's OAuth application in a browser at least once; otherwise the provider
answers with a consent page, which is reported back as an actionable error.

A provider that bounces to its own login page has rejected the *session*; one
that answers 401/403 with no redirect has refused the *request*, which usually
means something other than an expired cookie. The two are reported apart.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from curl_cffi.requests import AsyncSession

logger = logging.getLogger("astrbot")

# Field names forks use for the OAuth state token, in preference order.
_STATE_KEYS = ("flow_token", "state", "token", "oauth_state", "flowToken")

# Longest response body quoted back in an error message.
_ERROR_BODY_LIMIT = 300


def _abridge(text: str, limit: int = _ERROR_BODY_LIMIT) -> str:
    """Shorten a response body for inclusion in an error message."""
    body = " ".join(str(text or "").split())
    if len(body) <= limit:
        return body
    return f"{body[:limit]}…"


def _extract_flow_token(payload: Any) -> str:
    """Pull the OAuth state token out of any shape a fork might return.

    Accepts ``data.flow_token``, a bare ``data`` string, the same keys at the
    top level, and the ``state``/``token`` aliases.
    """
    if isinstance(payload, str):
        return payload.strip()
    if not isinstance(payload, dict):
        return ""

    data = payload.get("data")
    if isinstance(data, str) and data.strip():
        return data.strip()
    for source in (data, payload):
        if isinstance(source, dict):
            for key in _STATE_KEYS:
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""

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
    # Additional cookies the provider needs before it treats a non-browser
    # request as signed in. Github in particular answers a request carrying only
    # user_session with a redirect to its login page.
    companion_cookies: tuple[str, ...] = ()
    # Cookie that carries a solved bot-management challenge. Deliberately not in
    # all_cookies: it is only needed when the host actually challenges, so
    # demanding it up front would report a working credential as incomplete.
    challenge_cookie: str = "cf_clearance"
    # Query parameters beyond client_id and state. These mirror the station's own
    # browser flow exactly: every provider validates the authorize request
    # against the registered application, so a parameter the browser omits is not
    # a harmless extra — supplying a guessed one is grounds for rejection.
    extra_authorize_params: dict[str, str] = field(default_factory=dict)

    @property
    def all_cookies(self) -> tuple[str, ...]:
        """Every cookie name worth copying, primary first."""
        return (self.cookie_hint, *self.companion_cookies)

    @property
    def authorize_host(self) -> str:
        """Host whose cookies the user must copy, e.g. ``github.com``."""
        return urlparse(self.authorize_url).netloc or self.authorize_url


PROVIDERS: dict[str, OAuthProvider] = {
    GITHUB_OAUTH: OAuthProvider(
        slug="github",
        label="Github OAuth",
        authorize_url="https://github.com/login/oauth/authorize",
        enabled_key="github_oauth",
        client_id_key="github_client_id",
        cookie_hint="user_session",
        # user_session on its own is not enough: Github checks the same-site
        # mirror and its session cookie before honouring an authorize request,
        # and otherwise redirects to its own login page.
        companion_cookies=("__Host-user_session_same_site", "_gh_sess", "logged_in"),
        extra_authorize_params={"scope": "user:email"},
    ),
    LINUXDO_OAUTH: OAuthProvider(
        slug="linuxdo",
        label="LinuxDO OAuth",
        authorize_url="https://connect.linux.do/oauth2/authorize",
        enabled_key="linuxdo_oauth",
        client_id_key="linuxdo_client_id",
        cookie_hint="_t",
        companion_cookies=("_forum_session",),
        extra_authorize_params={"response_type": "code"},
    ),
}


@dataclass
class OAuthLoginResult:
    """Outcome of one OAuth login attempt."""

    success: bool
    message: str
    session_cookie: str = ""
    # The provider cookie after any rotation, when it changed during the flow.
    # Empty means "unchanged"; the caller must not overwrite a working value
    # with an empty string.
    rotated_provider_cookie: str = ""


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a ``Cookie`` header into a mapping, keeping the last of duplicates."""
    jar: dict[str, str] = {}
    for part in str(value or "").split(";"):
        name, sep, cookie_value = part.strip().partition("=")
        name = name.strip()
        if name and sep:
            jar[name] = cookie_value.strip()
    return jar


def format_cookie_header(jar: dict[str, str]) -> str:
    """Render a cookie mapping back into a ``Cookie`` header value."""
    return "; ".join(f"{name}={value}" for name, value in jar.items() if name)


def merge_rotated_cookies(current: str, response_cookies: Any) -> str:
    """Merge a response's ``Set-Cookie`` values over the stored cookie.

    Providers rotate session cookies as they are used, and a browser stays
    signed in precisely because it keeps the rotated values. Replaying one
    frozen snapshot forever goes stale on its own and looks like a replayed
    session. Only the names the response actually set are replaced, so a
    partial response cannot drop the rest of the jar.

    Args:
        current: The cookie header currently stored for the credential.
        response_cookies: Cookie jar from a provider response.

    Returns:
        The merged cookie header, or an empty string when nothing changed.
    """
    jar = parse_cookie_header(current)
    if not jar:
        return ""

    changed = False
    try:
        items = list(response_cookies.items())
    except Exception:
        return ""

    for name, raw in items:
        name = str(name or "").strip()
        if not name or name not in jar:
            # Only refresh cookies we already hold. A provider may set unrelated
            # cookies (analytics, flash messages) that add noise and no value.
            continue
        value = str(getattr(raw, "value", raw) or "")
        # An expiry is signalled by a blank or sentinel value; keeping the old
        # one is safer than storing a deletion.
        if not value or value in ("deleted", '""'):
            continue
        if jar[name] != value:
            jar[name] = value
            changed = True

    return format_cookie_header(jar) if changed else ""


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


def _safe_location(location: str) -> str:
    """Render a redirect target for the trace with secrets removed.

    A redirect can carry the authorization code and the state, neither of which
    belongs in a stored log.
    """
    try:
        parsed = urlparse(str(location or ""))
    except ValueError:
        return ""
    if not parsed.scheme and not parsed.netloc and not parsed.path:
        return ""
    redacted = {}
    for key, values in parse_qs(parsed.query).items():
        redacted[key] = "***" if key in ("code", "state", "flow_token") else (values[0] if values else "")
    query = "&".join(f"{k}={v}" for k, v in redacted.items())
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
    return f"{base}?{query}" if query else base


def _cookie_names(cookie: str) -> set[str]:
    """Return the cookie names present in a raw ``Cookie`` header value."""
    names = set()
    for part in str(cookie or "").split(";"):
        name, _, _value = part.strip().partition("=")
        if name.strip():
            names.add(name.strip())
    return names


def _missing_cookies(provider: OAuthProvider, cookie: str) -> list[str]:
    """Return the recommended cookies absent from what the user pasted."""
    present = _cookie_names(cookie)
    return [name for name in provider.all_cookies if name not in present]


def _refused_request_message(
    provider: OAuthProvider,
    cookie: str,
    status: int,
    body: str,
) -> str:
    """Explain an authorize request refused outright, with no redirect.

    Distinct from a bounce to the login page: the session may well be valid
    while the request itself is refused, so this lists the plausible causes
    instead of asserting the cookie is dead. Any message the provider supplied
    comes first — it is better evidence than any guess made here.
    """
    detail = _abridge(_strip_html(body), 160)
    missing = _missing_cookies(provider, cookie)

    reasons = []
    if missing:
        reasons.append(f"Cookie 缺少 {', '.join(missing)}")
    reasons.append("该账号尚未在浏览器中授权过此站点的 OAuth 应用")
    reasons.append(f"{provider.authorize_host} 拒绝了服务端发起的请求（风控 / 频率限制）")
    reasons.append("会话 Cookie 已失效")

    message = (
        f"{provider.label} 拒绝了授权请求 (HTTP {status})，未返回跳转。可能原因："
        + "；".join(f"{index}. {reason}" for index, reason in enumerate(reasons, 1))
        + f"。请先在浏览器完成一次 {provider.authorize_host} 的 OAuth 授权，"
        f"并复制该域名的完整 Cookie（至少 {', '.join(provider.all_cookies)}）。"
    )
    if detail:
        message += f" 站点返回：{detail}"
    return message


def _strip_html(text: str) -> str:
    """Reduce an HTML error page to its readable text."""
    without_scripts = re.sub(
        r"<(script|style)\b.*?</\1>", " ", str(text or ""), flags=re.S | re.I
    )
    return " ".join(re.sub(r"<[^>]+>", " ", without_scripts).split())


# Markers of a Cloudflare interstitial. The visible title is localised, so match
# the machine-readable pieces too — the challenge script path and the form the
# challenge posts back are stable across languages.
_CLOUDFLARE_MARKERS: tuple[str, ...] = (
    "just a moment",
    "enable javascript and cookies to continue",
    "/cdn-cgi/challenge-platform/",
    "cf-browser-verification",
    "cf_chl_opt",
    "__cf_chl_",
    "checking if the site connection is secure",
    "attention required! | cloudflare",
)


def is_cloudflare_challenge(status: int, body: str, headers: Any = None) -> bool:
    """Recognise Cloudflare's bot-management interstitial.

    Worth telling apart from any other refusal: nothing about the user's cookie
    is wrong, so every remedy for an expired session is the wrong advice. The
    ``cf-mitigated`` header states it outright when present; otherwise the body
    of the challenge page is the evidence.
    """
    if status not in (403, 503, 429):
        return False
    try:
        mitigated = str((headers or {}).get("cf-mitigated") or "").strip().lower()
    except Exception:
        mitigated = ""
    if mitigated == "challenge":
        return True
    text = str(body or "").lower()
    return any(marker in text for marker in _CLOUDFLARE_MARKERS)


def _cloudflare_challenge_message(provider: OAuthProvider, status: int) -> str:
    """Explain a Cloudflare interstitial, and what actually gets past one.

    The clearance cookie is bound to the IP address and User-Agent that solved
    the challenge, which is the part users get wrong: copying it out of a browser
    on another machine, or leaving a proxy in the way, invalidates it. Say so
    rather than letting them retry the copy forever.
    """
    return (
        f"{provider.authorize_host} 返回了 Cloudflare 人机验证页 (HTTP {status})，"
        "这不是凭据失效——服务端请求无法执行验证页里的 JavaScript。"
        f"可尝试：1. 在浏览器通过验证后，把 {provider.challenge_cookie} 一起复制进该凭据"
        f"（与 {', '.join(provider.all_cookies)} 放在同一行）；"
        "2. 该 Cookie 绑定 IP 与 User-Agent，需与浏览器同出口 IP（通常要去掉站点代理），"
        "且「全局设置」的浏览器指纹要与该浏览器一致；"
        "3. 它通常仅数十分钟有效，定时签到多半会再次被拦，"
        f"更稳妥的做法是给该站点换用 Github OAuth 或普通 Token / Cookie 凭据。"
    )


def _rejected_session_message(provider: OAuthProvider, cookie: str) -> str:
    """Explain a provider bouncing an authorize request to its login page.

    An expired cookie and an incomplete one look identical from here, and in
    practice the second is more common: people copy only the cookie named in
    the hint. So name the missing ones instead of only claiming expiry.
    """
    missing = _missing_cookies(provider, cookie)
    if missing:
        return (
            f"{provider.label} 未接受该会话 Cookie（缺少 {', '.join(missing)}）。"
            f"请从浏览器开发者工具复制 {provider.authorize_host} 的完整 Cookie，"
            f"至少包含 {', '.join(provider.all_cookies)}，而不是只复制 {provider.cookie_hint}。"
        )
    return (
        f"{provider.label} 会话 Cookie 已失效或被拒绝，"
        f"请重新从浏览器复制 {provider.authorize_host} 的完整 Cookie。"
    )


class OAuthLoginClient:
    """Runs the relay-station OAuth login flow for one site."""

    def __init__(
        self,
        session: AsyncSession,
        base_url: str,
        impersonate: str,
        proxy: str | None = None,
        on_attempt: Callable[..., None] | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            session: Active curl_cffi session.
            base_url: Relay station root URL without a trailing slash.
            impersonate: Browser fingerprint to reuse for every leg.
            proxy: Site-wide proxy, applied to the third-party legs too.
            on_attempt: Optional callback recording each leg in the caller's
                request trace. Without it an OAuth failure is invisible in the
                log detail view, which is the only place a user can see what
                the station actually replied.
        """
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.impersonate = impersonate
        self.proxy = proxy or None
        self._on_attempt = on_attempt
        # Set by the authorize leg. Held here rather than returned, because a
        # rejected login still needs its rotation persisted — replaying a value
        # the provider has already retired guarantees the next failure.
        self._rotated_provider_cookie = ""


    def _record(
        self,
        step: str,
        method: str,
        url: str,
        *,
        status: int | None = None,
        success: bool = False,
        response_text: str = "",
        message: str = "",
        error: str = "",
    ) -> None:
        """Forward one leg to the caller's trace, if it wants them."""
        if self._on_attempt is None:
            return
        try:
            self._on_attempt(
                step=step,
                method=method,
                endpoint=url,
                status=status,
                success=success,
                response_text=response_text,
                message=message,
                error=error,
            )
        except Exception:  # tracing must never break the login
            pass

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
            self._record("探测 OAuth 配置", "GET", url, error=str(exc))
            raise OAuthError(f"探测站点 OAuth 配置失败: {exc}") from exc

        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""

        def fail(detail: str) -> OAuthError:
            self._record("探测 OAuth 配置", "GET", url, status=status,
                         response_text=body, error=detail)
            return OAuthError(detail)

        try:
            payload = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise fail("站点 /api/status 未返回 JSON，无法探测 OAuth 配置") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise fail("站点 /api/status 响应缺少 data 字段")

        if data.get(provider.enabled_key) is False:
            raise fail(f"站点未启用 {provider.label}")

        client_id = str(data.get(provider.client_id_key) or "").strip()
        if not client_id:
            raise fail(f"站点未配置 {provider.label} 的 client_id")

        self._record("探测 OAuth 配置", "GET", url, status=status, success=True,
                     response_text=body)
        return client_id

    async def _fetch_flow_token(self, provider: OAuthProvider) -> tuple[str, str]:
        """Ask the station for a single-use OAuth ``state`` token.

        Classic one-api / New-API registers this as ``GET`` and answers with the
        state as a bare ``data`` string, while storing it in a **server-side
        session** keyed by a cookie set on this very response. That cookie has
        to travel to the callback, or the station compares the returned state
        against an empty session and answers ``state is empty or not same``.
        Newer forks use ``POST`` and nest the value under ``data.flow_token``,
        so both methods are tried.

        Returns:
            Tuple of ``(state, station_cookie)``. The cookie is empty when the
            station did not set one.
        """
        url = f"{self.base_url}/api/oauth/state"
        attempts: list[tuple[str, int | None, str]] = []

        for method in ("GET", "POST"):
            step = "获取 OAuth state"
            try:
                if method == "GET":
                    response = await self._request(
                        "GET", url, params={"provider": provider.slug}
                    )
                else:
                    response = await self._request(
                        "POST",
                        url,
                        headers={"Content-Type": "application/json"},
                        json_body={"provider": provider.slug, "intent": "login"},
                    )
            except Exception as exc:
                self._record(step, method, url, error=str(exc))
                raise OAuthError(f"获取 OAuth state 失败: {exc}") from exc

            status = getattr(response, "status_code", None)
            body = getattr(response, "text", "") or ""

            # A 404/405 here means the route is not registered for this verb;
            # the other verb may still work, so keep going before giving up.
            if status in (404, 405):
                attempts.append((method, status, body))
                self._record(
                    step, method, url, status=status, response_text=body,
                    message="该方法不被支持，尝试其他方法",
                )
                continue

            try:
                payload = json.loads(body)
            except (TypeError, ValueError):
                attempts.append((method, status, body))
                self._record(step, method, url, status=status,
                             response_text=body, error="响应非 JSON")
                continue

            flow_token = _extract_flow_token(payload)
            if flow_token:
                station_cookie = _cookie_string(getattr(response, "cookies", {}) or {})
                self._record(
                    step, method, url, status=status, success=True,
                    response_text=body,
                    message=("已取得 state 与会话 Cookie" if station_cookie
                             else "已取得 state（站点未下发会话 Cookie）"),
                )
                return flow_token, station_cookie

            message = ""
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
            detail = message or f"响应中没有可用的 state 字段：{_abridge(body)}"
            self._record(step, method, url, status=status,
                         response_text=body, error=detail)
            raise OAuthError(f"OAuth state 接口未返回 state（{detail}）")

        # Neither verb exists. Older builds validated nothing, so a local state
        # is worth trying, but a station that does validate will reject it.
        local_state = secrets.token_urlsafe(24)
        tried = ", ".join(f"{m} HTTP {s}" for m, s, _ in attempts)
        self._record(
            "获取 OAuth state", "-", url, success=True,
            message=f"站点无 state 接口（{tried}），改用本地生成的 state",
        )
        logger.info("No /api/oauth/state on %s (%s); using a local state.", self.base_url, tried)
        return local_state, ""

    async def _authorize(
        self,
        provider: OAuthProvider,
        client_id: str,
        state: str,
        third_party_cookie: str,
    ) -> tuple[str, str]:
        """Exchange the third-party session cookie for an authorization code.

        Returns:
            Tuple of ``(code, rotated_cookie)``. The rotated cookie is empty
            unless the provider refreshed one of the cookies we already hold.
        """
        params = {"client_id": client_id, "state": state, **provider.extra_authorize_params}

        try:
            response = await self._request(
                "GET",
                provider.authorize_url,
                headers={
                    "Cookie": third_party_cookie,
                    # A browser reaches this page by clicking the provider button
                    # on the station's login page. Send that navigation's full
                    # signature — a Referer without the matching Sec-Fetch-Site
                    # describes a request no browser can make, and bot scoring
                    # reads the inconsistency. Everything else (Accept,
                    # Sec-Ch-Ua, Accept-Language) is left to the impersonation,
                    # which already sends the real Chrome values; overriding one
                    # by hand only makes the header set disagree with the
                    # User-Agent it claims.
                    "Referer": f"{self.base_url}/",
                    "Sec-Fetch-Site": "cross-site",
                },
                params=params,
                allow_redirects=False,
            )
        except Exception as exc:
            self._record(f"{provider.label} 授权", "GET", provider.authorize_url, error=str(exc))
            raise OAuthError(f"请求 {provider.label} 授权端点失败: {exc}") from exc

        status = response.status_code
        location = str(response.headers.get("location") or "")
        body = getattr(response, "text", "") or ""
        step = f"{provider.label} 授权"

        def fail(detail: str) -> OAuthError:
            # A redirect carries its reason in the Location header, and the body
            # is a full consent or login page worth no space. A non-redirect
            # rejection has no Location at all, so there the body is the only
            # evidence — record an abridged copy rather than nothing.
            self._record(
                step, "GET", provider.authorize_url, status=status,
                message=f"Location: {_safe_location(location)}" if location else "",
                response_text="" if location else _abridge(body, 400),
                error=detail,
            )
            return OAuthError(detail)

        # Capture rotation even on failure paths: the provider may have moved the
        # session on before rejecting, and storing the new value keeps the next
        # run from replaying one it has already retired.
        rotated = merge_rotated_cookies(third_party_cookie, getattr(response, "cookies", {}))
        if rotated:
            self._rotated_provider_cookie = rotated

        code = _extract_code(location)
        if code:
            self._record(step, "GET", provider.authorize_url, status=status, success=True,
                         message="已取得授权码" + ("（凭据 Cookie 已轮换，将回写）" if rotated else ""))
            return code, rotated

        redirect_error = _extract_error(location)
        if redirect_error:
            raise fail(f"{provider.label} 拒绝授权: {redirect_error}")

        if 300 <= status < 400 and "login" in location.lower():
            # Bounced to the provider's own login page: the session was not
            # accepted, so an expired or incomplete cookie is the likely cause.
            raise fail(_rejected_session_message(provider, third_party_cookie))
        if is_cloudflare_challenge(status, body, getattr(response, "headers", None)):
            # Checked before the generic refusal: a challenge page says nothing
            # about the credential, so every remedy for a bad cookie is wrong
            # advice here and would send the user re-copying it for nothing.
            raise fail(_cloudflare_challenge_message(provider, status))
        if status in (401, 403):
            # No redirect at all. The session may be fine while the *request* is
            # refused — a blocked client, a rate limit, or an application that
            # has not been authorized for this account — so do not assert that
            # the cookie is dead when the body may say otherwise.
            raise fail(_refused_request_message(provider, third_party_cookie, status, body))
        raise fail(
            f"{provider.label} 未直接返回授权码 (HTTP {status})，"
            f"请先在浏览器登录该站点并完成一次 OAuth 授权"
        )

    async def _exchange(
        self,
        provider: OAuthProvider,
        code: str,
        state: str,
        station_cookie: str = "",
    ) -> str:
        """Trade the authorization code for the station's session cookie.

        Args:
            provider: Identity provider being used.
            code: Authorization code from the provider.
            state: State that was sent to the provider.
            station_cookie: Cookie the station set when it issued the state. It
                keys the server-side session holding that state, so without it
                the station compares against an empty session and rejects the
                callback with ``state is empty or not same``.
        """
        url = f"{self.base_url}/api/oauth/{provider.slug}"
        headers = {"Cookie": station_cookie} if station_cookie else None
        try:
            response = await self._request(
                "GET",
                url,
                headers=headers,
                params={"code": code, "state": state},
                allow_redirects=False,
            )
        except Exception as exc:
            self._record("OAuth 回调", "GET", url, error=str(exc))
            raise OAuthError(f"回调站点 OAuth 接口失败: {exc}") from exc

        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""
        session_cookie = _cookie_string(response.cookies)
        if session_cookie:
            self._record("OAuth 回调", "GET", url, status=status, success=True,
                         response_text=body, message="已取得站点会话 Cookie")
            return session_cookie

        message = ""
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
        except (TypeError, ValueError):
            message = ""
        detail = message or f"站点未在 OAuth 回调中下发会话 Cookie (HTTP {status})"
        self._record("OAuth 回调", "GET", url, status=status,
                     response_text=body, error=detail)
        raise OAuthError(detail)

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
                f"{provider.label} 凭据为空，请填入 {provider.authorize_host} 的完整 Cookie"
                f"（至少包含 {', '.join(provider.all_cookies)}）",
            )

        # Warn rather than refuse: a provider may still accept a partial cookie,
        # and guessing wrong would block a working setup.
        missing = _missing_cookies(provider, cookie)
        if missing:
            logger.info(
                "%s cookie for %s is missing %s; the authorize leg may be rejected.",
                provider.label,
                self.base_url,
                ", ".join(missing),
            )
            self._record(
                f"{provider.label} 凭据检查",
                "-",
                provider.authorize_host,
                success=True,
                message=f"Cookie 缺少 {', '.join(missing)}，若授权被拒请补全",
            )

        try:
            client_id = await self._fetch_client_id(provider)
            state, station_cookie = await self._fetch_flow_token(provider)
            code, rotated_cookie = await self._authorize(provider, client_id, state, cookie)
            session_cookie = await self._exchange(provider, code, state, station_cookie)
        except OAuthError as exc:
            logger.info("OAuth login failed for %s at %s: %s", provider.slug, self.base_url, exc)
            return OAuthLoginResult(
                False,
                str(exc),
                rotated_provider_cookie=self._rotated_provider_cookie,
            )

        if rotated_cookie:
            logger.info("%s rotated its session cookie for %s; writing it back.",
                        provider.label, self.base_url)
        logger.info("OAuth login succeeded for %s at %s", provider.slug, self.base_url)
        return OAuthLoginResult(
            True,
            f"{provider.label} 登录成功",
            session_cookie,
            rotated_provider_cookie=rotated_cookie or self._rotated_provider_cookie,
        )
