"""Recognising a Cloudflare challenge, and getting a request past it.

Cloudflare attaches its verdict to the TLS fingerprint of the client, so a
request it challenged is first retried with other browser fingerprints, and the
first one it lets through is kept for the rest of the run. That is cheap, but a
managed challenge often turns every fingerprint away; the request is then
re-issued from a headless browser that solves the challenge (see
:mod:`core.browser`), when Playwright is installed and the option is on.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .browser import (
    CHANNEL_AUTO,
    BrowserOptions,
    BrowserRequest,
    BrowserSolver,
    BrowserUnavailable,
    normalize_channel,
    normalize_timeout,
)
from .browser import DEFAULT_TIMEOUT_SECONDS as DEFAULT_BROWSER_TIMEOUT
from .http_client import fingerprint_label, get_impersonate_options

logger = logging.getLogger("astrbot")

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

# Fingerprints screened when a request is challenged, in order. Profiles of one
# family tend to share a verdict, so the order alternates families. chrome150
# leads: it is the first profile whose ClientHello carries the ML-DSA signature
# algorithms, and in interleaved tests it alone passed connect.linux.do's
# managed challenge — removing just those algorithms from it got it challenged.
# The rest passed at other times; verdicts drift, so none is assumed to pass:
# each is tried against the real request.
FALLBACK_FINGERPRINTS: tuple[str, ...] = (
    "chrome150",
    "firefox133",
    "safari184",
    "safari2601",
    "chrome146",
    "safari180",
    "firefox147",
)
MAX_FALLBACK_ATTEMPTS = 4
# Rapid retries from one IP earn a 429 that reads exactly like a challenge.
FALLBACK_PACING_SECONDS = 2.0

# Re-issues the original request with the given fingerprint.
Sender = Callable[[str], Awaitable[Any]]
# Appends a step to the caller's request trace:
# ``record(step, method, url, *, status=None, success=False, message="")``.
Recorder = Callable[..., None]


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


def is_response_challenge(response: Any) -> bool:
    """Apply :func:`is_cloudflare_challenge` to a curl_cffi-style response."""
    return is_cloudflare_challenge(
        getattr(response, "status_code", 0),
        getattr(response, "text", "") or "",
        getattr(response, "headers", None),
    )


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


@dataclass(frozen=True)
class CloudflareOptions:
    """User settings governing challenge handling."""

    fingerprint_fallback: bool = True
    # Re-issue a request the fingerprints did not get past from a headless
    # browser. Only takes effect with a browser handed to the context.
    browser_fallback: bool = True
    browser_headless: bool = True
    browser_channel: str = CHANNEL_AUTO
    browser_timeout: float = DEFAULT_BROWSER_TIMEOUT

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | None) -> CloudflareOptions:
        """Read the options out of the plugin settings."""
        settings = settings or {}
        return cls(
            fingerprint_fallback=_as_bool(settings.get("cf_fingerprint_fallback"), True),
            browser_fallback=_as_bool(settings.get("cf_browser_fallback"), True),
            browser_headless=_as_bool(settings.get("cf_browser_headless"), True),
            browser_channel=normalize_channel(settings.get("cf_browser_channel")),
            browser_timeout=normalize_timeout(
                settings.get("cf_browser_timeout_seconds", DEFAULT_BROWSER_TIMEOUT)
            ),
        )

    @property
    def browser(self) -> BrowserOptions:
        """How the browser is to be launched."""
        return BrowserOptions(
            headless=self.browser_headless,
            channel=self.browser_channel,
            timeout=self.browser_timeout,
        )


def normalize_cloudflare_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Coerce the Cloudflare keys of a settings dict in place, and return it."""
    options = CloudflareOptions.from_settings(settings)
    settings["cf_fingerprint_fallback"] = options.fingerprint_fallback
    settings["cf_browser_fallback"] = options.browser_fallback
    settings["cf_browser_headless"] = options.browser_headless
    settings["cf_browser_channel"] = options.browser_channel
    timeout = options.browser_timeout
    settings["cf_browser_timeout_seconds"] = int(timeout) if timeout.is_integer() else timeout
    return settings


def fallback_fingerprints(exclude: str) -> list[str]:
    """The fingerprints to screen, limited to what the installed curl_cffi offers."""
    available = set(get_impersonate_options())
    ladder = [profile for profile in FALLBACK_FINGERPRINTS if profile in available and profile != exclude]
    return ladder[:MAX_FALLBACK_ATTEMPTS]


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


@dataclass
class Resolution:
    """What :meth:`CloudflareContext.resolve` settled on."""

    response: Any
    # When the returned response is still a challenge: what was tried against
    # it, phrased to be appended to a failure message as it stands.
    detail: str = ""


class CloudflareContext:
    """Challenge handling shared by every request of one run.

    One context goes with one client session: a fingerprint that got through
    for a host is reused by the later requests to it, and a host that turned
    every fingerprint away is not screened again. The same goes for the
    browser: its clearance is carried to the next request of the run, a host
    it got past skips the fingerprints from then on, and one it did not get
    past is not handed to it again.
    """

    def __init__(
        self,
        options: CloudflareOptions | None = None,
        *,
        pacing: float = FALLBACK_PACING_SECONDS,
        browser: BrowserSolver | None = None,
    ) -> None:
        """Initialize the context.

        Args:
            options: Settings; the defaults enable fingerprint screening.
            pacing: Seconds between fingerprint retries.
            browser: The plugin's headless browser. Without one a challenge
                the fingerprints did not get past is only reported.
        """
        self.options = options or CloudflareOptions()
        self._pacing = pacing
        self._browser = browser
        self._profiles: dict[str, str] = {}
        self._unscreened: set[str] = set()
        # Cloudflare cookies the browser holds, by the proxy it went out
        # through: a clearance is bound to the IP address that earned it.
        self._clearance: dict[str, list[dict[str, Any]]] = {}
        self._browsed: set[str] = set()
        self._unbrowsed: set[str] = set()
        # Why the browser cannot run, once that is known; not retried this run.
        self._browser_unavailable = ""

    def impersonate_for(self, url: str, default: str) -> str:
        """Fingerprint to use for ``url``: one that got through earlier, else ``default``."""
        return self._profiles.get(_host(url), default)

    async def resolve(
        self,
        *,
        method: str,
        url: str,
        response: Any,
        impersonate: str,
        send: Sender,
        record: Recorder | None = None,
        mldsa: bool = False,
        browser_request: BrowserRequest | None = None,
    ) -> Resolution:
        """Return ``response``, or a replacement that got past its challenge.

        Every retry is appended to the trace through ``record``; the response
        that comes back is left for the caller to record, since the caller
        knows what the request was for.

        Args:
            mldsa: Whether ``send`` adds ML-DSA to the fingerprints it is
                given. Sending is the caller's; this only names them in the
                trace as what actually went out.
            browser_request: The same request, described for the browser. A
                caller that leaves it out gets fingerprint screening only.
        """
        if not is_response_challenge(response):
            return Resolution(response)
        host = _host(url)
        tried: list[str] = []
        notes: list[str] = []
        browsable = browser_request is not None and self._browser is not None

        if not self.options.fingerprint_fallback:
            notes.append("Cloudflare 指纹轮换已在全局设置中关闭")
        elif not (browsable and self.options.browser_fallback and host in self._browsed):
            # Skipped for a host the browser already got past this run: the
            # fingerprints lost it then, and the clearance is the browser's.
            passed, summary = await self._screen(
                host, method, url, response, impersonate, send, record, mldsa
            )
            if passed is not None:
                return Resolution(passed)
            tried.append(summary)

        if browsable:
            if self.options.browser_fallback:
                passed, summary = await self._browse(host, browser_request, record)
                if passed is not None:
                    return Resolution(passed)
                tried.append(summary)
            else:
                notes.append("无头浏览器验证已在全局设置中关闭")

        parts = ([f"已自动尝试：{'；'.join(tried)}"] if tried else []) + notes
        return Resolution(response, "；".join(parts))

    async def _browse(
        self,
        host: str,
        request: BrowserRequest,
        record: Recorder | None,
    ) -> tuple[Any | None, str]:
        """Re-issue the request from the headless browser.

        Returns:
            Tuple of the response that got through (None if it did not) and a
            summary of what happened.
        """
        step = "Cloudflare 无头浏览器"
        if self._browser_unavailable:
            return None, self._browser_unavailable
        if host in self._unbrowsed:
            return None, "无头浏览器本轮未能通过该站点的验证，跳过"
        proxy_key = request.proxy or ""
        try:
            outcome = await self._browser.request(
                request, self.options.browser, self._clearance.get(proxy_key, ())
            )
        except BrowserUnavailable as exc:
            self._browser_unavailable = f"无头浏览器不可用：{exc}"
            _record(record, step, request.method, request.url, message=self._browser_unavailable)
            logger.warning("Cloudflare browser unavailable: %s", exc)
            return None, self._browser_unavailable
        except Exception as exc:
            self._unbrowsed.add(host)
            message = f"无头浏览器请求异常：{exc}"
            _record(record, step, request.method, request.url, message=message, error=str(exc))
            logger.warning("Cloudflare browser failed on %s: %s", host, exc, exc_info=True)
            return None, message

        if outcome.clearance:
            self._clearance[proxy_key] = outcome.clearance
        candidate = outcome.response
        status = getattr(candidate, "status_code", "?")
        took = f"用时 {outcome.elapsed:.1f} 秒"
        if not is_response_challenge(candidate):
            self._browsed.add(host)
            verdict = "通过人机验证" if outcome.solved else "未遇到人机验证"
            _record(record, step, request.method, request.url, status=status, success=True,
                    message=f"{outcome.browser} {verdict} (HTTP {status})，{took}，本轮后续请求沿用其 Cookie")
            logger.info("Cloudflare let %s through in %s (%s)", host, outcome.browser, took)
            return candidate, ""

        self._unbrowsed.add(host)
        message = (
            f"{outcome.browser} 在 {self.options.browser_timeout:g} 秒内未能通过人机验证 "
            f"(HTTP {status})"
        )
        _record(record, step, request.method, request.url, status=status, message=message)
        return None, message

    async def _screen(
        self,
        host: str,
        method: str,
        url: str,
        challenged: Any,
        impersonate: str,
        send: Sender,
        record: Recorder | None,
        mldsa: bool,
    ) -> tuple[Any | None, str]:
        """Retry with other fingerprints until one is let through.

        Returns:
            Tuple of the response that passed (None if none did) and a summary.
        """
        if host in self._unscreened:
            return None, "指纹轮换本轮已全部被拦截，跳过"
        ladder = fallback_fingerprints(impersonate)
        if not ladder:
            return None, "当前 curl_cffi 没有可轮换的指纹"

        outcomes = [
            f"{fingerprint_label(impersonate, mldsa)} 收到人机验证页 "
            f"(HTTP {getattr(challenged, 'status_code', '?')})"
        ]
        for profile in ladder:
            if self._pacing:
                await asyncio.sleep(self._pacing)
            label = fingerprint_label(profile, mldsa)
            try:
                candidate = await send(profile)
            except Exception as exc:
                outcomes.append(f"{label} 请求异常")
                logger.debug("Fingerprint %s failed on %s: %s", label, host, exc)
                continue
            status = getattr(candidate, "status_code", "?")
            if not is_response_challenge(candidate):
                self._profiles[host] = profile
                outcomes.append(f"{label} 通过 (HTTP {status})")
                _record(record, "Cloudflare 指纹轮换", method, url, status=status, success=True,
                        message="；".join(outcomes) + "，本轮后续请求沿用该指纹")
                logger.info("Cloudflare let %s through with fingerprint %s", host, label)
                return candidate, ""
            outcomes.append(f"{label} 仍被拦截 (HTTP {status})")

        self._unscreened.add(host)
        _record(record, "Cloudflare 指纹轮换", method, url, message="；".join(outcomes))
        return None, f"指纹轮换 {', '.join(fingerprint_label(p, mldsa) for p in ladder)} 均未通过"


def _record(record: Recorder | None, step: str, method: str, url: str, **fields: Any) -> None:
    if record is None:
        return
    try:
        record(step, method, url, **fields)
    except Exception:  # tracing must never break the request
        logger.debug("Could not record the Cloudflare step %s", step, exc_info=True)
