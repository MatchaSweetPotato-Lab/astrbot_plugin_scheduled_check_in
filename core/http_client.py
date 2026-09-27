"""Shared HTTP client configuration for check-in plugin requests."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from curl_cffi.requests import AsyncSession, BrowserType

DEFAULT_TIMEOUT_SECONDS = 15.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 300.0
_IMPERSONATE_OPTIONS = tuple(browser.value for browser in BrowserType)
# chrome150 (curl_cffi 0.16+) is the first profile whose ClientHello advertises
# the ML-DSA signature algorithms current Chrome sends. Cloudflare challenges a
# Chrome-shaped handshake without them (connect.linux.do's managed challenge),
# so it is preferred; chrome131 covers curl_cffi builds that predate it.
_PREFERRED_IMPERSONATES = ("chrome150", "chrome131")
DEFAULT_IMPERSONATE = next(
    (option for option in _PREFERRED_IMPERSONATES if option in _IMPERSONATE_OPTIONS), ""
)
if not DEFAULT_IMPERSONATE:
    raise RuntimeError("curl_cffi provides neither the chrome150 nor the chrome131 fingerprint")

# Post-quantum ML-DSA signature algorithms (0x0904-0x0906), by the names curl
# accepts. Current Chrome lists them ahead of its classic algorithms, and they
# are the whole TLS difference between chrome150, which connect.linux.do let
# through in interleaved tests, and chrome146, which it challenged. The verdict
# drifts, though: there were hours when it challenged chrome150 as well.
MLDSA_SIGNATURE_ALGORITHMS: tuple[str, ...] = ("mldsa44", "mldsa65", "mldsa87")
# What every Chrome and Edge profile of curl_cffi sends besides them, in order.
# An override replaces the whole list, so tests/test_http_client.py checks this
# against the ClientHellos the installed build actually sends.
_CHROMIUM_SIGNATURE_ALGORITHMS: tuple[str, ...] = (
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
)
# Chrome and Edge profile names with their major version, e.g. chrome131_android.
_CHROMIUM_PROFILE = re.compile(r"^(?:chrome|edge)(\d+)")
# First Chrome version whose profile carries ML-DSA by itself.
_FIRST_NATIVE_MLDSA_VERSION = 150
# Builds without chrome150 (curl_cffi 0.15 and older) reject the ML-DSA names
# with curl error 43, failing the request, so nothing is added there.
_MLDSA_BUILD = "chrome150" in _IMPERSONATE_OPTIONS

# How the ML-DSA option applies to a fingerprint; see mldsa_support().
MLDSA_NATIVE = "native"
MLDSA_ADDED = "added"
MLDSA_NOT_CHROMIUM = "not_chromium"
MLDSA_OLD_BUILD = "old_build"


@dataclass(frozen=True)
class RequestOptions:
    """Global settings every site's requests follow, OAuth legs included."""

    # Add ML-DSA to the TLS handshake of fingerprints that lack it; see
    # mldsa_support(). chrome150 carries it anyway.
    tls_mldsa: bool = False
    # Solve an Aliyun acw_sc__v2 challenge wherever one comes back, and retry.
    solve_acw_sc_v2: bool = True

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | None) -> "RequestOptions":
        """Read the options out of the plugin settings."""
        settings = settings or {}
        return cls(
            tls_mldsa=settings.get("http_tls_mldsa", False) is True,
            solve_acw_sc_v2=settings.get("acw_sc_v2_auto_solve", True) is not False,
        )


def _get_timeout_seconds(settings: Mapping[str, Any]) -> float:
    """Read and clamp the configured request timeout."""
    try:
        timeout = float(settings.get("http_timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(timeout, MAX_TIMEOUT_SECONDS))


def get_impersonate_options() -> list[str]:
    """Return the browser fingerprints exposed by the installed curl_cffi build."""
    return [
        DEFAULT_IMPERSONATE,
        *[option for option in _IMPERSONATE_OPTIONS if option != DEFAULT_IMPERSONATE],
    ]


def normalize_impersonate(value: Any) -> str:
    """Validate a configured fingerprint and fall back to the default one."""
    if isinstance(value, str):
        normalized_value = value.strip().lower()
        if normalized_value in _IMPERSONATE_OPTIONS:
            return normalized_value
    return DEFAULT_IMPERSONATE


def mldsa_support(impersonate: str) -> str:
    """Say how the ML-DSA option applies to a fingerprint.

    Returns:
        ``native`` when its ClientHello already carries ML-DSA, ``added`` when
        the option adds it, and otherwise why the option leaves it alone:
        ``not_chromium`` for Firefox, Safari and Tor, which do not send ML-DSA,
        so adding it would match no real browser; ``old_build`` when the
        installed curl_cffi cannot send it.
    """
    match = _CHROMIUM_PROFILE.match(str(impersonate or ""))
    if match is None:
        return MLDSA_NOT_CHROMIUM
    if int(match.group(1)) >= _FIRST_NATIVE_MLDSA_VERSION:
        return MLDSA_NATIVE
    return MLDSA_ADDED if _MLDSA_BUILD else MLDSA_OLD_BUILD


def mldsa_extra_fp(impersonate: str, enabled: bool) -> dict[str, Any] | None:
    """Return the ``extra_fp`` that adds ML-DSA to a request's ClientHello.

    None when nothing needs to change: the option is off, or it does not apply
    to the fingerprint (see :func:`mldsa_support`). Only the signature
    algorithms change — curl_cffi keeps the rest of the impersonation — and
    curl opens a new connection for the altered handshake instead of reusing
    one made without it.
    """
    if not enabled or mldsa_support(impersonate) != MLDSA_ADDED:
        return None
    return {"tls_signature_algorithms": [*MLDSA_SIGNATURE_ALGORITHMS, *_CHROMIUM_SIGNATURE_ALGORITHMS]}


def fingerprint_label(impersonate: str, mldsa: bool = False) -> str:
    """Name the fingerprint a request goes out with, marking an added ML-DSA."""
    return f"{impersonate}+ML-DSA" if mldsa_extra_fp(impersonate, mldsa) else impersonate


def create_client_session(settings: Mapping[str, Any] | None = None) -> AsyncSession:
    """Create a curl_cffi session with the plugin's shared request settings."""
    settings = settings or {}
    # Verify TLS certificates by default; callers must explicitly opt out.
    ssl_verify = settings.get("http_ssl_verify", True) is not False
    timeout_seconds = _get_timeout_seconds(settings)
    return AsyncSession(
        impersonate=normalize_impersonate(settings.get("http_impersonate")),
        verify=ssl_verify,
        trust_env=True,
        timeout=timeout_seconds,
    )
