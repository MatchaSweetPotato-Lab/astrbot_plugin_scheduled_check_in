"""Canonical shapes and normalization helpers for site configuration.

A site owns three things:

* a **credential list** — Authorization Tokens, Cookies, and OAuth logins;
* a **check-in action** — path, protocol, chosen credential, extra headers;
* a **balance action** — same structure, minus the OAuth protocol.

Storage, the HTTP adapters, and the web API all normalize through this module
so a hand-edited database row and a freshly submitted form end up identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ----------------------------------------------------------------------
# Credential types
# ----------------------------------------------------------------------
CRED_TOKEN = "token"
CRED_COOKIE = "cookie"
CRED_GITHUB_OAUTH = "github_oauth"
CRED_LINUXDO_OAUTH = "linuxdo_oauth"

CREDENTIAL_TYPES: tuple[str, ...] = (
    CRED_TOKEN,
    CRED_COOKIE,
    CRED_GITHUB_OAUTH,
    CRED_LINUXDO_OAUTH,
)

# OAuth credentials, in the order tried when no credential is named.
OAUTH_CREDENTIAL_TYPES: tuple[str, ...] = (CRED_GITHUB_OAUTH, CRED_LINUXDO_OAUTH)

# Direct-request credentials, in the order tried when no credential is named.
REQUEST_CREDENTIAL_TYPES: tuple[str, ...] = (CRED_TOKEN, CRED_COOKIE)

CREDENTIAL_LABELS: dict[str, str] = {
    CRED_TOKEN: "Authorization Token",
    CRED_COOKIE: "Cookie",
    CRED_GITHUB_OAUTH: "Github OAuth",
    CRED_LINUXDO_OAUTH: "LinuxDO OAuth",
}

# ----------------------------------------------------------------------
# Action protocols
# ----------------------------------------------------------------------
PROTOCOL_AUTO = "auto"
PROTOCOL_GET = "get"
PROTOCOL_POST = "post"
PROTOCOL_OAUTH = "oauth"

CHECKIN_PROTOCOLS: tuple[str, ...] = (PROTOCOL_AUTO, PROTOCOL_GET, PROTOCOL_POST, PROTOCOL_OAUTH)
BALANCE_PROTOCOLS: tuple[str, ...] = (PROTOCOL_AUTO, PROTOCOL_GET, PROTOCOL_POST)

# ----------------------------------------------------------------------
# Site frameworks
# ----------------------------------------------------------------------
SITE_TYPE_NEW_API = "new-api"
SITE_TYPE_GENERIC = "generic_rest"
SITE_TYPES: tuple[str, ...] = (SITE_TYPE_NEW_API, SITE_TYPE_GENERIC)

# Header New-API uses to scope a Cookie session to a numeric user id.
NEW_API_USER_HEADER = "new-api-user"

ACTION_CHECKIN = "checkin"
ACTION_BALANCE = "balance"


# ----------------------------------------------------------------------
# Headers
# ----------------------------------------------------------------------
def parse_header_text(text: str) -> list[dict[str, str]]:
    """Parse ``Key: Value`` lines (the legacy storage format) into pairs."""
    pairs: list[dict[str, str]] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        if key:
            pairs.append({"key": key, "value": value.strip()})
    return pairs


def normalize_headers(raw: Any) -> list[dict[str, str]]:
    """Coerce any supported header representation into a list of pairs.

    Accepts the current list-of-pairs form, a plain mapping, and the legacy
    newline-separated ``Key: Value`` text. Entries without a key are dropped.
    """
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        return parse_header_text(raw)
    if isinstance(raw, dict):
        return [
            {"key": str(key).strip(), "value": "" if value is None else str(value)}
            for key, value in raw.items()
            if str(key).strip()
        ]
    if not isinstance(raw, list):
        return []

    pairs: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            key = str(item.get("key", "")).strip()
            value = item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            key = str(item[0]).strip()
            value = item[1]
        else:
            continue
        if key:
            pairs.append({"key": key, "value": "" if value is None else str(value)})
    return pairs


def headers_to_mapping(pairs: Any) -> dict[str, str]:
    """Flatten header pairs into a mapping, later entries winning."""
    mapping: dict[str, str] = {}
    for pair in normalize_headers(pairs):
        mapping[pair["key"]] = pair["value"]
    return mapping


def find_header(pairs: Any, key: str) -> str:
    """Return a header value by case-insensitive name, or an empty string."""
    wanted = str(key or "").strip().lower()
    for pair in normalize_headers(pairs):
        if pair["key"].lower() == wanted:
            return pair["value"]
    return ""


def upsert_header(pairs: Any, key: str, value: str) -> list[dict[str, str]]:
    """Return header pairs with ``key`` set to ``value`` (case-insensitive)."""
    normalized = normalize_headers(pairs)
    wanted = str(key or "").strip()
    if not wanted:
        return normalized
    lowered = wanted.lower()
    for pair in normalized:
        if pair["key"].lower() == lowered:
            pair["value"] = "" if value is None else str(value)
            return normalized
    normalized.append({"key": wanted, "value": "" if value is None else str(value)})
    return normalized


# ----------------------------------------------------------------------
# Credentials
# ----------------------------------------------------------------------
def normalize_credential_type(raw: Any) -> str:
    """Map a credential type onto a supported value, defaulting to token."""
    candidate = str(raw or "").strip().lower().replace("-", "_")
    aliases = {
        "bearer_token": CRED_TOKEN,
        "authorization": CRED_TOKEN,
        "authorization_token": CRED_TOKEN,
        "github": CRED_GITHUB_OAUTH,
        "linuxdo": CRED_LINUXDO_OAUTH,
        "linux_do": CRED_LINUXDO_OAUTH,
        "linux_do_oauth": CRED_LINUXDO_OAUTH,
    }
    candidate = aliases.get(candidate, candidate)
    return candidate if candidate in CREDENTIAL_TYPES else CRED_TOKEN


def is_oauth_credential(credential: Any) -> bool:
    """Return whether a credential dict uses an OAuth login flow."""
    if not isinstance(credential, dict):
        return False
    return credential.get("type") in OAUTH_CREDENTIAL_TYPES


def credential_label(credential: Any) -> str:
    """Return a human-friendly name for a credential."""
    if not isinstance(credential, dict):
        return ""
    label = str(credential.get("label") or "").strip()
    if label:
        return label
    return CREDENTIAL_LABELS.get(str(credential.get("type") or ""), "凭据")


def normalize_credential(raw: Any, index: int = 0) -> dict[str, Any]:
    """Normalize one credential entry.

    Args:
        raw: Raw credential mapping.
        index: Position in the list, used to synthesize a missing id.

    Returns:
        A credential dict with a stable id, type, and type-specific fields.
    """
    source = raw if isinstance(raw, dict) else {}
    cred_type = normalize_credential_type(source.get("type"))
    cred_id = str(source.get("id") or "").strip() or f"cred_{index + 1}"
    credential: dict[str, Any] = {
        "id": cred_id,
        "type": cred_type,
        "label": str(source.get("label") or "").strip(),
        "value": str(source.get("value") or "").strip(),
    }
    if cred_type == CRED_TOKEN:
        # Users paste raw tokens far more often than "Bearer <token>".
        credential["auto_bearer"] = bool(source.get("auto_bearer", True))
    if cred_type in OAUTH_CREDENTIAL_TYPES:
        credential["session_cookie"] = str(source.get("session_cookie") or "").strip()
        credential["session_updated_at"] = str(source.get("session_updated_at") or "").strip()
        # When the provider last rotated the cookie we hold. Kept here because
        # normalization runs on every read and write, and an unlisted field
        # would be dropped on the next save.
        credential["value_updated_at"] = str(source.get("value_updated_at") or "").strip()
    return credential


def normalize_credentials(raw: Any) -> list[dict[str, Any]]:
    """Normalize a credential list, dropping malformed entries and duplicate ids."""
    if not isinstance(raw, list):
        return []
    credentials: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        credential = normalize_credential(item, index)
        if credential["id"] in seen:
            credential["id"] = f"{credential['id']}_{index + 1}"
        seen.add(credential["id"])
        credentials.append(credential)
    return credentials


def find_credential(credentials: Any, credential_id: str) -> dict[str, Any] | None:
    """Look a credential up by id."""
    wanted = str(credential_id or "").strip()
    if not wanted or not isinstance(credentials, list):
        return None
    for credential in credentials:
        if isinstance(credential, dict) and str(credential.get("id") or "") == wanted:
            return credential
    return None


def _first_of_type(credentials: list[Any], types: tuple[str, ...]) -> dict[str, Any] | None:
    """Return the first credential matching ``types`` in preference order."""
    for wanted in types:
        for credential in credentials:
            if isinstance(credential, dict) and credential.get("type") == wanted:
                return credential
    return None


@dataclass
class CredentialPlan:
    """How an action should authenticate."""

    # "request" sends the credential directly; "oauth" logs in first and uses
    # the resulting station session cookie.
    mode: str
    credential: dict[str, Any] | None
    reason: str = ""


def resolve_credential(credentials: Any, protocol: str) -> CredentialPlan:
    """Pick the credential an action should use.

    Explicit selection wins. Otherwise Authorization Token is preferred over
    Cookie for direct requests, and Github over LinuxDO for OAuth. An action
    that finds no direct credential falls back to an OAuth login when one is
    configured, since that is the only remaining way to authenticate.

    Args:
        credentials: Normalized credential list.
        protocol: Action protocol (``auto``/``get``/``post``/``oauth``).

    Returns:
        A ``CredentialPlan``; ``credential`` is None when nothing is usable.
    """
    items = [item for item in credentials if isinstance(item, dict)] if isinstance(credentials, list) else []
    if not items:
        return CredentialPlan("request", None, "站点未配置任何凭据")

    if protocol == PROTOCOL_OAUTH:
        chosen = _first_of_type(items, OAUTH_CREDENTIAL_TYPES)
        if chosen is None:
            return CredentialPlan("oauth", None, "签到协议为 OAuth，但未配置 OAuth 凭据")
        return CredentialPlan("oauth", chosen)

    chosen = _first_of_type(items, REQUEST_CREDENTIAL_TYPES)
    if chosen is not None:
        return CredentialPlan("request", chosen)

    fallback = _first_of_type(items, OAUTH_CREDENTIAL_TYPES)
    if fallback is not None:
        return CredentialPlan("oauth", fallback, "未配置 Token/Cookie 凭据，改用 OAuth 登录")
    return CredentialPlan("request", None, "站点未配置可用凭据")


def resolve_action_credential(credentials: Any, action: Any) -> CredentialPlan:
    """Resolve the credential for one action config, honouring its explicit pick."""
    protocol = normalize_protocol(action.get("protocol") if isinstance(action, dict) else None, allow_oauth=True)
    explicit_id = str((action or {}).get("credential_id") or "").strip() if isinstance(action, dict) else ""
    if explicit_id:
        chosen = find_credential(credentials, explicit_id)
        if chosen is not None:
            mode = "oauth" if is_oauth_credential(chosen) else "request"
            return CredentialPlan(mode, chosen)
    return resolve_credential(credentials, protocol)


# ----------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------
def normalize_protocol(raw: Any, allow_oauth: bool) -> str:
    """Map a protocol onto a supported value, defaulting to framework detection."""
    candidate = str(raw or "").strip().lower()
    allowed = CHECKIN_PROTOCOLS if allow_oauth else BALANCE_PROTOCOLS
    if candidate in ("", "follow", "framework"):
        return PROTOCOL_AUTO
    return candidate if candidate in allowed else PROTOCOL_AUTO


def normalize_path(raw: Any) -> str:
    """Normalize a custom endpoint path, keeping absolute URLs intact."""
    path = str(raw or "").strip()
    if not path:
        return ""
    if path.startswith(("http://", "https://")):
        return path
    return path if path.startswith("/") else f"/{path}"


def normalize_action(raw: Any, allow_oauth: bool) -> dict[str, Any]:
    """Normalize one action (check-in or balance) config block.

    Args:
        raw: Raw action mapping.
        allow_oauth: Whether the OAuth protocol is selectable.

    Returns:
        An action dict with path, protocol, credential_id, headers, and the
        acw_sc__v2 solver flag.
    """
    source = raw if isinstance(raw, dict) else {}
    return {
        "path": normalize_path(source.get("path")),
        "protocol": normalize_protocol(source.get("protocol"), allow_oauth=allow_oauth),
        "credential_id": str(source.get("credential_id") or "").strip(),
        "headers": normalize_headers(source.get("headers")),
        "solve_acw_sc_v2": bool(source.get("solve_acw_sc_v2")),
    }


def normalize_site_type(raw: Any) -> str:
    """Map a framework type onto a supported value.

    Aliases cover the names earlier versions stored, so an untouched database
    row still selects the adapter it always used.
    """
    candidate = str(raw or "").strip().lower()
    aliases = {
        "one-api": SITE_TYPE_NEW_API,
        "one_api": SITE_TYPE_NEW_API,
        "new_api": SITE_TYPE_NEW_API,
        "generic": SITE_TYPE_GENERIC,
        "generic-rest": SITE_TYPE_GENERIC,
        "rest": SITE_TYPE_GENERIC,
        "custom": SITE_TYPE_GENERIC,
    }
    candidate = aliases.get(candidate, candidate)
    return candidate if candidate in SITE_TYPES else SITE_TYPE_NEW_API


def wants_new_api_user_probe(site: Any, action: Any) -> bool:
    """Return whether ``new-api-user`` should be probed and written back.

    Only New-API style sites following the framework protocol qualify, and only
    while the header is still unset.
    """
    if not isinstance(site, dict) or not isinstance(action, dict):
        return False
    if normalize_site_type(site.get("type")) != SITE_TYPE_NEW_API:
        return False
    if normalize_protocol(action.get("protocol"), allow_oauth=True) != PROTOCOL_AUTO:
        return False
    return not find_header(action.get("headers"), NEW_API_USER_HEADER).strip()
