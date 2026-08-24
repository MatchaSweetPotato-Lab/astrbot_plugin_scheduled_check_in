"""AES-256-GCM vault protecting sensitive site configuration at rest.

A single random **data encryption key** (DEK, also called the vault key)
encrypts every protected field. The DEK itself is never stored: instead each
*key slot* keeps its own wrapped copy, encrypted under a key derived from that
slot's secret. Holding any one slot secret is enough to unwrap the DEK, so a
user can unlock with the base64 key they saved, or with a WebAuthn PRF output
from Windows Hello / Touch ID / a passkey / a FIDO2 security key.

    Vault Key (DEK)
      ├── user key slot        secret = the base64 key shown once to the user
      ├── webauthn slot        secret = WebAuthn PRF output
      └── webauthn slot        ...

Nothing key-derived is persisted. After a plugin reload the vault starts
*locked* and one slot secret must be supplied through the dashboard before
credentials, custom headers, or proxies can be read.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger("astrbot")

# Ciphertext marker. Values without it are stored in plaintext, which keeps
# enabling encryption on an existing database a purely additive migration.
CIPHER_PREFIX = "enc:v1:"

# Marker for a wrapped DEK held in a key slot.
WRAP_PREFIX = "wrap:v1:"

# Returned in place of ciphertext while the vault is locked. The NUL prefix
# cannot occur in a user-supplied value, so it is unambiguous.
LOCKED_PLACEHOLDER = "\x00locked"

_VERIFIER_PLAINTEXT = "astrbot-checkin-vault-v1"
_KEY_BYTES = 32
_NONCE_BYTES = 12
_SALT_BYTES = 32

# Domain separation for slot key derivation. Including the slot type means the
# same secret used for a different slot kind can never yield the same KEK.
_KEK_INFO_PREFIX = b"astrbot-checkin-vault/v1/slot/"


class VaultError(RuntimeError):
    """Base class for vault failures."""


class VaultLockedError(VaultError):
    """Raised when protected data is accessed while the vault holds no key."""


class InvalidVaultKeyError(VaultError):
    """Raised when a key is malformed or does not match the stored verifier."""


def generate_key() -> str:
    """Return a fresh base64-encoded AES-256 key for the user to store."""
    return base64.b64encode(os.urandom(_KEY_BYTES)).decode("ascii")


def decode_key(key: str) -> bytes:
    """Decode and validate a base64-encoded AES-256 key.

    Args:
        key: Base64 text as displayed to the user.

    Returns:
        The 32 raw key bytes.

    Raises:
        InvalidVaultKeyError: If the text is not base64 or has the wrong length.
    """
    candidate = str(key or "").strip()
    if not candidate:
        raise InvalidVaultKeyError("密钥不能为空")
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidVaultKeyError("密钥不是合法的 Base64 字符串") from exc
    if len(raw) != _KEY_BYTES:
        raise InvalidVaultKeyError(f"密钥必须解码为 {_KEY_BYTES} 字节（AES-256）")
    return raw


def is_ciphertext(value: Any) -> bool:
    """Return whether a stored value is vault ciphertext."""
    return isinstance(value, str) and value.startswith(CIPHER_PREFIX)


def is_locked_placeholder(value: Any) -> bool:
    """Return whether a value is the placeholder handed out while locked."""
    return isinstance(value, str) and value == LOCKED_PLACEHOLDER


# ----------------------------------------------------------------------
# Key slots
# ----------------------------------------------------------------------
def generate_dek() -> bytes:
    """Return a fresh random data encryption key (the vault key)."""
    return os.urandom(_KEY_BYTES)


def generate_salt() -> bytes:
    """Return a fresh random salt for a key slot."""
    return os.urandom(_SALT_BYTES)


def encode_bytes(raw: bytes) -> str:
    """Base64-encode a binary value for storage or transport."""
    return base64.b64encode(raw).decode("ascii")


def decode_bytes(value: str, expected_length: int | None = None) -> bytes:
    """Decode a base64 value, accepting the URL-safe alphabet as well.

    Args:
        value: Base64 or base64url text, with or without padding.
        expected_length: Enforced byte length when given.

    Returns:
        The decoded bytes.

    Raises:
        InvalidVaultKeyError: If the text is not base64 or has the wrong length.
    """
    candidate = str(value or "").strip()
    if not candidate:
        raise InvalidVaultKeyError("值不能为空")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError) as exc:
            raise InvalidVaultKeyError("不是合法的 Base64 字符串") from exc
    if expected_length is not None and len(raw) != expected_length:
        raise InvalidVaultKeyError(f"长度必须为 {expected_length} 字节，实际为 {len(raw)}")
    return raw


def derive_kek(secret: bytes, kdf_salt: bytes, slot_type: str) -> bytes:
    """Derive a slot's key-encryption key from its secret.

    HKDF gives domain separation — the same authenticator secret used for
    another purpose yields a different key — and evens out a user-supplied
    secret that may not be uniformly random.

    Args:
        secret: Raw slot secret (user key bytes, or a WebAuthn PRF output).
        kdf_salt: Per-slot random salt.
        slot_type: Slot kind, mixed into the HKDF info string.

    Returns:
        A 32-byte key-encryption key.
    """
    if not secret:
        raise InvalidVaultKeyError("槽位密钥不能为空")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=kdf_salt,
        info=_kek_info(slot_type),
    ).derive(secret)


def _kek_info(slot_type: str) -> bytes:
    """Build the HKDF info string for a slot type."""
    return _KEK_INFO_PREFIX + str(slot_type or "unknown").encode("utf-8")


def wrap_dek(dek: bytes, kek: bytes, slot_id: str) -> str:
    """Encrypt the DEK for storage in one key slot.

    The slot id is authenticated as additional data, so a wrapped blob cannot be
    moved to a different slot row even by someone who can write to the database.

    Args:
        dek: The vault key to protect.
        kek: Key-encryption key from :func:`derive_kek`.
        slot_id: Slot the wrapped value belongs to.

    Returns:
        Prefixed base64 ciphertext.
    """
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(kek).encrypt(nonce, dek, _slot_aad(slot_id))
    return WRAP_PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def unwrap_dek(wrapped: str, kek: bytes, slot_id: str) -> bytes:
    """Recover the DEK from a key slot.

    Args:
        wrapped: Stored value produced by :func:`wrap_dek`.
        kek: Key-encryption key from :func:`derive_kek`.
        slot_id: Slot the wrapped value belongs to.

    Returns:
        The unwrapped vault key.

    Raises:
        InvalidVaultKeyError: If the value is malformed, or the key or slot id
            does not match. A failed unwrap *is* the verification step.
    """
    text = str(wrapped or "")
    if not text.startswith(WRAP_PREFIX):
        raise InvalidVaultKeyError("槽位数据格式不正确")
    payload = text[len(WRAP_PREFIX):]
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidVaultKeyError("槽位密文损坏，无法解封") from exc
    if len(raw) <= _NONCE_BYTES:
        raise InvalidVaultKeyError("槽位密文长度不足")
    try:
        dek = AESGCM(kek).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _slot_aad(slot_id))
    except InvalidTag as exc:
        raise InvalidVaultKeyError("密钥与该槽位不匹配") from exc
    if len(dek) != _KEY_BYTES:
        raise InvalidVaultKeyError("解封出的数据密钥长度非法")
    return dek


def _slot_aad(slot_id: str) -> bytes:
    """Return the additional authenticated data binding a wrap to its slot."""
    return str(slot_id or "").encode("utf-8")


class Vault:
    """Encrypts and decrypts sensitive fields with the in-memory vault key."""

    def __init__(self) -> None:
        """Create a disabled, keyless vault."""
        self._key: bytes | None = None
        self._enabled: bool = False

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        """Whether encryption at rest is turned on."""
        return self._enabled

    @property
    def unlocked(self) -> bool:
        """Whether a validated key is currently held in memory."""
        return self._key is not None

    @property
    def locked(self) -> bool:
        """Whether encryption is on but no key has been supplied yet."""
        return self._enabled and self._key is None

    def status(self) -> dict[str, bool]:
        """Return the vault state for the dashboard."""
        return {
            "enabled": self._enabled,
            "unlocked": self.unlocked,
            "locked": self.locked,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def enable(self) -> tuple[str, str]:
        """Turn on encryption with a freshly generated key.

        Used for the legacy single-key layout, where the user's key doubles as
        the vault key. New databases call :meth:`enable_with_dek` instead.

        Returns:
            Tuple of ``(key_text, verifier)``. The key is shown to the user
            once and never stored; the verifier must be persisted.
        """
        key_text = generate_key()
        self._key = decode_key(key_text)
        self._enabled = True
        return key_text, self.encrypt(_VERIFIER_PLAINTEXT)

    def enable_with_dek(self, dek: bytes) -> str:
        """Turn on encryption with a caller-provided vault key.

        Args:
            dek: The random vault key that slots will wrap.

        Returns:
            The verifier ciphertext to persist.
        """
        if len(dek) != _KEY_BYTES:
            raise InvalidVaultKeyError(f"数据密钥必须为 {_KEY_BYTES} 字节")
        self._key = bytes(dek)
        self._enabled = True
        return self.encrypt(_VERIFIER_PLAINTEXT)

    def load_dek(self, dek: bytes) -> None:
        """Load an already-unwrapped vault key into memory.

        Args:
            dek: Vault key recovered from a key slot.
        """
        if len(dek) != _KEY_BYTES:
            raise InvalidVaultKeyError(f"数据密钥必须为 {_KEY_BYTES} 字节")
        self._key = bytes(dek)
        self._enabled = True

    def export_dek(self) -> bytes:
        """Return the in-memory vault key so a new slot can wrap it.

        Raises:
            VaultLockedError: If the vault holds no key.
        """
        if self._key is None:
            raise VaultLockedError("配置已加密，请先解锁后再管理密钥槽位")
        return bytes(self._key)

    def unlock(self, key: str, verifier: str) -> None:
        """Validate and load a key against the stored verifier.

        Only used for the legacy single-key layout, where the user's key is the
        vault key itself. Slot-based unlocking is verified by the wrap instead.

        Args:
            key: Base64 key text supplied by the user.
            verifier: Verifier ciphertext read from storage.

        Raises:
            InvalidVaultKeyError: If the key is malformed or does not match.
        """
        raw = decode_key(key)
        previous_key, previous_enabled = self._key, self._enabled
        self._key, self._enabled = raw, True
        try:
            if self.decrypt(verifier) != _VERIFIER_PLAINTEXT:
                raise InvalidVaultKeyError("密钥与已加密的数据不匹配")
        except VaultError:
            self._key, self._enabled = previous_key, previous_enabled
            raise
        except Exception as exc:
            self._key, self._enabled = previous_key, previous_enabled
            raise InvalidVaultKeyError("密钥与已加密的数据不匹配") from exc

    def adopt(self, enabled: bool) -> None:
        """Apply the persisted enabled flag without supplying a key."""
        self._enabled = bool(enabled)
        if not self._enabled:
            self._key = None

    def lock(self) -> None:
        """Drop the in-memory key while keeping encryption enabled."""
        self._key = None

    def disable(self) -> None:
        """Turn encryption off and drop the key."""
        self._key = None
        self._enabled = False

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a value, or pass it through when encryption is off.

        Args:
            plaintext: Value to protect. Empty values are never encrypted so
                that "unset" stays visible while the vault is locked.

        Returns:
            Prefixed ciphertext, or the original value when encryption is off.

        Raises:
            VaultLockedError: If encryption is enabled but no key is loaded.
        """
        text = "" if plaintext is None else str(plaintext)
        if not self._enabled or not text:
            return text
        if self._key is None:
            raise VaultLockedError("配置已加密，请先在 Web 端输入密钥解锁")
        nonce = os.urandom(_NONCE_BYTES)
        sealed = AESGCM(self._key).encrypt(nonce, text.encode("utf-8"), None)
        return CIPHER_PREFIX + base64.b64encode(nonce + sealed).decode("ascii")

    def decrypt(self, stored: str) -> str:
        """Decrypt a stored value, passing plaintext through unchanged.

        Args:
            stored: Value as held in the database.

        Returns:
            The plaintext value.

        Raises:
            VaultLockedError: If the value is ciphertext and no key is loaded.
            InvalidVaultKeyError: If the loaded key cannot open the value.
        """
        if not is_ciphertext(stored):
            return "" if stored is None else str(stored)
        if self._key is None:
            raise VaultLockedError("配置已加密，请先在 Web 端输入密钥解锁")
        payload = stored[len(CIPHER_PREFIX):]
        try:
            raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidVaultKeyError("密文格式损坏，无法解密") from exc
        if len(raw) <= _NONCE_BYTES:
            raise InvalidVaultKeyError("密文长度不足，无法解密")
        try:
            opened = AESGCM(self._key).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], None)
        except InvalidTag as exc:
            raise InvalidVaultKeyError("密钥与已加密的数据不匹配") from exc
        return opened.decode("utf-8")

    def decrypt_or_placeholder(self, stored: str) -> str:
        """Decrypt a value, or return the locked placeholder when keyless."""
        if not is_ciphertext(stored):
            return "" if stored is None else str(stored)
        if self._key is None:
            return LOCKED_PLACEHOLDER
        return self.decrypt(stored)

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------
    def encrypt_json(self, value: Any) -> str:
        """Serialize a JSON-compatible value and encrypt the result.

        There is deliberately no matching ``decrypt_json`` here. Reading these
        columns has to stay possible while the vault is locked — the site list
        renders with the protected fields blank — so the read path lives in
        ``SiteStorage._decode_json``, which treats a locked vault as "return the
        default" rather than an error.
        """
        if value in (None, "", [], {}):
            return ""
        return self.encrypt(json.dumps(value, ensure_ascii=False))
