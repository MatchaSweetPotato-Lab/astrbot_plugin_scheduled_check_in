"""Unit tests for the AES-256-GCM configuration vault."""

from __future__ import annotations

import base64
import os
import unittest

import tests  # noqa: F401
from core.crypto import (
    CIPHER_PREFIX,
    LOCKED_PLACEHOLDER,
    InvalidVaultKeyError,
    Vault,
    VaultLockedError,
    decode_key,
    generate_key,
    is_ciphertext,
    is_locked_placeholder,
)


class KeyHelperTests(unittest.TestCase):
    def test_generated_key_decodes_to_32_bytes(self) -> None:
        self.assertEqual(len(decode_key(generate_key())), 32)

    def test_generated_keys_are_unique(self) -> None:
        self.assertNotEqual(generate_key(), generate_key())

    def test_rejects_empty_key(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            decode_key("")

    def test_rejects_non_base64_key(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            decode_key("not base64 at all!!")

    def test_rejects_wrong_length_key(self) -> None:
        short = base64.b64encode(os.urandom(16)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            decode_key(short)

    def test_ciphertext_detection(self) -> None:
        self.assertTrue(is_ciphertext(f"{CIPHER_PREFIX}abc"))
        self.assertFalse(is_ciphertext("abc"))
        self.assertFalse(is_ciphertext(None))
        self.assertTrue(is_locked_placeholder(LOCKED_PLACEHOLDER))
        self.assertFalse(is_locked_placeholder("locked"))


class VaultStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault()

    def test_starts_disabled_and_unlocked(self) -> None:
        self.assertEqual(
            self.vault.status(), {"enabled": False, "unlocked": False, "locked": False}
        )

    def test_disabled_vault_passes_values_through(self) -> None:
        self.assertEqual(self.vault.encrypt("secret"), "secret")
        self.assertEqual(self.vault.decrypt("secret"), "secret")

    def test_enable_reports_unlocked(self) -> None:
        self.vault.enable()
        self.assertEqual(
            self.vault.status(), {"enabled": True, "unlocked": True, "locked": False}
        )

    def test_lock_keeps_encryption_enabled(self) -> None:
        self.vault.enable()
        self.vault.lock()
        self.assertEqual(
            self.vault.status(), {"enabled": True, "unlocked": False, "locked": True}
        )

    def test_disable_clears_everything(self) -> None:
        self.vault.enable()
        self.vault.disable()
        self.assertEqual(
            self.vault.status(), {"enabled": False, "unlocked": False, "locked": False}
        )

    def test_adopt_marks_enabled_without_a_key(self) -> None:
        self.vault.adopt(True)
        self.assertTrue(self.vault.locked)

    def test_adopt_false_drops_a_loaded_key(self) -> None:
        self.vault.enable()
        self.vault.adopt(False)
        self.assertFalse(self.vault.unlocked)


class VaultRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault()
        self.key, self.verifier = self.vault.enable()

    def test_round_trips_a_value(self) -> None:
        sealed = self.vault.encrypt("sk-secret")
        self.assertTrue(is_ciphertext(sealed))
        self.assertNotIn("sk-secret", sealed)
        self.assertEqual(self.vault.decrypt(sealed), "sk-secret")

    def test_round_trips_unicode(self) -> None:
        sealed = self.vault.encrypt("代理 http://例子.测试:7890")
        self.assertEqual(self.vault.decrypt(sealed), "代理 http://例子.测试:7890")

    def test_same_plaintext_seals_differently(self) -> None:
        """A random nonce per call keeps repeated values from matching."""
        self.assertNotEqual(self.vault.encrypt("same"), self.vault.encrypt("same"))

    def test_empty_values_are_not_encrypted(self) -> None:
        """'Unset' has to stay visible while the vault is locked."""
        self.assertEqual(self.vault.encrypt(""), "")
        self.assertEqual(self.vault.encrypt(None), "")

    def test_decrypt_passes_plaintext_through(self) -> None:
        self.assertEqual(self.vault.decrypt("legacy-plaintext"), "legacy-plaintext")

    def test_json_round_trip(self) -> None:
        payload = [{"id": "c1", "type": "token", "value": "sk-a"}]
        sealed = self.vault.encrypt_json(payload)
        self.assertTrue(is_ciphertext(sealed))
        self.assertEqual(self.vault.decrypt_json(sealed, []), payload)

    def test_empty_json_values_seal_to_empty(self) -> None:
        for empty in (None, "", [], {}):
            self.assertEqual(self.vault.encrypt_json(empty), "")
        self.assertEqual(self.vault.decrypt_json("", ["fallback"]), ["fallback"])

    def test_malformed_json_falls_back_to_default(self) -> None:
        sealed = self.vault.encrypt("{not json")
        self.assertEqual(self.vault.decrypt_json(sealed, []), [])


class VaultUnlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault()
        self.key, self.verifier = self.vault.enable()
        self.sealed = self.vault.encrypt("sk-secret")

    def test_locked_vault_refuses_to_encrypt(self) -> None:
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.encrypt("value")

    def test_locked_vault_refuses_to_decrypt(self) -> None:
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.decrypt(self.sealed)

    def test_locked_vault_returns_placeholder_instead(self) -> None:
        self.vault.lock()
        self.assertEqual(self.vault.decrypt_or_placeholder(self.sealed), LOCKED_PLACEHOLDER)
        self.assertEqual(self.vault.decrypt_or_placeholder("plain"), "plain")

    def test_correct_key_unlocks_and_reads(self) -> None:
        self.vault.lock()
        self.vault.unlock(self.key, self.verifier)
        self.assertTrue(self.vault.unlocked)
        self.assertEqual(self.vault.decrypt(self.sealed), "sk-secret")

    def test_wrong_key_is_rejected(self) -> None:
        self.vault.lock()
        wrong = base64.b64encode(os.urandom(32)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.vault.unlock(wrong, self.verifier)

    def test_failed_unlock_leaves_the_vault_locked(self) -> None:
        """A rejected key must not half-open the vault."""
        self.vault.lock()
        wrong = base64.b64encode(os.urandom(32)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.vault.unlock(wrong, self.verifier)
        self.assertTrue(self.vault.locked)
        self.assertFalse(self.vault.unlocked)

    def test_corrupt_ciphertext_reports_a_clear_error(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            self.vault.decrypt(f"{CIPHER_PREFIX}!!!not-base64!!!")

    def test_truncated_ciphertext_reports_a_clear_error(self) -> None:
        short = base64.b64encode(os.urandom(8)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.vault.decrypt(f"{CIPHER_PREFIX}{short}")

    def test_tampered_ciphertext_is_rejected(self) -> None:
        """GCM authentication has to catch a flipped byte."""
        raw = bytearray(base64.b64decode(self.sealed[len(CIPHER_PREFIX):]))
        raw[-1] ^= 0xFF
        tampered = CIPHER_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            self.vault.decrypt(tampered)

    def test_a_second_vault_can_open_the_same_data(self) -> None:
        """Mirrors a plugin reload: new object, same key and verifier."""
        other = Vault()
        other.adopt(True)
        other.unlock(self.key, self.verifier)
        self.assertEqual(other.decrypt(self.sealed), "sk-secret")


if __name__ == "__main__":
    unittest.main()
