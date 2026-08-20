"""Unit tests for the multi-slot key wrapping primitives."""

from __future__ import annotations

import base64
import os
import unittest

import tests  # noqa: F401
from core.crypto import (
    WRAP_PREFIX,
    InvalidVaultKeyError,
    Vault,
    VaultLockedError,
    decode_bytes,
    derive_kek,
    encode_bytes,
    generate_dek,
    generate_salt,
    unwrap_dek,
    wrap_dek,
)


class DekTests(unittest.TestCase):
    def test_dek_is_32_bytes(self) -> None:
        self.assertEqual(len(generate_dek()), 32)

    def test_deks_are_unique(self) -> None:
        self.assertNotEqual(generate_dek(), generate_dek())

    def test_salt_is_32_bytes(self) -> None:
        self.assertEqual(len(generate_salt()), 32)

    def test_salts_are_unique(self) -> None:
        self.assertNotEqual(generate_salt(), generate_salt())


class ByteCodingTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        raw = os.urandom(32)
        self.assertEqual(decode_bytes(encode_bytes(raw)), raw)

    def test_accepts_urlsafe_alphabet(self) -> None:
        """WebAuthn credential ids arrive base64url-encoded."""
        raw = bytes(range(256))[:32]
        urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        self.assertEqual(decode_bytes(urlsafe), raw)

    def test_accepts_missing_padding(self) -> None:
        raw = os.urandom(30)
        self.assertEqual(decode_bytes(base64.b64encode(raw).decode().rstrip("=")), raw)

    def test_enforces_expected_length(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            decode_bytes(encode_bytes(os.urandom(16)), expected_length=32)

    def test_rejects_empty(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            decode_bytes("")

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            decode_bytes("!!! not base64 !!!")


class DeriveKekTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = os.urandom(32)
        self.salt = generate_salt()

    def test_is_deterministic(self) -> None:
        first = derive_kek(self.secret, self.salt, "user_key")
        second = derive_kek(self.secret, self.salt, "user_key")
        self.assertEqual(first, second)

    def test_returns_32_bytes(self) -> None:
        self.assertEqual(len(derive_kek(self.secret, self.salt, "user_key")), 32)

    def test_slot_type_separates_domains(self) -> None:
        """The same secret and salt must not yield the same key for two kinds."""
        user = derive_kek(self.secret, self.salt, "user_key")
        webauthn = derive_kek(self.secret, self.salt, "webauthn_prf")
        self.assertNotEqual(user, webauthn)

    def test_salt_changes_the_key(self) -> None:
        other = derive_kek(self.secret, generate_salt(), "user_key")
        self.assertNotEqual(derive_kek(self.secret, self.salt, "user_key"), other)

    def test_secret_changes_the_key(self) -> None:
        other = derive_kek(os.urandom(32), self.salt, "user_key")
        self.assertNotEqual(derive_kek(self.secret, self.salt, "user_key"), other)

    def test_rejects_an_empty_secret(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            derive_kek(b"", self.salt, "user_key")


class WrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dek = generate_dek()
        self.salt = generate_salt()
        self.secret = os.urandom(32)
        self.kek = derive_kek(self.secret, self.salt, "webauthn_prf")
        self.slot_id = "slot_abc"
        self.wrapped = wrap_dek(self.dek, self.kek, self.slot_id)

    def test_round_trip(self) -> None:
        self.assertEqual(unwrap_dek(self.wrapped, self.kek, self.slot_id), self.dek)

    def test_wrapped_value_is_prefixed(self) -> None:
        self.assertTrue(self.wrapped.startswith(WRAP_PREFIX))

    def test_wrapped_value_hides_the_dek(self) -> None:
        self.assertNotIn(encode_bytes(self.dek).rstrip("="), self.wrapped)

    def test_wrapping_twice_differs(self) -> None:
        """A random nonce per wrap keeps two slots from looking related."""
        self.assertNotEqual(self.wrapped, wrap_dek(self.dek, self.kek, self.slot_id))

    def test_a_wrong_secret_is_rejected(self) -> None:
        wrong = derive_kek(os.urandom(32), self.salt, "webauthn_prf")
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(self.wrapped, wrong, self.slot_id)

    def test_a_wrong_slot_type_is_rejected(self) -> None:
        wrong = derive_kek(self.secret, self.salt, "user_key")
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(self.wrapped, wrong, self.slot_id)

    def test_a_blob_cannot_be_moved_to_another_slot(self) -> None:
        """The slot id is authenticated, so a swapped row fails to unwrap."""
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(self.wrapped, self.kek, "slot_other")

    def test_tampering_is_detected(self) -> None:
        raw = bytearray(base64.b64decode(self.wrapped[len(WRAP_PREFIX):]))
        raw[-1] ^= 0xFF
        tampered = WRAP_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(tampered, self.kek, self.slot_id)

    def test_missing_prefix_is_rejected(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(base64.b64encode(b"x" * 40).decode(), self.kek, self.slot_id)

    def test_corrupt_base64_is_rejected(self) -> None:
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(f"{WRAP_PREFIX}!!!", self.kek, self.slot_id)

    def test_truncated_payload_is_rejected(self) -> None:
        short = base64.b64encode(os.urandom(8)).decode("ascii")
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(f"{WRAP_PREFIX}{short}", self.kek, self.slot_id)


class MultiSlotTests(unittest.TestCase):
    """Any one slot secret must recover the same vault key."""

    def setUp(self) -> None:
        self.dek = generate_dek()
        self.slots = {}
        for slot_id, slot_type in (
            ("slot_user", "user_key"),
            ("slot_win", "webauthn_prf"),
            ("slot_mac", "webauthn_prf"),
        ):
            secret = os.urandom(32)
            salt = generate_salt()
            kek = derive_kek(secret, salt, slot_type)
            self.slots[slot_id] = {
                "secret": secret,
                "salt": salt,
                "type": slot_type,
                "wrapped": wrap_dek(self.dek, kek, slot_id),
            }

    def test_every_slot_recovers_the_same_dek(self) -> None:
        for slot_id, slot in self.slots.items():
            kek = derive_kek(slot["secret"], slot["salt"], slot["type"])
            self.assertEqual(unwrap_dek(slot["wrapped"], kek, slot_id), self.dek, slot_id)

    def test_one_slot_secret_cannot_open_another(self) -> None:
        win = self.slots["slot_win"]
        mac = self.slots["slot_mac"]
        kek = derive_kek(win["secret"], mac["salt"], mac["type"])
        with self.assertRaises(InvalidVaultKeyError):
            unwrap_dek(mac["wrapped"], kek, "slot_mac")

    def test_dropping_a_slot_leaves_the_others_usable(self) -> None:
        del self.slots["slot_win"]
        for slot_id, slot in self.slots.items():
            kek = derive_kek(slot["secret"], slot["salt"], slot["type"])
            self.assertEqual(unwrap_dek(slot["wrapped"], kek, slot_id), self.dek)


class VaultDekTests(unittest.TestCase):
    def test_enable_with_dek_uses_the_given_key(self) -> None:
        dek = generate_dek()
        vault = Vault()
        vault.enable_with_dek(dek)
        self.assertTrue(vault.unlocked)
        self.assertEqual(vault.export_dek(), dek)

    def test_enable_with_dek_returns_a_working_verifier(self) -> None:
        dek = generate_dek()
        vault = Vault()
        verifier = vault.enable_with_dek(dek)
        sealed = vault.encrypt("secret")

        # A fresh vault loading the same DEK must read the same data.
        other = Vault()
        other.load_dek(dek)
        self.assertEqual(other.decrypt(sealed), "secret")
        self.assertTrue(verifier.startswith("enc:v1:"))

    def test_load_dek_unlocks(self) -> None:
        vault = Vault()
        vault.adopt(True)
        self.assertTrue(vault.locked)
        vault.load_dek(generate_dek())
        self.assertTrue(vault.unlocked)

    def test_export_dek_refuses_while_locked(self) -> None:
        vault = Vault()
        vault.adopt(True)
        with self.assertRaises(VaultLockedError):
            vault.export_dek()

    def test_export_dek_returns_a_copy(self) -> None:
        """Callers must not be able to mutate the vault's key in place."""
        dek = generate_dek()
        vault = Vault()
        vault.load_dek(dek)
        exported = bytearray(vault.export_dek())
        exported[0] ^= 0xFF
        self.assertEqual(vault.export_dek(), dek)

    def test_rejects_a_wrong_length_dek(self) -> None:
        vault = Vault()
        with self.assertRaises(InvalidVaultKeyError):
            vault.load_dek(os.urandom(16))
        with self.assertRaises(InvalidVaultKeyError):
            vault.enable_with_dek(os.urandom(31))

    def test_lock_drops_the_dek(self) -> None:
        vault = Vault()
        vault.enable_with_dek(generate_dek())
        vault.lock()
        self.assertTrue(vault.locked)
        with self.assertRaises(VaultLockedError):
            vault.export_dek()


if __name__ == "__main__":
    unittest.main()
