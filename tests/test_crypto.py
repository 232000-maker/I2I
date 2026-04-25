"""
File: tests/test_crypto.py
Purpose: Unit tests for the crypto_utils module.

Tests verify:
- Key pair generation produces valid X25519 keys
- Key persistence and loading round-trips correctly
- ECDH shared secrets produce matching boxes on both sides
- Encryption/decryption round-trips produce identical plaintext
- Safety numbers are symmetric (same for both peers)
- Public key to address derivation is deterministic
- Invalid inputs raise appropriate exceptions
"""

import os
import sys
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import nacl.public
import nacl.exceptions

from src.crypto_utils import (
    generate_keypair,
    save_keypair,
    load_or_generate_keypair,
    compute_shared_secret,
    encrypt_message,
    decrypt_message,
    compute_safety_number,
    public_key_to_hex,
    hex_to_public_key_bytes,
    generate_peer_address,
    NONCE_SIZE,
)


# ─────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def temp_keys_dir(tmp_path, monkeypatch):
    """Redirect key storage to a temporary directory for isolation."""
    import src.crypto_utils as cu
    monkeypatch.setattr(cu, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(cu, "PRIVATE_KEY_FILE", tmp_path / "keys" / "private.key")
    monkeypatch.setattr(cu, "PUBLIC_KEY_FILE", tmp_path / "keys" / "public.key")
    return tmp_path


@pytest.fixture
def alice_keys():
    return generate_keypair()


@pytest.fixture
def bob_keys():
    return generate_keypair()


# ─────────────────────────────────────────────
#  Key Generation Tests
# ─────────────────────────────────────────────

class TestKeyGeneration:
    """Tests for X25519 key pair generation."""

    def test_generate_keypair_returns_valid_types(self, alice_keys):
        """generate_keypair() must return (PrivateKey, PublicKey) objects."""
        priv, pub = alice_keys
        assert isinstance(priv, nacl.public.PrivateKey)
        assert isinstance(pub, nacl.public.PublicKey)

    def test_public_key_is_32_bytes(self, alice_keys):
        """X25519 public keys are exactly 32 bytes."""
        _, pub = alice_keys
        assert len(bytes(pub)) == 32

    def test_private_key_is_32_bytes(self, alice_keys):
        """X25519 private keys are exactly 32 bytes."""
        priv, _ = alice_keys
        assert len(bytes(priv)) == 32

    def test_each_keypair_is_unique(self):
        """Each call to generate_keypair() must produce a unique key pair."""
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        assert bytes(pub_a) != bytes(pub_b)

    def test_public_key_derived_from_private(self, alice_keys):
        """PublicKey must be correctly derived from PrivateKey."""
        priv, pub = alice_keys
        derived = priv.public_key
        assert bytes(derived) == bytes(pub)


# ─────────────────────────────────────────────
#  Key Storage Tests
# ─────────────────────────────────────────────

class TestKeyStorage:
    """Tests for key persistence and loading."""

    def test_save_and_load_preserves_keys(self, temp_keys_dir):
        """Keys saved to disk must round-trip without data loss."""
        priv, pub = generate_keypair()
        save_keypair(priv, pub)
        loaded_priv, loaded_pub = load_or_generate_keypair()
        assert bytes(loaded_pub) == bytes(pub)
        assert bytes(loaded_priv) == bytes(priv)

    def test_load_generates_new_if_missing(self, temp_keys_dir):
        """If no key files exist, load_or_generate_keypair() must create them."""
        priv, pub = load_or_generate_keypair()
        assert isinstance(priv, nacl.public.PrivateKey)
        assert isinstance(pub, nacl.public.PublicKey)

    def test_keys_dir_created_on_save(self, temp_keys_dir):
        """save_keypair() must create the keys/ directory if it doesn't exist."""
        import src.crypto_utils as cu
        priv, pub = generate_keypair()
        save_keypair(priv, pub)
        assert cu.KEYS_DIR.exists()
        assert cu.PRIVATE_KEY_FILE.exists()
        assert cu.PUBLIC_KEY_FILE.exists()


# ─────────────────────────────────────────────
#  ECDH Key Exchange Tests
# ─────────────────────────────────────────────

class TestKeyExchange:
    """Tests for X25519 ECDH shared secret computation."""

    def test_shared_secret_symmetric(self, alice_keys, bob_keys):
        """
        Alice->Bob and Bob->Alice shared secrets must produce boxes that
        encrypt/decrypt each other's messages.
        """
        alice_priv, alice_pub = alice_keys
        bob_priv, bob_pub = bob_keys

        alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

        message = b"Test message"
        ciphertext, nonce = encrypt_message(alice_box, message)
        decrypted = decrypt_message(bob_box, ciphertext, nonce)
        assert decrypted == message

    def test_invalid_public_key_raises(self, alice_keys):
        """compute_shared_secret() must reject public keys of wrong length."""
        priv, _ = alice_keys
        with pytest.raises(ValueError):
            compute_shared_secret(priv, b"short_key")

    def test_invalid_hex_key_bytes_raises(self, alice_keys):
        """hex_to_public_key_bytes() must reject malformed hex."""
        with pytest.raises(ValueError):
            hex_to_public_key_bytes("not_hex_at_all")

    def test_wrong_length_public_key_hex(self, alice_keys):
        """hex_to_public_key_bytes() must reject hex strings not 64 chars."""
        with pytest.raises(ValueError):
            hex_to_public_key_bytes("aabbcc")


# ─────────────────────────────────────────────
#  Encryption / Decryption Tests
# ─────────────────────────────────────────────

class TestEncryption:
    """Tests for XSalsa20-Poly1305 authenticated encryption."""

    @pytest.fixture(autouse=True)
    def setup_box(self, alice_keys, bob_keys):
        alice_priv, alice_pub = alice_keys
        bob_priv, bob_pub = bob_keys
        self.alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        self.bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

    def test_encrypt_decrypt_roundtrip(self):
        """Plaintext encrypted by Alice must be correctly decrypted by Bob."""
        plaintext = b"Hello, I2I!"
        ciphertext, nonce = encrypt_message(self.alice_box, plaintext)
        decrypted = decrypt_message(self.bob_box, ciphertext, nonce)
        assert decrypted == plaintext

    def test_nonce_is_24_bytes(self):
        """Each encrypt_message() call must produce a 24-byte nonce."""
        _, nonce = encrypt_message(self.alice_box, b"data")
        assert len(nonce) == NONCE_SIZE

    def test_nonces_are_unique(self):
        """Successive calls must produce different nonces."""
        _, nonce1 = encrypt_message(self.alice_box, b"msg1")
        _, nonce2 = encrypt_message(self.alice_box, b"msg2")
        assert nonce1 != nonce2

    def test_tampered_ciphertext_raises(self):
        """Tampered ciphertext must fail MAC verification."""
        ciphertext, nonce = encrypt_message(self.alice_box, b"secret")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits
        with pytest.raises(Exception):
            decrypt_message(self.bob_box, bytes(tampered), nonce)

    def test_wrong_nonce_raises(self):
        """Using the wrong nonce must fail decryption."""
        import nacl.utils
        ciphertext, nonce = encrypt_message(self.alice_box, b"secret")
        wrong_nonce = nacl.utils.random(NONCE_SIZE)
        with pytest.raises(Exception):
            decrypt_message(self.bob_box, ciphertext, wrong_nonce)

    def test_invalid_nonce_length_raises(self):
        """decrypt_message() must reject nonces not 24 bytes."""
        ciphertext, _ = encrypt_message(self.alice_box, b"data")
        with pytest.raises(ValueError):
            decrypt_message(self.bob_box, ciphertext, b"short_nonce")

    def test_empty_plaintext(self):
        """Encryption of empty bytes must round-trip correctly."""
        ciphertext, nonce = encrypt_message(self.alice_box, b"")
        decrypted = decrypt_message(self.bob_box, ciphertext, nonce)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Large payload (4 KB) must encrypt and decrypt correctly."""
        data = os.urandom(4 * 1024)
        ciphertext, nonce = encrypt_message(self.alice_box, data)
        decrypted = decrypt_message(self.bob_box, ciphertext, nonce)
        assert decrypted == data


# ─────────────────────────────────────────────
#  Safety Number Tests
# ─────────────────────────────────────────────

class TestSafetyNumbers:
    """Tests for safety number (MITM fingerprint) generation."""

    def test_safety_number_is_symmetric(self, alice_keys, bob_keys):
        """compute_safety_number(A, B) must equal compute_safety_number(B, A)."""
        _, alice_pub = alice_keys
        _, bob_pub = bob_keys
        sn_a = compute_safety_number(bytes(alice_pub), bytes(bob_pub))
        sn_b = compute_safety_number(bytes(bob_pub), bytes(alice_pub))
        assert sn_a == sn_b

    def test_safety_number_format(self, alice_keys, bob_keys):
        """Safety number must be a formatted string of digit groups."""
        _, alice_pub = alice_keys
        _, bob_pub = bob_keys
        sn = compute_safety_number(bytes(alice_pub), bytes(bob_pub))
        groups = sn.split(" ")
        assert len(groups) == 6
        for g in groups:
            assert g.isdigit() and len(g) == 5

    def test_different_pairs_give_different_numbers(self, alice_keys, bob_keys):
        """Different key pairs must produce different safety numbers."""
        _, alice_pub = alice_keys
        _, bob_pub = bob_keys
        priv_c, pub_c = generate_keypair()
        sn1 = compute_safety_number(bytes(alice_pub), bytes(bob_pub))
        sn2 = compute_safety_number(bytes(alice_pub), bytes(pub_c))
        assert sn1 != sn2


# ─────────────────────────────────────────────
#  Address Derivation Tests
# ─────────────────────────────────────────────

class TestAddressDerivation:
    """Tests for .b32.i2p address generation."""

    def test_address_ends_with_b32_i2p(self, alice_keys):
        """Generated address must end with .b32.i2p."""
        _, pub = alice_keys
        addr = generate_peer_address(pub)
        assert addr.endswith(".b32.i2p")

    def test_address_is_deterministic(self, alice_keys):
        """Same public key must always produce the same address."""
        _, pub = alice_keys
        addr1 = generate_peer_address(pub)
        addr2 = generate_peer_address(pub)
        assert addr1 == addr2

    def test_different_keys_give_different_addresses(self, alice_keys, bob_keys):
        """Different public keys must produce different addresses."""
        _, alice_pub = alice_keys
        _, bob_pub = bob_keys
        assert generate_peer_address(alice_pub) != generate_peer_address(bob_pub)

    def test_public_key_hex_roundtrip(self, alice_keys):
        """Public key hex encoding/decoding must be lossless."""
        _, pub = alice_keys
        hex_str = public_key_to_hex(pub)
        recovered = hex_to_public_key_bytes(hex_str)
        assert recovered == bytes(pub)
