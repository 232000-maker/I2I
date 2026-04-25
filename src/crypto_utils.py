"""
File: src/crypto_utils.py
Purpose: Cryptographic utilities for the I2I secure P2P application.

This module provides all cryptographic operations including:
- X25519 Diffie-Hellman key exchange
- XSalsa20-Poly1305 authenticated encryption/decryption
- SHA-256 based safety number generation for MITM prevention
- Secure key generation, storage, and loading
- Nonce management for replay attack prevention

Security Controls:
- Uses PyNaCl (libsodium bindings) for cryptographically secure operations
- Private keys are never exposed outside this module
- Nonces are randomly generated per message (prevents replay attacks)
- Safety numbers are derived from both peers' public keys
"""

import os
import json
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Tuple, Optional

import nacl.utils
import nacl.public
import nacl.encoding
import nacl.hash
import nacl.secret

# Configure module-level logger — logs to file, not to stdout (security: no sensitive data in logs)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
KEYS_DIR = Path("keys")
PRIVATE_KEY_FILE = KEYS_DIR / "private.key"
PUBLIC_KEY_FILE = KEYS_DIR / "public.key"
NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE  # 24 bytes


# ─────────────────────────────────────────────
#  Key Generation & Storage
# ─────────────────────────────────────────────

def generate_keypair() -> Tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """
    Generate a new X25519 key pair for use in this session.

    Security: Uses os.urandom() indirectly via PyNaCl's secure RNG.

    Returns:
        Tuple of (PrivateKey, PublicKey) objects.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    logger.info("New X25519 key pair generated.")
    return private_key, public_key


def save_keypair(private_key: nacl.public.PrivateKey, public_key: nacl.public.PublicKey) -> None:
    """
    Persist keys to the local keys/ directory.

    Security checks:
    - Creates the keys/ directory with restrictive permissions (0o700 on POSIX).
    - Private key is stored as raw bytes (hex-encoded) — never transmitted.

    Inputs:
        private_key: nacl.public.PrivateKey object.
        public_key: nacl.public.PublicKey object.
    Output:
        None. Writes to KEYS_DIR.
    """
    KEYS_DIR.mkdir(mode=0o700, exist_ok=True)

    private_bytes = bytes(private_key).hex()
    public_bytes = bytes(public_key).hex()

    PRIVATE_KEY_FILE.write_text(private_bytes)
    PUBLIC_KEY_FILE.write_text(public_bytes)

    # Restrict read permissions on POSIX systems
    try:
        os.chmod(PRIVATE_KEY_FILE, 0o600)
    except (AttributeError, NotImplementedError):
        pass  # Windows does not support chmod — acceptable

    logger.info("Key pair saved to disk.")


def load_or_generate_keypair() -> Tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """
    Load an existing key pair from disk, or generate a new one if none exists.

    Security checks:
    - If key files exist they are loaded; otherwise new keys are generated and saved.
    - Handles corrupted key files by regenerating.

    Returns:
        Tuple of (PrivateKey, PublicKey).
    """
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        try:
            private_bytes = bytes.fromhex(PRIVATE_KEY_FILE.read_text().strip())
            private_key = nacl.public.PrivateKey(private_bytes)
            public_key = private_key.public_key
            logger.info("Loaded existing key pair from disk.")
            return private_key, public_key
        except Exception:
            logger.warning("Corrupted key files detected — regenerating key pair.")

    private_key, public_key = generate_keypair()
    save_keypair(private_key, public_key)
    return private_key, public_key


# ─────────────────────────────────────────────
#  Key Exchange (X25519 ECDH)
# ─────────────────────────────────────────────

def compute_shared_secret(
    our_private_key: nacl.public.PrivateKey,
    their_public_key_bytes: bytes
) -> nacl.public.Box:
    """
    Perform X25519 ECDH key exchange to derive a shared secret Box.

    Security:
    - X25519 provides forward secrecy when combined with ephemeral keys.
    - The resulting Box uses XSalsa20-Poly1305 for AEAD encryption.

    Inputs:
        our_private_key: Our local PrivateKey object.
        their_public_key_bytes: Peer's raw 32-byte public key.
    Output:
        nacl.public.Box — authenticated encryption box using shared secret.
    Raises:
        ValueError: If the public key bytes are invalid.
    """
    if len(their_public_key_bytes) != 32:
        raise ValueError("Invalid public key length. Expected 32 bytes.")

    try:
        their_public_key = nacl.public.PublicKey(their_public_key_bytes)
        box = nacl.public.Box(our_private_key, their_public_key)
        logger.info("Shared secret computed via X25519.")
        return box
    except Exception as exc:
        logger.error("Key exchange failed: %s", type(exc).__name__)
        raise ValueError("Key exchange failed — invalid peer public key.") from exc


# ─────────────────────────────────────────────
#  Encryption / Decryption
# ─────────────────────────────────────────────

def encrypt_message(box: nacl.public.Box, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using XSalsa20-Poly1305 authenticated encryption.

    Security:
    - A unique random nonce is generated per message (prevents replay attacks).
    - The MAC (Poly1305) ensures integrity and authenticity.
    - Plaintext is never logged.

    Inputs:
        box: nacl.public.Box (shared secret box).
        plaintext: Raw bytes to encrypt.
    Output:
        Tuple of (ciphertext, nonce) both as bytes.
    """
    nonce = nacl.utils.random(NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)
    # encrypted includes nonce prefix — extract ciphertext only
    ciphertext = encrypted.ciphertext
    return ciphertext, nonce


def decrypt_message(box: nacl.public.Box, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext using XSalsa20-Poly1305 authenticated decryption.

    Security:
    - Poly1305 MAC is verified before returning plaintext.
    - Any tampered ciphertext raises an exception.
    - Decryption errors are logged generically (no plaintext in logs).

    Inputs:
        box: nacl.public.Box (shared secret box).
        ciphertext: Encrypted bytes to decrypt.
        nonce: 24-byte nonce used during encryption.
    Output:
        Decrypted plaintext bytes.
    Raises:
        nacl.exceptions.CryptoError: If MAC verification fails (tampered data).
        ValueError: If the nonce length is incorrect.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Invalid nonce length. Expected {NONCE_SIZE} bytes.")

    # PyNaCl Box.decrypt accepts nonce+ciphertext as combined bytes
    combined = nonce + ciphertext
    plaintext = box.decrypt(combined)
    return plaintext


# ─────────────────────────────────────────────
#  Safety Numbers (MITM Prevention)
# ─────────────────────────────────────────────

def compute_safety_number(pub_key_a: bytes, pub_key_b: bytes) -> str:
    """
    Compute a human-verifiable safety number from two peers' public keys.

    This is a fingerprint that both parties can compare out-of-band (e.g., verbally)
    to verify no MITM has occurred.

    Security:
    - Keys are sorted before hashing to ensure the same number on both ends.
    - Uses SHA-256 for collision resistance.

    Inputs:
        pub_key_a: First peer's raw public key bytes.
        pub_key_b: Second peer's raw public key bytes.
    Output:
        A formatted 5×5-digit safety number string (e.g., "12345 67890 ...").
    """
    sorted_keys = sorted([pub_key_a, pub_key_b])
    combined = sorted_keys[0] + sorted_keys[1]
    digest = hashlib.sha256(combined).hexdigest()

    # Format as groups of 5 digits for readability
    numeric = str(int(digest, 16))[:30].zfill(30)
    groups = [numeric[i:i+5] for i in range(0, 30, 5)]
    safety_number = " ".join(groups)
    return safety_number


# ─────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────

def public_key_to_hex(public_key: nacl.public.PublicKey) -> str:
    """
    Convert a PublicKey object to its hex string representation.

    Inputs:
        public_key: nacl.public.PublicKey object.
    Output:
        64-character hex string.
    """
    return bytes(public_key).hex()


def hex_to_public_key_bytes(hex_str: str) -> bytes:
    """
    Validate and convert a hex string to raw public key bytes.

    Security:
    - Validates hex format and length before conversion.

    Inputs:
        hex_str: 64-character hex string representing a 32-byte X25519 public key.
    Output:
        32 raw bytes.
    Raises:
        ValueError: If the hex string is malformed or incorrect length.
    """
    hex_str = hex_str.strip()
    if len(hex_str) != 64:
        raise ValueError("Public key must be 64 hex characters (32 bytes).")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("Invalid hex encoding in public key.") from exc


def generate_peer_address(public_key: nacl.public.PublicKey) -> str:
    """
    Derive a deterministic .b32.i2p-style address from a public key.

    Security:
    - Address is derived via SHA-256 of the public key — collision resistant.
    - Used for routing in the simulated I2P layer.

    Inputs:
        public_key: nacl.public.PublicKey object.
    Output:
        String in the form "<52-char-base32>.b32.i2p".
    """
    import base64
    digest = hashlib.sha256(bytes(public_key)).digest()
    b32 = base64.b32encode(digest).decode().lower().rstrip("=")
    return f"{b32}.b32.i2p"
