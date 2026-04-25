"""
File: tests/test_attack_simulations.py
Purpose: Simulated attack tests for the I2I Secure P2P Messenger.

This module tests the application's defences against real attack vectors
described in the course lecture material (Lec 13-15), including:

- Brute-force / credential-stuffing → account lockout
- SQL/code injection payloads in messages and filenames
- Path traversal (Unix & Windows) in filenames
- Oversized inputs / integer-overflow style DoS
- Replay attack prevention (duplicate nonces)
- Tampered ciphertext (MAC failure)
- Unsafe password detection (weak password policy)
- XSS injection in messages
- Rate-limiting / flooding DoS
- File integrity verification (SHA-256 tamper detection)
"""

import sys
import time
import os
import hashlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import nacl.public
import nacl.exceptions

from src.crypto_utils import (
    generate_keypair,
    compute_shared_secret,
    encrypt_message,
    decrypt_message,
    compute_safety_number,
    NONCE_SIZE,
)
from src.security_utils import (
    validate_message,
    validate_peer_address,
    validate_public_key_hex,
    sanitize_filename,
    compute_file_hash,
    verify_file_hash,
    validate_password_strength,
    sanitize_message_for_display,
    RateLimiter,
    MAX_MESSAGE_SIZE_BYTES,
)
from src.auth_manager import AuthManager
from src.peer_connection import PeerSession


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _make_session_pair():
    """Create two PeerSession objects that share an encryption box."""
    import socket
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
    bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

    # Use a dummy socket (we won't actually send over the wire in these tests)
    dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    safety = compute_safety_number(bytes(alice_pub), bytes(bob_pub))

    alice_session = PeerSession(
        sock=dummy_sock,
        peer_address="bob_peer_addr",
        peer_public_key_bytes=bytes(bob_pub),
        box=alice_box,
        safety_number=safety,
    )
    bob_session = PeerSession(
        sock=dummy_sock,
        peer_address="alice_peer_addr",
        peer_public_key_bytes=bytes(alice_pub),
        box=bob_box,
        safety_number=safety,
    )
    return alice_session, bob_session, alice_box, bob_box


# ─────────────────────────────────────────────
#  1. Brute-Force / Account Lockout Tests
# ─────────────────────────────────────────────

class TestAccountLockout:
    """
    Simulates a credential-stuffing / brute-force attack.
    After MAX_FAILED_ATTEMPTS wrong passwords the account must be locked.
    (Chapter 1 — Authentication Bypass; Chapter 6 — Password Handling)
    """

    def setup_method(self):
        """Reset the in-memory failed-attempts dict before each test."""
        AuthManager._failed_attempts.clear()

    def test_lockout_after_three_failures(self, tmp_path, monkeypatch):
        """Account must be locked after 3 consecutive bad passwords."""
        monkeypatch.setattr("src.auth_manager.AUTH_FILE", tmp_path / "users.json")
        (tmp_path / "users.json").parent.mkdir(parents=True, exist_ok=True)

        AuthManager.register("victim", "Secure@123", "USER")

        # Three wrong attempts
        for _ in range(AuthManager.MAX_FAILED_ATTEMPTS):
            result = AuthManager.verify_user("victim", "WrongPass1!")
            assert result is None

        # Fourth attempt — must raise PermissionError (locked)
        with pytest.raises(PermissionError, match="locked"):
            AuthManager.verify_user("victim", "WrongPass1!")

    def test_correct_password_resets_lockout_counter(self, tmp_path, monkeypatch):
        """A successful login must clear the failed-attempts counter."""
        monkeypatch.setattr("src.auth_manager.AUTH_FILE", tmp_path / "users.json")
        (tmp_path / "users.json").parent.mkdir(parents=True, exist_ok=True)

        AuthManager.register("user2", "Secure@456", "USER")

        # Two wrong, then correct
        AuthManager.verify_user("user2", "wrong1!")
        AuthManager.verify_user("user2", "wrong2!")
        role = AuthManager.verify_user("user2", "Secure@456")
        assert role == "USER"

        # Counter must be cleared — should not be locked
        assert "user2" not in AuthManager._failed_attempts

    def test_unknown_user_does_not_reveal_existence(self, tmp_path, monkeypatch):
        """
        A login attempt for an unknown username must return None (not raise),
        preventing username enumeration.
        """
        monkeypatch.setattr("src.auth_manager.AUTH_FILE", tmp_path / "users.json")
        (tmp_path / "users.json").parent.mkdir(parents=True, exist_ok=True)

        result = AuthManager.verify_user("ghost_user", "anypassword1A!")
        assert result is None


# ─────────────────────────────────────────────
#  2. Weak Password Policy Tests
# ─────────────────────────────────────────────

class TestPasswordStrength:
    """
    Tests the password strength policy.
    (Chapter 6 — Hidden Dangers in Password Handling; OWASP best practices)
    """

    @pytest.mark.parametrize("weak_pw,reason", [
        ("sho1A!", "too short"),           # 6 chars — below 8 minimum
        ("alllowercase1!", "no uppercase"),
        ("ALLUPPERCASE1!", "no lowercase"),
        ("NoDigitsHere!", "no digit"),
        ("NoSpecials1234", "no special char"),
        ("        ", "all whitespace"),
    ])
    def test_weak_passwords_rejected(self, weak_pw, reason):
        """Weak passwords must raise ValueError (reason: {reason})."""
        with pytest.raises(ValueError):
            validate_password_strength(weak_pw)

    @pytest.mark.parametrize("strong_pw", [
        "Secure@123",
        "P@ssw0rd!",
        "Tr0ub4dor&3",
        "MyStr0ng#Pass",
    ])
    def test_strong_passwords_accepted(self, strong_pw):
        """Strong passwords must not raise."""
        validate_password_strength(strong_pw)  # Should not raise

    def test_register_rejects_weak_password(self, tmp_path, monkeypatch):
        """AuthManager.register() must enforce password strength."""
        monkeypatch.setattr("src.auth_manager.AUTH_FILE", tmp_path / "users.json")
        (tmp_path / "users.json").parent.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError):
            AuthManager.register("testuser", "weakpw", "USER")

    def test_bcrypt_hash_not_plaintext(self, tmp_path, monkeypatch):
        """Stored password hash must start with bcrypt prefix $2b$."""
        import json
        monkeypatch.setattr("src.auth_manager.AUTH_FILE", tmp_path / "users.json")
        (tmp_path / "users.json").parent.mkdir(parents=True, exist_ok=True)

        AuthManager.register("hashcheck", "Secure@789", "USER")
        data = json.loads((tmp_path / "users.json").read_text())
        assert data["hashcheck"]["password"].startswith("$2b$"), (
            "Password must be stored as a bcrypt hash."
        )


# ─────────────────────────────────────────────
#  3. Injection Attack Tests (SQL, Command, Code)
# ─────────────────────────────────────────────

class TestInjectionPrevention:
    """
    Injects SQL, OS command, and code payloads into message and filename
    validators, confirming they are rejected or neutralized.
    (Chapters 15, 16, 22 — OS Command Injection, SQL Injection, Code Injection)
    """

    # --- Message validator ---

    @pytest.mark.parametrize("payload", [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "<script>alert('xss')</script>",
        "$(rm -rf /)",
        "`evil.sh`",
        "eval(compile('import os; os.system(\"id\")', '', 'exec'))",
    ])
    def test_injection_payloads_accepted_as_text(self, payload):
        """
        Injection strings must NOT be blocked at the message-validation layer —
        they are just strings.  The defence is that messages are encrypted and
        never executed; this test confirms the validator does not crash on them.
        """
        # validate_message only checks length/type, not content semantics.
        # This is intentional: the encryption layer is the primary defence.
        result = validate_message(payload)
        assert isinstance(result, str)

    # --- Filename validator (attacker-controlled filenames) ---

    @pytest.mark.parametrize("dangerous,must_not_contain", [
        ("../../etc/passwd", ["../", "/"]),
        ("..\\..\\Windows\\cmd.exe", ["..\\", "\\"]),
        ("/etc/shadow", ["/"]),
        ("C:\\Windows\\System32\\cmd.exe", ["\\", "/"]),
        ("file\x00name.txt", ["\x00"]),
    ])
    def test_path_traversal_filenames_sanitized(self, dangerous, must_not_contain):
        """Attacker-supplied filenames must not contain traversal sequences after sanitization."""
        safe = sanitize_filename(dangerous)
        for bad in must_not_contain:
            assert bad not in safe, (
                f"sanitize_filename({dangerous!r}) still contains {bad!r}: got {safe!r}"
            )
        assert ".." not in safe

    def test_null_byte_injection_in_filename(self):
        """Null-byte injection must be stripped from filenames."""
        result = sanitize_filename("legit\x00.exe")
        assert "\x00" not in result

    def test_double_dot_collapse(self):
        """Double (or more) dots must be collapsed to single dot."""
        result = sanitize_filename("file...name.txt")
        assert ".." not in result


# ─────────────────────────────────────────────
#  4. XSS Prevention Tests
# ─────────────────────────────────────────────

class TestXSSPrevention:
    """
    Tests that messages containing HTML/JS are escaped before display.
    (Chapter 10 — Cross-Site Scripting)
    """

    @pytest.mark.parametrize("raw,expected_snippet", [
        ("<script>alert('xss')</script>", "&lt;script&gt;"),
        ('<img src=x onerror="alert(1)">', "&lt;img"),
        ("Hello <b>World</b>", "Hello &lt;b&gt;World&lt;/b&gt;"),
        ("It's a 'test' & a \"check\"", "It&#x27;s"),
    ])
    def test_html_tags_escaped(self, raw, expected_snippet):
        """HTML special characters must be escaped in display output."""
        result = sanitize_message_for_display(raw)
        assert expected_snippet in result
        assert "<script>" not in result
        assert "<img" not in result or "&lt;img" in result

    def test_safe_message_unchanged(self):
        """Plain text without HTML must pass through unchanged."""
        msg = "Hello, world! How are you?"
        assert sanitize_message_for_display(msg) == msg

    def test_non_string_returns_empty(self):
        """Non-string input must return empty string (safe fallback)."""
        assert sanitize_message_for_display(None) == ""
        assert sanitize_message_for_display(123) == ""


# ─────────────────────────────────────────────
#  5. Replay Attack Tests
# ─────────────────────────────────────────────

class TestReplayAttackPrevention:
    """
    Simulates an attacker capturing an encrypted frame and resending it.
    (Chapter 1 — Authentication Bypass; nonce tracking in PeerSession)
    """

    def test_duplicate_nonce_rejected(self):
        """A nonce seen before must be rejected (replay attack)."""
        import nacl.utils
        nonce = nacl.utils.random(NONCE_SIZE)

        alice_session, _, _, _ = _make_session_pair()
        # First use — must succeed
        assert alice_session.register_nonce(nonce) is True
        # Second use — must fail (replay)
        assert alice_session.register_nonce(nonce) is False

    def test_unique_nonces_accepted(self):
        """Each fresh nonce must be accepted."""
        import nacl.utils
        alice_session, _, _, _ = _make_session_pair()

        for _ in range(50):
            nonce = nacl.utils.random(NONCE_SIZE)
            assert alice_session.register_nonce(nonce) is True

    def test_nonce_set_bounded_to_prevent_memory_exhaustion(self):
        """
        After 10,001 nonces the set is pruned to prevent unbounded memory growth.
        (DoS prevention — Chapter 7 Integer Overflow / resource exhaustion)
        """
        import nacl.utils
        alice_session, _, _, _ = _make_session_pair()
        for _ in range(10_001):
            alice_session.register_nonce(nacl.utils.random(NONCE_SIZE))
        # After pruning, internal set must be ≤ 5,001 (5,000 kept + the triggering nonce)
        assert len(alice_session._used_nonces) <= 5_001


# ─────────────────────────────────────────────
#  6. Tampered Ciphertext (MAC Failure) Tests
# ─────────────────────────────────────────────

class TestMessageIntegrity:
    """
    Simulates an active MITM attacker modifying ciphertext in transit.
    (Chapter 4 — Missing Encryption; Chapter 5 — Broken Cryptographic Algorithms)
    """

    def test_bit_flip_in_ciphertext_rejected(self):
        """Any modification to the ciphertext must fail MAC verification."""
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()
        alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

        plaintext = b"Top secret message"
        ciphertext, nonce = encrypt_message(alice_box, plaintext)

        # Flip one bit
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_message(bob_box, bytes(tampered), nonce)

    def test_truncated_ciphertext_rejected(self):
        """A truncated ciphertext must fail decryption."""
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()
        alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

        ciphertext, nonce = encrypt_message(alice_box, b"hello")
        with pytest.raises(Exception):
            decrypt_message(bob_box, ciphertext[:5], nonce)

    def test_wrong_key_cannot_decrypt(self):
        """A third party without the shared secret cannot decrypt the message."""
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()
        mallory_priv, mallory_pub = generate_keypair()

        alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        # Mallory computes a box using her own key + Alice's pub (wrong secret)
        mallory_box = compute_shared_secret(mallory_priv, bytes(alice_pub))

        ciphertext, nonce = encrypt_message(alice_box, b"secret")
        with pytest.raises(Exception):
            decrypt_message(mallory_box, ciphertext, nonce)

    def test_wrong_nonce_rejected(self):
        """Decryption with the wrong nonce must fail."""
        import nacl.utils
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()
        alice_box = compute_shared_secret(alice_priv, bytes(bob_pub))
        bob_box = compute_shared_secret(bob_priv, bytes(alice_pub))

        ciphertext, _ = encrypt_message(alice_box, b"data")
        wrong_nonce = nacl.utils.random(NONCE_SIZE)
        with pytest.raises(Exception):
            decrypt_message(bob_box, ciphertext, wrong_nonce)


# ─────────────────────────────────────────────
#  7. Safety Number (MITM Fingerprint) Tests
# ─────────────────────────────────────────────

class TestMITMPrevention:
    """
    Verifies the safety number mechanism that allows out-of-band MITM detection.
    (Chapter 1 — Authentication Bypass via MITM)
    """

    def test_safety_number_symmetric(self):
        """Both peers must compute the same safety number."""
        _, alice_pub = generate_keypair()
        _, bob_pub = generate_keypair()
        sn_a = compute_safety_number(bytes(alice_pub), bytes(bob_pub))
        sn_b = compute_safety_number(bytes(bob_pub), bytes(alice_pub))
        assert sn_a == sn_b

    def test_mitm_changes_safety_number(self):
        """
        If Mallory intercepts and substitutes her key, the safety number
        computed by Alice and Bob will differ — exposing the MITM.
        """
        _, alice_pub = generate_keypair()
        _, bob_pub = generate_keypair()
        _, mallory_pub = generate_keypair()

        # What Alice computes (talking to Mallory-as-Bob)
        sn_alice = compute_safety_number(bytes(alice_pub), bytes(mallory_pub))
        # What Bob computes (talking to Mallory-as-Alice)
        sn_bob = compute_safety_number(bytes(mallory_pub), bytes(bob_pub))

        assert sn_alice != sn_bob, (
            "MITM substitution must produce different safety numbers on each side."
        )

    def test_safety_number_format_groups_of_five(self):
        """Safety number must be 6 groups of 5 digits separated by spaces."""
        _, alice_pub = generate_keypair()
        _, bob_pub = generate_keypair()
        sn = compute_safety_number(bytes(alice_pub), bytes(bob_pub))
        groups = sn.split(" ")
        assert len(groups) == 6
        for g in groups:
            assert g.isdigit()
            assert len(g) == 5


# ─────────────────────────────────────────────
#  8. Rate Limiting / Flooding DoS Tests
# ─────────────────────────────────────────────

class TestFloodingDOSPrevention:
    """
    Simulates a malicious peer sending messages at high rate to cause DoS.
    (Chapter 7 — Integer Overflow / resource exhaustion; rate limiting)
    """

    def test_flood_attack_blocked_after_capacity(self):
        """A peer sending > capacity messages in one burst must be throttled."""
        rl = RateLimiter()
        attacker = "evil_peer"

        allowed = sum(1 for _ in range(100) if rl.is_allowed(attacker))
        blocked = 100 - allowed

        # We expect at most CAPACITY (20) messages allowed in a burst
        from src.security_utils import RATE_LIMIT_CAPACITY
        assert allowed <= RATE_LIMIT_CAPACITY
        assert blocked > 0

    def test_legitimate_peer_unaffected_by_flood(self):
        """A flood from one peer must not degrade service for another peer."""
        rl = RateLimiter()
        flooder = "flooder_peer"
        legitimate = "legit_peer"

        # Flood from attacker
        for _ in range(100):
            rl.is_allowed(flooder)

        # Legitimate peer still gets through
        assert rl.is_allowed(legitimate) is True

    def test_message_size_limit_prevents_amplification(self):
        """A message exceeding MAX_MESSAGE_SIZE_BYTES must be rejected."""
        big_payload = "X" * (MAX_MESSAGE_SIZE_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_message(big_payload)


# ─────────────────────────────────────────────
#  9. File Integrity (Tamper Detection) Tests
# ─────────────────────────────────────────────

class TestFileIntegrityAttacks:
    """
    Simulates an attacker modifying a file in transit.
    (Chapter 8 — Downloading Code Without Integrity Checks)
    """

    def test_tampered_file_detected(self, tmp_path):
        """SHA-256 mismatch on received file must be detected."""
        f = tmp_path / "payload.bin"
        f.write_bytes(b"original content")
        expected_hash = compute_file_hash(f)

        # Attacker modifies the file
        f.write_bytes(b"malicious content")
        assert verify_file_hash(f, expected_hash) is False

    def test_unmodified_file_passes_integrity(self, tmp_path):
        """An unmodified file must pass the hash check."""
        f = tmp_path / "clean.bin"
        data = os.urandom(4096)
        f.write_bytes(data)
        h = compute_file_hash(f)
        assert verify_file_hash(f, h) is True

    def test_hash_is_sha256_length(self, tmp_path):
        """compute_file_hash() must return a 64-character hex string (SHA-256)."""
        f = tmp_path / "any.txt"
        f.write_bytes(b"data")
        h = compute_file_hash(f)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ─────────────────────────────────────────────
# 10. Input Validation Edge Cases
# ─────────────────────────────────────────────

class TestInputValidationEdgeCases:
    """
    Additional edge cases for input validation.
    (Chapter 2 — Reliance on Untrusted Inputs)
    """

    def test_empty_message_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            validate_message("")

    def test_whitespace_only_message_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            validate_message("   \t\n")

    def test_unicode_emoji_message_accepted(self):
        """Unicode-heavy messages within size limit must be accepted."""
        msg = "🔒 Secure message! 🔐" * 10
        if len(msg.encode("utf-8")) <= MAX_MESSAGE_SIZE_BYTES:
            result = validate_message(msg)
            assert result.strip() == msg.strip()

    def test_invalid_public_key_hex_rejected(self):
        """Non-hex characters in public key must be rejected."""
        with pytest.raises(ValueError):
            validate_public_key_hex("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

    def test_invalid_peer_address_rejected(self):
        """Invalid .b32.i2p addresses must be rejected."""
        with pytest.raises(ValueError):
            validate_peer_address("http://evil.com/../../etc/passwd")

    @pytest.mark.parametrize("reserved", ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"])
    def test_windows_reserved_filenames_blocked(self, reserved):
        """Windows reserved device names must be rejected as filenames."""
        with pytest.raises(ValueError, match="Reserved"):
            sanitize_filename(f"{reserved}.txt")
