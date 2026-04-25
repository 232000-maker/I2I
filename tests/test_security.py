"""
File: tests/test_security.py
Purpose: Unit tests for the security_utils module.

Tests verify:
- Message validation rejects oversized, empty, and non-string inputs
- Peer address validation enforces .b32.i2p format strictly
- Public key hex validation enforces 64-char hex strings
- Filename sanitization prevents path traversal attacks
- Rate limiting correctly throttles high-rate senders
- File hash computation and verification work correctly
"""

import sys
import time
import hashlib
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security_utils import (
    validate_message,
    validate_peer_address,
    validate_public_key_hex,
    validate_file_path,
    sanitize_filename,
    compute_file_hash,
    verify_file_hash,
    RateLimiter,
    MAX_MESSAGE_SIZE_BYTES,
    MAX_FILE_SIZE_BYTES,
)


# ─────────────────────────────────────────────
#  Message Validation Tests
# ─────────────────────────────────────────────

class TestMessageValidation:
    """Tests for validate_message()."""

    def test_valid_short_message_passes(self):
        assert validate_message("Hello!") == "Hello!"

    def test_strip_whitespace(self):
        assert validate_message("  hi  ") == "hi"

    def test_empty_message_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_message("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            validate_message("   \t\n ")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="string"):
            validate_message(12345)

    def test_oversized_message_raises(self):
        big_msg = "a" * (MAX_MESSAGE_SIZE_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_message(big_msg)

    def test_max_size_exactly_passes(self):
        msg = "a" * MAX_MESSAGE_SIZE_BYTES
        result = validate_message(msg)
        assert result == msg

    def test_unicode_message(self):
        msg = "مرحبا بالعالم 🔒"
        result = validate_message(msg)
        assert result == msg


# ─────────────────────────────────────────────
#  Peer Address Validation Tests
# ─────────────────────────────────────────────

class TestPeerAddressValidation:
    """Tests for validate_peer_address()."""

    VALID_ADDRESS = "a" * 52 + ".b32.i2p"  # 52 lowercase a's

    def test_valid_address_passes(self):
        addr = "abcde2abcde2abcde2abcde2abcde2abcde2abcde2abcde2abcd.b32.i2p"
        # Build a valid 52-char base32 address
        valid = "a2" * 26 + ".b32.i2p"  # 52 chars using valid base32 chars
        result = validate_peer_address(valid)
        assert result == valid.lower()

    def test_rejects_plain_hostname(self):
        with pytest.raises(ValueError):
            validate_peer_address("example.com")

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            validate_peer_address("abc.b32.i2p")  # Too short prefix

    def test_rejects_injection_attempt(self):
        with pytest.raises(ValueError):
            validate_peer_address("../../etc/passwd.b32.i2p")

    def test_rejects_uppercase(self):
        # Valid base32 address but uppercase (should pass since we lowercase it)
        addr = "A" * 52 + ".b32.i2p"
        # 'A' is valid base32 char but must be lowercased
        # After strip/lower: aaaa...a.b32.i2p which is valid
        result = validate_peer_address(addr)
        assert result == addr.lower()

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="string"):
            validate_peer_address(None)


# ─────────────────────────────────────────────
#  Public Key Hex Validation Tests
# ─────────────────────────────────────────────

class TestPublicKeyHexValidation:
    """Tests for validate_public_key_hex()."""

    VALID_HEX = "a" * 64

    def test_valid_hex_passes(self):
        result = validate_public_key_hex(self.VALID_HEX)
        assert result == self.VALID_HEX

    def test_valid_hex_uppercase_passes(self):
        result = validate_public_key_hex("A" * 64)
        assert result == "a" * 64

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            validate_public_key_hex("aabb")

    def test_too_long_raises(self):
        with pytest.raises(ValueError):
            validate_public_key_hex("a" * 65)

    def test_non_hex_chars_raises(self):
        with pytest.raises(ValueError):
            validate_public_key_hex("g" * 64)  # 'g' is not valid hex

    def test_non_string_raises(self):
        with pytest.raises(ValueError):
            validate_public_key_hex(12345)


# ─────────────────────────────────────────────
#  Filename Sanitization Tests
# ─────────────────────────────────────────────

class TestFilenameSanitization:
    """Tests for sanitize_filename(). Critical security tests."""

    def test_normal_filename_preserved(self):
        assert sanitize_filename("document.pdf") == "document.pdf"

    def test_path_traversal_stripped(self):
        """../../etc/passwd must become passwd."""
        result = sanitize_filename("../../etc/passwd")
        assert result == "passwd"
        assert ".." not in result
        assert "/" not in result

    def test_windows_path_traversal_stripped(self):
        result = sanitize_filename("..\\..\\Windows\\System32\\cmd.exe")
        # os.path.basename on Windows gives cmd.exe
        assert ".." not in result

    def test_null_byte_removed(self):
        result = sanitize_filename("file\x00.txt")
        assert "\x00" not in result

    def test_special_chars_replaced(self):
        result = sanitize_filename("my file (final).txt")
        # Spaces and parentheses replaced with underscores
        assert " " not in result
        assert "(" not in result

    def test_double_dots_collapsed(self):
        result = sanitize_filename("file...name.txt")
        assert ".." not in result

    def test_windows_reserved_name_rejected(self):
        with pytest.raises(ValueError, match="Reserved"):
            sanitize_filename("CON.txt")

    def test_empty_after_sanitization_raises(self):
        with pytest.raises(ValueError):
            sanitize_filename("../")  # Becomes empty after basename

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="string"):
            sanitize_filename(1234)

    def test_max_length_enforced(self):
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255


# ─────────────────────────────────────────────
#  File Validation Tests
# ─────────────────────────────────────────────

class TestFileValidation:
    """Tests for validate_file_path()."""

    def test_valid_file_passes(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = validate_file_path(str(f))
        assert result == f.resolve()

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            validate_file_path(str(tmp_path / "nonexistent.txt"))

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        with pytest.raises(ValueError, match="empty"):
            validate_file_path(str(f))

    def test_directory_raises(self, tmp_path):
        with pytest.raises(ValueError, match="regular file"):
            validate_file_path(str(tmp_path))


# ─────────────────────────────────────────────
#  File Hash Tests
# ─────────────────────────────────────────────

class TestFileHash:
    """Tests for compute_file_hash() and verify_file_hash()."""

    def test_hash_matches_manual_sha256(self, tmp_path):
        f = tmp_path / "data.bin"
        data = b"secure content"
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert compute_file_hash(f) == expected

    def test_verify_correct_hash_returns_true(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"abc")
        h = compute_file_hash(f)
        assert verify_file_hash(f, h) is True

    def test_verify_wrong_hash_returns_false(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"abc")
        assert verify_file_hash(f, "0" * 64) is False

    def test_hash_different_files_differ(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"content a")
        f2.write_bytes(b"content b")
        assert compute_file_hash(f1) != compute_file_hash(f2)


# ─────────────────────────────────────────────
#  Rate Limiter Tests
# ─────────────────────────────────────────────

class TestRateLimiter:
    """Tests for the token bucket rate limiter."""

    def test_first_message_allowed(self):
        rl = RateLimiter()
        assert rl.is_allowed("peer1") is True

    def test_burst_within_capacity_allowed(self):
        """20 messages in a row (= bucket capacity) must all be allowed."""
        rl = RateLimiter()
        results = [rl.is_allowed("peer1") for _ in range(20)]
        assert all(results)

    def test_exceeding_capacity_blocked(self):
        """Message 21 (> capacity) must be blocked."""
        rl = RateLimiter()
        for _ in range(20):
            rl.is_allowed("peer1")
        # 21st should be blocked
        assert rl.is_allowed("peer1") is False

    def test_different_peers_independent(self):
        """Different peer IDs have independent rate limit buckets."""
        rl = RateLimiter()
        for _ in range(20):
            rl.is_allowed("peer1")
        # peer1 is exhausted but peer2 should still be allowed
        assert rl.is_allowed("peer2") is True
        assert rl.is_allowed("peer1") is False

    def test_reset_clears_bucket(self):
        """reset() must restore a peer's full bucket."""
        rl = RateLimiter()
        for _ in range(20):
            rl.is_allowed("peer1")
        assert rl.is_allowed("peer1") is False
        rl.reset("peer1")
        assert rl.is_allowed("peer1") is True

    def test_refill_over_time(self):
        """After waiting, bucket refills proportionally."""
        from src.security_utils import RATE_LIMIT_REFILL_RATE, RATE_LIMIT_CAPACITY
        rl = RateLimiter()
        for _ in range(RATE_LIMIT_CAPACITY):
            rl.is_allowed("peer1")
        assert rl.is_allowed("peer1") is False
        time.sleep(1.0 / RATE_LIMIT_REFILL_RATE + 0.05)  # Wait for ~1 token
        assert rl.is_allowed("peer1") is True
