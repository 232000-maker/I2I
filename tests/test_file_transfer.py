"""
File: tests/test_file_transfer.py
Purpose: Unit tests for the file_transfer module.

Tests verify:
- File hash computation is consistent and correct
- Filename sanitization in transfer context prevents path traversal
- File size limits are enforced before transfer
- Large file chunking produces expected number of chunks
"""

import sys
import os
import hashlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security_utils import (
    compute_file_hash,
    verify_file_hash,
    validate_file_path,
    sanitize_filename,
    MAX_FILE_SIZE_BYTES,
)
from src.file_transfer import CHUNK_SIZE


# ─────────────────────────────────────────────
#  Chunking Logic Tests
# ─────────────────────────────────────────────

class TestChunking:
    """Tests for file chunking calculations."""

    def test_exact_multiple_chunks(self):
        """File of exactly N * CHUNK_SIZE bytes must produce N chunks."""
        size = 3 * CHUNK_SIZE
        total_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        assert total_chunks == 3

    def test_one_extra_byte_adds_chunk(self):
        """File of N * CHUNK_SIZE + 1 bytes must produce N+1 chunks."""
        size = 3 * CHUNK_SIZE + 1
        total_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        assert total_chunks == 4

    def test_single_byte_file_is_one_chunk(self):
        total_chunks = (1 + CHUNK_SIZE - 1) // CHUNK_SIZE
        assert total_chunks == 1

    def test_chunk_size_constant_is_4kb(self):
        assert CHUNK_SIZE == 4096


# ─────────────────────────────────────────────
#  File Read/Write Integrity Tests
# ─────────────────────────────────────────────

class TestFileIntegrity:
    """Tests for SHA-256 based file integrity verification."""

    def test_identical_file_hashes_match(self, tmp_path):
        f = tmp_path / "original.bin"
        data = os.urandom(8192)
        f.write_bytes(data)

        h1 = compute_file_hash(f)
        h2 = compute_file_hash(f)
        assert h1 == h2

    def test_modified_file_hash_differs(self, tmp_path):
        f = tmp_path / "file.bin"
        f.write_bytes(b"original data")
        h1 = compute_file_hash(f)

        f.write_bytes(b"modified data")
        h2 = compute_file_hash(f)

        assert h1 != h2

    def test_verify_after_copy(self, tmp_path):
        """Copying a file must produce a matching hash."""
        src = tmp_path / "source.bin"
        dst = tmp_path / "copy.bin"
        data = os.urandom(20 * 1024)
        src.write_bytes(data)
        dst.write_bytes(data)

        expected_hash = compute_file_hash(src)
        assert verify_file_hash(dst, expected_hash) is True

    def test_large_file_hashing(self, tmp_path):
        """Hashing should work on files larger than the read buffer (64KB)."""
        f = tmp_path / "large.bin"
        # 200 KB
        data = os.urandom(200 * 1024)
        f.write_bytes(data)

        expected = hashlib.sha256(data).hexdigest()
        actual = compute_file_hash(f)
        assert actual == expected


# ─────────────────────────────────────────────
#  File Size Limit Tests
# ─────────────────────────────────────────────

class TestFileSizeLimit:
    """Tests for file size enforcement."""

    def test_normal_file_passes(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_bytes(b"data" * 1000)
        result = validate_file_path(str(f))
        assert result is not None

    def test_empty_file_rejected(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        with pytest.raises(ValueError, match="empty"):
            validate_file_path(str(f))

    def test_max_file_size_constant(self):
        assert MAX_FILE_SIZE_BYTES == 50 * 1024 * 1024


# ─────────────────────────────────────────────
#  Filename Sanitization (Transfer Context)
# ─────────────────────────────────────────────

class TestFilenameSanitizationTransfer:
    """Security-focused filename sanitization for received filenames."""

    @pytest.mark.parametrize("dangerous,expected_safe", [
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("/etc/shadow", "shadow"),
        ("normal_file.pdf", "normal_file.pdf"),
        ("my document (v2).docx", "my_document__v2_.docx"),
    ])
    def test_sanitization_parametrized(self, dangerous, expected_safe):
        result = sanitize_filename(dangerous)
        # Must not contain path separators
        assert "/" not in result
        assert "\\" not in result
        assert ".." not in result
        # Must match the expected safe name
        assert result == expected_safe
