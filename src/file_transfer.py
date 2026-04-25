"""
File: src/file_transfer.py
Purpose: Secure chunked file transfer module for the I2I application.

All file chunks and acknowledgments flow through the encrypted message handler
(send_raw_envelope / parse_and_decrypt_envelope), avoiding any direct socket
reads that would race with the receive loop thread.

Transfer Protocol:
  1. Sender  ──[FILE_META  {filename, chunks, hash, size}]──► Receiver
  2. Receiver ──[FILE_ACK  {ack: "ready"}]──────────────────► Sender
  3. For each chunk i:
       Sender  ──[FILE_CHUNK {chunk_index, total, data_hex}]──► Receiver
       Receiver ──[FILE_ACK  {ack: "chunk_i"}]─────────────────► Sender
  4. Receiver verifies SHA-256 of reassembled file.

Security Controls:
- All frames are encrypted via the session Box (XSalsa20-Poly1305).
- Filenames are sanitized before write (path traversal prevention).
- Files written only to received_files/ directory.
- SHA-256 integrity verified after full reassembly.
- Tampered or incomplete files are deleted before notifying the UI.
- ACK synchronization uses threading.Event — no direct socket reads.
"""

import json
import time
import logging
import threading
from pathlib import Path
from typing import Optional, Callable

from src.peer_connection import PeerSession
from src.message_handler import (
    send_raw_envelope,
    MESSAGE_TYPE_FILE_CHUNK,
    MESSAGE_TYPE_FILE_META,
    MESSAGE_TYPE_FILE_ACK,
)
from src.security_utils import (
    validate_file_path,
    sanitize_filename,
    compute_file_hash,
    verify_file_hash,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
CHUNK_SIZE = 4 * 1024       # 4 KB
MAX_CHUNK_RETRIES = 3
ACK_TIMEOUT = 30            # Seconds to wait for each ACK
RECEIVED_FILES_DIR = Path("received_files")


# ─────────────────────────────────────────────
#  File Sender
# ─────────────────────────────────────────────

class FileSender:
    """
    Sends a file to a peer using the encrypted message layer.

    ACK synchronization uses threading.Event so no socket reads happen
    here — the ACK message arrives through the normal receive loop and is
    delivered via on_ack_received().

    Security:
    - File path and size validated before transfer begins.
    - Each chunk sent as an encrypted FILE_CHUNK envelope.
    - Waits for ACK before sending the next chunk (back-pressure).
    - Retries up to MAX_CHUNK_RETRIES per chunk before aborting.
    """

    def __init__(
        self,
        session: PeerSession,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self._session = session
        self._on_progress = on_progress
        self._ack_event = threading.Event()
        self._last_ack: Optional[str] = None
        self._ack_lock = threading.Lock()

    def on_ack_received(self, token: str) -> None:
        """
        Called by the message dispatcher when a FILE_ACK arrives for this peer.

        Inputs:
            token: The ACK string (e.g. "ready", "chunk_0", "error").
        """
        with self._ack_lock:
            self._last_ack = token
        self._ack_event.set()

    def send_file(self, file_path: str) -> bool:
        """
        Validate, chunk, encrypt and send a file to the connected peer.

        Inputs:
            file_path: Path to the local file to send (user-supplied).
        Output:
            True on success, False on any failure.
        """
        # ── Validate ──────────────────────────
        try:
            path = validate_file_path(file_path)
        except (ValueError, FileNotFoundError) as exc:
            logger.error("File validation failed: %s", exc)
            return False

        filename = sanitize_filename(path.name)
        file_hash = compute_file_hash(path)
        file_size = path.stat().st_size
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        logger.info("Starting file transfer: %s (%d bytes, %d chunks).", filename, file_size, total_chunks)

        # ── Send metadata ─────────────────────
        meta_payload = json.dumps({
            "filename": filename,
            "total_chunks": total_chunks,
            "file_hash": file_hash,
            "size": file_size,
        }).encode("utf-8")

        if not send_raw_envelope(self._session, MESSAGE_TYPE_FILE_META, meta_payload):
            logger.error("Failed to send file metadata.")
            return False

        # ── Wait for receiver ready ───────────
        if not self._wait_for_ack("ready"):
            logger.error("Receiver did not acknowledge file transfer start.")
            return False

        # ── Send chunks ───────────────────────
        with open(path, "rb") as f:
            for chunk_index in range(total_chunks):
                chunk_data = f.read(CHUNK_SIZE)
                ok = self._send_chunk_with_retry(chunk_index, total_chunks, chunk_data)
                if not ok:
                    logger.error("Transfer aborted at chunk %d.", chunk_index)
                    return False
                if self._on_progress:
                    self._on_progress(chunk_index + 1, total_chunks)

        logger.info("File transfer complete: %s", filename)
        return True

    def _send_chunk_with_retry(
        self, chunk_index: int, total_chunks: int, chunk_data: bytes
    ) -> bool:
        """
        Send one chunk and wait for its ACK, retrying up to MAX_CHUNK_RETRIES.

        Inputs:
            chunk_index: Zero-based index of this chunk.
            total_chunks: Total number of chunks expected.
            chunk_data: Raw bytes for this chunk.
        Output:
            True if ACKed, False after exhausting retries.
        """
        chunk_payload = json.dumps({
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
            "data": chunk_data.hex(),
        }).encode("utf-8")

        for attempt in range(1, MAX_CHUNK_RETRIES + 1):
            if not send_raw_envelope(self._session, MESSAGE_TYPE_FILE_CHUNK, chunk_payload):
                logger.warning("Send failed for chunk %d (attempt %d).", chunk_index, attempt)
                continue

            if self._wait_for_ack(f"chunk_{chunk_index}"):
                return True

            logger.warning("No ACK for chunk %d (attempt %d/%d).", chunk_index, attempt, MAX_CHUNK_RETRIES)

        return False

    def _wait_for_ack(self, expected: str) -> bool:
        """
        Block until the expected ACK token arrives or timeout expires.

        Security: Validates the exact token — prevents spoofed/mismatched ACKs.

        Inputs:
            expected: The ACK string to wait for.
        Output:
            True if matching ACK received within ACK_TIMEOUT seconds.
        """
        self._ack_event.clear()
        received = self._ack_event.wait(timeout=ACK_TIMEOUT)
        if not received:
            return False
        with self._ack_lock:
            return self._last_ack == expected


# ─────────────────────────────────────────────
#  File Receiver
# ─────────────────────────────────────────────

class FileReceiver:
    """
    Receives a file from a peer, chunk by chunk, through the message layer.

    handle_meta() and handle_chunk() are called by the GUI message dispatcher
    when FILE_META and FILE_CHUNK envelopes arrive — no direct socket access.

    Security:
    - Filename sanitized before any disk writes.
    - Chunks stored in memory by index; out-of-order chunks are tolerated
      but the final set must be complete.
    - SHA-256 of the reassembled file is verified; file deleted on mismatch.
    - Files written only to RECEIVED_FILES_DIR.
    """

    def __init__(
        self,
        session: PeerSession,
        max_file_size: int,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_complete: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        """
        Inputs:
            session: Active PeerSession from the sender (used to send ACKs).
            max_file_size: Enforced maximum file size for receiving (RBAC).
            on_progress: Optional callback(received_count, total_chunks).
            on_complete: Optional callback(saved_path_or_empty, success: bool).
        """
        self._session = session
        self._max_file_size = max_file_size
        self._on_progress = on_progress
        self._on_complete = on_complete

        # Transfer state
        self._filename: Optional[str] = None
        self._total_chunks: Optional[int] = None
        self._expected_hash: Optional[str] = None
        self._chunks: dict[int, bytes] = {}   # {chunk_index: raw_bytes}
        self._ready = False

        RECEIVED_FILES_DIR.mkdir(exist_ok=True)

    def handle_meta(self, payload: bytes) -> None:
        """
        Process a FILE_META envelope from the sender.

        Security:
        - Validates and sanitizes filename from peer (untrusted source).
        - Rejects transfers that exceed MAX_FILE_SIZE_BYTES.
        - Sends ACK "ready" or "error" through the encrypted message layer.

        Inputs:
            payload: Decrypted bytes of the FILE_META envelope.
        """
        try:
            meta = json.loads(payload.decode("utf-8"))
            self._filename = sanitize_filename(meta["filename"])
            self._total_chunks = int(meta["total_chunks"])
            self._expected_hash = str(meta["file_hash"])
            file_size = int(meta["size"])
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Invalid file metadata: %s", exc)
            self._send_ack("error")
            return

        if file_size > self._max_file_size:
            logger.warning("Incoming file too large (%d bytes) — rejecting due to RBAC limit.", file_size)
            self._send_ack("error")
            return

        if self._total_chunks <= 0 or self._total_chunks > 15000:
            logger.warning("Invalid chunk count: %d", self._total_chunks)
            self._send_ack("error")
            return

        logger.info("Accepting file: %s (%d chunks).", self._filename, self._total_chunks)
        self._chunks = {}
        self._ready = True
        self._send_ack("ready")

    def handle_chunk(self, payload: bytes) -> None:
        """
        Process a FILE_CHUNK envelope from the sender.

        Security:
        - Validates chunk_index is within expected range.
        - ACKs each chunk through the encrypted message layer.
        - Triggers reassembly when all chunks are received.
        - SHA-256 verified before calling on_complete.

        Inputs:
            payload: Decrypted bytes of the FILE_CHUNK envelope.
        """
        if not self._ready:
            logger.warning("Received chunk before metadata — discarding.")
            return

        try:
            envelope = json.loads(payload.decode("utf-8"))
            chunk_index = int(envelope["chunk_index"])
            chunk_data = bytes.fromhex(envelope["data"])
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Malformed chunk envelope: %s", exc)
            return

        if chunk_index < 0 or chunk_index >= self._total_chunks:
            logger.warning("Chunk index %d out of range (0-%d).", chunk_index, self._total_chunks - 1)
            return

        self._chunks[chunk_index] = chunk_data
        self._send_ack(f"chunk_{chunk_index}")

        received_count = len(self._chunks)
        if self._on_progress:
            self._on_progress(received_count, self._total_chunks)

        logger.debug("Chunk %d/%d received.", chunk_index + 1, self._total_chunks)

        # Check if all chunks are present
        if received_count == self._total_chunks:
            self._reassemble()

    def _reassemble(self) -> None:
        """
        Reassemble all chunks into the output file and verify SHA-256.

        Security:
        - Writes to RECEIVED_FILES_DIR only (never arbitrary paths).
        - Verifies SHA-256 hash; deletes file and notifies failure on mismatch.
        - Adds timestamp suffix to avoid overwriting existing files.
        """
        # Build sorted output path (avoid overwriting existing files)
        out_path = RECEIVED_FILES_DIR / self._filename
        if out_path.exists():
            stem, suffix = out_path.stem, out_path.suffix
            out_path = RECEIVED_FILES_DIR / f"{stem}_{int(time.time())}{suffix}"

        try:
            with open(out_path, "wb") as f:
                for i in range(self._total_chunks):
                    if i not in self._chunks:
                        logger.error("Missing chunk %d during reassembly.", i)
                        if self._on_complete:
                            self._on_complete("", False)
                        return
                    f.write(self._chunks[i])
        except OSError as exc:
            logger.error("Failed to write output file: %s", type(exc).__name__)
            out_path.unlink(missing_ok=True)
            if self._on_complete:
                self._on_complete("", False)
            return

        # SHA-256 integrity check
        if not verify_file_hash(out_path, self._expected_hash):
            logger.error("File integrity check FAILED — deleting corrupted file.")
            out_path.unlink(missing_ok=True)
            if self._on_complete:
                self._on_complete("", False)
            return

        logger.info("File received and verified: %s", out_path.name)
        self._ready = False
        if self._on_complete:
            self._on_complete(str(out_path), True)

    def _send_ack(self, token: str) -> None:
        """
        Send an ACK back to the sender through the encrypted message layer.

        Inputs:
            token: ACK token string (e.g. "ready", "chunk_0", "error").
        """
        payload = json.dumps({"ack": token}).encode("utf-8")
        send_raw_envelope(self._session, MESSAGE_TYPE_FILE_ACK, payload)
