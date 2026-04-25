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
import os
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

CHUNK_SIZE = 4 * 1024
MAX_CHUNK_RETRIES = 3
ACK_TIMEOUT = 30
RECEIVED_FILES_DIR = Path("received_files")


class FileSender:
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
        with self._ack_lock:
            self._last_ack = token
            self._ack_event.set()

    def send_file(self, file_path: str) -> bool:
        try:
            path = validate_file_path(file_path)
        except Exception as exc:
            logger.error("File validation failed: %s", exc)
            return False

        filename = sanitize_filename(path.name)
        file_hash = compute_file_hash(path)
        file_size = path.stat().st_size
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        meta_payload = json.dumps(
            {
                "filename": filename,
                "total_chunks": total_chunks,
                "file_hash": file_hash,
                "size": file_size,
            }
        ).encode("utf-8")

        if not send_raw_envelope(self._session, MESSAGE_TYPE_FILE_META, meta_payload):
            return False

        if not self._wait_for_ack("ready"):
            return False

        with open(path, "rb") as f:
            for chunk_index in range(total_chunks):
                chunk_data = f.read(CHUNK_SIZE)
                chunk_payload = json.dumps(
                    {
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "data": chunk_data.hex(),
                    }
                ).encode("utf-8")

                success = False
                for attempt in range(MAX_CHUNK_RETRIES):
                    if send_raw_envelope(
                        self._session, MESSAGE_TYPE_FILE_CHUNK, chunk_payload
                    ):
                        if self._wait_for_ack(f"chunk_{chunk_index}"):
                            success = True
                            break
                if not success:
                    return False
                if self._on_progress:
                    self._on_progress(chunk_index + 1, total_chunks)
        return True

    def _wait_for_ack(self, expected: str) -> bool:
        self._ack_event.clear()
        if not self._ack_event.wait(timeout=ACK_TIMEOUT):
            return False
        with self._ack_lock:
            return self._last_ack == expected


class FileReceiver:
    def __init__(
        self,
        session: PeerSession,
        max_file_size: int,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_complete: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        self._session = session
        self._max_file_size = max_file_size
        self._on_progress = on_progress
        self._on_complete = on_complete
        self._temp_file: Optional[Path] = None
        self._total_chunks: int = 0
        self._expected_hash: Optional[str] = None
        self._received_chunks: set[int] = set()
        self._ready = False
        RECEIVED_FILES_DIR.mkdir(exist_ok=True)

    def handle_meta(self, payload: bytes) -> None:
        try:
            meta = json.loads(payload.decode("utf-8"))
            filename = sanitize_filename(meta["filename"])
            size = int(meta["size"])

            if size > self._max_file_size:
                self._send_ack("error")
                return

            self._total_chunks = int(meta["total_chunks"])
            self._expected_hash = meta["file_hash"]

            # FIXED: Add a timestamp to the .part file to prevent collisions
            unique_id = int(time.time() * 1000)
            self._temp_file = RECEIVED_FILES_DIR / f"{filename}_{unique_id}.part"

            with open(self._temp_file, "wb") as f:
                f.truncate(size)  # Pre-allocate space on disk

            self._received_chunks = set()
            self._ready = True
            self._send_ack("ready")
        except Exception:
            self._send_ack("error")

    def handle_chunk(self, payload: bytes) -> None:
        if not self._ready or not self._temp_file:
            return
        try:
            envelope = json.loads(payload.decode("utf-8"))
            idx = int(envelope["chunk_index"])
            data = bytes.fromhex(envelope["data"])

            if 0 <= idx < self._total_chunks:
                with open(self._temp_file, "r+b") as f:
                    f.seek(idx * CHUNK_SIZE)
                    f.write(data)

                self._received_chunks.add(idx)
                self._send_ack(f"chunk_{idx}")

                if self._on_progress:
                    self._on_progress(len(self._received_chunks), self._total_chunks)

                if len(self._received_chunks) == self._total_chunks:
                    self._reassemble()
        except Exception:
            pass

    def _reassemble(self) -> None:
        final_path = self._temp_file.with_suffix("")  # Remove .part
        if final_path.exists():
            final_path = (
                RECEIVED_FILES_DIR
                / f"{final_path.stem}_{int(time.time())}{final_path.suffix}"
            )

        try:
            os.rename(self._temp_file, final_path)
            if verify_file_hash(final_path, self._expected_hash):
                if self._on_complete:
                    self._on_complete(str(final_path), True)
            else:
                final_path.unlink(missing_ok=True)
                if self._on_complete:
                    self._on_complete("", False)
        except Exception:
            if self._temp_file and self._temp_file.exists():
                self._temp_file.unlink()
            if self._on_complete:
                self._on_complete("", False)
        finally:
            self._ready = False

    def _send_ack(self, token: str) -> None:
        payload = json.dumps({"ack": token}).encode("utf-8")
        send_raw_envelope(self._session, MESSAGE_TYPE_FILE_ACK, payload)
