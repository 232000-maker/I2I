"""
File: src/message_handler.py
Purpose: Encrypted message send/receive logic for the I2I application.

This module handles the high-level message protocol on top of the encrypted
peer session layer. It is responsible for:
- Constructing JSON message envelopes
- Encrypting payloads before transmission
- Decrypting and validating received message envelopes
- Detecting and rejecting replay attacks via nonce tracking
- Message size enforcement

Message Format:
{
  "type": "message",          # "message" | "key_exchange" | "file_chunk" | "file_ack"
  "sender": "<peer_address>",
  "data": "<hex-encoded ciphertext>",
  "nonce": "<hex-encoded 24-byte nonce>",
  "timestamp": <unix_float>
}

Security Controls:
- All message content is encrypted using the session Box (XSalsa20-Poly1305).
- Nonces are random and registered for replay attack detection.
- Timestamps are validated (allow ±5 minutes — handles clock skew).
- Malformed envelopes are rejected without exposing error details.
- No plaintext message content in logs.
"""

import json
import time
import logging
from typing import Optional, Tuple
import nacl.exceptions
from src.peer_connection import PeerSession, _send_framed
from src.crypto_utils import encrypt_message, decrypt_message, NONCE_SIZE
from src.security_utils import validate_message, rate_limiter

logger = logging.getLogger(__name__)

MESSAGE_TYPE_CHAT = "message"
MESSAGE_TYPE_FILE_CHUNK = "file_chunk"
MESSAGE_TYPE_FILE_ACK = "file_ack"
MESSAGE_TYPE_FILE_META = "file_meta"
MESSAGE_TYPE_CONTROL = "control"
TIMESTAMP_TOLERANCE_SECONDS = 300
MAX_TIMESTAMP_FUTURE_SECONDS = 60


def send_chat_message(session: PeerSession, plaintext: str) -> bool:
    try:
        plaintext = validate_message(plaintext)
    except ValueError as exc:
        logger.warning("Message validation failed: %s", exc)
        return False

    if not rate_limiter.is_allowed(session.peer_address):
        logger.warning("Rate limit: message to peer rejected.")
        return False
    return _send_envelope(session, MESSAGE_TYPE_CHAT, plaintext.encode("utf-8"))


def send_raw_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    return _send_envelope(session, msg_type, payload)


def _send_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    """
    FIXED: We now wrap the metadata AND the payload into one JSON object,
    and then encrypt that ENTIRE object to protect metadata.
    """
    try:
        envelope_dict = {
            "type": msg_type,
            "sender": session.peer_address,
            "timestamp": time.time(),
            "payload": payload.hex(),
        }
        envelope_bytes = json.dumps(envelope_dict).encode("utf-8")

        # Encrypt the whole JSON blob
        ciphertext, nonce = encrypt_message(session.box, envelope_bytes)

        # Send: [Nonce (24 bytes)][Ciphertext]
        _send_framed(session.sock, nonce + ciphertext)
        return True
    except Exception:
        logger.error("Failed to send message (details suppressed).")
        return False


def parse_and_decrypt_envelope(
    session: PeerSession, raw_bytes: bytes
) -> Optional[Tuple[str, bytes]]:
    """
    FIXED: Decrypt first, then parse.
    This prevents DoS attacks via malformed JSON before authentication.
    """
    if len(raw_bytes) < NONCE_SIZE + 16:  # Min nonce + min Poly1305 tag
        return None

    nonce = raw_bytes[:NONCE_SIZE]
    ciphertext = raw_bytes[NONCE_SIZE:]

    # 1. DECRYPT FIRST (Verifies MAC)
    try:
        decrypted_blob = decrypt_message(session.box, ciphertext, nonce)
    except nacl.exceptions.CryptoError:
        logger.warning("MAC verification failed - discarding tampered message.")
        return None
    except Exception:
        return None

    # 2. PARSE JSON SECOND (Only happens if MAC is valid)
    try:
        envelope = json.loads(decrypted_blob.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Decrypted blob was not valid JSON.")
        return None

    # Validate fields
    required = {"type", "timestamp", "payload"}
    if not required.issubset(envelope.keys()):
        return None

    # Timestamp validation
    try:
        timestamp = float(envelope["timestamp"])
        now = time.time()
        if (now - timestamp > TIMESTAMP_TOLERANCE_SECONDS) or (
            timestamp > now + MAX_TIMESTAMP_FUTURE_SECONDS
        ):
            logger.warning("Message timestamp expired or too far in future.")
            return None
    except (ValueError, TypeError):
        return None

    # Replay protection
    if not session.register_nonce(nonce):
        return None

    try:
        msg_type = envelope["type"]
        payload = bytes.fromhex(envelope["payload"])
        return msg_type, payload
    except Exception:
        return None
