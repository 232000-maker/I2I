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
import secrets
from typing import Optional, Tuple

import nacl.exceptions

from src.peer_connection import PeerSession, _send_framed
from src.crypto_utils import encrypt_message, decrypt_message, NONCE_SIZE
from src.security_utils import validate_message, rate_limiter

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
MESSAGE_TYPE_CHAT = "message"
MESSAGE_TYPE_FILE_CHUNK = "file_chunk"
MESSAGE_TYPE_FILE_ACK = "file_ack"
MESSAGE_TYPE_FILE_META = "file_meta"
MESSAGE_TYPE_CONTROL = "control"
TIMESTAMP_TOLERANCE_SECONDS = 300   # 5 minutes
MAX_TIMESTAMP_FUTURE_SECONDS = 60   # reject messages > 1 min in future


# ─────────────────────────────────────────────
#  Sending
# ─────────────────────────────────────────────

def send_chat_message(session: PeerSession, plaintext: str) -> bool:
    """
    Validate, encrypt, and send a chat message to a peer.

    Security checks:
    - Input is validated for length and type before encryption.
    - Rate limiting is enforced per peer.
    - Plaintext is encrypted with a unique random nonce before sending.
    - Nothing about the plaintext is logged.

    Inputs:
        session: Active PeerSession to the recipient.
        plaintext: The message string typed by the user.
    Output:
        True if sent successfully, False otherwise.
    """
    # Input validation
    try:
        plaintext = validate_message(plaintext)
    except ValueError as exc:
        logger.warning("Message validation failed: %s", exc)
        return False

    # Rate limiting
    if not rate_limiter.is_allowed(session.peer_address):
        logger.warning("Rate limit: message to peer rejected.")
        return False

    return _send_envelope(session, MESSAGE_TYPE_CHAT, plaintext.encode("utf-8"))


def send_raw_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    """
    Send an encrypted envelope of arbitrary type.

    Security:
    - Used internally for file chunks and acknowledgments.
    - All payloads are encrypted before transmission.

    Inputs:
        session: Active PeerSession.
        msg_type: One of the MESSAGE_TYPE_* constants.
        payload: Raw bytes to encrypt and send.
    Output:
        True on success, False on failure.
    """
    return _send_envelope(session, msg_type, payload)


def _send_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    """
    Internal: Construct and send an encrypted message envelope.

    Format: length-prefixed JSON envelope with hex-encoded encrypted payload.

    Security:
    - Random nonce generated per message (PyNaCl nacl.utils.random).
    - Timestamp included for replay/ordering detection.

    Inputs:
        session: Active PeerSession.
        msg_type: Message type string.
        payload: Already-validated raw bytes to encrypt.
    Output:
        True on success.
    """
    try:
        ciphertext, nonce = encrypt_message(session.box, payload)
        envelope = {
            "type": msg_type,
            "sender": session.peer_address,  # Our address from session
            "data": ciphertext.hex(),
            "nonce": nonce.hex(),
            "timestamp": time.time(),
        }
        envelope_bytes = json.dumps(envelope).encode("utf-8")
        _send_framed(session.sock, envelope_bytes)
        return True
    except Exception:
        logger.error("Failed to send message (details suppressed for security).")
        return False


# ─────────────────────────────────────────────
#  Receiving
# ─────────────────────────────────────────────

def parse_and_decrypt_envelope(
    session: PeerSession,
    raw_bytes: bytes,
) -> Optional[Tuple[str, bytes]]:
    """
    Parse, validate, and decrypt a received message envelope.

    Security checks:
    - JSON parsing errors are caught and rejected without leaking details.
    - Required fields are verified before decryption.
    - Nonce is checked for replay attacks via session.register_nonce().
    - Timestamp is validated to be within acceptable tolerance.
    - MAC verification by PyNaCl catches any tampered ciphertext.

    Inputs:
        session: Active PeerSession whose box is used for decryption.
        raw_bytes: Raw bytes received from the peer (the framed envelope).
    Output:
        Tuple of (msg_type: str, plaintext: bytes) on success, or None on failure.
    """
    # Parse JSON envelope
    try:
        envelope = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Received malformed JSON envelope — discarding.")
        return None

    # Validate required fields
    required_fields = {"type", "data", "nonce", "timestamp"}
    if not required_fields.issubset(envelope.keys()):
        logger.warning("Received envelope missing required fields — discarding.")
        return None

    msg_type = envelope["type"]
    if not isinstance(msg_type, str) or len(msg_type) > 32:
        logger.warning("Invalid message type field — discarding.")
        return None

    # Validate and decode hex fields
    try:
        ciphertext = bytes.fromhex(envelope["data"])
        nonce = bytes.fromhex(envelope["nonce"])
    except (ValueError, KeyError):
        logger.warning("Malformed hex data in envelope — discarding.")
        return None

    if len(nonce) != NONCE_SIZE:
        logger.warning("Invalid nonce size — discarding.")
        return None

    # Timestamp validation (anti-replay / clock skew detection)
    try:
        timestamp = float(envelope["timestamp"])
    except (ValueError, TypeError):
        logger.warning("Invalid timestamp — discarding.")
        return None

    now = time.time()
    age = now - timestamp
    if age > TIMESTAMP_TOLERANCE_SECONDS or timestamp > now + MAX_TIMESTAMP_FUTURE_SECONDS:
        logger.warning("Message timestamp out of acceptable range — possible replay attack.")
        return None

    # Replay attack prevention — nonce must be unique
    if not session.register_nonce(nonce):
        logger.warning("Duplicate nonce detected — replay attack rejected.")
        return None

    # Decrypt and verify MAC
    try:
        plaintext = decrypt_message(session.box, ciphertext, nonce)
        return msg_type, plaintext
    except nacl.exceptions.CryptoError:
        logger.warning("Decryption/MAC failure — tampered or invalid message.")
        return None
    except Exception:
        logger.error("Unexpected decryption error (details suppressed).")
        return None
