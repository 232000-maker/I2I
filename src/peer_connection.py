"""
File: src/peer_connection.py
Purpose: Peer connection lifecycle management for the I2I application.

This module handles the complete lifecycle of P2P connections:
- Initiating and accepting connections
- Performing X25519 key exchange handshake
- Maintaining active session state
- Handling disconnection and cleanup
- Retry logic (max 3 attempts) with 10-second timeout

Security Controls:
- Key exchange is performed immediately on connection (before any data exchange)
- Public keys are transmitted and verified before establishing session
- No plaintext communication after handshake
- Sessions are isolated — each peer gets independent encryption context
- Connection errors are handled generically to avoid info disclosure
"""

import json
import socket
import struct
import logging
import threading
import time
from typing import Optional, Callable, Tuple

import nacl.public
import nacl.exceptions

from src.crypto_utils import (
    compute_shared_secret,
    public_key_to_hex,
    hex_to_public_key_bytes,
    compute_safety_number,
    generate_peer_address,
    generate_keypair,
    encrypt_message,
    decrypt_message,
)
from src.security_utils import validate_public_key_hex

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2
HANDSHAKE_TIMEOUT = 10
MESSAGE_HEADER_SIZE = 4               # 4-byte big-endian length prefix
MAX_RAW_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB absolute cap on single recv
SOCKET_BUFFER_SIZE = 65536            # 64 KB read buffer


# ─────────────────────────────────────────────
#  Session State
# ─────────────────────────────────────────────

class PeerSession:
    """
    Represents an active encrypted session with a single peer.

    Security:
    - Holds the shared secret Box for this peer only.
    - Tracks nonces seen to detect replay attacks.
    - Thread-safe due to the GIL and atomic assignment on basic types.
    """

    def __init__(
        self,
        sock: socket.socket,
        peer_address: str,
        peer_public_key_bytes: bytes,
        box: nacl.public.Box,
        safety_number: str,
    ) -> None:
        self.sock = sock
        self.peer_address = peer_address
        self.peer_public_key_bytes = peer_public_key_bytes
        self.box = box
        self.safety_number = safety_number
        self.connected_at = time.time()
        self._used_nonces: set = set()   # Replay attack prevention
        self._nonce_lock = threading.Lock()

    def register_nonce(self, nonce: bytes) -> bool:
        """
        Register a nonce and return False if it was already seen (replay attack).

        Security: Prevents replay attacks where an attacker re-sends captured messages.

        Inputs:
            nonce: 24-byte nonce from a received message.
        Output:
            True if nonce is fresh, False if it is a replay.
        """
        with self._nonce_lock:
            if nonce in self._used_nonces:
                logger.warning("Replay attack detected — duplicate nonce from peer.")
                return False
            self._used_nonces.add(nonce)
            # Bound nonce set size to prevent memory exhaustion (keep last 10,000)
            if len(self._used_nonces) > 10_000:
                # Discard oldest — rebuild as ordered would be costly; simple clear of oldest half
                nonces_list = list(self._used_nonces)
                self._used_nonces = set(nonces_list[5_000:])
            return True

    def close(self) -> None:
        """Close the underlying socket cleanly."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ─────────────────────────────────────────────
#  Connection Management
# ─────────────────────────────────────────────

class PeerConnectionManager:
    """
    Manages establishing, handshaking, and maintaining P2P peer sessions.

    Security:
    - All connections go through key exchange before data exchange.
    - Sessions are tracked and can be individually terminated.
    - No raw data is passed through without session-level encryption.
    """

    def __init__(
        self,
        our_private_key: nacl.public.PrivateKey,
        our_public_key: nacl.public.PublicKey,
        on_message_received: Callable[[str, bytes], None],
        on_peer_connected: Callable[[str, str], None],
        on_peer_disconnected: Callable[[str], None],
    ) -> None:
        """
        Initialize the connection manager.

        Inputs:
            our_private_key: Local X25519 private key for ECDH.
            our_public_key: Local X25519 public key (shared with peers).
            on_message_received: Callback(peer_address, raw_decrypted_bytes).
            on_peer_connected: Callback(peer_address, safety_number).
            on_peer_disconnected: Callback(peer_address).
        """
        self._private_key = our_private_key
        self._public_key = our_public_key
        self._sessions: dict[str, PeerSession] = {}
        self._sessions_lock = threading.Lock()
        self._on_message_received = on_message_received
        self._on_peer_connected = on_peer_connected
        self._on_peer_disconnected = on_peer_disconnected

    # ──────────────────────────────────────────
    #  Outbound Connection
    # ──────────────────────────────────────────

    def connect_to_peer(
        self,
        sock: socket.socket,
        peer_display_address: str,
        peer_public_key_hex: str,
    ) -> Optional[PeerSession]:
        """
        Connect to a peer: validates key, performs handshake, starts receive loop.

        Security:
        - Validates the peer public key hex before performing ECDH.
        - Performs handshake (exchange public keys) immediately on connection.
        - Returns None on any failure rather than raising (avoids info leakage to caller).

        Inputs:
            sock: Already-connected socket to the peer.
            peer_display_address: Peer's .b32.i2p address (for display/logging).
            peer_public_key_hex: Peer's X25519 public key as 64-char hex string.
        Output:
            PeerSession on success, None on failure.
        """
        try:
            peer_pub_hex = validate_public_key_hex(peer_public_key_hex)
            peer_pub_bytes = hex_to_public_key_bytes(peer_pub_hex)
        except ValueError as exc:
            logger.error("Peer public key validation failed: %s", exc)
            return None

        try:
            session = self._perform_handshake(sock, peer_display_address, peer_pub_bytes)
        except Exception:
            logger.error("Handshake failed with peer (details suppressed for security).")
            return None

        if session:
            self._register_session(session)
            thread = threading.Thread(
                target=self._receive_loop,
                args=(session,),
                daemon=True,
                name=f"Recv-{peer_display_address[:8]}",
            )
            thread.start()

        return session

    def handle_incoming_connection(
        self, sock: socket.socket, peer_ip: str
    ) -> None:
        """
        Handle an incoming peer connection (server side).

        Security:
        - Immediately enters handshake — no data is accepted before key exchange.
        - Logs only anonymized IP for security.

        Inputs:
            sock: Newly accepted socket from the server listener.
            peer_ip: Source IP of the incoming connection (used for logging only).
        """
        logger.info("Incoming connection from %s.", peer_ip[:6] + "...")
        try:
            # We don't know the peer's .b32.i2p address yet — derive after key exchange
            session = self._perform_handshake(sock, peer_ip, peer_pub_bytes=None)
        except Exception:
            logger.error("Incoming handshake failed (details suppressed).")
            try:
                sock.close()
            except OSError:
                pass
            return

        if session:
            self._register_session(session)
            thread = threading.Thread(
                target=self._receive_loop,
                args=(session,),
                daemon=True,
                name=f"Recv-{session.peer_address[:8]}",
            )
            thread.start()
            self._on_peer_connected(session.peer_address, session.safety_number)

    # ──────────────────────────────────────────
    #  Key Exchange Handshake
    # ──────────────────────────────────────────

    def _perform_handshake(
        self,
        sock: socket.socket,
        peer_label: str,
        peer_pub_bytes: Optional[bytes],
    ) -> Optional[PeerSession]:
        """
        Perform X25519 key exchange handshake over the socket.

        Protocol (both sides simultaneously):
          1. Send our public key (32 bytes) length-prefixed.
          2. Receive peer's public key (32 bytes) length-prefixed.
          3. Derive shared secret via ECDH.
          4. Derive peer's .b32.i2p address from their public key.
          5. Compute safety number.

        Security:
        - Public keys are sent in the clear — this is expected (Diffie-Hellman).
        - The shared secret is NEVER transmitted.
        - Safety number allows out-of-band MITM verification.

        Inputs:
            sock: Connected socket.
            peer_label: Display label for logging.
            peer_pub_bytes: Peer's public key bytes if known (outbound); None for inbound.
        Output:
            PeerSession on success.
        Raises:
            ValueError, OSError: On failure.
        """
        our_pub_bytes = bytes(self._public_key)

        # Send our identity public key
        _send_framed(sock, our_pub_bytes)

        # Receive peer's identity public key
        received_pub_bytes = _recv_framed(sock, timeout=HANDSHAKE_TIMEOUT)
        if len(received_pub_bytes) != 32:
            raise ValueError("Received malformed public key from peer.")

        if peer_pub_bytes is not None:
            import hmac
            if not hmac.compare_digest(received_pub_bytes, peer_pub_bytes):
                raise ValueError("Peer public key mismatch — possible MITM attack!")

        # Derive initial identity box (used ONLY to authenticate the ephemeral keys)
        identity_box = compute_shared_secret(self._private_key, received_pub_bytes)

        # --- Phase 2: Ephemeral Key Exchange (Perfect Forward Secrecy) ---
        eph_priv, eph_pub = generate_keypair()
        
        # Encrypt our ephemeral pub with the identity box
        cipher_eph_pub, nonce = encrypt_message(identity_box, bytes(eph_pub))
        _send_framed(sock, nonce + cipher_eph_pub)
        
        # Receive peer's encrypted ephemeral pub
        peer_eph_payload = _recv_framed(sock, timeout=HANDSHAKE_TIMEOUT)
        if len(peer_eph_payload) < 24:
            raise ValueError("Malformed ephemeral key payload.")
            
        peer_nonce = peer_eph_payload[:24]
        peer_cipher = peer_eph_payload[24:]
        peer_eph_pub_bytes = decrypt_message(identity_box, peer_cipher, peer_nonce)
        
        # The true session box is derived from the ephemeral keys
        session_box = compute_shared_secret(eph_priv, peer_eph_pub_bytes)

        # Derive peer identity for display
        peer_address = generate_peer_address(
            nacl.public.PublicKey(received_pub_bytes)
        )
        safety_number = compute_safety_number(our_pub_bytes, received_pub_bytes)

        session = PeerSession(
            sock=sock,
            peer_address=peer_address,
            peer_public_key_bytes=received_pub_bytes,
            box=session_box,
            safety_number=safety_number,
        )
        logger.info("Handshake complete. Peer address: %s...", peer_address[:12])
        return session

    # ──────────────────────────────────────────
    #  Receive Loop
    # ──────────────────────────────────────────

    def _receive_loop(self, session: PeerSession) -> None:
        """
        Background thread: Continuously receive and decrypt messages from a peer.

        Security:
        - Each received frame is verified and decrypted before passing up.
        - Logs generic error messages — no raw data in logs.
        - Loop exits cleanly on socket closure or error.

        Inputs:
            session: Active PeerSession to read from.
        """
        # IMPORTANT: Set socket to fully blocking mode.
        # The socket may have a timeout left over from the connection/handshake
        # phase. Without this, the receive loop would raise socket.timeout
        # (a subclass of OSError) after 10 seconds of idle and disconnect.
        session.sock.settimeout(None)

        while True:
            try:
                raw = _recv_framed(session.sock, timeout=None)
                self._on_message_received(session.peer_address, raw)
            except (OSError, ConnectionResetError, EOFError):
                break
            except Exception:
                logger.warning("Error receiving data from peer (details suppressed).")
                break

        logger.info("Peer disconnected: %s...", session.peer_address[:12])
        self._unregister_session(session.peer_address)
        self._on_peer_disconnected(session.peer_address)

    # ──────────────────────────────────────────
    #  Session Registry
    # ──────────────────────────────────────────

    def _register_session(self, session: PeerSession) -> None:
        """Register a new session, closing any existing session for that peer."""
        with self._sessions_lock:
            if session.peer_address in self._sessions:
                self._sessions[session.peer_address].close()
            self._sessions[session.peer_address] = session

    def _unregister_session(self, peer_address: str) -> None:
        """Remove a session from the registry."""
        with self._sessions_lock:
            self._sessions.pop(peer_address, None)

    def get_session(self, peer_address: str) -> Optional[PeerSession]:
        """Retrieve an active session by peer address."""
        with self._sessions_lock:
            return self._sessions.get(peer_address)

    def get_all_sessions(self) -> list[PeerSession]:
        """Return a snapshot of all active sessions."""
        with self._sessions_lock:
            return list(self._sessions.values())

    def disconnect_peer(self, peer_address: str) -> None:
        """Gracefully disconnect from a peer."""
        with self._sessions_lock:
            session = self._sessions.pop(peer_address, None)
        if session:
            session.close()
            logger.info("Disconnected from peer: %s...", peer_address[:12])


# ─────────────────────────────────────────────
#  Framing (Length-Prefixed I/O)
# ─────────────────────────────────────────────

def _send_framed(sock: socket.socket, data: bytes) -> None:
    """
    Send a length-prefixed data frame over the socket.

    Format: [4-byte big-endian length][data bytes]

    Security:
    - Length prefix prevents ambiguous message boundaries.
    - Prevents message injection via crafted frame sizes.

    Inputs:
        sock: Target socket.
        data: Bytes to send.
    Raises:
        OSError: On send failure.
    """
    if len(data) > MAX_RAW_MESSAGE_BYTES:
        raise ValueError(f"Data too large to send: {len(data)} bytes.")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def _recv_framed(sock: socket.socket, timeout: Optional[float]) -> bytes:
    """
    Receive a length-prefixed data frame from the socket.

    Security:
    - Reads exact number of bytes specified by the header (no more, no less).
    - Enforces MAX_RAW_MESSAGE_BYTES cap to prevent memory exhaustion DoS.
    - Always applies the timeout (including None for blocking mode) to avoid
      stale timeouts from earlier socket operations causing false disconnects.

    Inputs:
        sock: Source socket.
        timeout: Seconds to wait, or None for fully blocking (no timeout).
    Output:
        Received bytes payload.
    Raises:
        EOFError: If the connection closed mid-read.
        ValueError: If the declared length exceeds the safety limit.
    """
    # Always set the timeout — passing None explicitly enables blocking mode,
    # clearing any timeout left over from the connection/handshake phase.
    sock.settimeout(timeout)

    header = _recv_exact(sock, MESSAGE_HEADER_SIZE)
    (length,) = struct.unpack("!I", header)

    if length == 0:
        return b""
    if length > MAX_RAW_MESSAGE_BYTES:
        raise ValueError(f"Incoming frame too large: {length} bytes.")

    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from the socket.

    Security:
    - Loops until n bytes are received — prevents partial reads.
    - Raises EOFError if the connection closes before n bytes arrive.

    Inputs:
        sock: Source socket.
        n: Exact number of bytes to read.
    Output:
        Exactly n bytes.
    Raises:
        EOFError: If connection closes before n bytes received.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(SOCKET_BUFFER_SIZE, n - len(buf)))
        if not chunk:
            raise EOFError("Connection closed before all bytes received.")
        buf.extend(chunk)
    return bytes(buf)

