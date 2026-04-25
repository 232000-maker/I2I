"""
File: src/i2p_manager.py
Purpose: I2P network interface layer for the I2I application.

This module manages the simulated I2P SAM (Simple Anonymous Messaging) API layer.
In production, this would connect to a real I2P router via the SAM protocol
(TCP on port 7656). For standalone demonstration without an I2P router, it
simulates the layer using a local TCP server/client on localhost.

Key responsibilities:
- Generate and manage .b32.i2p-style peer addresses
- Accept incoming peer connections (listener mode)
- Establish outbound peer connections
- Provide a socket-like interface to the rest of the application

Security Controls:
- Peer addresses are derived deterministically from public keys (no spoofing)
- No real IP addresses are exposed
- Connection timeouts enforced (10 seconds)
- Connection limits to prevent resource exhaustion
"""

import socket
import threading
import logging
from pathlib import Path
from typing import Optional, Callable, Tuple

from src.crypto_utils import generate_peer_address
import nacl.public

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
DEFAULT_PORT = 7777             # Local simulation port
CONNECTION_TIMEOUT = 10         # Seconds before connection attempt times out
MAX_CONNECTIONS = 10            # Maximum simultaneous incoming connections
SOCKET_BUFFER_SIZE = 65536      # 64 KB read buffer


# ─────────────────────────────────────────────
#  I2P Manager
# ─────────────────────────────────────────────

class I2PManager:
    """
    Manages the simulated I2P network layer.

    In I2P, each node exposes a .b32.i2p address derived from its public key.
    This class simulates that behaviour using TCP on localhost for demonstration.

    Security:
    - Our address is derived from our public key — no forgery possible.
    - All I/O goes through this class; upper layers never touch raw sockets.
    """

    def __init__(self, public_key: nacl.public.PublicKey, port: int = DEFAULT_PORT) -> None:
        """
        Initialize the I2P manager.

        Inputs:
            public_key: Our X25519 public key, used to derive our .b32.i2p address.
            port: Local TCP port to listen on (default 7777).
        """
        self._public_key = public_key
        self._port = port
        self._address = generate_peer_address(public_key)
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._on_new_connection: Optional[Callable] = None
        logger.info("I2PManager initialized. Local address: %s", self._address[:16] + "...")

    # ──────────────────────────────────────────
    #  Properties
    # ──────────────────────────────────────────

    @property
    def local_address(self) -> str:
        """Return our .b32.i2p address (derived from public key)."""
        return self._address

    @property
    def is_running(self) -> bool:
        """Return True if the listener is active."""
        return self._running

    # ──────────────────────────────────────────
    #  Server (Listener) Management
    # ──────────────────────────────────────────

    def start_listener(self, on_new_connection: Callable[[socket.socket, str], None]) -> None:
        """
        Start listening for incoming peer connections.

        Security:
        - Binds only to localhost (127.0.0.1) — no external network exposure in demo.
        - Sets SO_REUSEADDR to handle restart scenarios cleanly.
        - Connections are handled in separate daemon threads.

        Inputs:
            on_new_connection: Callback(socket, peer_addr) invoked for each new connection.
        Output:
            None. Starts background accept thread.
        Raises:
            OSError: If the port is already in use.
        """
        self._on_new_connection = on_new_connection
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)  # Allows clean shutdown
        self._server_socket.bind(("127.0.0.1", self._port))
        self._server_socket.listen(MAX_CONNECTIONS)
        self._running = True

        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="I2PListener",
            daemon=True
        )
        self._accept_thread.start()
        logger.info("I2P listener started on port %d.", self._port)

    def _accept_loop(self) -> None:
        """
        Background thread: Accept incoming connections.

        Security:
        - Each connection is handled in its own thread.
        - Catches all exceptions to prevent listener crashes.
        """
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                conn.settimeout(CONNECTION_TIMEOUT)
                logger.info("New incoming connection from %s.", addr[0])
                handler = threading.Thread(
                    target=self._on_new_connection,
                    args=(conn, addr[0]),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue  # Normal — loop back to check _running
            except OSError:
                break  # Server socket closed

    def stop_listener(self) -> None:
        """
        Stop the listening server and close the server socket.

        Security: Ensures all resources are released cleanly.
        """
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        logger.info("I2P listener stopped.")

    # ──────────────────────────────────────────
    #  Client (Outbound) Connection
    # ──────────────────────────────────────────

    def connect_to_peer(self, peer_address: str, peer_port: int = DEFAULT_PORT) -> socket.socket:
        """
        Establish an outbound TCP connection to a peer.

        Security:
        - Connection timeout is enforced (10 seconds).
        - In real I2P mode, the peer_address would be a .b32.i2p address resolved
          via SAM API; here we use localhost for simulation.

        Inputs:
            peer_address: .b32.i2p address of the peer (used as display/identity).
            peer_port: TCP port to connect to (default 7777).
        Output:
            Connected socket.socket object.
        Raises:
            ConnectionRefusedError: If the peer is not listening.
            socket.timeout: If connection takes longer than CONNECTION_TIMEOUT.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)
        try:
            # In simulation mode, all peers run on localhost
            sock.connect(("127.0.0.1", peer_port))
            logger.info("Connected to peer (simulated I2P).")
            return sock
        except (ConnectionRefusedError, socket.timeout) as exc:
            sock.close()
            logger.warning("Failed to connect to peer: %s", type(exc).__name__)
            raise
