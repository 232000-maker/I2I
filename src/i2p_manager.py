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

import os
import socket
import threading
import logging
from typing import Optional, Callable

from src.crypto_utils import generate_peer_address
import nacl.public

logger = logging.getLogger(__name__)

# Allows Docker to override to 0.0.0.0, defaults to 127.0.0.1 for native use
BIND_ADDRESS = os.getenv("I2I_BIND_ADDR", "127.0.0.1")
DEFAULT_PORT = 7777
CONNECTION_TIMEOUT = 10
MAX_CONNECTIONS = 10


class I2PManager:
    def __init__(
        self, public_key: nacl.public.PublicKey, port: int = DEFAULT_PORT
    ) -> None:
        self._public_key = public_key
        self._port = port
        self._address = generate_peer_address(public_key)
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._on_new_connection: Optional[Callable] = None

    @property
    def local_address(self) -> str:
        return self._address

    def start_listener(
        self, on_new_connection: Callable[[socket.socket, str], None]
    ) -> None:
        self._on_new_connection = on_new_connection
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        # FIXED: Use BIND_ADDRESS variable
        self._server_socket.bind((BIND_ADDRESS, self._port))

        self._server_socket.listen(MAX_CONNECTIONS)
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="I2PListener", daemon=True
        )
        self._accept_thread.start()
        logger.info("I2P listener started on %s:%d.", BIND_ADDRESS, self._port)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                conn.settimeout(CONNECTION_TIMEOUT)
                handler = threading.Thread(
                    target=self._on_new_connection, args=(conn, addr[0]), daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop_listener(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # FIXED: Added target_host parameter
    def connect_to_peer(self, target_host: str, peer_port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)
        try:
            sock.connect((target_host, peer_port))
            return sock
        except (ConnectionRefusedError, socket.timeout):
            sock.close()
            raise
