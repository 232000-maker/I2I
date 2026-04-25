"""
File: gui/app.py
Purpose: Tkinter-based GUI for the I2I secure P2P messaging application.

This module provides the desktop user interface including:
- Dark-themed chat window
- Peer connection management
- Real-time message display
- File send/receive notifications
- Safety number display for MITM prevention verification
- Connection status indicator

Security Design:
- GUI validates all inputs before passing to the application layer
- Safety numbers are prominently displayed for out-of-band MITM verification
- Sensitive information (keys, addresses) is not stored in GUI widgets
- All background network I/O happens in daemon threads; GUI updates are
  scheduled on the main thread via root.after() to remain thread-safe

Architecture:
- The GUI communicates with the application via callback functions
- The GUI never directly touches sockets or cryptographic primitives
"""

import os
import json
import time
import socket
import logging
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from pathlib import Path
from typing import Optional, Callable

import nacl.public

from src.crypto_utils import (
    load_or_generate_keypair,
    public_key_to_hex,
    generate_peer_address,
)
from src.i2p_manager import I2PManager
from src.peer_connection import PeerConnectionManager
from src.message_handler import (
    send_chat_message,
    send_raw_envelope,
    parse_and_decrypt_envelope,
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_FILE_META,
    MESSAGE_TYPE_FILE_CHUNK,
    MESSAGE_TYPE_FILE_ACK,
    MESSAGE_TYPE_CONTROL,
)
from src.file_transfer import FileSender, FileReceiver, RECEIVED_FILES_DIR
from src.security_utils import (
    validate_peer_address,
    validate_public_key_hex,
)
from src.validators import Validators, MAX_FILE_SIZE_ADMIN, MAX_FILE_SIZE_USER

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  Color Palette — Dark Secure Theme
# ─────────────────────────────────────────────
BG_DARK   = "#0d1117"      # Main background
BG_MID    = "#161b22"      # Panel background
BG_CARD   = "#21262d"      # Card / input background
ACCENT    = "#58a6ff"      # Primary accent (blue)
ACCENT2   = "#3fb950"      # Secondary accent (green)
WARN      = "#d29922"      # Warning yellow
DANGER    = "#f85149"      # Danger red
TEXT_MAIN = "#e6edf3"      # Primary text
TEXT_DIM  = "#8b949e"      # Dimmed text
BORDER    = "#30363d"      # Border color
SENT_BG   = "#1f3a5f"      # Sent message background
RECV_BG   = "#1a2a1a"      # Received message background


class I2IApp:
    """
    Main application window for the I2I secure P2P messenger.

    Security:
    - Instantiates its own key pair on startup.
    - Displays the .b32.i2p address and public key for sharing with peers.
    - All network operations are in daemon threads.
    - Safety numbers are shown for every connected peer.
    """

    def __init__(self, username: str, role: str) -> None:
        self.username = username
        self.role = role
        self.logout_requested = False
        # ── Load or generate keys ──────────────────
        self._private_key, self._public_key = load_or_generate_keypair()
        self._our_address = generate_peer_address(self._public_key)
        self._our_pub_hex = public_key_to_hex(self._public_key)

        # ── Active peer sessions ───────────────────
        self._current_peer: Optional[str] = None  # Currently selected peer address

        # ── Build I2P / connection layers ─────────
        self._i2p = I2PManager(self._public_key, port=7777)
        self._conn_mgr = PeerConnectionManager(
            our_private_key=self._private_key,
            our_public_key=self._public_key,
            on_message_received=self._on_message_received,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
        )

        # ── Message buffer per peer ────────────────
        self._messages: dict[str, list[tuple[str, str, str]]] = {}  # {addr: [(sender, text, time)]}
        self._file_receivers: dict[str, FileReceiver] = {}
        self._file_senders: dict[str, FileSender] = {}

        # ── Build GUI ──────────────────────────────
        self.root = tk.Tk()
        self.root.title("I2I — Secure P2P Messenger")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self._setup_styles()
        self._build_layout()
        self._start_listener()

        logger.info("I2IApp started. Address: %s...", self._our_address[:12])

    # ──────────────────────────────────────────
    #  Style Configuration
    # ──────────────────────────────────────────

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme."""
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=BG_MID, relief="flat")
        style.configure("TLabel", background=BG_DARK, foreground=TEXT_MAIN, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG_DARK, foreground=ACCENT, font=("Segoe UI", 13, "bold"))
        style.configure("Dim.TLabel", background=BG_MID, foreground=TEXT_DIM, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=BG_MID, foreground=ACCENT2, font=("Segoe UI", 9, "bold"))
        style.configure(
            "Accent.TButton",
            background=ACCENT, foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0, padding=(12, 6),
        )
        style.map("Accent.TButton",
            background=[("active", "#1f6feb"), ("disabled", BG_CARD)],
        )
        style.configure(
            "Danger.TButton",
            background=DANGER, foreground="#ffffff",
            font=("Segoe UI", 9),
            borderwidth=0, padding=(8, 4),
        )
        style.configure(
            "Green.TButton",
            background=ACCENT2, foreground="#000000",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0, padding=(12, 6),
        )
        style.configure(
            "TEntry",
            fieldbackground=BG_CARD, foreground=TEXT_MAIN,
            insertcolor=TEXT_MAIN, bordercolor=BORDER,
            font=("Segoe UI", 10),
        )
        style.configure(
            "TListbox", background=BG_MID, foreground=TEXT_MAIN,
        )
        style.configure("Horizontal.TSeparator", background=BORDER)

    # ──────────────────────────────────────────
    #  Layout Construction
    # ──────────────────────────────────────────

    def _build_layout(self) -> None:
        """Build and arrange all GUI widgets."""
        # ── Top bar ───────────────────────────────
        top_bar = tk.Frame(self.root, bg=BG_MID, height=52)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)

        tk.Label(
            top_bar, text="🔒 I2I Secure Messenger",
            bg=BG_MID, fg=ACCENT, font=("Segoe UI", 14, "bold")
        ).pack(side="left", padx=16, pady=10)

        user_info_lbl = tk.Label(
            top_bar, text=f"👤 Logged in as: {self.username} [{self.role}]",
            bg=BG_MID, fg=TEXT_MAIN, font=("Segoe UI", 10, "bold")
        )
        user_info_lbl.pack(side="left", padx=20)

        ttk.Button(
            top_bar, text="🚪 Exit", style="Danger.TButton",
            command=self._on_close
        ).pack(side="right", padx=(4, 16), pady=10)

        ttk.Button(
            top_bar, text="🔓 Logout", style="Accent.TButton",
            command=self._on_logout
        ).pack(side="right", padx=4, pady=10)

        self._status_label = tk.Label(
            top_bar, text="● Offline",
            bg=BG_MID, fg=DANGER, font=("Segoe UI", 9, "bold")
        )
        self._status_label.pack(side="right", padx=16)

        # ── Main pane ─────────────────────────────
        main = tk.PanedWindow(self.root, orient="horizontal", bg=BG_DARK,
                               sashwidth=4, sashrelief="flat")
        main.pack(fill="both", expand=True)

        # Left panel — identity + connections
        left = tk.Frame(main, bg=BG_MID, width=320)
        left.pack_propagate(False)
        main.add(left, minsize=260)

        self._build_left_panel(left)

        # Right panel — chat
        right = tk.Frame(main, bg=BG_DARK)
        main.add(right, minsize=450)

        self._build_chat_panel(right)

    def _build_left_panel(self, parent: tk.Frame) -> None:
        """Build the left identity and peer management panel."""
        # ── Identity card ────────────────────────
        id_frame = tk.LabelFrame(
            parent, text=" 🪪 Your Identity ",
            bg=BG_MID, fg=ACCENT, font=("Segoe UI", 9, "bold"),
            bd=1, relief="solid", highlightthickness=0,
        )
        id_frame.pack(fill="x", padx=10, pady=(12, 6))

        tk.Label(
            id_frame, text="Your .b32.i2p Address:",
            bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(6, 0))

        addr_display = tk.Text(
            id_frame, height=3, bg=BG_CARD, fg=ACCENT2,
            font=("Consolas", 8), bd=0, wrap="char",
            state="normal", selectbackground=ACCENT,
        )
        addr_display.pack(fill="x", padx=8, pady=(2, 0))
        addr_display.insert("1.0", self._our_address)
        addr_display.config(state="disabled")

        tk.Label(
            id_frame, text="Public Key (hex):",
            bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(6, 0))

        pub_display = tk.Text(
            id_frame, height=4, bg=BG_CARD, fg=TEXT_DIM,
            font=("Consolas", 7), bd=0, wrap="char",
            state="normal",
        )
        pub_display.pack(fill="x", padx=8, pady=(2, 8))
        pub_display.insert("1.0", self._our_pub_hex)
        pub_display.config(state="disabled")

        ttk.Button(
            id_frame, text="📋 Copy Address",
            style="Accent.TButton",
            command=lambda: self._copy_to_clipboard(self._our_address),
        ).pack(padx=8, pady=(0, 8), fill="x")

        # ── Connect to peer ─────────────────────
        conn_frame = tk.LabelFrame(
            parent, text=" 🔗 Connect to Peer ",
            bg=BG_MID, fg=ACCENT, font=("Segoe UI", 9, "bold"),
            bd=1, relief="solid",
        )
        conn_frame.pack(fill="x", padx=10, pady=6)

        tk.Label(
            conn_frame, text="Peer Public Key (hex):",
            bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(8, 0))

        self._peer_key_entry = tk.Text(
            conn_frame, height=4, bg=BG_CARD, fg=TEXT_MAIN,
            font=("Consolas", 8), bd=0, insertbackground=TEXT_MAIN,
        )
        self._peer_key_entry.pack(fill="x", padx=8, pady=(2, 0))

        tk.Label(
            conn_frame, text="Peer Port (default 7777):",
            bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(4, 0))

        self._port_var = tk.StringVar(value="7778")
        port_entry = ttk.Entry(conn_frame, textvariable=self._port_var, width=10)
        port_entry.pack(anchor="w", padx=8, pady=(2, 0))

        ttk.Button(
            conn_frame, text="⚡ Connect",
            style="Green.TButton",
            command=self._connect_to_peer,
        ).pack(padx=8, pady=8, fill="x")

        # ── Connected peers ──────────────────────
        peers_frame = tk.LabelFrame(
            parent, text=" 👥 Connected Peers ",
            bg=BG_MID, fg=ACCENT, font=("Segoe UI", 9, "bold"),
            bd=1, relief="solid",
        )
        peers_frame.pack(fill="both", expand=True, padx=10, pady=6)

        self._peers_listbox = tk.Listbox(
            peers_frame,
            bg=BG_CARD, fg=TEXT_MAIN,
            selectbackground=ACCENT, selectforeground="#ffffff",
            font=("Consolas", 8), bd=0, highlightthickness=0,
            activestyle="none",
        )
        self._peers_listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self._peers_listbox.bind("<<ListboxSelect>>", self._on_peer_selected)

        ttk.Button(
            peers_frame, text="❌ Disconnect",
            style="Danger.TButton",
            command=self._disconnect_peer,
        ).pack(padx=4, pady=(0, 4), fill="x")

        # Admin Kick Feature
        if self.role == "ADMIN":
            ttk.Button(
                peers_frame, text="👢 Force Kick (Admin)",
                style="Danger.TButton",
                command=self._kick_peer,
            ).pack(padx=4, pady=(0, 4), fill="x")

    def _build_chat_panel(self, parent: tk.Frame) -> None:
        """Build the right chat panel."""
        # ── Chat header ───────────────────────────
        header = tk.Frame(parent, bg=BG_MID, height=50)
        header.pack(fill="x")
        header.pack_propagate(False)

        self._chat_title_label = tk.Label(
            header, text="Select a peer to chat",
            bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 11, "bold")
        )
        self._chat_title_label.pack(side="left", padx=16, pady=10)

        self._safety_btn = ttk.Button(
            header, text="🔐 Safety Number",
            style="Accent.TButton",
            command=self._show_safety_number,
        )
        self._safety_btn.pack(side="right", padx=8, pady=8)

        # ── Message display ───────────────────────
        msg_frame = tk.Frame(parent, bg=BG_DARK)
        msg_frame.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        self._chat_display = scrolledtext.ScrolledText(
            msg_frame,
            bg=BG_DARK, fg=TEXT_MAIN,
            font=("Segoe UI", 10), bd=0, wrap="word",
            state="disabled",
            selectbackground=ACCENT,
        )
        self._chat_display.pack(fill="both", expand=True)

        # Configure text tags for message styling
        self._chat_display.tag_config("sent_label", foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        self._chat_display.tag_config("recv_label", foreground=ACCENT2, font=("Segoe UI", 9, "bold"))
        self._chat_display.tag_config("system", foreground=WARN, font=("Segoe UI", 9, "italic"))
        self._chat_display.tag_config("timestamp", foreground=TEXT_DIM, font=("Segoe UI", 8))
        self._chat_display.tag_config("message_text", foreground=TEXT_MAIN, font=("Segoe UI", 10))

        # ── Input bar ─────────────────────────────
        input_frame = tk.Frame(parent, bg=BG_MID, height=110)
        input_frame.pack(fill="x", padx=8, pady=8)
        input_frame.pack_propagate(False)

        self._message_entry = tk.Text(
            input_frame,
            bg=BG_CARD, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
            font=("Segoe UI", 10), bd=0, height=3, wrap="word",
        )
        self._message_entry.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)
        self._message_entry.bind("<Return>", self._on_enter_pressed)
        self._message_entry.bind("<Shift-Return>", lambda e: None)  # Allow newline with Shift

        btn_frame = tk.Frame(input_frame, bg=BG_MID)
        btn_frame.pack(side="right", padx=(0, 8), pady=8, fill="y")

        ttk.Button(
            btn_frame, text="📎 File",
            style="Accent.TButton",
            command=self._send_file,
        ).pack(pady=(0, 4), fill="x", expand=True)
        
        if self.role == "ADMIN":
            ttk.Button(
                btn_frame, text="📢 Broadcast",
                style="Accent.TButton",
                command=self._send_broadcast,
            ).pack(pady=(0, 4), fill="x", expand=True)

        ttk.Button(
            btn_frame, text="➤ Send",
            style="Green.TButton",
            command=self._send_message,
        ).pack(fill="x", expand=True)

    # ──────────────────────────────────────────
    #  Listener Startup
    # ──────────────────────────────────────────

    def _start_listener(self) -> None:
        """Start the I2P listener and update status label."""
        try:
            self._i2p.start_listener(
                on_new_connection=self._conn_mgr.handle_incoming_connection
            )
            self._status_label.config(text="● Listening", fg=ACCENT2)
            logger.info("Listener started successfully.")
        except OSError as exc:
            self._status_label.config(text="● Port in use", fg=WARN)
            logger.error("Failed to start listener: %s", exc)

    # ──────────────────────────────────────────
    #  Connection Actions
    # ──────────────────────────────────────────

    def _connect_to_peer(self) -> None:
        """
        Initiate an outbound connection to a peer.

        Security:
        - Validates peer public key before connecting.
        - Runs connection in a daemon thread (non-blocking GUI).
        """
        peer_key_hex = self._peer_key_entry.get("1.0", "end").strip()

        try:
            peer_key_hex = validate_public_key_hex(peer_key_hex)
        except ValueError as exc:
            messagebox.showerror("Invalid Input", str(exc))
            return

        try:
            port = int(self._port_var.get())
            if not (1024 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number between 1024 and 65535.")
            return

        threading.Thread(
            target=self._do_connect,
            args=(peer_key_hex, port),
            daemon=True,
        ).start()

    def _do_connect(self, peer_key_hex: str, port: int) -> None:
        """Background thread: perform the actual connection."""
        try:
            sock = self._i2p.connect_to_peer("", port)
        except (ConnectionRefusedError, socket.timeout) as exc:
            self.root.after(0, lambda: messagebox.showerror(
                "Connection Failed", "Could not connect to peer. Is the peer running?"
            ))
            return

        from src.crypto_utils import hex_to_public_key_bytes, generate_peer_address
        import nacl.public as np
        peer_addr = generate_peer_address(np.PublicKey(bytes.fromhex(peer_key_hex)))

        session = self._conn_mgr.connect_to_peer(sock, peer_addr, peer_key_hex)
        if session:
            self.root.after(0, self._on_peer_connected, session.peer_address, session.safety_number)
        else:
            self.root.after(0, lambda: messagebox.showerror(
                "Handshake Failed", "Key exchange failed. Peer identity could not be verified."
            ))

    def _disconnect_peer(self) -> None:
        """Disconnect the currently selected peer."""
        if self._current_peer:
            self._conn_mgr.disconnect_peer(self._current_peer)

    # ──────────────────────────────────────────
    #  Message Actions
    # ──────────────────────────────────────────

    def _send_message(self) -> None:
        """
        Send a chat message to the current peer.

        Security:
        - Passes through message_handler.send_chat_message which validates and encrypts.
        - Clears the input field regardless of success.
        """
        if not self._current_peer:
            messagebox.showinfo("No Peer", "Select or connect to a peer first.")
            return

        text = self._message_entry.get("1.0", "end-1c").strip()
        if not text:
            return

        if not Validators.validate_message(text):
            messagebox.showerror("Validation Error", "Message is invalid or exceeds maximum size limit.")
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if not session:
            messagebox.showerror("Disconnected", "Peer is no longer connected.")
            return

        success = send_chat_message(session, text)
        self._message_entry.delete("1.0", "end")

        if success:
            self._append_message(self._current_peer, "You", text, sent=True)
        else:
            self._append_system_message("Message could not be sent (rate limit or validation error).")

    def _on_enter_pressed(self, event: tk.Event) -> str:
        """Send message on Enter key (Shift+Enter allows newline)."""
        if not (event.state & 0x1):  # Shift not held
            self._send_message()
            return "break"  # Prevent newline insertion

    def _send_file(self) -> None:
        """Open file dialog and send selected file to current peer."""
        if not self._current_peer:
            messagebox.showinfo("No Peer", "Select or connect to a peer first.")
            return

        file_path = filedialog.askopenfilename(title="Select file to send")
        if not file_path:
            return

        try:
            Validators.validate_file_size(Path(file_path), self.role)
        except Exception as exc:
            messagebox.showerror("Authorization/Validation Error", str(exc))
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if not session:
            messagebox.showerror("Disconnected", "Peer is no longer connected.")
            return

        def _do_send():
            sender = FileSender(
                session,
                on_progress=lambda s, t: self.root.after(
                    0, self._append_system_message,
                    f"File transfer: {s}/{t} chunks sent..."
                ),
            )
            self._file_senders[session.peer_address] = sender
            ok = sender.send_file(file_path)
            self._file_senders.pop(session.peer_address, None)
            self.root.after(
                0, self._append_system_message,
                "✅ File sent successfully." if ok else "❌ File transfer failed."
            )

        threading.Thread(target=_do_send, daemon=True).start()
        self._append_system_message(f"📤 Sending file: {Path(file_path).name}")

    def _kick_peer(self) -> None:
        """Admin only: Send a kick command to forcefully disconnect the peer."""
        if not self._current_peer:
            messagebox.showinfo("No Peer", "Select a peer to kick.")
            return
            
        session = self._conn_mgr.get_session(self._current_peer)
        if session:
            # Send control message
            payload = json.dumps({"command": "kick"}).encode("utf-8")
            send_raw_envelope(session, MESSAGE_TYPE_CONTROL, payload)
            
            self._append_system_message(f"👢 You kicked {self._current_peer[:12]} from the session.")
            self.root.after(500, self._disconnect_peer)

    def _send_broadcast(self) -> None:
        """Admin only: Send an announcement to all connected peers."""
        text = self._message_entry.get("1.0", "end-1c").strip()
        if not text:
            return
            
        sessions = self._conn_mgr.get_all_sessions()
        if not sessions:
            messagebox.showinfo("No Peers", "You have no active connections to broadcast to.")
            return
            
        announcement = f"🚨 [ADMIN ANNOUNCEMENT]: {text}"
        if not Validators.validate_message(announcement):
            messagebox.showerror("Validation Error", "Broadcast message is too large.")
            return
            
        for session in sessions:
            send_chat_message(session, announcement)
            self._append_message(session.peer_address, "You (Broadcast)", announcement, sent=True)
            
        self._message_entry.delete("1.0", "end")

    # ──────────────────────────────────────────
    #  Network Callbacks
    # ──────────────────────────────────────────

    def _on_message_received(self, peer_address: str, raw_bytes: bytes) -> None:
        """
        Called by PeerConnectionManager when raw bytes arrive from a peer.

        Security:
        - Passes raw bytes through parse_and_decrypt_envelope before any processing.
        - File metadata triggers FileReceiver initialization.
        - All UI updates scheduled on main thread via root.after().
        """
        session = self._conn_mgr.get_session(peer_address)
        if not session:
            return

        result = parse_and_decrypt_envelope(session, raw_bytes)
        if result is None:
            return

        msg_type, plaintext = result

        if msg_type == MESSAGE_TYPE_CHAT:
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Received non-UTF-8 message payload — discarding.")
                return
            self.root.after(
                0, self._append_message,
                peer_address, peer_address[:12] + "...", text, False
            )

        elif msg_type == MESSAGE_TYPE_FILE_META:
            if peer_address not in self._file_receivers:
                max_size = MAX_FILE_SIZE_ADMIN if self.role == "ADMIN" else MAX_FILE_SIZE_USER
                receiver = FileReceiver(
                    session,
                    max_file_size=max_size,
                    on_progress=lambda r, t: self.root.after(
                        0, self._append_system_message,
                        f"📥 Receiving file: {r}/{t} chunks..."
                    ),
                    on_complete=lambda path, success: self.root.after(
                        0, self._append_system_message,
                        f"✅ File saved to: {path}" if success else "❌ File receive failed."
                    ),
                )
                self._file_receivers[peer_address] = receiver
            self._file_receivers[peer_address].handle_meta(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_CHUNK:
            if peer_address in self._file_receivers:
                self._file_receivers[peer_address].handle_chunk(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_ACK:
            if peer_address in self._file_senders:
                try:
                    envelope = json.loads(plaintext.decode("utf-8"))
                    self._file_senders[peer_address].on_ack_received(envelope.get("ack", ""))
                except Exception:
                    pass

        elif msg_type == MESSAGE_TYPE_CONTROL:
            try:
                cmd = json.loads(plaintext.decode("utf-8")).get("command")
                if cmd == "kick":
                    self.root.after(0, lambda: messagebox.showwarning("Kicked", "You have been forcefully disconnected by an Admin."))
                    self.root.after(0, lambda: self._conn_mgr.disconnect_peer(peer_address))
            except Exception:
                pass

    def _on_peer_connected(self, peer_address: str, safety_number: str) -> None:
        """Called when a new peer session is established."""
        if peer_address not in self._messages:
            self._messages[peer_address] = []

        # Add to peer list
        peers = [self._peers_listbox.get(i) for i in range(self._peers_listbox.size())]
        display = peer_address[:20] + "..."
        if display not in peers:
            self._peers_listbox.insert("end", display)

        # Store safety number in message history
        self._append_system_message(
            f"🔗 Connected to {peer_address[:12]}...\n"
            f"🔐 Safety Number: {safety_number}\n"
            f"   Verify this number with your peer out-of-band!",
            peer_address=peer_address,
        )
        self._status_label.config(text=f"● {self._peers_listbox.size()} peer(s)", fg=ACCENT2)

        # Auto-select first peer
        if not self._current_peer:
            self._peers_listbox.selection_set(0)
            self._on_peer_selected(None)

    def _on_peer_disconnected(self, peer_address: str) -> None:
        """Called when a peer disconnects."""
        self._append_system_message(
            f"⚠️ Peer disconnected: {peer_address[:12]}...",
            peer_address=peer_address,
        )
        # Remove from listbox
        display = peer_address[:20] + "..."
        for i in range(self._peers_listbox.size()):
            if self._peers_listbox.get(i) == display:
                self._peers_listbox.delete(i)
                break

        if peer_address in self._file_receivers:
            del self._file_receivers[peer_address]

        total = self._peers_listbox.size()
        self._status_label.config(
            text=f"● {total} peer(s)" if total > 0 else "● Listening",
            fg=ACCENT2 if total > 0 else TEXT_DIM,
        )

    # ──────────────────────────────────────────
    #  UI Helpers
    # ──────────────────────────────────────────

    def _on_peer_selected(self, event) -> None:
        """Handle peer selection from the listbox."""
        selection = self._peers_listbox.curselection()
        if not selection:
            return
        sessions = self._conn_mgr.get_all_sessions()
        idx = selection[0]
        if idx < len(sessions):
            self._current_peer = sessions[idx].peer_address
            self._chat_title_label.config(
                text=f"Chat: {self._current_peer[:20]}...",
                fg=ACCENT,
            )
            self._refresh_chat()

    def _refresh_chat(self) -> None:
        """Reload the chat display for the currently selected peer."""
        self._chat_display.config(state="normal")
        self._chat_display.delete("1.0", "end")

        if self._current_peer and self._current_peer in self._messages:
            for sender, text, ts in self._messages[self._current_peer]:
                self._render_message(sender, text, ts, sender == "You")

        self._chat_display.config(state="disabled")
        self._chat_display.see("end")

    def _append_message(
        self,
        peer_address: str,
        sender: str,
        text: str,
        sent: bool,
    ) -> None:
        """Add a message to the history and update display if this peer is selected."""
        ts = time.strftime("%H:%M:%S")
        if peer_address not in self._messages:
            self._messages[peer_address] = []
        self._messages[peer_address].append((sender, text, ts))

        if self._current_peer == peer_address:
            self._chat_display.config(state="normal")
            self._render_message(sender, text, ts, sent)
            self._chat_display.config(state="disabled")
            self._chat_display.see("end")

    def _render_message(self, sender: str, text: str, ts: str, sent: bool) -> None:
        """Render a single message bubble in the chat display."""
        label_tag = "sent_label" if sent else "recv_label"
        padding = "    " if sent else ""
        self._chat_display.insert("end", f"{padding}[{ts}] {sender}\n", label_tag)
        self._chat_display.insert("end", f"{padding}{text}\n\n", "message_text")

    def _append_system_message(self, text: str, peer_address: Optional[str] = None) -> None:
        """Append a system notification to the chat display."""
        addr = peer_address or self._current_peer
        ts = time.strftime("%H:%M:%S")
        if addr:
            if addr not in self._messages:
                self._messages[addr] = []
            self._messages[addr].append(("SYSTEM", text, ts))

        if addr == self._current_peer or addr is None:
            self._chat_display.config(state="normal")
            self._chat_display.insert("end", f"[{ts}] {text}\n\n", "system")
            self._chat_display.config(state="disabled")
            self._chat_display.see("end")

    def _show_safety_number(self) -> None:
        """Display the safety number for the current peer in a popup."""
        if not self._current_peer:
            messagebox.showinfo("No Peer", "No peer selected.")
            return
        session = self._conn_mgr.get_session(self._current_peer)
        if not session:
            messagebox.showinfo("Disconnected", "Peer session not active.")
            return

        popup = tk.Toplevel(self.root)
        popup.title("Safety Number Verification")
        popup.configure(bg=BG_DARK)
        popup.geometry("420x250")
        popup.resizable(False, False)

        tk.Label(
            popup, text="🔐 Safety Number",
            bg=BG_DARK, fg=ACCENT, font=("Segoe UI", 14, "bold")
        ).pack(pady=(20, 4))

        tk.Label(
            popup,
            text="Compare this number with your peer verbally or via another channel.\n"
                 "If it matches, your connection is secure (no MITM).",
            bg=BG_DARK, fg=TEXT_DIM, font=("Segoe UI", 9),
            wraplength=380, justify="center",
        ).pack(pady=(0, 16))

        num_frame = tk.Frame(popup, bg=BG_CARD, bd=1, relief="solid")
        num_frame.pack(padx=30, fill="x")

        tk.Label(
            num_frame, text=session.safety_number,
            bg=BG_CARD, fg=ACCENT2, font=("Consolas", 18, "bold"),
            pady=12,
        ).pack()

        tk.Label(
            popup, text=f"Peer: {session.peer_address[:24]}...",
            bg=BG_DARK, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(pady=8)

        ttk.Button(
            popup, text="Close", style="Accent.TButton",
            command=popup.destroy,
        ).pack(pady=8)

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to the system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    # ──────────────────────────────────────────
    #  Application Lifecycle
    # ──────────────────────────────────────────

    def run(self) -> None:
        """Enter the Tkinter main event loop."""
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_logout(self) -> None:
        """Flag for logout and close the window."""
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            self.logout_requested = True
            self._on_close()

    def _on_close(self) -> None:
        """Clean up resources and close the application."""
        self._i2p.stop_listener()
        for session in self._conn_mgr.get_all_sessions():
            session.close()
        self.root.destroy()
