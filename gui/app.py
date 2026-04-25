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
#  Color Palette
# ─────────────────────────────────────────────
BG_DARK = "#0d1117"
BG_MID = "#161b22"
BG_CARD = "#21262d"
ACCENT = "#58a6ff"
ACCENT2 = "#3fb950"
WARN = "#d29922"
DANGER = "#f85149"
TEXT_MAIN = "#e6edf3"
TEXT_DIM = "#8b949e"
BORDER = "#30363d"


class I2IApp:
    def __init__(self, username: str, role: str) -> None:
        self.username = username
        self.role = role
        self.logout_requested = False

        # ── Load or generate keys ──────────────────
        self._private_key, self._public_key = load_or_generate_keypair()
        self._our_address = generate_peer_address(self._public_key)
        self._our_pub_hex = public_key_to_hex(self._public_key)

        # ── Active peer sessions ───────────────────
        self._current_peer: Optional[str] = None

        # ── FIXED: Respect Environment Port ────────
        try:
            env_port = int(os.getenv("I2I_LISTEN_PORT", 7777))
        except ValueError:
            env_port = 7777

        self._i2p = I2PManager(self._public_key, port=env_port)
        self._conn_mgr = PeerConnectionManager(
            our_private_key=self._private_key,
            our_public_key=self._public_key,
            on_message_received=self._on_message_received,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
        )

        # ── Buffers ────────────────────────────────
        self._messages: dict[str, list[tuple[str, str, str]]] = {}
        self._file_receivers: dict[str, FileReceiver] = {}
        self._file_senders: dict[str, FileSender] = {}

        # ── Build GUI ──────────────────────────────
        self.root = tk.Tk()
        self.root.title(f"I2I Messenger - {self.username} (Port: {env_port})")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self._setup_styles()
        self._build_layout()
        self._start_listener()

        logger.info("I2IApp started on port %d.", env_port)

    def _setup_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=BG_MID, relief="flat")
        style.configure(
            "TLabel", background=BG_DARK, foreground=TEXT_MAIN, font=("Segoe UI", 10)
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=(12, 6),
        )
        style.configure(
            "Danger.TButton",
            background=DANGER,
            foreground="#ffffff",
            font=("Segoe UI", 9),
        )
        style.configure(
            "Green.TButton",
            background=ACCENT2,
            foreground="#000000",
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "TEntry",
            fieldbackground=BG_CARD,
            foreground=TEXT_MAIN,
            insertcolor=TEXT_MAIN,
        )

    def _build_layout(self) -> None:
        # Top bar
        top_bar = tk.Frame(self.root, bg=BG_MID, height=52)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)

        tk.Label(
            top_bar,
            text="🔒 I2I Secure Messenger",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 14, "bold"),
        ).pack(side="left", padx=16)
        tk.Label(
            top_bar,
            text=f"👤 Logged in as: {self.username} [{self.role}]",
            bg=BG_MID,
            fg=TEXT_MAIN,
        ).pack(side="left", padx=20)

        ttk.Button(
            top_bar, text="🚪 Exit", style="Danger.TButton", command=self._on_close
        ).pack(side="right", padx=16)
        ttk.Button(
            top_bar, text="🔓 Logout", style="Accent.TButton", command=self._on_logout
        ).pack(side="right", padx=4)

        self._status_label = tk.Label(
            top_bar,
            text="● Offline",
            bg=BG_MID,
            fg=DANGER,
            font=("Segoe UI", 9, "bold"),
        )
        self._status_label.pack(side="right", padx=16)

        main = tk.PanedWindow(self.root, orient="horizontal", bg=BG_DARK, sashwidth=4)
        main.pack(fill="both", expand=True)

        # Left Panel
        left = tk.Frame(main, bg=BG_MID, width=320)
        left.pack_propagate(False)
        main.add(left, minsize=260)

        # --- FIXED IDENTITY FRAME ---
        id_frame = tk.LabelFrame(
            left,
            text=" 🪪 Your Identity ",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
            bd=1,
        )
        id_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(
            id_frame,
            text="Address (.b32.i2p):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8)
        addr_txt = tk.Text(
            id_frame, height=3, bg=BG_CARD, fg=ACCENT2, font=("Consolas", 8), bd=0
        )
        addr_txt.pack(fill="x", padx=8, pady=2)
        addr_txt.insert("1.0", self._our_address)
        addr_txt.config(state="disabled")

        tk.Label(
            id_frame,
            text="Public Key (Hex):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8)
        pub_txt = tk.Text(
            id_frame, height=4, bg=BG_CARD, fg=TEXT_MAIN, font=("Consolas", 8), bd=0
        )
        pub_txt.pack(fill="x", padx=8, pady=2)
        pub_txt.insert("1.0", self._our_pub_hex)
        pub_txt.config(state="disabled")

        ttk.Button(
            id_frame,
            text="📋 Copy Key",
            style="Accent.TButton",
            command=lambda: self._copy_to_clipboard(self._our_pub_hex),
        ).pack(padx=8, pady=(5, 8), fill="x")
        # ----------------------------

        conn_frame = tk.LabelFrame(
            left,
            text=" 🔗 Connect to Peer ",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
            bd=1,
        )
        conn_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(
            conn_frame,
            text="Peer Key (hex):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8)
        self._peer_key_entry = tk.Text(
            conn_frame, height=4, bg=BG_CARD, fg=TEXT_MAIN, bd=0
        )
        self._peer_key_entry.pack(fill="x", padx=8, pady=2)

        tk.Label(
            conn_frame, text="Port:", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8)
        self._port_var = tk.StringVar(value="7777")
        ttk.Entry(conn_frame, textvariable=self._port_var).pack(
            anchor="w", padx=8, pady=2
        )

        ttk.Button(
            conn_frame,
            text="⚡ Connect",
            style="Green.TButton",
            command=self._connect_to_peer,
        ).pack(padx=8, pady=8, fill="x")

        self._peers_listbox = tk.Listbox(
            left, bg=BG_CARD, fg=TEXT_MAIN, bd=0, highlightthickness=0
        )
        self._peers_listbox.pack(fill="both", expand=True, padx=10, pady=10)
        self._peers_listbox.bind("<<ListboxSelect>>", self._on_peer_selected)

        # Right Panel
        right = tk.Frame(main, bg=BG_DARK)
        main.add(right, minsize=450)

        header = tk.Frame(right, bg=BG_MID, height=50)
        header.pack(fill="x")
        self._chat_title_label = tk.Label(
            header,
            text="Select a peer to chat",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 11, "bold"),
        )
        self._chat_title_label.pack(side="left", padx=16)

        self._safety_btn = ttk.Button(
            header,
            text="🔐 Safety Number",
            style="Accent.TButton",
            command=self._show_safety_number,
        )
        self._safety_btn.pack(side="right", padx=8, pady=8)

        self._chat_display = scrolledtext.ScrolledText(
            right,
            bg=BG_DARK,
            fg=TEXT_MAIN,
            state="disabled",
            wrap="word",
            font=("Segoe UI", 10),
        )
        self._chat_display.pack(fill="both", expand=True, padx=8, pady=8)

        self._chat_display.tag_config(
            "sent", foreground=ACCENT, font=("Segoe UI", 10, "bold")
        )
        self._chat_display.tag_config(
            "recv", foreground=ACCENT2, font=("Segoe UI", 10, "bold")
        )
        self._chat_display.tag_config(
            "system", foreground=WARN, font=("Segoe UI", 9, "italic")
        )

        input_frame = tk.Frame(right, bg=BG_MID, height=110)
        input_frame.pack(fill="x", padx=8, pady=8)

        self._message_entry = tk.Text(
            input_frame, bg=BG_CARD, fg=TEXT_MAIN, height=3, font=("Segoe UI", 10)
        )
        self._message_entry.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self._message_entry.bind("<Return>", lambda e: self._send_message() or "break")

        btn_f = tk.Frame(input_frame, bg=BG_MID)
        btn_f.pack(side="right", padx=5)
        ttk.Button(
            btn_f, text="📎 File", style="Accent.TButton", command=self._send_file
        ).pack(fill="x", pady=2)
        ttk.Button(
            btn_f, text="➤ Send", style="Green.TButton", command=self._send_message
        ).pack(fill="x", pady=2)

    def _start_listener(self) -> None:
        try:
            self._i2p.start_listener(
                on_new_connection=self._conn_mgr.handle_incoming_connection
            )
            self._status_label.config(text="● Listening", fg=ACCENT2)
        except OSError:
            self._status_label.config(text="● Port in use", fg=WARN)

    def _connect_to_peer(self) -> None:
        key_hex = self._peer_key_entry.get("1.0", "end").strip()
        try:
            key_hex = validate_public_key_hex(key_hex)
            port = int(self._port_var.get())
        except Exception as e:
            messagebox.showerror("Invalid Input", str(e))
            return
        threading.Thread(
            target=self._do_connect, args=(key_hex, port), daemon=True
        ).start()

    def _do_connect(self, key_hex: str, port: int) -> None:
        try:
            sock = self._i2p.connect_to_peer("", port)
            import nacl.public as np

            peer_addr = generate_peer_address(np.PublicKey(bytes.fromhex(key_hex)))
            session = self._conn_mgr.connect_to_peer(sock, peer_addr, key_hex)
            if session:
                self.root.after(
                    0,
                    self._on_peer_connected,
                    session.peer_address,
                    session.safety_number,
                )
        except Exception:
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Connection Failed", "Peer not found or handshake failed."
                ),
            )

    def _on_message_received(self, peer_address: str, raw_bytes: bytes) -> None:
        session = self._conn_mgr.get_session(peer_address)
        if not session:
            return

        result = parse_and_decrypt_envelope(session, raw_bytes)
        if not result:
            return

        msg_type, plaintext = result

        if msg_type == MESSAGE_TYPE_CHAT:
            text = plaintext.decode("utf-8")
            self.root.after(
                0, self._append_message, peer_address, peer_address[:12], text, False
            )

        elif msg_type == MESSAGE_TYPE_FILE_META:
            max_s = MAX_FILE_SIZE_ADMIN if self.role == "ADMIN" else MAX_FILE_SIZE_USER
            rx = FileReceiver(
                session,
                max_file_size=max_s,
                on_progress=lambda r, t: self.root.after(
                    0,
                    self._append_system,
                    f"📥 Receiving: {r}/{t} chunks",
                    peer_address,
                ),
                on_complete=lambda p, s: self.root.after(
                    0,
                    self._append_system,
                    f"✅ Saved: {p}" if s else "❌ Receive Failed",
                    peer_address,
                ),
            )
            self._file_receivers[peer_address] = rx
            rx.handle_meta(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_CHUNK:
            if peer_address in self._file_receivers:
                self._file_receivers[peer_address].handle_chunk(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_ACK:
            if peer_address in self._file_senders:
                try:
                    ack = json.loads(plaintext.decode("utf-8")).get("ack")
                    self._file_senders[peer_address].on_ack_received(ack)
                except:
                    pass

        elif msg_type == MESSAGE_TYPE_CONTROL:
            try:
                cmd = json.loads(plaintext.decode("utf-8")).get("command")
                if cmd == "kick":
                    self.root.after(
                        0,
                        lambda: messagebox.showwarning(
                            "Kicked", "Admin has disconnected you."
                        ),
                    )
                    self.root.after(
                        0, lambda: self._conn_mgr.disconnect_peer(peer_address)
                    )
            except:
                pass

    def _send_message(self) -> None:
        if not self._current_peer:
            return
        text = self._message_entry.get("1.0", "end-1c").strip()
        if not text:
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if session and send_chat_message(session, text):
            self._append_message(self._current_peer, "You", text, True)
            self._message_entry.delete("1.0", "end")

    def _send_file(self) -> None:
        if not self._current_peer:
            return
        f_path = filedialog.askopenfilename()
        if not f_path:
            return

        try:
            Validators.validate_file_size(Path(f_path), self.role)
        except Exception as e:
            messagebox.showerror("RBAC Limit", str(e))
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if session:
            tx = FileSender(
                session,
                on_progress=lambda s, t: self.root.after(
                    0,
                    self._append_system,
                    f"📤 Sent {s}/{t} chunks",
                    self._current_peer,
                ),
            )
            self._file_senders[self._current_peer] = tx
            threading.Thread(target=lambda: tx.send_file(f_path), daemon=True).start()

    def _on_peer_connected(self, addr: str, sn: str) -> None:
        if addr not in self._messages:
            self._messages[addr] = []
        self._peers_listbox.insert("end", addr[:20] + "...")
        self._append_system(f"🔗 Connected. Safety Number: {sn}", addr)

        if not self._current_peer:
            self._peers_listbox.selection_set(0)
            self._on_peer_selected(None)

    def _on_peer_disconnected(self, addr: str) -> None:
        self._append_system("⚠️ Peer disconnected.", addr)
        display = addr[:20] + "..."
        for i in range(self._peers_listbox.size()):
            if self._peers_listbox.get(i) == display:
                self._peers_listbox.delete(i)
                break

    def _on_peer_selected(self, event) -> None:
        sel = self._peers_listbox.curselection()
        if not sel:
            return
        sessions = self._conn_mgr.get_all_sessions()
        if sel[0] < len(sessions):
            self._current_peer = sessions[sel[0]].peer_address
            self._chat_title_label.config(
                text=f"Chatting with: {self._current_peer[:15]}...", fg=ACCENT
            )
            self._refresh_chat()

    def _refresh_chat(self) -> None:
        self._chat_display.config(state="normal")
        self._chat_display.delete("1.0", "end")
        if self._current_peer in self._messages:
            for s, t, _ in self._messages[self._current_peer]:
                tag = "sent" if s == "You" else ("recv" if s != "SYSTEM" else "system")
                self._chat_display.insert("end", f"{s}: ", tag)
                self._chat_display.insert("end", f"{t}\n\n")
        self._chat_display.config(state="disabled")
        self._chat_display.see("end")

    def _append_message(self, addr, sender, text, sent) -> None:
        if addr not in self._messages:
            self._messages[addr] = []
        self._messages[addr].append((sender, text, ""))
        if addr == self._current_peer:
            self._refresh_chat()

    def _append_system(self, text, addr=None) -> None:
        target = addr or self._current_peer
        if target:
            if target not in self._messages:
                self._messages[target] = []
            self._messages[target].append(("SYSTEM", text, ""))
            if target == self._current_peer:
                self._refresh_chat()

    def _show_safety_number(self) -> None:
        if self._current_peer:
            session = self._conn_mgr.get_session(self._current_peer)
            if session:
                messagebox.showinfo(
                    "Safety Number",
                    f"Verify this with peer:\n\n{session.safety_number}",
                )

    def _copy_to_clipboard(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_logout(self) -> None:
        if messagebox.askyesno("Logout", "Confirm logout?"):
            self.logout_requested = True
            self._on_close()

    def _on_close(self) -> None:
        self._i2p.stop_listener()
        for s in self._conn_mgr.get_all_sessions():
            s.close()
        self.root.destroy()
