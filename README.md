# I2I — Secure Peer-to-Peer Messenger

> **Decentralized, end-to-end encrypted messaging and file sharing over I2P**  
> Built with Python · PyNaCl · X25519 · XSalsa20-Poly1305

**Group:** Syed Mueez (23I-2000) · Huzaifa Khan (23I-6123) · Muhammad Abdullah (23I-2064)  
**Course:** Secure Software Development (SSD) — Assignment 3

---

## Table of Contents
1. [Project Description](#project-description)
2. [Security Features](#security-features-implemented)
3. [Folder Structure](#folder-structure)
4. [Dependencies](#dependencies)
5. [Environment Variables](#environment-variables)
6. [Setup Instructions](#setup-instructions)
7. [How to Run](#how-to-run)
8. [How to Run Tests](#how-to-run-tests)
9. [Protocol Overview](#protocol-overview)

---

## Project Description

**I2I** (Identity-to-Identity) is a decentralized peer-to-peer messaging and file-sharing application. It operates over the I2P (Invisible Internet Project) anonymity network, routing all communications through layered tunnels to hide IP addresses and metadata.

The application eliminates reliance on central servers — peers communicate directly using cryptographic identities (X25519 public keys). This implementation includes a simulated I2P SAM layer using TCP on localhost, allowing standalone demonstration without requiring a real I2P router daemon.

### Core Features:
- **Real-time encrypted messaging** between peers
- **Secure file transfer** with chunking (4 KB) and SHA-256 integrity verification
- **Identity verification** via Safety Numbers (MITM prevention)
- **Dark-themed Tkinter GUI** with peer management
- **Fully decentralized** — no server required

---

## Security Features Implemented

| Feature | Implementation |
|---|---|
| **End-to-End Encryption** | XSalsa20-Poly1305 (PyNaCl) with X25519 ECDH key exchange |
| **Authentication & RBAC** | Local login with `bcrypt` password hashing and Role-Based Access Control |
| **Brute Force Protection** | Account Lockout policy triggers after 3 failed login attempts (5 min) |
| **Privilege Escalation Protection** | Admin role assignment requires a Secret Passcode (configured via `.env`) |
| **Forward Secrecy** | Each session uses a fresh ECDH-derived shared secret |
| **Replay Attack Prevention** | Per-session nonce set tracks all received nonces |
| **MITM Prevention** | Safety Numbers (SHA-256 fingerprint of both public keys) |
| **Rate Limiting** | Token bucket (20 burst, 5/sec) per peer — DoS protection |
| **Input Validation Layer** | Centralized formal validation in `src/validators.py` |
| **Filename Sanitization** | `os.path.basename()` + regex + reserved name rejection |
| **File Integrity Verification** | SHA-256 hash verified after full reassembly |
| **Secure Logging** | Internal logs only (never to stdout); no sensitive data logged |
| **Key Security** | Private key stored with `chmod 600` on POSIX; never transmitted |
| **Timestamp Validation** | Rejects messages older than 5 min or >1 min in future |
| **Message Size Limits** | 4 KB chat, 50 MB files |
| **Path Traversal Prevention** | Received filenames written only to `received_files/` |
| **No Hardcoded Secrets** | All configuration via environment variables / `.env` |
| **Generic Error Responses** | Users see generic errors; details only in secure log file |

---

## Folder Structure

```
i2i/
├── src/                          # Core application modules
│   ├── __init__.py
│   ├── crypto_utils.py           # X25519, XSalsa20-Poly1305, safety numbers
│   ├── i2p_manager.py            # I2P SAM API simulation (TCP listener/connector)
│   ├── peer_connection.py        # P2P session lifecycle & handshake
│   ├── message_handler.py        # Encrypted message send/receive
│   ├── file_transfer.py          # Chunked secure file transfer
│   └── security_utils.py        # Input validation, rate limiting, sanitization
├── gui/
│   ├── __init__.py
│   └── app.py                   # Tkinter dark-theme GUI
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py            # Crypto unit tests
│   ├── test_security.py          # Security/validation unit tests
│   └── test_file_transfer.py    # File transfer unit tests
├── docs/
│   └── security_documentation.md # Detailed security features document
├── keys/                         # Auto-created: key storage (gitignored)
├── logs/                         # Auto-created: rotating log files (gitignored)
├── received_files/               # Auto-created: received file destination (gitignored)
├── .env.example                  # Environment variable template
├── .gitignore
├── requirements.txt
├── main.py                       # Application entry point
└── README.md
```

---

## Dependencies

All dependencies are specified in `requirements.txt`:

```
PyNaCl>=1.5.0          # Cryptographic operations (X25519 + XSalsa20-Poly1305)
bcrypt>=4.0.1          # Secure password hashing for authentication
pytest>=7.4.0          # Unit testing framework
pytest-cov>=4.1.0      # Test coverage reporting
python-dotenv>=1.0.0   # Environment variable loading
```

> **Python version:** 3.11 or higher required (uses `match`, walrus operator, `Path.unlink(missing_ok)`)

---

## Environment Variables

Copy `.env.example` to `.env` and adjust if needed:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `I2I_LISTEN_PORT` | `7777` | Local port to listen for incoming connections |
| `I2I_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `I2I_MAX_FILE_MB` | `50` | Maximum file size in MB |
| `I2I_MAX_MSG_KB` | `4` | Maximum message size in KB |
| `I2I_ADMIN_SECRET` | `SSD-ADMIN-CODE` | Passcode required to register as ADMIN |

> **Security note:** Never commit your `.env` file. The `.gitignore` excludes it automatically.

---

## Setup Instructions

### 1. Prerequisites
- Python 3.11+ installed
- pip package manager

### 2. Clone / Extract Project
```bash
cd i2i/
```

### 3. Create Virtual Environment (Recommended)
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure Environment
```bash
copy .env.example .env   # Windows
# Or: cp .env.example .env  (Linux/macOS)
```

---

## How to Run

### Running a Single Instance
```bash
python main.py
```

On first launch:
- The **Login/Registration Screen** will appear.
- You can register a new username and password (passwords are `bcrypt` hashed).
- A new X25519 key pair is generated and saved to `keys/`.
- The GUI displays your `.b32.i2p` address and public key.

### Connecting Two Peers (Local Testing)
Open **two terminals**:

**Terminal 1 (Peer A — listens on port 7777):**
```bash
python main.py
```

**Terminal 2 (Peer B — listens on port 7778):**
```bash
# Edit .env to set I2I_LISTEN_PORT=7778 or set directly:
python -c "
import os; os.environ['I2I_LISTEN_PORT'] = '7778'
from gui.app import I2IApp
I2IApp().run()
"
```

Or run a second instance by temporarily changing the port in `main.py` / i2p_manager:

**Simplified two-instance test:**
1. In Peer B's GUI: paste Peer A's **public key hex** (shown in the GUI)
2. Set port to `7777`
3. Click **Connect**
4. Verify the **Safety Number** matches on both sides
5. Start chatting!

---

## How to Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_crypto.py -v
pytest tests/test_security.py -v
pytest tests/test_file_transfer.py -v
```

Expected output: All tests pass. The test suite covers:
- 30+ crypto unit tests (key gen, ECDH, encrypt/decrypt, safety numbers)
- 25+ security tests (validation, sanitization, rate limiting)
- 15+ file transfer tests (chunking, integrity, size limits)

---

## Protocol Overview

```
HANDSHAKE:
  Alice ──[pub_key_A]──► Bob
  Alice ◄──[pub_key_B]── Bob
  Both compute: shared_secret = ECDH(own_priv, peer_pub)
  Both display: safety_number = SHA256(sort(pub_A, pub_B))

MESSAGE SEND:
  nonce = random_bytes(24)
  ciphertext = XSalsa20Poly1305(shared_secret, nonce, plaintext)
  envelope = JSON({type, sender, data: hex(ciphertext), nonce: hex(nonce), timestamp})
  frame = [4-byte-length][envelope_bytes]
  sock.sendall(frame)

FILE TRANSFER:
  1. Sender → FILE_META: {filename, total_chunks, sha256_hash, size}
  2. Receiver → ACK "ready"
  3. For each chunk:
     Sender → FILE_CHUNK: {chunk_index, total_chunks, data: hex(chunk)}
     Receiver → ACK "chunk_N"
  4. Receiver verifies SHA-256 of reassembled file
```
