# How to Run — I2I Secure P2P Messenger

**Group:** Syed Mueez (23I-2000) · Huzaifa Khan (23I-6123) · Muhammad Abdullah (23I-2064)

---

## ✅ Prerequisites

Before running, make sure you have the following installed:

| Requirement | Version        | How to Check       |
| ----------- | -------------- | ------------------ |
| Python      | 3.11 or higher | `python --version` |
| pip         | Latest         | `pip --version`    |

> **Windows Users:** Make sure Python is added to your system PATH during installation.

---

## 📦 Step 1 — Install Dependencies

Open a terminal (Command Prompt or PowerShell) inside the `i2i/` folder and run:

```bash
pip install -r requirements.txt
```

This will install:

- `PyNaCl` — Cryptographic library (X25519 + XSalsa20-Poly1305)
- `bcrypt` — Secure password hashing
- `pytest` — Unit testing framework
- `pytest-cov` — Test coverage
- `python-dotenv` — Environment variable loader

---

## ⚙️ Step 2 — Configure Environment (Optional)

Copy the example environment file:

```bash
# Windows (Command Prompt)
copy .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

The default settings work out of the box. Edit `.env` only if you need to change the port:

```
I2I_LISTEN_PORT=7777    # Port this instance listens on
I2I_LOG_LEVEL=INFO      # Log verbosity
I2I_MAX_FILE_MB=50      # Maximum file size in MB
I2I_MAX_MSG_KB=4        # Maximum message size in KB
I2I_ADMIN_SECRET=YOUR_SECRET_CODE_HERE  # Code required to register as ADMIN
```

---

## ▶️ Step 3 — Run the Application

```bash
python main.py
```

**What happens on first launch:**

1. A **Secure Login** screen will appear.
2. If this is your first time, type a username and password and click **Register**. Passwords are automatically salted and hashed using `bcrypt`.
   - _To register as an ADMIN, use the username `admin`. When prompted for the Admin Secret Code, enter the value you set for `I2I_ADMIN_SECRET` in your `.env` file._
3. Once registered, click **Login**.
4. A new X25519 key pair is automatically generated for your identity.
5. The application starts listening for incoming connections on port `7777`.
6. The GUI opens — your `.b32.i2p` address, public key, and assigned **Role** (USER or ADMIN) are shown at the top.

---

## 💬 Step 4 — Connect Two Peers (Local Testing)

To test messaging between two instances on the **same machine**, open **two separate terminals**.

### Terminal 1 — Peer A (listens on port 7777)

```bash
cd "c:\Users\ma420\OneDrive\Desktop\SSD Project\i2i"
python main.py
```

### Terminal 2 — Peer B (listens on port 7778)

Since both instances need different ports, edit the port in `.env` **for the second instance** temporarily, or run it like this:

**Option A — Edit a second copy of .env:**

1. Create a folder called `i2i_peerB/` and copy the entire `i2i/` project into it.
2. In `i2i_peerB/.env`, set `I2I_LISTEN_PORT=7778`
3. Run: `python main.py` from inside `i2i_peerB/`

**Option B — Quick inline override (PowerShell):**

```powershell
$env:I2I_LISTEN_PORT = "7778"; python main.py
```

**Option B — Quick inline override (Command Prompt):**

```cmd
set I2I_LISTEN_PORT=7778 && python main.py
```

---

## 🔗 Step 5 — Establish a Connection

Once both instances are running:

### In Peer B's GUI:

1. Copy **Peer A's Public Key** (shown in Peer A's GUI under "Your Identity")
2. Paste it into the **"Peer Public Key (hex)"** text box in Peer B's GUI
3. Set the **Port** to `7777` (Peer A's listening port)
4. Click ⚡ **Connect**

### Verify the Safety Number:

- Both GUIs will show a **Safety Number** (e.g., `12345 67890 11111 22222 33333 44444`)
- Read it out loud or compare it via chat/phone
- If they match → connection is **secure, no MITM**

---

## 📤 Step 6 — Send a Message

1. Select the connected peer from the **Connected Peers** list on the left
2. Type your message in the input box at the bottom
3. Press **Enter** or click ➤ **Send**
4. The message appears in the chat window — fully **end-to-end encrypted**

---

## 📁 Step 7 — Send a File

1. Select the connected peer
2. Click **📎 File**
3. Choose any file from your computer. Note the **Role-Based Access Control (RBAC)** limits:
   - **USER Role:** Maximum 10 MB.
   - **ADMIN Role:** Maximum 50 MB.
4. The file is split into 4 KB encrypted chunks and sent securely.
5. The recipient's backend will strictly enforce file limits and sanitize the filename.
6. The received file is saved safely to: `received_files/`
7. SHA-256 integrity is verified automatically after transfer.

---

## 🔐 Step 8 — Verify Safety Number Manually

At any time:

1. Select a peer from the list
2. Click **🔐 Safety Number** in the top-right of the chat panel
3. A popup shows the full 30-digit safety number
4. Compare this with your peer — if it matches, you are safe from MITM attacks

---

## 👑 Step 9 — Admin Exclusive Features

If you are logged in as an `ADMIN` (registered using your configured `.env` secret code), you get exclusive access to:

1. 📢 **Network Broadcasts:** Type a message and click the **Broadcast** button. It will prepend `🚨 [ADMIN ANNOUNCEMENT]` and send it simultaneously to **all** currently connected peers.
2. 👢 **Force Kick:** In the Connected Peers list, select a peer and click **Force Kick (Admin)**. This sends a cryptographic control message commanding the peer's client to instantly sever the connection.

---

## 🧪 Running Security Checks & Tests

### Automated Security Audit Script

To quickly prove the security of the application (Authentication, Path Traversal, Overflow, RBAC, Logging), run:

```bash
python security_test.py
```

### Running Unit Tests

To run the full test suite:

```bash
python -m pytest tests/ -v
```

To run with coverage report:

```bash
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

To run a specific test file:

```bash
python -m pytest tests/test_crypto.py -v
python -m pytest tests/test_security.py -v
python -m pytest tests/test_file_transfer.py -v
```

Expected result: **87 tests passed** ✅

---

## 📂 Where Are My Files?

| Location           | Contents                                               |
| ------------------ | ------------------------------------------------------ |
| `keys/private.key` | Your private key (never share this)                    |
| `keys/public.key`  | Your public key (safe to share)                        |
| `keys/users.json`  | Local user database (bcrypt hashed, locked to `0o600`) |
| `received_files/`  | Files received from peers                              |
| `logs/i2i.log`     | Application logs (internal errors only)                |

---

## ❗ Troubleshooting

### "Port already in use" error

Another instance is already listening on port `7777`. Change the port:

```bash
set I2I_LISTEN_PORT=7778 && python main.py   # Windows CMD
```

### "ModuleNotFoundError: No module named 'nacl'"

Dependencies not installed. Run:

```bash
pip install -r requirements.txt
```

### "Connection refused" when connecting to peer

- Make sure Peer A is running and listening (check status label shows "● Listening")
- Make sure you entered the correct port number (e.g., `7777`)
- On Windows: allow Python through Windows Firewall if prompted

### GUI does not open / tkinter error

Tkinter is included with standard Python on Windows. If missing:

```bash
# Linux only
sudo apt-get install python3-tk
```

### Keys got corrupted / want to reset identity

Delete the keys folder — new keys will be generated on next launch:

```bash
# Windows
rmdir /s /q keys

# Linux / macOS
rm -rf keys/
```

---

## 📋 Quick Reference

```
python main.py                          # Launch the application
python -m pytest tests/ -v             # Run all tests
python -m pytest tests/ --cov=src      # Tests with coverage
```

---

## 📝 Notes for Grader

- No real I2P router is required — the I2P layer is simulated using local TCP.
- All cryptographic operations use **PyNaCl (libsodium)** — a battle-tested library.
- The application generates keys automatically on first run.
- All security controls (encryption, rate limiting, validation, logging) are active by default.
- Source code is fully commented with file-level and function-level docstrings.
