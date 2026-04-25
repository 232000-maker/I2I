# I2I — Secure Peer-to-Peer Messenger
### Security Features Documentation

**Group:** Syed Mueez (23I-2000) · Huzaifa Khan (23I-6123) · Muhammad Abdullah (23I-2064)  
**Assignment:** SSD Assignment 3 — Secure Implementation  

---

## 1. Authentication Method

I2I implements a dual-layer authentication model: **Local Credential Authentication** and **Cryptographic P2P Identity**.

### Local Access (Authentication)
- **Hashing:** Passwords are mathematically salted and hashed using `bcrypt`.
- **Brute Force Protection:** Active memory-based Account Lockout policy triggers after 3 failed login attempts, locking the account for 5 minutes (`PermissionError`).
- **Storage:** Stored locally in `keys/users.json` locked with `0o600` permissions.

### P2P Network Identity
| Aspect | Implementation |
|---|---|
| **Identity** | X25519 Public Key (32 bytes) |
| **Proof of identity** | Ability to perform ECDH with the matching private key |
| **Key persistence** | Private key stored on disk (`keys/private.key`) |
| **Key format** | Hex-encoded raw bytes |
| **Key permissions** | `chmod 600` on POSIX (owner read-only) |

### How It Works
1. On first launch, an X25519 key pair is generated using PyNaCl's secure RNG (backed by `libsodium`).
2. The public key is derived deterministically from the private key.
3. Each peer's `.b32.i2p` address is the Base32-encoded SHA-256 hash of their public key — this makes the address a verifiable fingerprint of their identity.
4. During handshake, both peers exchange public keys over the socket and perform ECDH to derive a shared secret. The party who can compute the correct shared secret proves they hold the private key.

---

## 2. Authorization Model & RBAC

I2I implements strict Role-Based Access Control (RBAC) enforced at both the GUI and backend network layers.

| Role | Privileges |
|---|---|
| **USER** | Standard chat; max file transfer limit of 10 MB. |
| **ADMIN** | Max file transfer limit of 50 MB; Network Broadcasts; Force Kick commands. |

### Privilege Escalation Protection
The `ADMIN` role cannot be assigned freely. The registration flow intercepts `admin` usernames and requires a Secret Passcode (configured securely via the `.env` file environment variables). If an attacker guesses incorrectly, the registration is aggressively blocked to prevent unauthorized privilege escalation.

### P2P Session Verification
Since I2I is a direct P2P system (no central server), peer authorization is **session-based**:

| Control | Implementation |
|---|---|
| **Authorization scope** | Per-session, per-peer |
| **Trust model** | Explicit: user manually initiates connections |
| **Out-of-band verification** | Safety Numbers (SHA-256 fingerprint of both public keys) |
| **MITM prevention** | Safety numbers must be verified verbally by both parties |

**Safety Numbers** are computed as:
```
sorted_keys = sorted([pub_key_a, pub_key_b])
safety_number = SHA256(sorted_keys[0] || sorted_keys[1])
```

The result is formatted as a 30-digit number (6 groups of 5) that users compare out-of-band. If numbers match, no MITM has interceded. This is the same design used by Signal messenger.

**Rate Limiting:** Each peer has an independent token bucket (capacity: 20 tokens, refill: 5/second). This prevents any single peer from flooding the application.

---

## 3. Encryption Used

### Algorithm: XSalsa20-Poly1305 (via PyNaCl / libsodium)

| Property | Value |
|---|---|
| **Key exchange** | X25519 ECDH (Diffie-Hellman on Curve25519) |
| **Symmetric cipher** | XSalsa20 stream cipher |
| **Message authentication** | Poly1305 MAC (AEAD) |
| **Nonce size** | 24 bytes (randomly generated per message) |
| **Key size** | 32 bytes (X25519 output) |
| **Library** | PyNaCl 1.5+ (Python bindings for libsodium) |

### End-to-End Encryption Flow:
1. Alice and Bob each have an X25519 key pair.
2. On connection, they exchange public keys over the socket (in the clear — this is intentional in DH).
3. Each side computes `shared_secret = ECDH(own_private, peer_public)`.
4. A `nacl.public.Box` is created from the shared secret — this provides XSalsa20-Poly1305 AEAD encryption.
5. Every message and file chunk is encrypted using this Box with a **unique random 24-byte nonce**.
6. The nonce is included with the ciphertext so the recipient can decrypt.

### Why XSalsa20-Poly1305?
- **Authentication + Encryption together** (AEAD): Tampering with ciphertext causes decryption failure.
- **Fast and secure**: Used in Signal Protocol, WireGuard, and NaCl library.
- **No padding oracle** attacks (stream cipher, not block cipher).

---

## 4. API Security Controls

I2I does not expose an HTTP API — it uses a custom **binary framing protocol over TCP**. The relevant security controls are:

| Control | Implementation |
|---|---|
| **Message framing** | 4-byte big-endian length prefix prevents boundary injection |
| **Input validation** | All received envelopes validated before processing |
| **Max message size** | 4 KB for chat messages; 50 MB for files |
| **Max frame size** | 10 MB absolute cap on any single recv (prevents memory DoS) |
| **Replay attack prevention** | Per-session nonce tracking set (up to 10,000 nonces) |
| **Timestamp validation** | Messages older than 5 minutes or >1 minute in the future are rejected |
| **Rate limiting** | Token bucket: 20 msg burst, 5 msg/second sustained per peer |
| **Connection timeout** | 10 seconds for handshake and connection establishment |

### Message Envelope Format:
```json
{
  "type": "message",
  "sender": "<peer_b32_address>",
  "data": "<hex-encoded XSalsa20-Poly1305 ciphertext>",
  "nonce": "<hex-encoded 24-byte random nonce>",
  "timestamp": 1713600023.45
}
```

---

## 5. Cloud Security Measures

**This project does not use cloud infrastructure** — it is a fully decentralized P2P application by design. There is no central server, no database, and no cloud storage.

The I2P network itself provides the anonymity layer — all traffic is routed through I2P's garlic routing tunnels, hiding IP addresses. In this implementation, I2P is simulated via localhost TCP to allow standalone demonstration.

---

## 6. Input Validation Strategy

**All external inputs are validated at the earliest entry point** (UI layer and protocol parsing). The strategy is:

### Validation Categories:

| Input Type | Validation |
|---|---|
| **Chat messages** | Type check (str), strip whitespace, max 4KB UTF-8 encoded |
| **Peer addresses** | Regex: `^[a-z2-7]{52}\.b32\.i2p$` |
| **Public keys** | Regex: `^[0-9a-fA-F]{64}$` (64 hex chars = 32 bytes) |
| **File paths** | Must exist, must be a regular file, max 50MB |
| **Received filenames** | `os.path.basename()`, null byte removal, safe-char regex, reserved name rejection |
| **JSON envelopes** | Required field presence check, type checking, hex decoding validation |
| **Chunk indices** | Must match expected sequential index |

### Path Traversal Prevention:
```python
filename = os.path.basename(filename)           # Strip directory components
filename = re.sub(r"[^\w.\-]", "_", filename)   # Allow only safe characters
filename = re.sub(r"\.{2,}", ".", filename)      # Collapse double dots
# Reject reserved Windows names (CON, PRN, NUL, etc.)
```

### Injection Prevention:
- **SQL Injection**: N/A (no SQL database used).
- **Command Injection**: No shell calls made. All file operations use `pathlib.Path` APIs.
- **XSS**: N/A (desktop Tkinter GUI, not web).
- **CSRF**: N/A (no web interface).
- **Binary injection**: Length-prefixed framing prevents any boundary manipulation.

---

## 7. Session Management

| Aspect | Implementation |
|---|---|
| **Session creation** | After successful X25519 handshake using **Ephemeral Keys** (Perfect Forward Secrecy) |
| **Session identifier** | Peer's `.b32.i2p` address (derived from their public key) |
| **Session isolation** | Each peer has a completely independent `PeerSession` object |
| **Session state** | Held in `PeerConnectionManager._sessions` dict (thread-safe with lock) |
| **Nonce tracking** | Per-session `_used_nonces` set, protects against replay attacks |
| **Session termination** | Explicit disconnect or socket closure |
| **Cleanup on disconnect** | Session object removed; rate limiter bucket reset |
| **Reconnection** | Requires new handshake (new session, new ECDH exchange) |

---

## 8. Error Handling Strategy

| Principle | Implementation |
|---|---|
| **Generic user-facing errors** | UI shows only "Connection failed" / "Message failed" (no internal detail) |
| **Detailed internal logging** | Full errors logged to `logs/i2i.log` via `logging` module |
| **No sensitive data in logs** | Private keys, plaintext messages, and peer IPs are never logged |
| **Anonymized peer IDs** | Only first 8 chars of peer address logged (e.g., `abc12345...`) |
| **Crypto errors** | `nacl.exceptions.CryptoError` caught; only "MAC failure" logged, nothing more |
| **Rotating log files** | Max 5 MB per file, 3 backups kept |

---

## 9. STRIDE Threat Model — Mitigations

| STRIDE Threat | Example Attack | Mitigation Implemented |
|---|---|---|
| **Spoofing** | Fake peer identity | Safety numbers; ECDH-based identity |
| **Tampering** | Modified ciphertext | Poly1305 MAC (AEAD) — decryption fails |
| **Repudiation** | Denying sent messages | Signed with shared secret implicitly |
| **Info Disclosure** | Intercepting traffic | E2EE; I2P hides IP metadata |
| **Denial of Service** | Message flooding | Rate limiting (token bucket) |
| **Elevation of Privilege** | Path traversal to overwrite system files | Filename sanitization; writes only to `received_files/` |
