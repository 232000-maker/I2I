# I2I — Secure Peer-to-Peer Messenger

### Detailed Security Features Documentation (Assignment 3)

**Group:** Syed Mueez (23I-2000) · Huzaifa Khan (23I-6123) · Muhammad Abdullah (23I-2064)
**Assignment:** SSD Assignment 3 — Secure Implementation

---

## 1. Authentication Method

I2I implements a dual-layer authentication model:

### Local Access Control

- **Mechanism:** User credentials (username/password) are required to unlock the application.
- **Hashing:** Passwords use `bcrypt` with unique salts.
- **Storage:** Stored in `keys/users.json` with `0o600` (Owner-Read/Write) permissions.
- **Brute Force Defense:** A memory-resident lockout policy triggers after 3 failed attempts (5-minute cooldown).

### P2P Cryptographic Identity

- **Identity Key:** 32-byte X25519 Public Key.
- **Proof of Identity:** Derived from the holder’s ability to perform an ECDH handshake with a matching private key stored in `keys/private.key`.

---

## 2. Authorization Model & RBAC

Strict Role-Based Access Control (RBAC) is enforced:

| Role      | Privileges                             | Limit            |
| --------- | -------------------------------------- | ---------------- |
| **USER**  | Standard Messaging & File Sharing      | 10 MB File Limit |
| **ADMIN** | Broadcasts, Force Kick, Extended Files | 50 MB File Limit |

- **Privilege Escalation Prevention:** Registration as `ADMIN` is only permitted if the user provides a secret code matching the `I2I_ADMIN_SECRET` environment variable.
- **Safety Numbers:** To prevent MITM attacks, a 30-digit Safety Number is generated: `SHA256(Sorted(PubKeyA, PubKeyB))`. Users verify this out-of-band to authorize the session.

---

## 3. Encryption Used

I2I utilizes the **PyNaCl (libsodium)** library for all cryptographic primitives:

- **Key Exchange:** X25519 Elliptic-Curve Diffie-Hellman (ECDH).
- **Session Security:** Fresh Ephemeral keys are generated per connection to provide **Perfect Forward Secrecy (PFS)**.
- **Cipher:** XSalsa20 stream cipher.
- **Message Authentication:** Poly1305 MAC (AEAD).
- **Nonce Management:** Unique, random 24-byte nonces are generated per frame and tracked in a per-session set to prevent **Replay Attacks**.

---

## 4. API & Network Security Controls

I2I uses a custom binary framing protocol over TCP (no HTTP/REST APIs used):

- **Framing:** 4-byte big-endian length prefix prevents boundary injection and "Slowloris" style frame attacks.
- **Verify-then-Parse:** The protocol mandates MAC verification _before_ JSON parsing. This mitigates Cryptographic DoS attacks where an attacker sends massive malformed JSON to exhaust CPU/RAM.
- **Rate Limiting:** Token Bucket algorithm (Capacity: 20, Refill: 5/sec) prevents message flooding.
- **Connection Limits:** `I2PManager` caps simultaneous incoming connections to 10 to prevent resource exhaustion.

---

## 5. Input Validation Strategy

All external inputs are validated at the earliest entry point (Fail-Fast):

- **Chat messages:** Type-checked, whitespace-stripped, and capped at 4 KB UTF-8.
- **Public keys:** Validated against a 64-character hex regex.
- **Path Traversal Prevention:**
  - `os.path.basename()` used to strip directory components.
  - Regex replacement of non-alphanumeric characters.
  - Rejection of Windows reserved device names (`CON`, `PRN`, etc.).
  - **Collision Resistance:** Appends Unix timestamps to received files to prevent IDOR-style overwrites.

---

## 6. Session Management

- **Isolation:** Each peer connection is encapsulated in a `PeerSession` object with an independent encryption context.
- **Handshake Timeout:** 10-second enforced timeout for key exchange to prevent "hanging" resource leaks.
- **Cleanup:** Upon socket closure, the session object, ephemeral keys, and the rate-limiting bucket are purged from memory.

---

## 7. Resource & Error Management

- **Memory Protection (Stream-to-Disk):** Unlike traditional implementations that buffer files in RAM, I2I’s `FileReceiver` pre-allocates file size on disk and writes chunks directly to specific offsets. This ensures the app can handle 50MB files on low-RAM systems without crashing.
- **Database Hardening:** `AuthManager` utilizes a `threading.Lock` to ensure atomic Read-Modify-Write operations on the user database, preventing race conditions during simultaneous registrations.
- **Generic Errors:** Error responses to peers are intentionally generic (e.g., "Handshake failed") to prevent information leakage (Oracle attacks).
