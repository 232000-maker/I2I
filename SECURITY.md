# Security Architecture & Mechanisms

This document outlines the formalized security structures and policies governing the I2I Secure P2P Messenger.

## 1. Authentication System
- **Identity & Registration:** Users register locally. Cryptographic identities (X25519) are generated only after successful local authentication.
- **Hashing:** Passwords are never stored in plaintext. They are salted and hashed using `bcrypt` (adaptive hashing) and stored in a local JSON structure locked with `0o600` permissions.
- **Account Lockout:** Active memory-based brute-force prevention. 3 failed login attempts result in a 5-minute lockout to mitigate credential stuffing.

## 2. Authorization Model (RBAC)
- **Roles:** The application implements Role-Based Access Control (RBAC):
    - `USER`: Standard role; file transfers capped at 10 MB.
    - `ADMIN`: Privileged role; file transfers up to 50 MB, Network Broadcasts, and Force Kick capabilities.
- **Privilege Escalation Protection:** The `ADMIN` role requires a Secret Passcode provided via a secure `.env` file. The application enforces "Fail-Safe Defaults"—if the secret is not configured in the environment, Admin registration is disabled.
- **Enforcement:** Role checks are performed at both the UI boundary and the logic layer (e.g., in `Validators.validate_file_size`).

## 3. Input Validation Layer
- **Centralized Validators:** All external data passes through `src/validators.py` and `src/security_utils.py`.
- **Message Validation:** Chat messages are limited to 4 KB to prevent buffer exhaustion.
- **Filename Sanitization:** To prevent Path Traversal, filenames are stripped of directory components, null bytes, and relative sequences (`../`). OS-reserved names (e.g., `CON`, `NUL`) are rejected.
- **Collision Prevention:** Received files are stored with unique timestamps to prevent Insecure Direct Object Reference (IDOR) overwrite attacks.

## 4. Encryption & Integrity
- **Algorithm:** End-to-End Encryption (E2EE) is implemented via `PyNaCl` (libsodium).
- **Key Exchange:** A two-phase handshake uses X25519 Identity keys to authenticate an Ephemeral X25519 exchange, ensuring **Perfect Forward Secrecy (PFS)**.
- **Symmetric Encryption:** Authenticated encryption (AEAD) is performed using XSalsa20-Poly1305.
- **"Verify-then-Parse" Protocol:** To prevent Cryptographic DoS, the system verifies the Poly1305 MAC *before* attempting to parse JSON metadata.
- **Integrity Check:** Files use SHA-256 hash verification post-reassembly.

## 5. Security Logging & Session Management
- **Safe Logging:** Logs are directed to rotating files in `logs/i2i.log`. Sensitive data (plaintext, keys, passwords) is never logged. Peer IDs are anonymized.
- **Resource Management:** A **Stream-to-Disk** mechanism writes file chunks directly to `.part` files on disk, ensuring constant memory usage and preventing RAM exhaustion DoS.
- **Race Condition Protection:** All User Database I/O is protected by a `threading.Lock` to prevent data corruption.
- **Rate Limiting:** A Token Bucket algorithm (20 burst, 5/sec) prevents per-peer flooding.
