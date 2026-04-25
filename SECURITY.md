# Security Architecture & Mechanisms

This document outlines the formalized security structures and policies governing the I2I Secure P2P Messenger.

## 1. Authentication System
- **Identity & Registration:** Users register locally on their machine before launching the P2P application. 
- **Hashing:** Passwords are never stored in plaintext. They are salted and hashed using `bcrypt` (with a per-user salt) and stored securely in a local JSON structure.
- **Login Flow:** The application enforces a mandatory login screen on launch to verify credentials before any cryptographic keys are generated or loaded.
- **Account Lockout:** Active memory-based brute-force prevention. 3 failed login attempts result in a 5-minute `PermissionError` lockout.

## 2. Authorization Model (RBAC)
- **Roles:** The application implements Role-Based Access Control (RBAC). 
    - `USER`: The standard role allowing basic chat capabilities and file transfers up to 10 MB.
    - `ADMIN`: A privileged role allowing larger file transfers up to 50 MB, Network Broadcasts, and Force Kick commands.
- **Privilege Escalation Protection:** The `ADMIN` role cannot be assigned freely. The registration flow intercepts `admin` usernames and requires a hardcoded Secret Passcode to prevent unauthorized privilege escalation.
- **Enforcement:** Roles are enforced at the GUI boundary before passing requests to the application logic layer, ensuring actions outside the user's role are rejected.

## 3. Input Validation Layer
- **Centralized Validators:** All input validations have been formalized into `src/validators.py`.
- **Message Validation:** Messages are strictly checked against a 4 KB size limit before they enter the encryption pipeline.
- **File Name Sanitization:** Filenames are strictly sanitized to prevent Path Traversal and Command Injection attacks. Null bytes, relative paths (`../`), and OS-reserved names (e.g., `CON`, `PRN`) are actively stripped or rejected.

## 4. Encryption & Integrity
- **Algorithm:** End-to-End Encryption (E2EE) is guaranteed via `PyNaCl` (libsodium).
- **Key Exchange:** X25519 Elliptic-Curve Diffie-Hellman is used to derive session secrets.
- **Symmetric Encryption:** Authenticated encryption is performed using XSalsa20-Poly1305.
- **Integrity Check:** Files transferred securely use a SHA-256 hash comparison between the initial metadata and the reassembled file chunks to guarantee data integrity.

## 5. Security Logging & Auditing
- **Centralized Logging:** The application uses Python's standard `logging` module to direct all system logs to rotating files in `logs/i2i.log`.
- **Sanitized Outputs:** No plaintext message data, passwords, or cryptographic keys are ever printed to `stdout` or saved in log files. Users only see generic UI errors, while actual traces remain secure in log files for administrative audit.

## 6. MITM Prevention & Replay Attack Defense
- **Safety Numbers:** Man-in-the-Middle (MITM) attacks are detected using a Safety Number, calculated via a deterministic SHA-256 hash of the two peers' sorted public keys.
- **Replay Protection:** A strict nonce-tracking system (random 24-byte nonces) and a timestamp constraint prevent attackers from capturing and replaying previous packets.

## 7. API Security Controls
- **Not Applicable (By Design):** The I2I messenger operates strictly on a decentralized Peer-to-Peer TCP socket architecture. No external REST APIs, GraphQL, or web endpoints are exposed, nullifying vulnerabilities related to API token leaks, insecure HTTP verbs, or endpoint enumeration.

## 8. Cloud Security Measures
- **Not Applicable (By Design):** The application is a local-first, self-hosted decentralized system. No centralized cloud databases (AWS, Firebase, etc.) are utilized, ensuring no single point of failure and zero cloud-related credential exposures.

## 9. Session Management
- **Perfect Forward Secrecy:** As of the latest patch, the X25519 Elliptic-Curve Diffie-Hellman handshake utilizes ephemeral (temporary) keys generated newly per socket connection. The long-term identity keys only authenticate the handshake.
- **Session Isolation:** Upon disconnection, all keys associated with that session are immediately discarded from memory.
- **Token Bucket Rate Limiting:** A token bucket mitigates Denial of Service (DoS) attacks by strictly capping the rate of incoming messages per session.
