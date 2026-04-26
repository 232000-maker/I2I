# Security Architecture and Documentation

This document provides a detailed overview of the security mechanisms, cryptographic protocols, and defensive design decisions implemented in the I2I Secure P2P Messenger.

## 1. Authentication and Identity Management

The application utilizes a two-tier authentication system to ensure both local and network-level security.

- **Local Password Security:** User credentials are required to access the local instance. Passwords are never stored in plaintext. They are salted and hashed using the bcrypt algorithm. The user database (`keys/users.json`) is restricted with 0o600 filesystem permissions.
- **Brute-Force Mitigation:** An in-memory tracking system implements an account lockout policy. Three consecutive failed login attempts result in a five-minute lockout period to prevent credential stuffing and brute-force attacks.
- **Cryptographic Identity:** Upon successful local authentication, the system generates or loads an X25519 key pair. A user's network identity is tied to their X25519 public key, with the .b32.i2p address derived deterministically via a SHA-256 hash of that public key.

## 2. Authorization and Role-Based Access Control (RBAC)

I2I enforces strict privilege separation between USER and ADMIN roles.

- **Role Definitions:**
  - USER: Can send messages and files up to 10 MB.
  - ADMIN: Can send messages, broadcast to all peers, force-disconnect (kick) peers, and transfer files up to 50 MB.
- **Privilege Escalation Protection:** The ADMIN role is protected by an environment-defined secret (`I2I_ADMIN_SECRET`). Admin registration is rejected unless the provided code matches the server-side configuration.
- **RBAC Enforcement:** Validation occurs at the logic layer. For example, `Validators.validate_file_size` checks the authenticated role before allowing a file transfer to proceed, preventing users from bypassing UI restrictions.

## 3. Cryptographic Implementation

The system uses the PyNaCl (libsodium) library for all cryptographic operations, following the salt-stack approach.

- **Key Exchange:** A two-phase handshake is performed. The identity X25519 keys are used to authenticate the exchange of ephemeral X25519 keys, providing Perfect Forward Secrecy (PFS). If a long-term identity key is compromised, past sessions remain secure.
- **Authenticated Encryption:** All data is encrypted using XSalsa20 and authenticated via Poly1305 (AEAD). This ensures both confidentiality and integrity.
- **Replay Protection:** Every encrypted frame includes a random 24-byte nonce. The application tracks nonces within a session-specific set. Duplicate nonces result in immediate packet rejection.
- **Safety Numbers:** To mitigate Man-In-The-Middle (MITM) attacks, the application generates a 30-digit safety number. This fingerprint is derived from the SHA-256 hash of the sorted public keys of both peers, intended for out-of-band verification.

## 4. Network and Protocol Security

The P2P communication protocol is designed to be resilient against common network-level attacks.

- **Framing Security:** A custom binary framing protocol uses a 4-byte big-endian length prefix. This prevents boundary injection and mitigates "Slowloris" style attacks by enforcing maximum frame sizes.
- **Verify-then-Parse:** The application implements a "Verify-then-Parse" order of operations. The Poly1305 MAC is verified before the JSON metadata is parsed. This prevents Cryptographic Denial of Service attacks where an attacker sends large, malformed JSON structures to exhaust CPU and memory resources.
- **Handshake Timeouts:** All connection attempts and handshakes are subject to a 10-second timeout to prevent resource exhaustion from half-open connections.

## 5. Input Validation and Sanitization

I2I treats all data received from the network as untrusted.

- **Message Validation:** Chat messages are capped at 4 KB and stripped of leading/trailing whitespace.
- **Path Traversal Prevention:** Filenames received during transfers are strictly sanitized. The system extracts the base name to remove directory components, removes null bytes, replaces non-alphanumeric characters with underscores, and rejects Windows-reserved filenames (e.g., CON, PRN, NUL).
- **XSS Mitigation:** All messages are passed through an HTML entity escaping function before being rendered in the GUI to prevent script injection.
- **File Integrity:** Upon completion of a file transfer, the system computes the SHA-256 hash of the reassembled file and compares it against the metadata hash provided by the sender.

## 6. Containerization and Docker Security

The implementation includes a Docker-based deployment model that adds several layers of infrastructure security.

- **User Namespacing and Least Privilege:** The Dockerfile creates a non-root user (`i2iuser`) and group (`i2igroup`). The `entrypoint.sh` script uses `gosu` to execute the application, ensuring that even if the application is compromised, the attacker does not gain root access to the container or host.
- **Network Isolation:** Docker Compose defines a private bridge network (`i2i-mesh`). Peers communicate within this isolated segment, and only the necessary web-VNC ports are exposed to the host system.
- **Resource Isolation:** By running in containers, the application's access to host resources (CPU, RAM) can be capped via Docker cgroup limits, preventing a compromised instance from impacting the host system's stability.
- **Filesystem Isolation:** Sensitive data (keys, logs, and downloads) is confined to specific volumes. The use of a "slim" Debian-based image (`bookworm-slim`) reduces the attack surface by excluding unnecessary binaries and libraries.
- **Controlled Display Environment:** Instead of using the host X11 socket, which is a common security risk, the container uses `Xvfb` (X Virtual Framebuffer) and `novnc`. This provides a virtualized display environment that is isolated from the host's graphical subsystem.

## 7. Resource and Error Management

- **Memory Protection:** File transfers use a stream-to-disk approach. Chunks are written directly to disk at specific offsets using `.part` files, preventing the application from crashing due to high RAM usage during large file transfers.
- **Generic Error Responses:** The application avoids descriptive error messages in network responses. Failures in key exchange or decryption return generic status codes to prevent information leakage to potential attackers.
- **Secure Logging:** Logs are written to a local file with rotating handlers to prevent disk exhaustion. No plaintext messages, private keys, or passwords are ever recorded in the logs. Peer addresses are anonymized.
