# I2I Secure P2P Messenger

**Group:** Syed Mueez (23I-2000), Huzaifa Khan (23I-6123), Muhammad Abdullah (23I-2064)  
**Course:** Secure Software Development (SSD) - Assignment 3

## Description

I2I (Identity-to-Identity) is a decentralized, peer-to-peer messaging and file-sharing application built with a focus on cryptographic security and local privacy. The system eliminates reliance on central servers by utilizing a simulated I2P network layer where peer addresses are derived deterministically from their public keys. The application provides an end-to-end encrypted (E2EE) tunnel for communication, enforcing role-based access control (RBAC) to manage resource usage and administrative privileges.

## Security Features Implemented

The application incorporates several secure coding principles and architectural controls:

- End-to-End Encryption (E2EE): All data is protected using XSalsa20-Poly1305 authenticated encryption via the PyNaCl (libsodium) library.
- Perfect Forward Secrecy (PFS): A two-phase handshake uses static identity keys to authenticate the exchange of ephemeral X25519 keys for every session.
- Role-Based Access Control (RBAC): The system differentiates between USER and ADMIN roles, enforcing file size limits (10 MB for users, 50 MB for admins) and restricting administrative commands like network broadcasts and peer kicking.
- Authentication Security: Local accounts are secured with bcrypt password hashing. A memory-resident lockout policy triggers after three failed attempts to prevent brute-force attacks.
- Man-In-The-Middle (MITM) Protection: Users can perform out-of-band verification using a 30-digit Safety Number derived from the shared cryptographic context.
- Input Validation: All external inputs, including chat messages, public keys, and filenames, are validated against strict length and format constraints.
- Path Traversal Prevention: Filenames are sanitized by stripping directory components and null bytes, and by rejecting reserved operating system filenames.
- Rate Limiting: A Token Bucket algorithm prevents message flooding by limiting the rate at which a peer can send data.
- Secure Logging: Application logs exclude sensitive data such as plaintext messages, private keys, or passwords. Peer identifiers are anonymized.
- Container Security: The Docker implementation uses a non-root user, isolated bridge networking, and a virtualized framebuffer (Xvfb) to minimize the host attack surface.

## Dependencies

The following Python libraries are required for the application:

- PyNaCl: Provides the cryptographic primitives for X25519 and XSalsa20-Poly1305.
- bcrypt: Handles secure, salted password hashing.
- python-dotenv: Loads configuration settings from environment files.
- pytest: Framework used for the unit test suite.
- pytest-cov: Provides coverage reporting for the source code.

## Environment Variables

The application is configured via a .env file. An example file (.env.example) is provided in the root directory.

- I2I_LISTEN_PORT: The TCP port the application listens on (e.g., 7777).
- I2I_BIND_ADDR: The network interface to bind to (use 0.0.0.0 for Docker, 127.0.0.1 for local).
- I2I_ADMIN_SECRET: The secret code required to register as an ADMIN.
- I2I_LOG_LEVEL: The verbosity of the application logs (e.g., INFO, WARNING).
- PUID/PGID: User and Group IDs used for filesystem permissions in Docker.

## Setup Instructions

### Docker Environment Setup

1.  **Initialize Configuration:**

    ```bash
    cp .env.example .env
    ```

2.  **Configure Environment Variables:**
    Open the `.env` file and ensure the following:
    - Set `I2I_BIND_ADDR=0.0.0.0` (Required for Docker networking).
    - Set `I2I_ADMIN_SECRET` to a code of your choice (e.g., `MySecret123`). This is required to register an Admin account.
    - Set `ADMIN_CODE` to the same value as `I2I_ADMIN_SECRET`.

3.  **Launch the Network:**
    ```bash
    docker-compose up --build -d
    ```

## How to Run Project

### 1. Access the Graphical Interfaces

Open two separate browser tabs to access the peer nodes:

- **Peer A:** [http://localhost:8777/vnc.html](http://localhost:8777/vnc.html)
- **Peer B:** [http://localhost:8778/vnc.html](http://localhost:8778/vnc.html)

_Click the "Connect" button in the browser to view the application._

### 2. Authentication Flow

- **Registering as ADMIN:** Use the username `admin`. When the application prompts for a secret code, enter the `I2I_ADMIN_SECRET` defined in your `.env` file.
- **Registering as USER:** Use any other username and password.

### 3. Establishing a Peer-to-Peer Connection

To connect Peer B to Peer A:

1.  **On Peer A:** Register/Login and copy the **Public Key (Hex)** displayed in the identity panel.
2.  **On Peer B:** Register/Login. In the connection panel, enter the following:
    - **Peer Public Key:** (Paste the key from Peer A)
    - **Host/IP:** `peer-a`
    - **Port:** `7777`
3.  Click **Connect**.

To connect Peer A back to Peer B:

1.  **On Peer B:** Copy the **Public Key (Hex)**.
2.  **On Peer A:** Enter `peer-b` in the **Host/IP** field, `7777` in the **Port** field, and paste the key.
3.  Click **Connect**.

## Testing and Verification

### Automated Security Audit

This script verifies authentication security, RBAC limits, path traversal prevention, and logging integrity.
docker exec -it i2i-peer-a python security_test.py

### Unit Test Suite

To run the full suite of 80+ tests covering cryptography, file transfers, and connection logic:
docker exec -it i2i-peer-a python -m pytest tests/ -v

### Shutdown

To stop the Docker containers and clean up the network:
docker-compose down
