"""
File: main.py
Purpose: Application entry point for I2I Secure P2P Messenger.

This script sets up secure logging, creates the received_files and logs
directories, and launches the Tkinter GUI.

Security:
- Logging is configured to write to a file (not stdout) to prevent
  sensitive error messages from appearing in the terminal.
- Log level is INFO by default (not DEBUG, which might include more detail).
- The logs/ directory is created with restrictive permissions where supported.
"""

import os
import sys
import logging
from pathlib import Path

# ─────────────────────────────────────────────
#  Secure Logging Setup
# ─────────────────────────────────────────────

def setup_logging() -> None:
    """
    Configure secure application logging.

    Security:
    - Logs are written to logs/i2i.log, not to stdout.
    - No plaintext message content or private keys are logged.
    - Uses rotating file handler to prevent unbounded log growth.

    Output: None. Configures the root logger.
    """
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    try:
        os.chmod(logs_dir, 0o700)
    except (AttributeError, NotImplementedError):
        pass  # Windows — acceptable

    from logging.handlers import RotatingFileHandler

    log_file = logs_dir / "i2i.log"
    handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=3,              # Keep last 3 log files
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)

    # Also show warnings and above to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)


# ─────────────────────────────────────────────
#  Directory Initialization
# ─────────────────────────────────────────────

def ensure_directories() -> None:
    """
    Create required application directories.

    Directory security:
    - keys/ — private key storage (mode 0o700 on POSIX)
    - received_files/ — incoming file destination (mode 0o755)
    - logs/ — log files (mode 0o700 on POSIX)
    """
    for directory, mode in [("keys", 0o700), ("received_files", 0o755), ("logs", 0o700)]:
        path = Path(directory)
        path.mkdir(exist_ok=True)
        try:
            os.chmod(path, mode)
        except (AttributeError, NotImplementedError):
            pass


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def main() -> None:
    """
    Launch the I2I application.

    Steps:
    1. Set up secure logging.
    2. Create required directories.
    3. Launch the Tkinter GUI.
    """
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("I2I Secure P2P Messenger starting up.")
    logger.info("=" * 60)

    ensure_directories()

    try:
        from gui.login import run_login_flow
        from gui.app import I2IApp
        
        while True:
            username, role = run_login_flow()
            if not username or not role:
                logger.info("Login cancelled. Exiting.")
                sys.exit(0)
                
            app = I2IApp(username, role)
            app.run()
            
            if getattr(app, 'logout_requested', False):
                logger.info("User logged out. Restarting login flow.")
                continue
            else:
                break
    except ImportError as exc:
        logger.critical("Import error — are all dependencies installed? %s", exc)
        print(f"\n[ERROR] Missing dependency: {exc}")
        print("Run: pip install -r requirements.txt\n")
        sys.exit(1)
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
