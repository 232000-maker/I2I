"""
File: src/auth_manager.py
Purpose: Authentication and Role-Based Access Control (RBAC) system.

Security:
- Passwords are securely hashed using bcrypt with per-user salt.
- Prevents cleartext credential storage.
- Defines roles (ADMIN, USER) for RBAC enforcement.
"""

import json
import bcrypt
import threading
from pathlib import Path
from typing import Optional, Dict, Any
import logging
from src.security_utils import validate_password_strength

logger = logging.getLogger(__name__)
AUTH_FILE = Path("keys/users.json")


class AuthManager:
    _failed_attempts: Dict[str, tuple[int, float]] = {}
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_SECONDS = 300
    _db_lock = threading.Lock()

    @staticmethod
    def _load_users() -> Dict[str, Any]:
        with AuthManager._db_lock:
            if not AUTH_FILE.exists():
                return {}
            try:
                with open(AUTH_FILE, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to load users: %s", e)
                return {}

    @staticmethod
    def _save_users(users: Dict[str, Any]) -> None:
        with AuthManager._db_lock:
            try:
                with open(AUTH_FILE, "w") as f:
                    json.dump(users, f, indent=4)
                import os

                try:
                    os.chmod(AUTH_FILE, 0o600)
                except:
                    pass
            except Exception as e:
                logger.error("Failed to save users: %s", e)
                raise

    @staticmethod
    def register(username: str, password: str, role: str = "USER") -> bool:
        if not username or not password:
            raise ValueError("Username and password are required.")

        validate_password_strength(password)

        with AuthManager._db_lock:
            if not AUTH_FILE.exists():
                users = {}
            else:
                with open(AUTH_FILE, "r") as f:
                    users = json.load(f)

            if username in users:
                raise ValueError("Username already exists.")

            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
                "utf-8"
            )
            users[username] = {"password": hashed, "role": role.upper()}

            # FIXED: Perform write and harden file inside the lock
            with open(AUTH_FILE, "w") as f:
                json.dump(users, f, indent=4)
            try:
                import os

                os.chmod(AUTH_FILE, 0o600)
            except:
                pass

        logger.info("Registered user: %s", username)
        return True

    @staticmethod
    def login(username: str, password: str) -> Optional[str]:
        return AuthManager.verify_user(username, password)

    @staticmethod
    def verify_user(username: str, password: str) -> Optional[str]:
        import time

        username = username.strip()

        if username in AuthManager._failed_attempts:
            attempts, lockout_time = AuthManager._failed_attempts[username]
            if (
                attempts >= AuthManager.MAX_FAILED_ATTEMPTS
                and time.time() < lockout_time
            ):
                raise PermissionError(
                    f"Account locked. Try again in {int((lockout_time - time.time()) // 60)} mins."
                )

        users = AuthManager._load_users()
        if username not in users:
            AuthManager._record_failed_attempt(username)
            return None

        user_data = users[username]
        if bcrypt.checkpw(
            password.encode("utf-8"), user_data["password"].encode("utf-8")
        ):
            if username in AuthManager._failed_attempts:
                del AuthManager._failed_attempts[username]
            return user_data.get("role", "USER")

        AuthManager._record_failed_attempt(username)
        return None

    @staticmethod
    def _record_failed_attempt(username: str) -> None:
        import time

        attempts, _ = AuthManager._failed_attempts.get(username, (0, 0.0))
        attempts += 1
        lockout = (
            time.time() + AuthManager.LOCKOUT_DURATION_SECONDS
            if attempts >= AuthManager.MAX_FAILED_ATTEMPTS
            else 0.0
        )
        AuthManager._failed_attempts[username] = (attempts, lockout)
