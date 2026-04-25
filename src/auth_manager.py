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
from pathlib import Path
from typing import Optional, Dict, Any
import logging

from src.security_utils import validate_password_strength

logger = logging.getLogger(__name__)

AUTH_FILE = Path("keys/users.json")

class AuthManager:
    """
    Handles local authentication using bcrypt and RBAC logic.
    """

    # Track failed login attempts in memory: {username: (attempts, lockout_timestamp)}
    _failed_attempts: Dict[str, tuple[int, float]] = {}
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_SECONDS = 300  # 5 minutes

    @staticmethod
    def _load_users() -> Dict[str, Any]:
        """Load the user database."""
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
        """Save the user database securely."""
        try:
            with open(AUTH_FILE, "w") as f:
                json.dump(users, f, indent=4)
            # Secure the file immediately against local read access
            import os
            try:
                os.chmod(AUTH_FILE, 0o600)
            except (AttributeError, NotImplementedError):
                pass
        except Exception as e:
            logger.error("Failed to save users: %s", e)
            raise

    @staticmethod
    def register(username: str, password: str, role: str = "USER") -> bool:
        """
        Register a new user with a hashed password.
        
        Args:
            username: The desired username.
            password: The plaintext password.
            role: The RBAC role (default 'USER').
            
        Returns:
            True if registration was successful.
            
        Raises:
            ValueError: If the username already exists or inputs are invalid.
        """
        if not username or not password:
            raise ValueError("Username and password are required.")

        # Enforce password strength policy before hashing
        validate_password_strength(password)

        users = AuthManager._load_users()
        if username in users:
            raise ValueError("Username already exists.")
            
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        users[username] = {
            "password": hashed,
            "role": role.upper()
        }
        
        AuthManager._save_users(users)
        logger.info("Registered new user: %s with role %s", username, role)
        return True

    @staticmethod
    def verify_user(username: str, password: str) -> Optional[str]:
        """
        Verify credentials. Uses bcrypt to mitigate timing attacks.
        Enforces Account Lockout policy after 3 failed attempts.
        Returns the user's role on success, None on failure.
        """
        import time
        username = username.strip()
        
        # Check lockout status
        if username in AuthManager._failed_attempts:
            attempts, lockout_time = AuthManager._failed_attempts[username]
            if attempts >= AuthManager.MAX_FAILED_ATTEMPTS:
                if time.time() < lockout_time:
                    logger.warning("Account locked for %s. Try again later.", username)
                    raise PermissionError(f"Account locked due to multiple failed attempts. Try again in {int((lockout_time - time.time())//60)} minutes.")
                else:
                    # Lockout expired, reset
                    del AuthManager._failed_attempts[username]

        users = AuthManager._load_users()
        if username not in users:
            AuthManager._record_failed_attempt(username)
            logger.warning("Login failed: Unknown username.")
            return None

        user_data = users[username]
        stored_hash = user_data["password"].encode("utf-8")
        
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            logger.info("User '%s' authenticated successfully.", username)
            # Reset failed attempts on success
            if username in AuthManager._failed_attempts:
                del AuthManager._failed_attempts[username]
            return user_data.get("role", "USER")
            
        AuthManager._record_failed_attempt(username)
        logger.warning("Login failed: Incorrect password for '%s'.", username)
        return None

    @staticmethod
    def _record_failed_attempt(username: str) -> None:
        """Increment failed attempts and set lockout if threshold reached."""
        import time
        attempts, _ = AuthManager._failed_attempts.get(username, (0, 0.0))
        attempts += 1
        lockout_time = time.time() + AuthManager.LOCKOUT_DURATION_SECONDS if attempts >= AuthManager.MAX_FAILED_ATTEMPTS else 0.0
        AuthManager._failed_attempts[username] = (attempts, lockout_time)
        return None

    @staticmethod
    def login(username: str, password: str) -> Optional[str]:
        """
        Authenticate a user and return their role.
        
        Args:
            username: The username.
            password: The plaintext password.
            
        Returns:
            The user's role (e.g., 'USER', 'ADMIN') if successful, else None.
        """
        return AuthManager.verify_user(username, password)
