"""
File: src/validators.py
Purpose: Formal input validation module.

Security:
- Provides a structured validation layer for messages and files.
- Centralizes security policies for inputs.
"""

import re
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_MESSAGE_SIZE_BYTES = 4 * 1024          # 4 KB
MAX_FILE_SIZE_USER = 10 * 1024 * 1024     # 10 MB for normal users
MAX_FILE_SIZE_ADMIN = 50 * 1024 * 1024    # 50 MB for admins

class Validators:
    """Structured validation layer for application inputs."""

    @staticmethod
    def validate_message(msg: str) -> bool:
        """
        Validate a user-supplied chat message.
        """
        if not msg or not isinstance(msg, str):
            return False
            
        encoded = msg.encode("utf-8")
        if len(encoded) > MAX_MESSAGE_SIZE_BYTES:
            logger.warning("Validation failed: Message too large (%d bytes).", len(encoded))
            return False
            
        return True

    @staticmethod
    def validate_filename(name: str) -> str:
        """
        Regex safe filename sanitization to prevent path traversal.
        """
        if not isinstance(name, str):
            raise ValueError("Filename must be a string.")

        # Normalize Windows backslash separators before extracting basename.
        # os.path.basename on Linux does not treat backslash as a separator.
        name = name.replace("\\", "/")
        filename = os.path.basename(name)
        filename = filename.replace("\x00", "")
        filename = re.sub(r"[^\w.\-]", "_", filename)
        filename = re.sub(r"\.{2,}", ".", filename)
        
        RESERVED = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
        }
        if filename.upper().split(".")[0] in RESERVED:
            logger.warning("Validation failed: Reserved filename attempted (%s).", filename)
            raise ValueError("Reserved filename not allowed.")
            
        if not filename or filename in {".", ".."}:
            logger.warning("Validation failed: Invalid filename after sanitization.")
            raise ValueError("Invalid filename.")
            
        return filename

    @staticmethod
    def validate_file_size(file_path: Path, role: str) -> bool:
        """
        Validate file size based on RBAC role.
        """
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError("File not found or is not a regular file.")
            
        size = file_path.stat().st_size
        max_size = MAX_FILE_SIZE_ADMIN if role == "ADMIN" else MAX_FILE_SIZE_USER
        
        if size > max_size:
            logger.warning("Validation failed: User %s exceeded file size limit (%d > %d).", role, size, max_size)
            raise ValueError(f"File size exceeds the {max_size // (1024 * 1024)}MB limit for your role ({role}).")
            
        if size == 0:
            raise ValueError("File is empty.")
            
        return True
