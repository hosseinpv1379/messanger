# -*- coding: utf-8 -*-
from cryptography.fernet import Fernet, InvalidToken
import config

_fernet = Fernet(config.FERNET_KEY)


def encrypt_message(text: str) -> bytes | None:
    try:
        return _fernet.encrypt(text.encode("utf-8"))
    except Exception:
        return None


def decrypt_message(encrypted: bytes) -> str | None:
    try:
        return _fernet.decrypt(encrypted).decode("utf-8")
    except (InvalidToken, Exception):
        return None


def encrypt_bytes(data: bytes) -> bytes | None:
    try:
        return _fernet.encrypt(data)
    except Exception:
        return None


def decrypt_bytes(encrypted: bytes) -> bytes | None:
    try:
        return _fernet.decrypt(encrypted)
    except (InvalidToken, Exception):
        return None
