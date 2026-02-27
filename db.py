# -*- coding: utf-8 -*-
import sqlite3
import hashlib
import secrets
from contextlib import contextmanager
from pathlib import Path

import config
from crypto_util import encrypt_message, decrypt_message


def get_conn():
    Path(config.DATABASE).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(config.DATABASE)


def init_db():
    with get_conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                body_encrypted BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                message_type TEXT DEFAULT 'text',
                file_path TEXT,
                file_name TEXT,
                mime_type TEXT,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            );
        """)
        _migrate_messages_media(c)
        cur = c.execute("SELECT 1 FROM admin LIMIT 1")
        if cur.fetchone() is None:
            # پیش‌فرض: admin / admin123
            h = hash_password("admin123")
            c.execute("INSERT INTO admin (username, password_hash) VALUES (?, ?)", ("admin", h))


def _migrate_messages_media(c):
    """اضافه کردن ستون‌های مدیا به جدول messages اگر جدول از قبل وجود دارد."""
    cur = c.execute("PRAGMA table_info(messages)")
    cols = [row[1] for row in cur.fetchall()]
    for col, defn in [
        ("message_type", "TEXT DEFAULT 'text'"),
        ("file_path", "TEXT"),
        ("file_name", "TEXT"),
        ("mime_type", "TEXT"),
    ]:
        if col not in cols:
            c.execute(f"ALTER TABLE messages ADD COLUMN {col} {defn}")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2**14, r=8, p=1)
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hex_hash = stored.split("$", 1)
        h = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2**14, r=8, p=1)
        return h.hex() == hex_hash
    except Exception:
        return False


def admin_verify(username: str, password: str) -> bool:
    with get_conn() as c:
        row = c.execute(
            "SELECT password_hash FROM admin WHERE username = ?", (username,)
        ).fetchone()
        return row is not None and verify_password(password, row[0])


def user_verify(username: str, password: str) -> int | None:
    """برگرداندن user id در صورت موفقیت."""
    with get_conn() as c:
        row = c.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return None
        return row[0] if verify_password(password, row[1]) else None


def user_add(username: str, password: str) -> tuple[bool, str]:
    """فقط ادمین. True و پیام خالی یعنی موفق."""
    import config
    username = (username or "").strip()
    if not username:
        return False, "نام کاربری خالی است."
    if len(username) < 2:
        return False, "نام کاربری حداقل ۲ کاراکتر."
    if len(username) > config.MAX_USERNAME_LEN:
        return False, f"نام کاربری حداکثر {config.MAX_USERNAME_LEN} کاراکتر."
    if len(password) < config.MIN_PASSWORD_LEN:
        return False, f"رمز عبور حداقل {config.MIN_PASSWORD_LEN} کاراکتر."
    if len(password) > config.MAX_PASSWORD_LEN:
        return False, f"رمز عبور حداکثر {config.MAX_PASSWORD_LEN} کاراکتر."
    with get_conn() as c:
        try:
            c.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            return True, ""
        except sqlite3.IntegrityError:
            return False, "این نام کاربری قبلاً ثبت شده است."


def user_list():
    with get_conn() as c:
        return [
            {"id": r[0], "username": r[1], "created_at": r[2]}
            for r in c.execute(
                "SELECT id, username, created_at FROM users ORDER BY username"
            )
        ]


def message_send(sender_id: int, receiver_id: int, body: str) -> bool:
    import config
    if not body or len(body) > config.MAX_MESSAGE_LEN:
        return False
    enc = encrypt_message(body)
    if enc is None:
        return False
    with get_conn() as c:
        c.execute(
            "INSERT INTO messages (sender_id, receiver_id, body_encrypted) VALUES (?, ?, ?)",
            (sender_id, receiver_id, enc),
        )
    return True


def messages_for_user(user_id: int, other_id: int | None = None):
    """لیست مکالمات یا پیام‌های با یک کاربر خاص. هر پیام با body، message_type، file_path و غیره."""
    with get_conn() as c:
        if other_id is not None:
            rows = c.execute(
                """SELECT id, sender_id, receiver_id, body_encrypted, created_at,
                          message_type, file_path, file_name, mime_type
                   FROM messages
                   WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                   ORDER BY created_at""",
                (user_id, other_id, other_id, user_id),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT id, sender_id, receiver_id, body_encrypted, created_at,
                          message_type, file_path, file_name, mime_type
                   FROM messages
                   WHERE sender_id = ? OR receiver_id = ?
                   ORDER BY created_at DESC""",
                (user_id, user_id),
            ).fetchall()
    out = []
    for r in rows:
        body = decrypt_message(r[3]) if r[3] else ""
        if body is None:
            body = "[پیام رمزنگاری‌شده قابل نمایش نیست]"
        msg_type = (r[5] if len(r) > 5 else None) or "text"
        file_path = r[6] if len(r) > 6 else None
        file_name = r[7] if len(r) > 7 else None
        mime_type = r[8] if len(r) > 8 else None
        out.append({
            "id": r[0], "sender_id": r[1], "receiver_id": r[2],
            "body": body.strip() if body and body != " " else "",
            "created_at": r[4],
            "message_type": msg_type,
            "file_path": file_path,
            "file_name": file_name or "",
            "mime_type": mime_type or "",
        })
    return out


def get_user_by_id(uid: int) -> dict | None:
    with get_conn() as c:
        row = c.execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchone()
        return {"id": row[0], "username": row[1]} if row else None


def get_user_by_username(username: str) -> dict | None:
    """یافتن کاربر با نام کاربری (برای باز کردن چت)."""
    username = (username or "").strip()
    if not username:
        return None
    with get_conn() as c:
        row = c.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
        return {"id": row[0], "username": row[1]} if row else None


def message_send_media(
    sender_id: int,
    receiver_id: int,
    caption: str,
    message_type: str,
    file_path: str,
    file_name: str,
    mime_type: str,
) -> bool:
    import config
    caption = (caption or "").strip()[: config.MAX_MESSAGE_LEN]
    enc = encrypt_message(caption or " ")
    if enc is None:
        enc = encrypt_message(" ")
    if enc is None:
        return False
    with get_conn() as c:
        c.execute(
            """INSERT INTO messages (sender_id, receiver_id, body_encrypted, message_type, file_path, file_name, mime_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sender_id, receiver_id, enc, message_type, file_path, file_name or "", mime_type or ""),
        )
    return True


def get_message_by_id(msg_id: int) -> dict | None:
    """برای سرو کردن فایل: فقط فیلدهای لازم."""
    with get_conn() as c:
        row = c.execute(
            "SELECT id, sender_id, receiver_id, message_type, file_path, file_name, mime_type FROM messages WHERE id = ?",
            (msg_id,),
        ).fetchone()
        if not row or not row[4]:  # no file_path
            return None
        return {
            "id": row[0],
            "sender_id": row[1],
            "receiver_id": row[2],
            "message_type": row[3],
            "file_path": row[4],
            "file_name": row[5] or "",
            "mime_type": row[6] or "",
        }
