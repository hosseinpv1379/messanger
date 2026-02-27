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
        _migrate_extra(c)
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
        ("deleted_at", "TIMESTAMP"),
    ]:
        if col not in cols:
            c.execute(f"ALTER TABLE messages ADD COLUMN {col} {defn}")


def _migrate_extra(c):
    """جدول‌ها و ستون‌های اضافی: بلوک، خوانده‌شده، بن کاربر."""
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked (
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            PRIMARY KEY (blocker_id, blocked_id),
            FOREIGN KEY (blocker_id) REFERENCES users(id),
            FOREIGN KEY (blocked_id) REFERENCES users(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS read_receipts (
            user_id INTEGER NOT NULL,
            other_id INTEGER NOT NULL,
            last_read_message_id INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, other_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (other_id) REFERENCES users(id)
        )
    """)
    cur = c.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]
    if "is_banned" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")


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


def _admin_get_hash(username: str) -> str | None:
    with get_conn() as c:
        row = c.execute(
            "SELECT password_hash FROM admin WHERE username = ?", (username,)
        ).fetchone()
        return row[0] if row else None


def admin_verify(username: str, password: str) -> bool:
    stored = _admin_get_hash(username)
    return stored is not None and verify_password(password, stored)


def admin_update_password(username: str, current_password: str, new_password: str) -> tuple[bool, str]:
    """تغییر رمز ادمین. موفق: (True, '')، ناموفق: (False, پیام خطا)."""
    import config
    if not username:
        return False, "ورود مجدد انجام دهید."
    stored = _admin_get_hash(username)
    if not stored or not verify_password(current_password, stored):
        return False, "رمز فعلی اشتباه است."
    new_password = (new_password or "")[: config.MAX_PASSWORD_LEN]
    if len(new_password) < config.MIN_PASSWORD_LEN:
        return False, f"رمز جدید حداقل {config.MIN_PASSWORD_LEN} کاراکتر باشد."
    with get_conn() as c:
        c.execute(
            "UPDATE admin SET password_hash = ? WHERE username = ?",
            (hash_password(new_password), username),
        )
    return True, ""


def user_verify(username: str, password: str) -> int | None:
    """برگرداندن user id در صورت موفقیت. کاربر مسدود نتواند وارد شود."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        if "is_banned" in cols:
            row = c.execute(
                "SELECT id, password_hash, is_banned FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        else:
            row = c.execute(
                "SELECT id, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row:
                row = (row[0], row[1], 0)
        if row is None:
            return None
        if len(row) > 2 and row[2]:
            return None
        return row[0] if verify_password(password, row[1]) else None


def user_verify_by_id(user_id: int, password: str) -> bool:
    """بررسی رمز عبور با شناسهٔ کاربر (برای حذف حساب و غیره)."""
    stored = _user_get_hash(user_id)
    return bool(stored and verify_password(password, stored))


def conversation_clear(user_id: int, other_id: int) -> bool:
    """حذف همهٔ پیام‌های بین دو کاربر (گفتگو برای هر دو پاک می‌شود)."""
    if user_id == other_id:
        return False
    with get_conn() as c:
        c.execute(
            """DELETE FROM messages WHERE
               (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)""",
            (user_id, other_id, other_id, user_id),
        )
        c.execute(
            "DELETE FROM read_receipts WHERE (user_id = ? AND other_id = ?) OR (user_id = ? AND other_id = ?)",
            (user_id, other_id, other_id, user_id),
        )
    return True


def _user_get_hash(user_id: int) -> str | None:
    with get_conn() as c:
        row = c.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row[0] if row else None


def user_update_password(user_id: int, current_password: str, new_password: str) -> tuple[bool, str]:
    """تغییر رمز کاربر. موفق: (True, '')، ناموفق: (False, پیام خطا)."""
    import config
    stored = _user_get_hash(user_id)
    if not stored or not verify_password(current_password, stored):
        return False, "رمز فعلی اشتباه است."
    new_password = (new_password or "")[: config.MAX_PASSWORD_LEN]
    if len(new_password) < config.MIN_PASSWORD_LEN:
        return False, f"رمز جدید حداقل {config.MIN_PASSWORD_LEN} کاراکتر باشد."
    with get_conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
    return True, ""


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


def user_list(search: str = ""):
    """لیست کاربران. search: فیلتر نام کاربری (خالی = همه)."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        has_banned = "is_banned" in cols
        if has_banned:
            sel = "SELECT id, username, created_at, is_banned FROM users"
        else:
            sel = "SELECT id, username, created_at FROM users"
        if search:
            q = (search or "").strip()
            q = f"%{q}%"
            sel += " WHERE username LIKE ?"
            params = (q,)
        else:
            params = ()
        sel += " ORDER BY username"
        rows = c.execute(sel, params).fetchall()
        out = []
        for r in rows:
            u = {"id": r[0], "username": r[1], "created_at": r[2]}
            if has_banned and len(r) > 3:
                u["is_banned"] = bool(r[3])
            else:
                u["is_banned"] = False
            out.append(u)
        return out


def is_blocked(blocker_id: int, blocked_id: int) -> bool:
    with get_conn() as c:
        r = c.execute(
            "SELECT 1 FROM blocked WHERE blocker_id = ? AND blocked_id = ?",
            (blocker_id, blocked_id),
        ).fetchone()
        return r is not None


def message_send(sender_id: int, receiver_id: int, body: str) -> bool:
    import config
    if is_blocked(receiver_id, sender_id):
        return False
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
    """لیست مکالمات یا پیام‌های با یک کاربر خاص. پیام‌های حذف‌شده نشان داده نمی‌شوند."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        deleted_clause = " AND (deleted_at IS NULL)" if "deleted_at" in cols else ""
        if other_id is not None:
            rows = c.execute(
                """SELECT id, sender_id, receiver_id, body_encrypted, created_at,
                          message_type, file_path, file_name, mime_type
                   FROM messages
                   WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                   """ + deleted_clause + """
                   ORDER BY created_at""",
                (user_id, other_id, other_id, user_id),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT id, sender_id, receiver_id, body_encrypted, created_at,
                          message_type, file_path, file_name, mime_type
                   FROM messages
                   WHERE (sender_id = ? OR receiver_id = ?)
                   """ + deleted_clause + """
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
        cur = c.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        if "is_banned" in cols:
            row = c.execute("SELECT id, username, is_banned FROM users WHERE id = ?", (uid,)).fetchone()
            if not row:
                return None
            return {"id": row[0], "username": row[1], "is_banned": bool(row[2])}
        row = c.execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "is_banned": False}


def get_user_by_username(username: str) -> dict | None:
    """یافتن کاربر با نام کاربری (برای باز کردن چت)."""
    username = (username or "").strip()
    if not username:
        return None
    with get_conn() as c:
        u = c.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not u:
        return None
    return get_user_by_id(u[0])


def get_conversations(user_id: int, limit: int = 100, search: str = "") -> list[dict]:
    """لیست گفتگوهای اخیر. کاربران بلاک‌شده حذف می‌شوند. search: فیلتر نام کاربری."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [row[1] for row in cur.fetchall()]
        has_type = "message_type" in cols
        if has_type:
            rows = c.execute(
                """SELECT
                     CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS other_id,
                     created_at, body_encrypted, message_type
                   FROM messages
                   WHERE (sender_id = ? OR receiver_id = ?)
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (user_id, user_id, user_id, limit * 2),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT
                     CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS other_id,
                     created_at, body_encrypted
                   FROM messages
                   WHERE sender_id = ? OR receiver_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (user_id, user_id, user_id, limit * 2),
            ).fetchall()
    seen: set[int] = set()
    out: list[dict] = []
    search_lower = (search or "").strip().lower()
    for r in rows:
        other_id = r[0]
        if other_id in seen:
            continue
        if is_blocked(user_id, other_id):
            continue
        seen.add(other_id)
        u = get_user_by_id(other_id)
        if not u:
            continue
        if search_lower and search_lower not in (u.get("username") or "").lower():
            continue
        body = decrypt_message(r[2]) if r[2] else ""
        if body is None:
            preview = "[پیام]"
        else:
            msg_type = (r[3] if has_type and len(r) > 3 else None) or "text"
            if msg_type == "image":
                preview = "📷 عکس"
            elif msg_type == "file":
                preview = "📎 فایل"
            elif msg_type == "voice":
                preview = "🎤 ویس"
            else:
                preview = (body.strip() or " ")[:50]
                if len((body or "").strip()) > 50:
                    preview += "…"
        out.append({
            "other_id": other_id,
            "other_username": u["username"],
            "last_at": r[1],
            "last_preview": preview,
        })
        if len(out) >= limit:
            break
    return out


def message_send_media(
    sender_id: int,
    receiver_id: int,
    caption: str,
    message_type: str,
    file_path: str,
    file_name: str,
    mime_type: str,
) -> bool:
    if is_blocked(receiver_id, sender_id):
        return False
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


def message_delete(message_id: int, user_id: int) -> bool:
    """حذف پیام (فقط فرستنده). حذف نرم با deleted_at."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        if "deleted_at" not in [r[1] for r in cur.fetchall()]:
            return False
        r = c.execute(
            "SELECT sender_id FROM messages WHERE id = ?",
            (message_id,),
        ).fetchone()
        if not r or r[0] != user_id:
            return False
        c.execute(
            "UPDATE messages SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?",
            (message_id,),
        )
    return True


def read_receipt_set(user_id: int, other_id: int, last_read_message_id: int) -> None:
    with get_conn() as c:
        c.execute(
            """INSERT INTO read_receipts (user_id, other_id, last_read_message_id, updated_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(user_id, other_id) DO UPDATE SET
                 last_read_message_id = excluded.last_read_message_id,
                 updated_at = CURRENT_TIMESTAMP""",
            (user_id, other_id, last_read_message_id),
        )


def read_receipt_get(user_id: int, other_id: int) -> int | None:
    """آخرین پیام‌خوانده‌شده توسط user_id در چت با other_id (برای نمایش تیک خوانده‌شده)."""
    with get_conn() as c:
        r = c.execute(
            "SELECT last_read_message_id FROM read_receipts WHERE user_id = ? AND other_id = ?",
            (user_id, other_id),
        ).fetchone()
        return r[0] if r else None


def block_add(blocker_id: int, blocked_id: int) -> bool:
    if blocker_id == blocked_id:
        return False
    with get_conn() as c:
        try:
            c.execute(
                "INSERT INTO blocked (blocker_id, blocked_id) VALUES (?, ?)",
                (blocker_id, blocked_id),
            )
            return True
        except sqlite3.IntegrityError:
            return True


def block_remove(blocker_id: int, blocked_id: int) -> bool:
    with get_conn() as c:
        c.execute(
            "DELETE FROM blocked WHERE blocker_id = ? AND blocked_id = ?",
            (blocker_id, blocked_id),
        )
    return True


def block_list(blocker_id: int) -> list[dict]:
    with get_conn() as c:
        rows = c.execute(
            "SELECT blocked_id FROM blocked WHERE blocker_id = ? ORDER BY blocked_id",
            (blocker_id,),
        ).fetchall()
    return [get_user_by_id(r[0]) for r in rows if get_user_by_id(r[0])]


def user_delete(user_id: int) -> bool:
    """حذف کاربر و پیام‌هایش (ادمین)."""
    with get_conn() as c:
        c.execute("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
        c.execute("DELETE FROM blocked WHERE blocker_id = ? OR blocked_id = ?", (user_id, user_id))
        c.execute("DELETE FROM read_receipts WHERE user_id = ? OR other_id = ?", (user_id, user_id))
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return True


def user_ban(user_id: int) -> bool:
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        if "is_banned" not in [r[1] for r in cur.fetchall()]:
            return False
        c.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (user_id,))
    return True


def user_unban(user_id: int) -> bool:
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        if "is_banned" not in [r[1] for r in cur.fetchall()]:
            return False
        c.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
    return True


def admin_set_user_password(user_id: int, new_password: str) -> tuple[bool, str]:
    import config
    new_password = (new_password or "")[: config.MAX_PASSWORD_LEN]
    if len(new_password) < config.MIN_PASSWORD_LEN:
        return False, f"رمز حداقل {config.MIN_PASSWORD_LEN} کاراکتر."
    with get_conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), user_id),
        )
    return True, ""
