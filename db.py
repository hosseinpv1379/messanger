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
        ("is_e2ee", "INTEGER DEFAULT 0"),
        ("reply_to_id", "INTEGER REFERENCES messages(id)"),
        ("edited_at", "TIMESTAMP"),
    ]:
        if col not in cols:
            c.execute(f"ALTER TABLE messages ADD COLUMN {col} {defn}")


def _migrate_extra(c):
    """جدول‌ها و ستون‌های اضافی: بلوک، خوانده‌شده، بن کاربر، گروه‌ها."""
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
    for col, defn in [("display_name", "TEXT"), ("bio", "TEXT"), ("avatar_path", "TEXT")]:
        if col not in cols:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
    # گروه‌ها
    c.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            created_by_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by_id) REFERENCES users(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY,
            group_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body_encrypted BLOB NOT NULL,
            message_type TEXT DEFAULT 'text',
            file_path TEXT,
            file_name TEXT,
            mime_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    """)
    _migrate_e2ee(c)


def _migrate_e2ee(c):
    """جدول کلید عمومی کاربران برای رمزنگاری انتها‑به‑انتها (E2EE)."""
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_public_keys (
            user_id INTEGER PRIMARY KEY,
            public_key BLOB NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    cur = c.execute("PRAGMA table_info(messages)")
    msg_cols = [row[1] for row in cur.fetchall()]
    if "is_e2ee" not in msg_cols:
        c.execute("ALTER TABLE messages ADD COLUMN is_e2ee INTEGER DEFAULT 0")
    if "reply_to_id" not in msg_cols:
        c.execute("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER REFERENCES messages(id)")
    if "edited_at" not in msg_cols:
        c.execute("ALTER TABLE messages ADD COLUMN edited_at TIMESTAMP")


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


def user_get_profile(user_id: int) -> dict | None:
    """پروفایل کاربر برای نمایش/ویرایش (username, display_name, bio, avatar_path)."""
    u = get_user_by_id(user_id)
    if not u:
        return None
    return {
        "id": u["id"],
        "username": u.get("username") or "",
        "display_name": (u.get("display_name") or "").strip() or None,
        "bio": (u.get("bio") or "").strip() or None,
        "avatar_path": u.get("avatar_path") or None,
    }


def user_update_profile(
    user_id: int,
    display_name: str | None = None,
    bio: str | None = None,
    avatar_path: str | None = None,
) -> bool:
    """به‌روزرسانی نمایش‌نام، بیو یا مسیر آواتار. None یعنی تغییر نده."""
    import config
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        updates = []
        params = []
        if "display_name" in cols and display_name is not None:
            val = (display_name or "").strip()[: getattr(config, "MAX_DISPLAY_NAME_LEN", 128)]
            updates.append("display_name = ?")
            params.append(val or None)
        if "bio" in cols and bio is not None:
            val = (bio or "").strip()[: getattr(config, "MAX_BIO_LEN", 500)]
            updates.append("bio = ?")
            params.append(val or None)
        if "avatar_path" in cols and avatar_path is not None:
            updates.append("avatar_path = ?")
            params.append(avatar_path.strip() if avatar_path else None)
        if not updates:
            return True
        params.append(user_id)
        c.execute("UPDATE users SET " + ", ".join(updates) + " WHERE id = ?", params)
    return True


def user_update_username(user_id: int, new_username: str) -> tuple[bool, str]:
    """تغییر نام کاربری. موفق: (True, '')، ناموفق: (False, پیام خطا)."""
    import config
    new_username = (new_username or "").strip()
    if not new_username:
        return False, "نام کاربری خالی است."
    if len(new_username) < 2:
        return False, "نام کاربری حداقل ۲ کاراکتر باشد."
    if len(new_username) > config.MAX_USERNAME_LEN:
        return False, f"نام کاربری حداکثر {config.MAX_USERNAME_LEN} کاراکتر."
    with get_conn() as c:
        existing = c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id)).fetchone()
        if existing:
            return False, "این نام کاربری قبلاً استفاده شده است."
        c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
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


def user_set_public_key(user_id: int, public_key: bytes) -> bool:
    """ذخیرهٔ کلید عمومی کاربر برای E2EE. کلید باید ۳۲ بایت (Curve25519) باشد."""
    if not public_key or len(public_key) != 32:
        return False
    with get_conn() as c:
        c.execute(
            """INSERT INTO user_public_keys (user_id, public_key, updated_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, updated_at = CURRENT_TIMESTAMP""",
            (user_id, public_key),
        )
    return True


def user_get_public_key(user_id: int) -> bytes | None:
    """کلید عمومی کاربر برای E2EE (۳۲ بایت) یا None."""
    with get_conn() as c:
        row = c.execute(
            "SELECT public_key FROM user_public_keys WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return row[0] if row else None


def get_public_keys_for_users(user_ids: list[int]) -> dict[int, str]:
    """برگرداندن نقشه user_id -> base64(public_key) برای لیست کاربران."""
    if not user_ids:
        return {}
    out = {}
    with get_conn() as c:
        for uid in user_ids:
            row = c.execute(
                "SELECT public_key FROM user_public_keys WHERE user_id = ?",
                (uid,),
            ).fetchone()
            if row:
                import base64
                out[uid] = base64.b64encode(row[0]).decode()
    return out


def is_blocked(blocker_id: int, blocked_id: int) -> bool:
    with get_conn() as c:
        r = c.execute(
            "SELECT 1 FROM blocked WHERE blocker_id = ? AND blocked_id = ?",
            (blocker_id, blocked_id),
        ).fetchone()
        return r is not None


def message_send(sender_id: int, receiver_id: int, body: str, body_e2ee_blob: bytes | None = None, reply_to_id: int | None = None) -> bool:
    import config
    if is_blocked(receiver_id, sender_id):
        return False
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        has_reply = "reply_to_id" in cols
        if body_e2ee_blob is not None:
            if has_reply and reply_to_id:
                c.execute(
                    "INSERT INTO messages (sender_id, receiver_id, body_encrypted, is_e2ee, reply_to_id) VALUES (?, ?, ?, 1, ?)",
                    (sender_id, receiver_id, body_e2ee_blob, reply_to_id),
                )
            else:
                c.execute(
                    "INSERT INTO messages (sender_id, receiver_id, body_encrypted, is_e2ee) VALUES (?, ?, ?, 1)",
                    (sender_id, receiver_id, body_e2ee_blob),
                )
            return True
        if not body or len(body) > config.MAX_MESSAGE_LEN:
            return False
        enc = encrypt_message(body)
        if enc is None:
            return False
        if has_reply and reply_to_id:
            c.execute(
                "INSERT INTO messages (sender_id, receiver_id, body_encrypted, reply_to_id) VALUES (?, ?, ?, ?)",
                (sender_id, receiver_id, enc, reply_to_id),
            )
        else:
            c.execute(
                "INSERT INTO messages (sender_id, receiver_id, body_encrypted) VALUES (?, ?, ?)",
                (sender_id, receiver_id, enc),
            )
        return True


def messages_for_user(user_id: int, other_id: int | None = None, include_e2ee_raw: bool = False):
    """لیست مکالمات یا پیام‌های با یک کاربر خاص. پیام‌های حذف‌شده نشان داده نمی‌شوند.
    اگر include_e2ee_raw=True و other_id مشخص باشد، پیام‌های E2EE به‌صورت body_e2ee (base64) برمی‌گردند
    و سرور متن را رمزگشایی نمی‌کند."""
    import base64
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        has_e2ee = "is_e2ee" in cols
        has_reply_to = "reply_to_id" in cols
        has_edited_at = "edited_at" in cols
        deleted_clause = " AND (deleted_at IS NULL)" if "deleted_at" in cols else ""
        if other_id is not None:
            sel = "id, sender_id, receiver_id, body_encrypted, created_at, message_type, file_path, file_name, mime_type"
            if has_e2ee:
                sel += ", is_e2ee"
            if has_reply_to:
                sel += ", reply_to_id"
            if has_edited_at:
                sel += ", edited_at"
            rows = c.execute(
                """SELECT """ + sel + """
                   FROM messages
                   WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                   """ + deleted_clause + """
                   ORDER BY created_at""",
                (user_id, other_id, other_id, user_id),
            ).fetchall()
        else:
            sel = "id, sender_id, receiver_id, body_encrypted, created_at, message_type, file_path, file_name, mime_type"
            if has_e2ee:
                sel += ", is_e2ee"
            rows = c.execute(
                "SELECT " + sel + " FROM messages WHERE (sender_id = ? OR receiver_id = ?) " + deleted_clause + " ORDER BY created_at DESC",
                (user_id, user_id),
            ).fetchall()
    out = []
    for r in rows:
        idx = 9
        is_e2ee = bool(has_e2ee and len(r) > idx and r[idx])
        if has_e2ee:
            idx += 1
        reply_to_id_val = r[idx] if has_reply_to and len(r) > idx else None
        if has_reply_to:
            idx += 1
        edited_at_val = r[idx] if has_edited_at and len(r) > idx else None
        body_e2ee = ""
        if is_e2ee and include_e2ee_raw and other_id is not None and r[3]:
            body = ""
            body_e2ee = base64.b64encode(r[3]).decode()
        else:
            if is_e2ee:
                body = "[پیام رمزنگاری‌شده — فقط در دستگاه شما و طرف مقابل قابل خواندن است]"
            else:
                body = decrypt_message(r[3]) if r[3] else ""
                if body is None:
                    body = "[پیام رمزنگاری‌شده قابل نمایش نیست]"
                body = body.strip() if body and body != " " else ""
        msg_type = (r[5] if len(r) > 5 else None) or "text"
        file_path = r[6] if len(r) > 6 else None
        file_name = r[7] if len(r) > 7 else None
        mime_type = r[8] if len(r) > 8 else None
        item = {
            "id": r[0], "sender_id": r[1], "receiver_id": r[2],
            "body": body,
            "created_at": r[4],
            "message_type": msg_type,
            "file_path": file_path,
            "file_name": file_name or "",
            "mime_type": mime_type or "",
        }
        if body_e2ee:
            item["body_e2ee"] = body_e2ee
            item["is_e2ee"] = True
        if reply_to_id_val and other_id is not None:
            item["reply_to_id"] = reply_to_id_val
            prep = get_message_reply_preview(reply_to_id_val, user_id, other_id)
            if prep:
                item["reply_preview"] = prep
        if edited_at_val:
            item["edited_at"] = edited_at_val
        out.append(item)
    return out


def get_user_by_id(uid: int) -> dict | None:
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(users)")
        cols = [r[1] for r in cur.fetchall()]
        sel_cols = ["id", "username"]
        if "is_banned" in cols:
            sel_cols.append("is_banned")
        if "display_name" in cols:
            sel_cols.append("display_name")
        if "bio" in cols:
            sel_cols.append("bio")
        if "avatar_path" in cols:
            sel_cols.append("avatar_path")
        row = c.execute(
            "SELECT " + ", ".join(sel_cols) + " FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if not row:
            return None
        out = {"id": row[0], "username": row[1], "is_banned": False}
        i = 2
        if "is_banned" in cols:
            out["is_banned"] = bool(row[i])
            i += 1
        if "display_name" in cols and i < len(row):
            out["display_name"] = row[i]
            i += 1
        if "bio" in cols and i < len(row):
            out["bio"] = row[i]
            i += 1
        if "avatar_path" in cols and i < len(row):
            out["avatar_path"] = row[i]
        return out


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
        has_e2ee = "is_e2ee" in cols
        if has_type and has_e2ee:
            rows = c.execute(
                """SELECT
                     CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS other_id,
                     created_at, body_encrypted, message_type, is_e2ee
                   FROM messages
                   WHERE (sender_id = ? OR receiver_id = ?)
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (user_id, user_id, user_id, limit * 2),
            ).fetchall()
        elif has_type:
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
        is_e2ee = bool(has_e2ee and has_type and len(r) > 4 and r[4])
        if is_e2ee:
            preview = "🔒 پیام"
        else:
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
            "unread_count": unread_count(user_id, other_id),
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
    caption_e2ee_blob: bytes | None = None,
    is_e2ee: bool = False,
) -> bool:
    if is_blocked(receiver_id, sender_id):
        return False
    import config
    if caption_e2ee_blob is not None and is_e2ee:
        body_blob = caption_e2ee_blob
        e2ee_flag = 1
    else:
        caption = (caption or "").strip()[: config.MAX_MESSAGE_LEN]
        enc = encrypt_message(caption or " ")
        if enc is None:
            enc = encrypt_message(" ")
        if enc is None:
            return False
        body_blob = enc
        e2ee_flag = 0
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        if "is_e2ee" in cols:
            c.execute(
                """INSERT INTO messages (sender_id, receiver_id, body_encrypted, message_type, file_path, file_name, mime_type, is_e2ee)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (sender_id, receiver_id, body_blob, message_type, file_path, file_name or "", mime_type or "", e2ee_flag),
            )
        else:
            c.execute(
                """INSERT INTO messages (sender_id, receiver_id, body_encrypted, message_type, file_path, file_name, mime_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (sender_id, receiver_id, body_blob, message_type, file_path, file_name or "", mime_type or ""),
            )
    return True


def get_message_reply_preview(reply_to_id: int, conversation_user_id: int, conversation_other_id: int) -> dict | None:
    """پیش‌نمایش پیامِ در حال پاسخ: فقط اگر آن پیام در همین گفتگو باشد."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        has_e2ee = "is_e2ee" in cols
        row = c.execute(
            "SELECT sender_id, receiver_id, body_encrypted, message_type, is_e2ee FROM messages WHERE id = ? AND deleted_at IS NULL",
            (reply_to_id,),
        ).fetchone() if "deleted_at" in cols else c.execute(
            "SELECT sender_id, receiver_id, body_encrypted, message_type FROM messages WHERE id = ?",
            (reply_to_id,),
        ).fetchone()
        if not row:
            return None
        s, rcv = row[0], row[1]
        if not ((s == conversation_user_id and rcv == conversation_other_id) or (s == conversation_other_id and rcv == conversation_user_id)):
            return None
        is_e2ee = bool(has_e2ee and len(row) > 4 and row[4])
        if is_e2ee:
            body = "[پیام]"
        else:
            body = decrypt_message(row[2]) if row[2] else ""
            if body is None:
                body = "[پیام]"
            else:
                body = (body.strip() or "")[:80]
                if len(body) > 80:
                    body += "…"
        msg_type = (row[3] if len(row) > 3 else None) or "text"
        u = get_user_by_id(s)
        return {"id": reply_to_id, "sender_id": s, "body": body, "message_type": msg_type, "sender_username": u["username"] if u else ""}


def message_edit(message_id: int, user_id: int, new_body: str) -> bool:
    """ویرایش پیام متنی (فقط فرستنده، فقط متن)."""
    import config
    new_body = (new_body or "").strip()
    if not new_body or len(new_body) > config.MAX_MESSAGE_LEN:
        return False
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        if "edited_at" not in [r[1] for r in cur.fetchall()]:
            return False
        row = c.execute(
            "SELECT sender_id, message_type, is_e2ee FROM messages WHERE id = ? AND deleted_at IS NULL",
            (message_id,),
        ).fetchone()
        if not row or row[0] != user_id or (row[1] or "text") != "text":
            return False
        if row[2]:
            return False
        enc = encrypt_message(new_body)
        if enc is None:
            return False
        c.execute(
            "UPDATE messages SET body_encrypted = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?",
            (enc, message_id),
        )
    return True


def unread_count(user_id: int, other_id: int) -> int:
    """تعداد پیام‌های خوانده‌نشده از طرف other_id برای user_id."""
    last_read = read_receipt_get(user_id, other_id)
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        deleted_clause = " AND deleted_at IS NULL" if "deleted_at" in [r[1] for r in cur.fetchall()] else ""
        if last_read is None:
            r = c.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_id = ? AND receiver_id = ?" + deleted_clause,
                (other_id, user_id),
            ).fetchone()
        else:
            r = c.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_id = ? AND receiver_id = ? AND id > ?" + deleted_clause,
                (other_id, user_id, last_read),
            ).fetchone()
        return r[0] if r else 0


def get_message_by_id(msg_id: int) -> dict | None:
    """برای سرو کردن فایل: فقط فیلدهای لازم. is_e2ee برای برگرداندن فایل بدون رمزگشایی سرور."""
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        has_e2ee = "is_e2ee" in cols
        if has_e2ee:
            row = c.execute(
                "SELECT id, sender_id, receiver_id, message_type, file_path, file_name, mime_type, is_e2ee FROM messages WHERE id = ?",
                (msg_id,),
            ).fetchone()
        else:
            row = c.execute(
                "SELECT id, sender_id, receiver_id, message_type, file_path, file_name, mime_type FROM messages WHERE id = ?",
                (msg_id,),
            ).fetchone()
        if not row or not row[4]:
            return None
        out = {
            "id": row[0],
            "sender_id": row[1],
            "receiver_id": row[2],
            "message_type": row[3],
            "file_path": row[4],
            "file_name": row[5] or "",
            "mime_type": row[6] or "",
        }
        if has_e2ee and len(row) > 7:
            out["is_e2ee"] = bool(row[7])
        else:
            out["is_e2ee"] = False
        return out


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
        c.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM groups WHERE created_by_id = ?", (user_id,))
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


# ——— گروه‌ها ———
def group_create(creator_id: int, name: str) -> tuple[dict | None, str]:
    """ساخت گروه. برگرداندن (group_dict, '') یا (None, error)."""
    name = (name or "").strip()
    if not name or len(name) < 2:
        return None, "نام گروه حداقل ۲ کاراکتر باشد."
    if len(name) > 128:
        return None, "نام گروه حداکثر ۱۲۸ کاراکتر."
    code = secrets.token_urlsafe(8)
    with get_conn() as c:
        try:
            cur = c.execute(
                "INSERT INTO groups (name, invite_code, created_by_id) VALUES (?, ?, ?)",
                (name, code, creator_id),
            )
            gid = cur.lastrowid
            c.execute(
                "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
                (gid, creator_id),
            )
        except sqlite3.IntegrityError:
            return None, "خطا در ساخت گروه. دوباره تلاش کنید."
    g = group_get(gid, creator_id)
    if g:
        g["invite_code"] = code
    return (g, "") if g else (None, "خطا در ساخت گروه.")


def group_get(group_id: int, user_id: int) -> dict | None:
    """اطلاعات گروه فقط اگر user_id عضو باشد."""
    with get_conn() as c:
        r = c.execute(
            """SELECT g.id, g.name, g.invite_code, g.created_by_id, g.created_at
               FROM groups g
               INNER JOIN group_members m ON m.group_id = g.id AND m.user_id = ?
               WHERE g.id = ?""",
            (user_id, group_id),
        ).fetchone()
        if not r:
            return None
        members = c.execute(
            "SELECT user_id FROM group_members WHERE group_id = ? ORDER BY joined_at",
            (group_id,),
        ).fetchall()
        member_ids = [row[0] for row in members]
    return {
        "id": r[0],
        "name": r[1],
        "invite_code": r[2],
        "created_by_id": r[3],
        "created_at": r[4],
        "members": [get_user_by_id(uid) for uid in member_ids if get_user_by_id(uid)],
    }


def group_list_for_user(user_id: int) -> list[dict]:
    """لیست گروه‌هایی که کاربر در آن‌ها عضو است (با آخرین پیام برای پیش‌نمایش)."""
    with get_conn() as c:
        rows = c.execute(
            """SELECT g.id, g.name, g.invite_code,
                      (SELECT body_encrypted FROM group_messages WHERE group_id = g.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_body,
                      (SELECT message_type FROM group_messages WHERE group_id = g.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1) AS last_type,
                      (SELECT created_at FROM group_messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) AS last_at
               FROM groups g
               INNER JOIN group_members m ON m.group_id = g.id AND m.user_id = ?
               ORDER BY CASE WHEN last_at IS NULL THEN 0 ELSE 1 END DESC, last_at DESC, g.id DESC""",
            (user_id,),
        ).fetchall()
    out = []
    for r in rows:
        body_enc = r[3]
        msg_type = r[4] or "text"
        last_at = r[5]
        if body_enc:
            preview = decrypt_message(body_enc)
            if preview is None:
                preview = "[پیام]"
            elif msg_type == "image":
                preview = "📷 عکس"
            elif msg_type == "file":
                preview = "📎 فایل"
            elif msg_type == "voice":
                preview = "🎤 ویس"
            else:
                preview = (preview.strip() or " ")[:50]
                if len((preview or "").strip()) > 50:
                    preview += "…"
        else:
            preview = "گروه بدون پیام"
        out.append({
            "id": r[0],
            "name": r[1],
            "invite_code": r[2],
            "last_preview": preview,
            "last_at": last_at,
        })
    return out


def group_is_member(group_id: int, user_id: int) -> bool:
    with get_conn() as c:
        r = c.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        ).fetchone()
    return r is not None


def group_join_by_code(invite_code: str, user_id: int) -> tuple[dict | None, str]:
    """عضویت در گروه با لینک/کد. برگرداندن (group, '') یا (None, error)."""
    code = (invite_code or "").strip()
    if not code:
        return None, "کد دعوت نامعتبر است."
    with get_conn() as c:
        g = c.execute(
            "SELECT id, name FROM groups WHERE invite_code = ?", (code,)
        ).fetchone()
        if not g:
            return None, "گروهی با این لینک یافت نشد."
        gid = g[0]
        exists = c.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            (gid, user_id),
        ).fetchone()
        if exists:
            return group_get(gid, user_id), ""
        c.execute(
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            (gid, user_id),
        )
    return group_get(gid, user_id), ""


def group_leave(group_id: int, user_id: int) -> tuple[bool, str]:
    """ترک گروه. اگر سازنده باشد گروه حذف می‌شود."""
    with get_conn() as c:
        creator = c.execute(
            "SELECT created_by_id FROM groups WHERE id = ?", (group_id,)
        ).fetchone()
        if not creator:
            return False, "گروه یافت نشد."
        if creator[0] == user_id:
            c.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            return True, ""
        c.execute(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            (group_id, user_id),
        )
    return True, ""


def group_messages_list(group_id: int, user_id: int) -> list[dict]:
    """پیام‌های گروه (فقط اگر عضو باشد)."""
    if not group_is_member(group_id, user_id):
        return []
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(group_messages)")
        cols = [r[1] for r in cur.fetchall()]
        deleted_clause = " AND deleted_at IS NULL" if "deleted_at" in cols else ""
        rows = c.execute(
            """SELECT id, sender_id, body_encrypted, created_at, message_type, file_path, file_name, mime_type
               FROM group_messages WHERE group_id = ? """ + deleted_clause + """ ORDER BY created_at""",
            (group_id,),
        ).fetchall()
    out = []
    for r in rows:
        body = decrypt_message(r[2]) if r[2] else ""
        if body is None:
            body = "[پیام رمزنگاری‌شده قابل نمایش نیست]"
        msg_type = (r[4] if len(r) > 4 else None) or "text"
        out.append({
            "id": r[0],
            "sender_id": r[1],
            "body": body.strip() if body and body != " " else "",
            "created_at": r[3],
            "message_type": msg_type,
            "file_path": r[5] if len(r) > 5 else None,
            "file_name": (r[6] if len(r) > 6 else None) or "",
            "mime_type": (r[7] if len(r) > 7 else None) or "",
        })
    return out


def group_message_send(group_id: int, sender_id: int, body: str) -> bool:
    if not group_is_member(group_id, sender_id):
        return False
    import config
    if not body or len(body) > config.MAX_MESSAGE_LEN:
        return False
    enc = encrypt_message(body)
    if enc is None:
        return False
    with get_conn() as c:
        c.execute(
            """INSERT INTO group_messages (group_id, sender_id, body_encrypted) VALUES (?, ?, ?)""",
            (group_id, sender_id, enc),
        )
    return True


def group_message_send_media(
    group_id: int,
    sender_id: int,
    caption: str,
    message_type: str,
    file_path: str,
    file_name: str,
    mime_type: str,
) -> bool:
    if not group_is_member(group_id, sender_id):
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
            """INSERT INTO group_messages (group_id, sender_id, body_encrypted, message_type, file_path, file_name, mime_type)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (group_id, sender_id, enc, message_type, file_path, file_name or "", mime_type or ""),
        )
    return True


def get_group_message_by_id(msg_id: int) -> dict | None:
    with get_conn() as c:
        row = c.execute(
            """SELECT id, group_id, sender_id, message_type, file_path, file_name, mime_type
               FROM group_messages WHERE id = ?""",
            (msg_id,),
        ).fetchone()
        if not row or not row[4]:
            return None
        return {
            "id": row[0],
            "group_id": row[1],
            "sender_id": row[2],
            "message_type": row[3],
            "file_path": row[4],
            "file_name": row[5] or "",
            "mime_type": row[6] or "",
        }


def group_message_delete(message_id: int, user_id: int) -> bool:
    with get_conn() as c:
        cur = c.execute("PRAGMA table_info(group_messages)")
        if "deleted_at" not in [r[1] for r in cur.fetchall()]:
            return False
        r = c.execute(
            "SELECT sender_id FROM group_messages WHERE id = ?", (message_id,)
        ).fetchone()
        if not r or r[0] != user_id:
            return False
        c.execute(
            "UPDATE group_messages SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?",
            (message_id,),
        )
    return True
