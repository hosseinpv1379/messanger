# -*- coding: utf-8 -*-
import os
from pathlib import Path
from cryptography.fernet import Fernet

_SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production-secret-key-12345")
SECRET_KEY = _SECRET_KEY

_BASE = Path(__file__).resolve().parent
DATABASE = os.path.join(_BASE, "messenger.db")

# کلید رمزنگاری پیام‌ها: اول از env، وگرنه از فایل ثابت (تا بعد از ریستارت هم پیام‌ها خوانا بمانند)
FERNET_KEY_FILE = _BASE / "fernet.key"

_key = os.environ.get("FERNET_KEY")
if _key:
    FERNET_KEY = _key.encode() if isinstance(_key, str) else _key
elif FERNET_KEY_FILE.exists():
    FERNET_KEY = FERNET_KEY_FILE.read_bytes().strip()
else:
    FERNET_KEY = Fernet.generate_key()
    FERNET_KEY_FILE.write_bytes(FERNET_KEY)

# محدودیت‌های ورودی
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 128
MIN_PASSWORD_LEN = 4
MAX_MESSAGE_LEN = 4096

# کوکی نشست
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

# آپلود مدیا
UPLOAD_DIR = _BASE / "uploads"
MAX_IMAGE_SIZE = 10 * 1024 * 1024   # ۱۰ مگ
MAX_FILE_SIZE = 25 * 1024 * 1024    # ۲۵ مگ
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
ALLOWED_FILE_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt", ".zip", ".rar", ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".m4a"}
ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ALLOWED_FILE_MIMES = set()  # برای فایل‌ها محدودیت MIME سخت نمی‌گیریم، فقط پسوند و حجم
