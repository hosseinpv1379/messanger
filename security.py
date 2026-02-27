# -*- coding: utf-8 -*-
"""امنیت: محدودیت نرخ، CSRF، هدرهای امنیتی."""
import time
import secrets
from collections import defaultdict
from threading import Lock

# محدودیت درخواست: آدرس IP -> لیست زمان‌های درخواست
_rate_log: dict[str, list[float]] = defaultdict(list)
_rate_lock = Lock()

# تنظیمات
RATE_LOGIN_PER_MIN = 5
RATE_REGISTER_PER_MIN = 3
RATE_API_SEND_PER_MIN = 30
RATE_WINDOW_SEC = 60


def _clean_old(times: list[float], window: float) -> None:
    cutoff = time.time() - window
    while times and times[0] < cutoff:
        times.pop(0)


def rate_limit(key: str, max_per_window: int, window_sec: float = RATE_WINDOW_SEC) -> bool:
    """اگر بیش از حد درخواست شده باشد False برمی‌گرداند."""
    with _rate_lock:
        times = _rate_log[key]
        _clean_old(times, window_sec)
        if len(times) >= max_per_window:
            return False
        times.append(time.time())
        return True


def get_client_ip():
    from flask import request
    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"


def csrf_token(session) -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_valid(session, token: str | None) -> bool:
    if not token or "csrf_token" not in session:
        return False
    return secrets.compare_digest(session["csrf_token"], token)


def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(self), camera=(self)"
    return response
