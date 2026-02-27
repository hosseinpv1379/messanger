# -*- coding: utf-8 -*-
import uuid
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, render_template, jsonify, send_file
from io import BytesIO
import config
import db
import security
from crypto_util import encrypt_bytes, decrypt_bytes

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE


@app.after_request
def _security_headers(response):
    return security.add_security_headers(response)


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def inner(*a, **k):
        if session.get("admin") != True:
            return redirect(url_for("login"))
        return f(*a, **k)
    return inner


def user_required(f):
    from functools import wraps
    @wraps(f)
    def inner(*a, **k):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return f(*a, **k)
    return inner


@app.route("/")
def index():
    if session.get("admin"):
        return redirect(url_for("admin_panel"))
    if session.get("user_id"):
        return redirect(url_for("messenger"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", csrf_token=security.csrf_token(session))
    # محدودیت نرخ
    ip = security.get_client_ip()
    if not security.rate_limit(f"login:{ip}", security.RATE_LOGIN_PER_MIN):
        return render_template(
            "login.html",
            csrf_token=security.csrf_token(session),
            error="تعداد تلاش‌های ورود زیاد است. یک دقیقه صبر کنید.",
        ), 429
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return render_template(
            "login.html",
            csrf_token=security.csrf_token(session),
            error="درخواست نامعتبر. دوباره تلاش کنید.",
        ), 400
    username = (request.form.get("username") or "").strip()[: config.MAX_USERNAME_LEN]
    password = (request.form.get("password") or "")[: config.MAX_PASSWORD_LEN]
    as_admin = request.form.get("as_admin") == "1"
    if as_admin:
        if db.admin_verify(username, password):
            session.clear()
            session["admin"] = True
            session["csrf_token"] = security.csrf_token(session)
            return redirect(url_for("admin_panel"))
    else:
        uid = db.user_verify(username, password)
        if uid is not None:
            session.clear()
            session["user_id"] = uid
            session["username"] = username
            session["csrf_token"] = security.csrf_token(session)
            return redirect(url_for("messenger"))
    return render_template(
        "login.html",
        csrf_token=security.csrf_token(session),
        error="نام کاربری یا رمز عبور اشتباه است.",
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@admin_required
def admin_panel():
    users = db.user_list()
    return render_template(
        "admin.html",
        users=users,
        csrf_token=security.csrf_token(session),
    )


@app.route("/admin/add-user", methods=["POST"])
@admin_required
def admin_add_user():
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    username = (request.form.get("username") or "").strip()[: config.MAX_USERNAME_LEN]
    password = (request.form.get("password") or "")[: config.MAX_PASSWORD_LEN]
    ok, msg = db.user_add(username, password)
    if ok:
        return redirect(url_for("admin_panel"))
    return render_template(
        "admin.html",
        users=db.user_list(),
        add_error=msg,
        csrf_token=security.csrf_token(session),
    )


@app.route("/messenger")
@user_required
def messenger():
    return render_template(
        "messenger.html",
        username=session.get("username"),
        user_id=session.get("user_id"),
        csrf_token=security.csrf_token(session),
    )


@app.route("/api/user-by-username/<username>")
@user_required
def api_user_by_username(username):
    """باز کردن چت با نام کاربری (مثل تلگرام)."""
    uid = session["user_id"]
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({"error": "کاربری با این نام یافت نشد"}), 404
    if user["id"] == uid:
        return jsonify({"error": "نمی‌توانید با خودتان چت کنید"}), 400
    return jsonify(user)


@app.route("/api/chat/<int:other_id>")
@user_required
def api_chat(other_id):
    uid = session["user_id"]
    messages = db.messages_for_user(uid, other_id)
    other = db.get_user_by_id(other_id)
    if not other:
        return jsonify({"error": "کاربر یافت نشد"}), 404
    return jsonify({"other": other, "messages": messages})


@app.route("/api/send", methods=["POST"])
@user_required
def api_send():
    ip = security.get_client_ip()
    if not security.rate_limit(f"send:{ip}", security.RATE_API_SEND_PER_MIN):
        return jsonify({"ok": False, "error": "ارسال پیام زیاد است. کمی صبر کنید."}), 429
    csrf = request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")
    if not security.csrf_valid(session, csrf):
        return jsonify({"ok": False, "error": "درخواست نامعتبر."}), 403
    uid = session["user_id"]
    data = request.get_json() or {}
    receiver_id = data.get("receiver_id")
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "متن پیام خالی است"}), 400
    if len(body) > config.MAX_MESSAGE_LEN:
        return jsonify({"ok": False, "error": f"پیام حداکثر {config.MAX_MESSAGE_LEN} کاراکتر مجاز است."}), 400
    if not receiver_id:
        return jsonify({"ok": False, "error": "گیرنده مشخص نیست"}), 400
    if receiver_id == uid:
        return jsonify({"ok": False, "error": "نمی‌توانید به خودتان پیام بفرستید"}), 400
    if db.get_user_by_id(receiver_id) is None:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    if not db.message_send(uid, receiver_id, body):
        return jsonify({"ok": False, "error": "خطا در ارسال پیام"}), 500
    return jsonify({"ok": True})


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
