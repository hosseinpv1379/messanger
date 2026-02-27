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
            session["admin_username"] = username
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


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    admin_username = session.get("admin_username")
    current = (request.form.get("current_password") or "")[: config.MAX_PASSWORD_LEN]
    new_pw = (request.form.get("new_password") or "")[: config.MAX_PASSWORD_LEN]
    confirm = (request.form.get("confirm_password") or "")[: config.MAX_PASSWORD_LEN]
    if new_pw != confirm:
        return render_template(
            "admin.html",
            users=db.user_list(),
            change_password_error="رمز جدید و تکرار آن یکسان نیستند.",
            csrf_token=security.csrf_token(session),
        )
    ok, msg = db.admin_update_password(admin_username, current, new_pw)
    if ok:
        return render_template(
            "admin.html",
            users=db.user_list(),
            change_password_ok=True,
            csrf_token=security.csrf_token(session),
        )
    return render_template(
        "admin.html",
        users=db.user_list(),
        change_password_error=msg,
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


@app.route("/api/conversations")
@user_required
def api_conversations():
    """لیست گفتگوهای اخیر (هیستوری چت) برای نمایش به کاربر."""
    uid = session["user_id"]
    convos = db.get_conversations(uid)
    return jsonify(convos)


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


def _get_csrf_from_request():
    csrf = request.headers.get("X-CSRF-Token")
    if csrf:
        return csrf
    if request.is_json:
        return (request.get_json() or {}).get("csrf_token")
    return request.form.get("csrf_token")


@app.route("/api/send", methods=["POST"])
@user_required
def api_send():
    ip = security.get_client_ip()
    if not security.rate_limit(f"send:{ip}", security.RATE_API_SEND_PER_MIN):
        return jsonify({"ok": False, "error": "ارسال پیام زیاد است. کمی صبر کنید."}), 429
    if not security.csrf_valid(session, _get_csrf_from_request()):
        return jsonify({"ok": False, "error": "درخواست نامعتبر."}), 403
    uid = session["user_id"]

    # ارسال مدیا (عکس/فایل) با multipart
    if request.files:
        f = request.files.get("file")
        receiver_id = request.form.get("receiver_id", type=int)
        caption = (request.form.get("body") or request.form.get("caption") or "").strip()[: config.MAX_MESSAGE_LEN]
        if not f or not receiver_id:
            return jsonify({"ok": False, "error": "فایل یا گیرنده مشخص نیست"}), 400
        if receiver_id == uid:
            return jsonify({"ok": False, "error": "نمی‌توانید به خودتان پیام بفرستید"}), 400
        if db.get_user_by_id(receiver_id) is None:
            return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
        fn = (f.filename or "").strip() or "file"
        ext = Path(fn).suffix.lower()
        content = f.read()
        size = len(content)
        if ext in config.ALLOWED_IMAGE_EXTENSIONS:
            if size > config.MAX_IMAGE_SIZE:
                return jsonify({"ok": False, "error": "حجم عکس حداکثر ۱۰ مگابایت"}), 400
            message_type = "image"
        else:
            if size > config.MAX_FILE_SIZE:
                return jsonify({"ok": False, "error": "حجم فایل حداکثر ۲۵ مگابایت"}), 400
            message_type = "file"
        config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = f"{uuid.uuid4().hex}{ext}"
        file_path = config.UPLOAD_DIR / safe_name
        enc_content = encrypt_bytes(content)
        if not enc_content:
            return jsonify({"ok": False, "error": "خطا در رمزنگاری فایل"}), 500
        file_path.write_bytes(enc_content)
        rel_path = safe_name
        mime = (getattr(f, "content_type") or "") or ("image/jpeg" if message_type == "image" else "application/octet-stream")
        if not db.message_send_media(uid, receiver_id, caption, message_type, str(rel_path), fn, mime):
            file_path.unlink(missing_ok=True)
            return jsonify({"ok": False, "error": "خطا در ذخیره پیام"}), 500
        return jsonify({"ok": True})

    # ارسال متن ساده (JSON)
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


@app.route("/api/file/<int:message_id>")
@user_required
def api_file(message_id):
    """سرو فایل/عکس پیام (فقط برای فرستنده یا گیرنده)."""
    uid = session["user_id"]
    msg = db.get_message_by_id(message_id)
    if not msg or (msg["sender_id"] != uid and msg["receiver_id"] != uid):
        return jsonify({"error": "پیام یافت نشد"}), 404
    full_path = config.UPLOAD_DIR / msg["file_path"]
    if not full_path.exists():
        return jsonify({"error": "فایل یافت نشد"}), 404
    enc = full_path.read_bytes()
    data = decrypt_bytes(enc)
    if not data:
        return jsonify({"error": "خطا در خواندن فایل"}), 500
    mime = msg["mime_type"] or "application/octet-stream"
    name = msg["file_name"] or "file"
    return send_file(BytesIO(data), mimetype=mime, as_attachment=(msg["message_type"] == "file"), download_name=name)


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
