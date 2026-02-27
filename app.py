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


@app.context_processor
def _inject_active_page():
    """کلاس بدنه برای هر صفحه (صفحهٔ فعال)."""
    name = request.endpoint.replace(".", "-") if request.endpoint else ""
    return {"active_page": name}




def admin_required(f):
    from functools import wraps
    @wraps(f)
    def inner(*a, **k):
        if session.get("admin") != True:
            return redirect(url_for("admin_login"))
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


@app.route("/register", methods=["GET", "POST"])
def register():
    """ثبت‌نام کاربر جدید — هر کس می‌تواند حساب بسازد."""
    if request.method == "GET":
        if session.get("user_id"):
            return redirect(url_for("messenger"))
        if session.get("admin"):
            return redirect(url_for("admin_panel"))
        return render_template("register.html", csrf_token=security.csrf_token(session))
    ip = security.get_client_ip()
    if not security.rate_limit(f"register:{ip}", security.RATE_REGISTER_PER_MIN):
        return render_template(
            "register.html",
            csrf_token=security.csrf_token(session),
            error="تعداد درخواست زیاد است. کمی صبر کنید.",
        ), 429
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return render_template(
            "register.html",
            csrf_token=security.csrf_token(session),
            error="درخواست نامعتبر. دوباره تلاش کنید.",
        ), 400
    username = (request.form.get("username") or "").strip()[: config.MAX_USERNAME_LEN]
    password = (request.form.get("password") or "")[: config.MAX_PASSWORD_LEN]
    confirm = (request.form.get("confirm_password") or "")[: config.MAX_PASSWORD_LEN]
    if password != confirm:
        return render_template(
            "register.html",
            csrf_token=security.csrf_token(session),
            error="رمز عبور و تکرار آن یکسان نیستند.",
        )
    ok, msg = db.user_add(username, password)
    if ok:
        return redirect(url_for("login", registered=1))
    return render_template(
        "register.html",
        csrf_token=security.csrf_token(session),
        error=msg,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            csrf_token=security.csrf_token(session),
            registered=request.args.get("registered") == "1",
        )
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
    uid = db.user_verify(username, password)
    if uid is not None:
        session.clear()
        session["user_id"] = uid
        session["username"] = username
        session["csrf_token"] = security.csrf_token(session)
        next_url = request.args.get("next", "").strip()
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("messenger"))
    return render_template(
        "login.html",
        csrf_token=security.csrf_token(session),
        error="نام کاربری یا رمز عبور اشتباه است.",
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """ورود مدیر — فقط از طریق این مسیر؛ در صفحهٔ ورود کاربران نمایش داده نمی‌شود."""
    if request.method == "GET":
        if session.get("admin"):
            return redirect(url_for("admin_panel"))
        return render_template("admin_login.html", csrf_token=security.csrf_token(session))
    ip = security.get_client_ip()
    if not security.rate_limit(f"admin_login:{ip}", security.RATE_LOGIN_PER_MIN):
        return render_template(
            "admin_login.html",
            csrf_token=security.csrf_token(session),
            error="تعداد تلاش‌های ورود زیاد است. یک دقیقه صبر کنید.",
        ), 429
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return render_template(
            "admin_login.html",
            csrf_token=security.csrf_token(session),
            error="درخواست نامعتبر. دوباره تلاش کنید.",
        ), 400
    username = (request.form.get("username") or "").strip()[: config.MAX_USERNAME_LEN]
    password = (request.form.get("password") or "")[: config.MAX_PASSWORD_LEN]
    if db.admin_verify(username, password):
        session.clear()
        session["admin"] = True
        session["admin_username"] = username
        session["csrf_token"] = security.csrf_token(session)
        return redirect(url_for("admin_panel"))
    return render_template(
        "admin_login.html",
        csrf_token=security.csrf_token(session),
        error="نام کاربری یا رمز عبور اشتباه است.",
    )


@app.route("/logout")
def logout():
    was_admin = session.get("admin")
    session.clear()
    return redirect(url_for("admin_login") if was_admin else url_for("login"))


@app.route("/admin")
@admin_required
def admin_panel():
    search = (request.args.get("q") or "").strip()
    users = db.user_list(search=search)
    stats = _admin_stats()
    return render_template(
        "admin.html",
        users=users,
        search=search,
        stats=stats,
        csrf_token=security.csrf_token(session),
    )


def _admin_stats():
    conn = db.get_conn()
    try:
        users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        return {"users_count": users_count, "messages_count": msg_count}
    finally:
        conn.close()


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
        stats=_admin_stats(),
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
            stats=_admin_stats(),
            change_password_ok=True,
            csrf_token=security.csrf_token(session),
        )
    return render_template(
        "admin.html",
        users=db.user_list(),
        stats=_admin_stats(),
        change_password_error=msg,
        csrf_token=security.csrf_token(session),
    )


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    db.user_delete(user_id)
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_ban_user(user_id):
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    db.user_ban(user_id)
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
@admin_required
def admin_unban_user(user_id):
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    db.user_unban(user_id)
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_user_password(user_id):
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("admin_panel"))
    new_pw = (request.form.get("new_password") or "")[: config.MAX_PASSWORD_LEN]
    ok, msg = db.admin_set_user_password(user_id, new_pw)
    if not ok:
        return render_template(
            "admin.html",
            users=db.user_list(),
            search=request.args.get("q", ""),
            stats=_admin_stats(),
            reset_error=msg,
            reset_user_id=user_id,
            csrf_token=security.csrf_token(session),
        )
    return redirect(url_for("admin_panel"))


@app.route("/messenger")
@user_required
def messenger():
    return render_template(
        "messenger.html",
        username=session.get("username"),
        user_id=session.get("user_id"),
        csrf_token=security.csrf_token(session),
        initial_group_id=request.args.get("group_id", type=int),
        join_error=request.args.get("join_error"),
    )


@app.route("/user/change-password", methods=["GET", "POST"])
@user_required
def user_change_password():
    """تغییر رمز عبور کاربر (غیرمتمرکز — هر کاربر رمز خودش را عوض می‌کند)."""
    if request.method == "GET":
        return render_template(
            "user_change_password.html",
            csrf_token=security.csrf_token(session),
        )
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("user_change_password"))
    uid = session["user_id"]
    current = (request.form.get("current_password") or "")[: config.MAX_PASSWORD_LEN]
    new_pw = (request.form.get("new_password") or "")[: config.MAX_PASSWORD_LEN]
    confirm = (request.form.get("confirm_password") or "")[: config.MAX_PASSWORD_LEN]
    if new_pw != confirm:
        return render_template(
            "user_change_password.html",
            csrf_token=security.csrf_token(session),
            error="رمز جدید و تکرار آن یکسان نیستند.",
        )
    ok, msg = db.user_update_password(uid, current, new_pw)
    if ok:
        return render_template(
            "user_change_password.html",
            csrf_token=security.csrf_token(session),
            success=True,
        )
    return render_template(
        "user_change_password.html",
        csrf_token=security.csrf_token(session),
        error=msg,
    )


@app.route("/user/delete-account", methods=["GET", "POST"])
@user_required
def user_delete_account():
    """حذف حساب کاربری با تأیید رمز عبور."""
    if request.method == "GET":
        return render_template(
            "user_delete_account.html",
            csrf_token=security.csrf_token(session),
        )
    if not security.csrf_valid(session, request.form.get("csrf_token")):
        return redirect(url_for("user_delete_account"))
    uid = session["user_id"]
    password = (request.form.get("password") or "")[: config.MAX_PASSWORD_LEN]
    confirm = (request.form.get("confirm_text") or "").strip()
    if confirm != "حذف کن":
        return render_template(
            "user_delete_account.html",
            csrf_token=security.csrf_token(session),
            error="برای تأیید عبارت «حذف کن» را دقیقاً وارد کنید.",
        )
    if not db.user_verify_by_id(uid, password):
        return render_template(
            "user_delete_account.html",
            csrf_token=security.csrf_token(session),
            error="رمز عبور اشتباه است.",
        )
    db.user_delete(uid)
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/conversations")
@user_required
def api_conversations():
    """لیست گفتگوهای اخیر. q= جستجو در نام کاربری."""
    uid = session["user_id"]
    q = (request.args.get("q") or "").strip()
    convos = db.get_conversations(uid, search=q)
    return jsonify(convos)


@app.route("/api/me/keys", methods=["PUT", "POST"])
@user_required
def api_me_keys():
    """ثبت کلید عمومی کاربر برای رمزنگاری انتها‑به‑انتها (E2EE). کلید ۳۲ بایت Curve25519 به صورت base64."""
    import base64
    uid = session["user_id"]
    data = request.get_json() or {}
    b64 = data.get("public_key") or ""
    try:
        key_bytes = base64.decodebytes(b64.encode() if isinstance(b64, str) else b64)
    except Exception:
        return jsonify({"ok": False, "error": "فرمت کلید نامعتبر"}), 400
    if len(key_bytes) != 32:
        return jsonify({"ok": False, "error": "کلید باید ۳۲ بایت باشد"}), 400
    if db.user_set_public_key(uid, key_bytes):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "خطا در ذخیره"}), 500


@app.route("/api/keys/<int:user_id>")
@user_required
def api_keys_get(user_id):
    """دریافت کلید عمومی یک کاربر برای E2EE (برای رمزنگاری پیام برای او)."""
    key = db.user_get_public_key(user_id)
    if key is None:
        return jsonify({"error": "کلید عمومی یافت نشد"}), 404
    import base64
    return jsonify({"public_key": base64.b64encode(key).decode()})


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


@app.route("/api/chat/<int:other_id>", methods=["GET", "POST"])
@user_required
def api_chat(other_id):
    uid = session["user_id"]
    if request.method == "POST":
        data = request.get_json() or {}
        if data.get("read_receipt"):
            mid = data.get("last_read_message_id", 0)
            if mid:
                db.read_receipt_set(uid, other_id, int(mid))
        return jsonify({"ok": True})
    messages = db.messages_for_user(uid, other_id, include_e2ee_raw=True)
    sender_ids = list({m["sender_id"] for m in messages if m.get("is_e2ee")})
    public_keys = db.get_public_keys_for_users(sender_ids) if sender_ids else {}
    other = db.get_user_by_id(other_id)
    if not other:
        return jsonify({"error": "کاربر یافت نشد"}), 404
    other_read_up_to = db.read_receipt_get(other_id, uid)
    i_blocked_them = db.is_blocked(uid, other_id)
    return jsonify({
        "other": other,
        "messages": messages,
        "public_keys": public_keys,
        "other_read_up_to": other_read_up_to,
        "i_blocked_them": i_blocked_them,
    })


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

    # ارسال مدیا (عکس/فایل) با multipart — پشتیبانی از E2EE: کلاینت فایل رمزشده می‌فرستد، سرور ذخیره می‌کند بدون دسترسی به محتوا
    if request.files:
        import base64
        f = request.files.get("file")
        receiver_id = request.form.get("receiver_id", type=int)
        e2ee_media = request.form.get("e2ee_media") == "1"
        caption_e2ee_b64 = request.form.get("caption_e2ee") or ""
        caption = (request.form.get("body") or request.form.get("caption") or "").strip()[: config.MAX_MESSAGE_LEN]
        if not f or not receiver_id:
            return jsonify({"ok": False, "error": "فایل یا گیرنده مشخص نیست"}), 400
        if receiver_id == uid:
            return jsonify({"ok": False, "error": "نمی‌توانید به خودتان پیام بفرستید"}), 400
        if db.get_user_by_id(receiver_id) is None:
            return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
        if db.is_blocked(receiver_id, uid):
            return jsonify({"ok": False, "error": "شما توسط این کاربر مسدود شده‌اید"}), 403
        fn = (f.filename or "").strip() or "file"
        ext = Path(fn).suffix.lower()
        content = f.read()
        size = len(content)
        is_voice = request.form.get("message_type") == "voice" or (
            (getattr(f, "content_type") or "").startswith("audio/")
        )
        if is_voice:
            if size > config.MAX_VOICE_SIZE:
                return jsonify({"ok": False, "error": "حجم ویس حداکثر ۵ مگابایت"}), 400
            message_type = "voice"
        elif ext in config.ALLOWED_IMAGE_EXTENSIONS:
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
        if e2ee_media:
            file_path.write_bytes(content)
            caption_e2ee_blob = None
            if caption_e2ee_b64:
                try:
                    caption_e2ee_blob = base64.b64decode((caption_e2ee_b64 or "").encode() if isinstance(caption_e2ee_b64, str) else caption_e2ee_b64)
                except Exception:
                    caption_e2ee_blob = None
            if not db.message_send_media(uid, receiver_id, "", message_type, str(safe_name), fn, request.form.get("mime_type") or "application/octet-stream", caption_e2ee_blob=caption_e2ee_blob, is_e2ee=True):
                file_path.unlink(missing_ok=True)
                return jsonify({"ok": False, "error": "خطا در ذخیره پیام"}), 500
        else:
            enc_content = encrypt_bytes(content)
            if not enc_content:
                return jsonify({"ok": False, "error": "خطا در رمزنگاری فایل"}), 500
            file_path.write_bytes(enc_content)
            mime = (getattr(f, "content_type") or "") or ("image/jpeg" if message_type == "image" else "application/octet-stream")
            if not db.message_send_media(uid, receiver_id, caption, message_type, str(safe_name), fn, mime):
                file_path.unlink(missing_ok=True)
                return jsonify({"ok": False, "error": "خطا در ذخیره پیام"}), 500
        return jsonify({"ok": True})

    # ارسال متن ساده (JSON) — پشتیبانی از E2EE
    data = request.get_json() or {}
    receiver_id = data.get("receiver_id")
    e2ee_ciphertext_b64 = data.get("e2ee_ciphertext")
    if e2ee_ciphertext_b64:
        # پیام E2EE: کلاینت رمزنگاری کرده؛ سرور فقط ذخیره می‌کند
        import base64
        if not receiver_id:
            return jsonify({"ok": False, "error": "گیرنده مشخص نیست"}), 400
        if receiver_id == uid:
            return jsonify({"ok": False, "error": "نمی‌توانید به خودتان پیام بفرستید"}), 400
        if db.get_user_by_id(receiver_id) is None:
            return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
        if db.is_blocked(receiver_id, uid):
            return jsonify({"ok": False, "error": "شما توسط این کاربر مسدود شده‌اید"}), 403
        try:
            blob = base64.decodebytes((e2ee_ciphertext_b64 or "").encode() if isinstance(e2ee_ciphertext_b64, str) else e2ee_ciphertext_b64)
        except Exception:
            return jsonify({"ok": False, "error": "فرمت پیام رمزنگاری‌شده نامعتبر"}), 400
        if not db.message_send(uid, receiver_id, "", body_e2ee_blob=blob):
            return jsonify({"ok": False, "error": "خطا در ارسال پیام"}), 500
        return jsonify({"ok": True})
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
    if db.is_blocked(receiver_id, uid):
        return jsonify({"ok": False, "error": "شما توسط این کاربر مسدود شده‌اید"}), 403
    if not db.message_send(uid, receiver_id, body):
        return jsonify({"ok": False, "error": "خطا در ارسال پیام"}), 500
    return jsonify({"ok": True})


@app.route("/api/message/<int:message_id>", methods=["DELETE"])
@user_required
def api_delete_message(message_id):
    uid = session["user_id"]
    if not security.csrf_valid(session, request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    if db.message_delete(message_id, uid):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "امکان حذف این پیام نیست"}), 400


@app.route("/api/conversation/<int:other_id>/clear", methods=["POST"])
@user_required
def api_clear_conversation(other_id):
    """حذف کامل گفتگو با یک کاربر (همهٔ پیام‌ها برای هر دو طرف)."""
    uid = session["user_id"]
    if not security.csrf_valid(session, request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    if other_id == uid:
        return jsonify({"ok": False, "error": "نامعتبر"}), 400
    if db.get_user_by_id(other_id) is None:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    db.conversation_clear(uid, other_id)
    return jsonify({"ok": True})


@app.route("/api/block/<int:other_id>", methods=["POST", "DELETE"])
@user_required
def api_block(other_id):
    uid = session["user_id"]
    if not security.csrf_valid(session, request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    if other_id == uid:
        return jsonify({"ok": False, "error": "امکان مسدود کردن خودتان نیست"}), 400
    if db.get_user_by_id(other_id) is None:
        return jsonify({"ok": False, "error": "کاربر یافت نشد"}), 404
    if request.method == "POST":
        db.block_add(uid, other_id)
        return jsonify({"ok": True})
    db.block_remove(uid, other_id)
    return jsonify({"ok": True})


@app.route("/api/blocked")
@user_required
def api_blocked_list():
    uid = session["user_id"]
    users = db.block_list(uid)
    return jsonify(users)


@app.route("/api/file/<int:message_id>")
@user_required
def api_file(message_id):
    """سرو فایل/عکس پیام. اگر is_e2ee باشد سرور رمزگشایی نمی‌کند و خام برمی‌گرداند تا کلاینت رمزگشایی کند."""
    uid = session["user_id"]
    msg = db.get_message_by_id(message_id)
    if not msg or (msg["sender_id"] != uid and msg["receiver_id"] != uid):
        return jsonify({"error": "پیام یافت نشد"}), 404
    full_path = config.UPLOAD_DIR / msg["file_path"]
    if not full_path.exists():
        return jsonify({"error": "فایل یافت نشد"}), 404
    raw = full_path.read_bytes()
    if msg.get("is_e2ee"):
        return send_file(BytesIO(raw), mimetype="application/octet-stream", as_attachment=False, download_name="")
    data = decrypt_bytes(raw)
    if not data:
        return jsonify({"error": "خطا در خواندن فایل"}), 500
    mime = msg["mime_type"] or "application/octet-stream"
    name = msg["file_name"] or "file"
    return send_file(BytesIO(data), mimetype=mime, as_attachment=(msg["message_type"] == "file"), download_name=name)


# ——— گروه‌ها ———
@app.route("/api/groups", methods=["GET"])
@user_required
def api_groups_list():
    uid = session["user_id"]
    groups = db.group_list_for_user(uid)
    return jsonify(groups)


@app.route("/api/groups", methods=["POST"])
@user_required
def api_groups_create():
    if not security.csrf_valid(session, _get_csrf_from_request()):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    uid = session["user_id"]
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    group, err = db.group_create(uid, name)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    base = request.url_root.rstrip("/")
    invite_link = f"{base}/join/{group['invite_code']}"
    return jsonify({"ok": True, "group": group, "invite_link": invite_link})


@app.route("/api/groups/<int:group_id>")
@user_required
def api_group_get(group_id):
    uid = session["user_id"]
    group = db.group_get(group_id, uid)
    if not group:
        return jsonify({"error": "گروه یافت نشد یا شما عضو نیستید"}), 404
    return jsonify(group)


@app.route("/api/groups/join", methods=["POST"])
@user_required
def api_groups_join():
    if not security.csrf_valid(session, _get_csrf_from_request()):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    uid = session["user_id"]
    data = request.get_json() or {}
    code = (data.get("invite_code") or data.get("code") or "").strip()
    group, err = db.group_join_by_code(code, uid)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "group": group})


@app.route("/api/groups/<int:group_id>/messages")
@user_required
def api_group_messages(group_id):
    uid = session["user_id"]
    if not db.group_is_member(group_id, uid):
        return jsonify({"error": "گروه یافت نشد یا عضو نیستید"}), 404
    messages = db.group_messages_list(group_id, uid)
    senders = {}
    for m in messages:
        sid = m["sender_id"]
        if sid not in senders:
            u = db.get_user_by_id(sid)
            senders[sid] = u["username"] if u else ""
    return jsonify({"messages": messages, "senders": senders})


@app.route("/api/groups/<int:group_id>/send", methods=["POST"])
@user_required
def api_group_send(group_id):
    ip = security.get_client_ip()
    if not security.rate_limit(f"send:{ip}", security.RATE_API_SEND_PER_MIN):
        return jsonify({"ok": False, "error": "ارسال پیام زیاد است. کمی صبر کنید."}), 429
    if not security.csrf_valid(session, _get_csrf_from_request()):
        return jsonify({"ok": False, "error": "درخواست نامعتبر."}), 403
    uid = session["user_id"]
    if not db.group_is_member(group_id, uid):
        return jsonify({"ok": False, "error": "عضو گروه نیستید"}), 403

    if request.files:
        f = request.files.get("file")
        caption = (request.form.get("body") or request.form.get("caption") or "").strip()[: config.MAX_MESSAGE_LEN]
        if not f:
            return jsonify({"ok": False, "error": "فایل مشخص نیست"}), 400
        fn = (f.filename or "").strip() or "file"
        ext = Path(fn).suffix.lower()
        content = f.read()
        size = len(content)
        is_voice = request.form.get("message_type") == "voice" or (
            (getattr(f, "content_type") or "").startswith("audio/")
        )
        if is_voice:
            if size > config.MAX_VOICE_SIZE:
                return jsonify({"ok": False, "error": "حجم ویس حداکثر ۵ مگابایت"}), 400
            message_type = "voice"
        elif ext in config.ALLOWED_IMAGE_EXTENSIONS:
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
        if not db.group_message_send_media(group_id, uid, caption, message_type, str(rel_path), fn, mime):
            file_path.unlink(missing_ok=True)
            return jsonify({"ok": False, "error": "خطا در ذخیره پیام"}), 500
        return jsonify({"ok": True})

    data = request.get_json() or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify({"ok": False, "error": "متن پیام خالی است"}), 400
    if len(body) > config.MAX_MESSAGE_LEN:
        return jsonify({"ok": False, "error": f"پیام حداکثر {config.MAX_MESSAGE_LEN} کاراکتر مجاز است."}), 400
    if not db.group_message_send(group_id, uid, body):
        return jsonify({"ok": False, "error": "خطا در ارسال پیام"}), 500
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/leave", methods=["POST"])
@user_required
def api_group_leave(group_id):
    if not security.csrf_valid(session, request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    uid = session["user_id"]
    ok, err = db.group_leave(group_id, uid)
    if not ok:
        return jsonify({"ok": False, "error": err or "خطا"}), 400
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/message/<int:message_id>", methods=["DELETE"])
@user_required
def api_group_delete_message(group_id, message_id):
    if not security.csrf_valid(session, request.headers.get("X-CSRF-Token") or (request.get_json() or {}).get("csrf_token")):
        return jsonify({"ok": False, "error": "درخواست نامعتبر"}), 403
    uid = session["user_id"]
    if not db.group_is_member(group_id, uid):
        return jsonify({"ok": False, "error": "عضو گروه نیستید"}), 403
    if db.group_message_delete(message_id, uid):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "امکان حذف این پیام نیست"}), 400


@app.route("/api/group-file/<int:message_id>")
@user_required
def api_group_file(message_id):
    uid = session["user_id"]
    msg = db.get_group_message_by_id(message_id)
    if not msg:
        return jsonify({"error": "پیام یافت نشد"}), 404
    if not db.group_is_member(msg["group_id"], uid):
        return jsonify({"error": "دسترسی مجاز نیست"}), 403
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


@app.route("/join/<invite_code>")
def join_group_link(invite_code):
    """لینک دعوت گروه: اگر لاگین باشد عضو می‌شود و به مسنجر می‌رود، وگرنه به لاگین."""
    if session.get("user_id") is None:
        return redirect(url_for("login", next=request.url))
    uid = session["user_id"]
    group, err = db.group_join_by_code(invite_code.strip(), uid)
    if err:
        return redirect(url_for("messenger", join_error=err))
    return redirect(url_for("messenger", group_id=group["id"]))


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
