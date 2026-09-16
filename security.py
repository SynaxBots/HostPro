import os
import secrets
import time
import zipfile
import re
from functools import wraps
from flask import session, request, redirect, url_for, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db
import config

def hash_password(password):
    return generate_password_hash(password)

def verify_password(pw_hash, password):
    return check_password_hash(pw_hash, password)

def validate_csrf_token(token):
    stored_token = session.get("_csrf_token")
    if not token or not stored_token:
        return False
    return secrets.compare_digest(token, stored_token)

def create_session_record(user_id, ip_address=None, user_agent=None):
    token = secrets.token_urlsafe(32)
    session["user_id"] = user_id
    session["session_token"] = token
    session["_session_token"] = token
    return token

def destroy_session_record(token=None):
    session.clear()

def get_user_by_session_token(token):
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ? LIMIT 1;", (user_id,))
    row = cursor.fetchone()
    if row and row["status"] != "suspended":
        return row
    return None

def record_audit_log(action, user_id, details="", ip_address=""):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?);",
            (user_id or 1, action, str(details), str(ip_address))
        )
        db.commit()
    except Exception as e:
        print(f"[Audit Log Error] {e}")

# In-memory rate limiting store: { ip_key: [timestamps] }
_rate_limits = {}

def generate_csrf_token():
    """Generates or returns existing session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf():
    """Validates CSRF token for state-changing HTTP methods."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        stored_token = session.get("_csrf_token")
        if not token or not stored_token or not secrets.compare_digest(token, stored_token):
            if request.is_json or request.path.startswith("/api/"):
                abort(jsonify({"error": "Invalid or missing CSRF token", "code": "CSRF_ERROR"}), 403)
            flash("Security check failed (CSRF token invalid). Please try again.", "error")
            abort(403)

def check_rate_limit(key, limit=30, window_seconds=60):
    """Enforces in-memory sliding window rate limiting."""
    ip = request.remote_addr or "127.0.0.1"
    bucket_key = f"{key}:{ip}"
    now = time.time()
    
    timestamps = _rate_limits.get(bucket_key, [])
    # Filter timestamps within window
    timestamps = [t for t in timestamps if now - t < window_seconds]
    
    if len(timestamps) >= limit:
        _rate_limits[bucket_key] = timestamps
        return False
        
    timestamps.append(now)
    _rate_limits[bucket_key] = timestamps
    return True

def login_required(f):
    """Ensures user is authenticated."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "code": "UNAUTHORIZED"}), 401
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
            
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            session.clear()
            flash("Session expired or user deleted. Please sign in again.", "error")
            return redirect(url_for("auth.login"))
            
        if user["status"] == "suspended":
            session.clear()
            flash("Your account has been suspended. Please contact support.", "error")
            return redirect(url_for("auth.login"))
            
        from flask import g
        user_dict = dict(user)
        user_dict.pop('password_hash', None)
        g.current_user = user_dict
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Ensures user has 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "code": "UNAUTHORIZED"}), 401
            return redirect(url_for("auth.login", next=request.url))
            
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["role"] != "admin" or user["status"] != "active":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Administrator privilege required", "code": "FORBIDDEN"}), 403
            flash("Access denied: Administrative privileges required.", "error")
            return redirect(url_for("dashboard.index"))
            
        from flask import g
        user_dict = dict(user)
        user_dict.pop('password_hash', None)
        g.current_user = user_dict
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Ensures user belongs to one of allowed roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get("user_id")
            if not user_id:
                return redirect(url_for("auth.login", next=request.url))
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user or user["role"] not in allowed_roles or user["status"] != "active":
                flash("You do not have permission to access this resource.", "error")
                return redirect(url_for("dashboard.index"))
            from flask import g
            user_dict = dict(user)
            user_dict.pop('password_hash', None)
            g.current_user = user_dict
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Returns current authenticated user row or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def is_safe_path(base_dir, path, follow_symlinks=True):
    """
    Checks whether 'path' resides strictly inside 'base_dir',
    preventing path traversal attacks (e.g. '../', absolute escapes).
    """
    base_dir = os.path.abspath(base_dir)
    if follow_symlinks:
        match_path = os.path.realpath(path)
    else:
        match_path = os.path.abspath(path)
    return base_dir == match_path or match_path.startswith(base_dir + os.sep)

def resolve_safe_path(base_dir, relative_path):
    """
    Resolves relative path inside base_dir safely. Returns absolute path or None if unsafe.
    """
    # Clean relative path
    cleaned = relative_path.lstrip("/\\")
    # Disallow null bytes
    if "\0" in cleaned:
        return None
    target = os.path.normpath(os.path.join(base_dir, cleaned))
    if is_safe_path(base_dir, target):
        return target
    return None

def safe_extract_zip(zip_filepath, destination_dir, max_files=1000, max_total_size=150 * 1024 * 1024):
    """
    Safely extracts a ZIP file into destination_dir with Zip-Slip protection,
    bomb protection, and symlink rejection.
    """
    dest_dir = os.path.abspath(destination_dir)
    os.makedirs(dest_dir, exist_ok=True)
    
    total_size = 0
    file_count = 0

    with zipfile.ZipFile(zip_filepath, 'r') as archive:
        for member in archive.infolist():
            file_count += 1
            if file_count > max_files:
                raise ValueError(f"ZIP archive exceeds file count limit ({max_files} files)")
                
            total_size += member.file_size
            if total_size > max_total_size:
                raise ValueError(f"ZIP archive exceeds maximum uncompressed size limit ({max_total_size // (1024*1024)} MB)")
                
            # Prevent Zip-Slip
            target_path = os.path.normpath(os.path.join(dest_dir, member.filename))
            if not is_safe_path(dest_dir, target_path, follow_symlinks=False):
                raise ValueError(f"Malicious archive member path detected: {member.filename}")
                
            # Block extracting or overwriting .sandbox_hook from archives
            member_parts = [p for p in member.filename.replace("\\", "/").split("/") if p and p != "."]
            if ".sandbox_hook" in member_parts:
                raise ValueError("ZIP archive contains protected system file '.sandbox_hook' which cannot be unpacked.")

            # Reject symlinks in zip
            # ZIP format stores unix mode in upper 16 bits of external_attr
            is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
            if is_symlink:
                raise ValueError(f"Symlinks inside ZIP archives are forbidden for security: {member.filename}")

        # Extract safely
        archive.extractall(dest_dir)
        
    return file_count, total_size

def validate_subdomain(subdomain):
    """Validates subdomain format and checks reserved words."""
    if not subdomain:
        return False, "Subdomain cannot be empty"
    subdomain = subdomain.lower().strip()
    if not re.match(r"^[a-z0-9][a-z0-9\-]{1,30}[a-z0-9]$", subdomain):
        return False, "Subdomain must be 3-32 characters, containing only lowercase letters, numbers, and hyphens (cannot start or end with hyphen)"
    
    reserved = {
        "admin", "api", "app", "dashboard", "mail", "ftp", "ssh", "root", "system",
        "billing", "status", "auth", "login", "register", "cdn", "assets", "static",
        "ns1", "ns2", "localhost", "proxy", "portal", "help", "support"
    }
    if subdomain in reserved:
        return False, f"Subdomain '{subdomain}' is reserved by the platform"
        
    return True, subdomain

def log_activity(user_id, action, details="", server_id=None):
    """Records an activity log entry."""
    try:
        db = get_db()
        ip = request.remote_addr if request else ""
        db.execute("""
        INSERT INTO activity_logs (user_id, server_id, action, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """, (user_id, server_id, action, details, ip))
        db.commit()
    except Exception as e:
        print(f"[ActivityLog Error] {e}")

def log_audit(admin_id, action, details, target_user_id=None, target_server_id=None):
    """Records an admin audit log entry."""
    try:
        db = get_db()
        ip = request.remote_addr if request else ""
        db.execute("""
        INSERT INTO audit_logs (admin_id, target_user_id, target_server_id, action, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (admin_id, target_user_id, target_server_id, action, details, ip))
        db.commit()
    except Exception as e:
        print(f"[AuditLog Error] {e}")
