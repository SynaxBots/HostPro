"""
Auth Blueprint for Vesper Python Hosting Platform
Features Telegram User ID + 6-Digit OTP authentication.
No email, username, or password required for user signup and login.
Sessions remembered for 30 days.
"""

import secrets
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g, jsonify
from security import (
    hash_password, verify_password, login_required,
    create_session_record, destroy_session_record,
    record_audit_log, generate_csrf_token
)
from database import get_db_connection, get_setting
from notifications import create_notification
from telegram_service import (
    send_telegram_otp, verify_telegram_otp,
    get_telegram_bot_username, get_telegram_bot_token
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/send-otp', methods=['POST'])
def send_otp():
    """
    Endpoint called by the Send OTP button.
    Dispatches a 6-digit OTP to the user's Telegram ID via the Telegram bot.
    """
    if request.is_json:
        data = request.get_json() or {}
        telegram_id = data.get('telegram_id', '')
    else:
        telegram_id = request.form.get('telegram_id', '')

    result = send_telegram_otp(telegram_id)
    status_code = 200 if result.get('success') else 400
    return jsonify(result), status_code

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login via Telegram User ID and 6-Digit OTP.
    No email, username, or password required.
    """
    if g.current_user:
        return redirect(url_for('dashboard.index'))

    bot_username = get_telegram_bot_username()

    if request.method == 'POST':
        telegram_id = request.form.get('telegram_id', '').strip()
        otp = (request.form.get('otp') or request.form.get('otp_code') or '').strip()

        if not telegram_id or not otp:
            flash('Please enter both your Telegram User ID and the 6-digit OTP.', 'error')
            return render_template('auth/login.html', telegram_id=telegram_id, bot_username=bot_username)

        # Verify the Telegram OTP
        is_valid, err_msg = verify_telegram_otp(telegram_id, otp)
        if not is_valid:
            flash(err_msg, 'error')
            return render_template('auth/login.html', telegram_id=telegram_id, bot_username=bot_username)

        # Check existing user
        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE telegram_id = ? OR username = ? LIMIT 1",
                (telegram_id, f"tg_{telegram_id}")
            ).fetchone()

            if not user:
                # If user doesn't exist yet, automatically create account with welcome bonus
                welcome_bonus = float(get_setting('welcome_bonus_inr', '100.0'))
                username = f"tg_{telegram_id}"
                email = f"{telegram_id}@telegram.vesper"
                pwd_hash = hash_password(secrets.token_hex(24))

                cursor = conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, telegram_id, role, wallet_balance, status)
                    VALUES (?, ?, ?, ?, 'user', ?, 'active')
                    """,
                    (username, email, pwd_hash, telegram_id, welcome_bonus)
                )
                user_id = cursor.lastrowid

                if welcome_bonus > 0:
                    conn.execute(
                        """
                        INSERT INTO transactions 
                        (user_id, amount_inr, type, description, status, transaction_ref)
                        VALUES (?, ?, 'deposit', 'Welcome signup bonus credit', 'success', ?)
                        """,
                        (user_id, welcome_bonus, f"BONUS-{user_id}-SIGNUP")
                    )

                create_notification(
                    user_id,
                    "Welcome to Vesper!",
                    f"Your account was created via Telegram with a ₹{welcome_bonus:.2f} wallet bonus.",
                    "success"
                )

                user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                record_audit_log('user_registered_telegram', user_id, f"Registered via Telegram ID: {telegram_id}", request.remote_addr)

        if user['status'] == 'suspended':
            flash('Your account has been suspended by an administrator. Please contact support.', 'error')
            return render_template('auth/login.html', telegram_id=telegram_id, bot_username=bot_username)

        # Create session with 30-day persistence
        token = create_session_record(
            user['id'],
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        session.permanent = True
        session['user_id'] = user['id']
        session['session_token'] = token

        record_audit_log('user_login_telegram', user['id'], f"Logged in with Telegram ID {telegram_id}", request.remote_addr)
        flash(f"Welcome back, {user['username']}! Signed in via Telegram.", 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('auth/login.html', bot_username=bot_username)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    User signup via Telegram User ID and 6-Digit OTP.
    No email, username, or password required.
    """
    if g.current_user:
        return redirect(url_for('dashboard.index'))

    # Check if registration is open
    allow_reg = get_setting('allow_registration', '1')
    if allow_reg == '0':
        flash('Public registration is currently disabled by system administrators.', 'error')
        return redirect(url_for('auth.login'))

    bot_username = get_telegram_bot_username()

    if request.method == 'POST':
        telegram_id = request.form.get('telegram_id', '').strip()
        otp = (request.form.get('otp') or request.form.get('otp_code') or '').strip()

        if not telegram_id or not otp:
            flash('Please enter both your Telegram User ID and the 6-digit OTP.', 'error')
            return render_template('auth/register.html', telegram_id=telegram_id, bot_username=bot_username)

        # Verify the Telegram OTP
        is_valid, err_msg = verify_telegram_otp(telegram_id, otp)
        if not is_valid:
            flash(err_msg, 'error')
            return render_template('auth/register.html', telegram_id=telegram_id, bot_username=bot_username)

        welcome_bonus = float(get_setting('welcome_bonus_inr', '100.0'))

        try:
            with get_db_connection() as conn:
                existing = conn.execute(
                    "SELECT id, username, status FROM users WHERE telegram_id = ? OR username = ?",
                    (telegram_id, f"tg_{telegram_id}")
                ).fetchone()

                if existing:
                    # User already registered, log them in
                    user_id = existing['id']
                    if existing['status'] == 'suspended':
                        flash('This account has been suspended. Please contact support.', 'error')
                        return render_template('auth/register.html', telegram_id=telegram_id, bot_username=bot_username)

                    token = create_session_record(user_id, request.remote_addr, request.headers.get('User-Agent'))
                    session.permanent = True
                    session['user_id'] = user_id
                    session['session_token'] = token
                    flash(f"Welcome back, {existing['username']}! Signed into your existing account.", 'info')
                    return redirect(url_for('dashboard.index'))

                username = f"tg_{telegram_id}"
                email = f"{telegram_id}@telegram.vesper"
                pwd_hash = hash_password(secrets.token_hex(24))

                cursor = conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, telegram_id, role, wallet_balance, status)
                    VALUES (?, ?, ?, ?, 'user', ?, 'active')
                    """,
                    (username, email, pwd_hash, telegram_id, welcome_bonus)
                )
                user_id = cursor.lastrowid

                # Record welcome bonus in ledger if > 0
                if welcome_bonus > 0:
                    conn.execute(
                        """
                        INSERT INTO transactions 
                        (user_id, amount_inr, type, description, status, transaction_ref)
                        VALUES (?, ?, 'deposit', 'Welcome signup bonus credit', 'success', ?)
                        """,
                        (user_id, welcome_bonus, f"BONUS-{user_id}-SIGNUP")
                    )

            # Create notification
            create_notification(
                user_id,
                "Welcome to Vesper!",
                f"Your account is ready with a complimentary ₹{welcome_bonus:.2f} wallet bonus. Deploy your first server from the dashboard!",
                "success"
            )

            # Auto-login after registration with 30-day session
            token = create_session_record(user_id, request.remote_addr, request.headers.get('User-Agent'))
            session.permanent = True
            session['user_id'] = user_id
            session['session_token'] = token

            record_audit_log('user_registered_telegram', user_id, f"Registered with Telegram ID: {telegram_id}", request.remote_addr)
            flash('Account created successfully via Telegram! Welcome to Vesper.', 'success')
            return redirect(url_for('dashboard.index'))

        except Exception as e:
            flash(f"Error creating account: {str(e)}", 'error')
            return render_template('auth/register.html', telegram_id=telegram_id, bot_username=bot_username)

    return render_template('auth/register.html', bot_username=bot_username)

@auth_bp.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    """
    Dedicated fallback login for platform administrators with username/password.
    """
    if g.current_user and g.current_user.get('role') == 'admin':
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')

        if not username_or_email or not password:
            flash('Please provide both username/email and password.', 'error')
            return render_template('auth/admin_login.html')

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (username_or_email, username_or_email)
            ).fetchone()

        if not user or not verify_password(user['password_hash'], password):
            flash('Invalid admin credentials.', 'error')
            return render_template('auth/admin_login.html')

        if user['role'] != 'admin':
            flash('Access denied: Administrator privileges required.', 'error')
            return render_template('auth/admin_login.html')

        token = create_session_record(user['id'], request.remote_addr, request.headers.get('User-Agent'))
        session.permanent = True
        session['user_id'] = user['id']
        session['session_token'] = token

        flash(f"Welcome back Administrator {user['username']}.", 'success')
        return redirect(url_for('admin.index'))

    return render_template('auth/admin_login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    token = session.get('session_token')
    if token:
        destroy_session_record(token)
    session.clear()
    flash('You have been signed out.', 'info')
    return redirect(url_for('auth.login'))
