"""
Dashboard and User Operations Blueprint
Handles user dashboard, server creation wizard, billing, plans, notifications, support tickets, and account settings.
"""

import os
import random
import string
import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from security import login_required, record_audit_log, hash_password, verify_password
from database import get_db_connection
from config import BASE_DOMAIN, DEFAULT_PORT_START, DEFAULT_PORT_END
from domain_manager import is_subdomain_available, reserve_subdomain
from port_manager import allocate_port
from process_manager import create_server_instance
from billing import add_wallet_funds, purchase_subscription, get_user_subscriptions
from notifications import get_user_notifications, mark_all_notifications_read, create_notification
from resource_manager import get_server_resource_usage
from upi_service import create_upi_order, get_upi_order, UPI_VPA, UPI_PAYEE_NAME

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    user_id = g.current_user['id']
    with get_db_connection() as conn:
        servers = conn.execute(
            """
            SELECT s.*, p.name as plan_name, p.ram_mb as plan_ram_mb, p.storage_mb as storage_limit_mb
            FROM servers s
            LEFT JOIN subscriptions sub ON s.subscription_id = sub.id
            LEFT JOIN plans p ON sub.plan_id = p.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
            """,
            (user_id,)
        ).fetchall()

        # Announcements
        announcements = conn.execute(
            "SELECT * FROM announcements WHERE is_published = 1 ORDER BY created_at DESC LIMIT 3"
        ).fetchall()

        # Recent activities
        activities = conn.execute(
            "SELECT * FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 6",
            (user_id,)
        ).fetchall()

    running_count = sum(1 for s in servers if s['status'] == 'running')
    total_storage_bytes = sum(s['storage_used_bytes'] or 0 for s in servers)
    total_storage_mb = total_storage_bytes / (1024 * 1024)

    active_subs = get_user_subscriptions(user_id)

    return render_template(
        'dashboard/index.html',
        servers=servers,
        running_count=running_count,
        total_storage_mb=total_storage_mb,
        active_subs=active_subs,
        announcements=announcements,
        activities=activities,
        base_domain=BASE_DOMAIN
    )

@dashboard_bp.route('/dashboard/create-server', methods=['GET', 'POST'])
@dashboard_bp.route('/dashboard/servers/create', methods=['GET', 'POST'])
@login_required
def create_server():
    user_id = g.current_user['id']
    subscriptions = get_user_subscriptions(user_id)

    if request.method == 'POST':
        subscription_id = request.form.get('subscription_id')
        name = request.form.get('name', '').strip()
        entry_file = request.form.get('entry_file', 'app.py').strip()
        startup_command = request.form.get('startup_command', '').strip() or None
        auto_restart = 1 if request.form.get('auto_restart') == '1' else 0
        zip_file = request.files.get('project_zip')

        if not name:
            flash('Server name is required.', 'error')
            return redirect(url_for('dashboard.create_server'))

        # Check subscription availability
        selected_sub = next((s for s in subscriptions if str(s['id']) == str(subscription_id)), None)
        if not selected_sub or selected_sub['used_servers'] >= selected_sub['max_servers']:
            flash('Selected subscription is invalid or has reached its max server capacity.', 'error')
            return redirect(url_for('dashboard.create_server'))

        # Auto-generate a clean internal identifier/subdomain
        subdomain = request.form.get('subdomain', '').strip().lower()
        if not subdomain or not is_subdomain_available(subdomain):
            for _ in range(10):
                candidate = f"app-{secrets.token_hex(4)}"
                if is_subdomain_available(candidate):
                    subdomain = candidate
                    break
            else:
                subdomain = f"app-{int(secrets.token_hex(3), 16)}"

        # Allocate port
        assigned_port = allocate_port()
        if not assigned_port:
            flash('No available host ports in the allocation pool. Please contact support.', 'error')
            return redirect(url_for('dashboard.create_server'))

        # Provision in DB
        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO servers 
                (user_id, subscription_id, name, subdomain, assigned_port, status, entry_file, startup_command, auto_restart)
                VALUES (?, ?, ?, ?, ?, 'stopped', ?, ?, ?)
                """,
                (user_id, subscription_id, name, subdomain, assigned_port, entry_file, startup_command, auto_restart)
            )
            server_id = cursor.lastrowid

        # Reserve domain
        reserve_subdomain(subdomain, user_id, server_id)

        # Create server directory and initial template/zip
        zip_bytes = None
        if zip_file and zip_file.filename.endswith('.zip'):
            zip_bytes = zip_file.read()

        create_server_instance(server_id, user_id, assigned_port, subdomain, zip_bytes)

        record_audit_log('server_created', user_id, f"Created server '{name}' on port {assigned_port}", request.remote_addr)
        flash(f"Server '{name}' created successfully on port {assigned_port}!", 'success')
        return redirect(url_for('server.detail', server_id=server_id))

    return render_template(
        'dashboard/create_server.html',
        subscriptions=subscriptions,
        base_domain=BASE_DOMAIN
    )

@dashboard_bp.route('/plans')
def plans():
    with get_db_connection() as conn:
        all_plans = conn.execute(
            "SELECT * FROM plans WHERE is_active = 1 ORDER BY price_inr ASC"
        ).fetchall()

    return render_template('plans.html', plans=all_plans)

@dashboard_bp.route('/billing')
@dashboard_bp.route('/dashboard/wallet')
@login_required
def billing():
    user_id = g.current_user['id']
    subscriptions = get_user_subscriptions(user_id)

    with get_db_connection() as conn:
        transactions = conn.execute(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
            (user_id,)
        ).fetchall()

    return render_template(
        'billing.html',
        subscriptions=subscriptions,
        transactions=transactions
    )

@dashboard_bp.route('/billing/deposit', methods=['GET', 'POST'])
@dashboard_bp.route('/billing/initiate-upi', methods=['GET', 'POST'])
@login_required
def deposit():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            amount = 0
    else:
        try:
            amount = float(request.args.get('amount', 0))
        except ValueError:
            amount = 0

    if amount < 1.0:
        flash('Please enter a valid deposit amount of at least ₹1.00.', 'error')
        return redirect(url_for('dashboard.billing'))

    order, err = create_upi_order(g.current_user['id'], amount)
    if err:
        flash(f"Failed to generate UPI payment: {err}", 'error')
        return redirect(url_for('dashboard.billing'))

    return redirect(url_for('dashboard.upi_pay', utr=order['utr']))

@dashboard_bp.route('/billing/pay-upi')
@login_required
def upi_pay():
    utr = request.args.get('utr', '').strip()
    if not utr:
        flash('Invalid payment session reference.', 'error')
        return redirect(url_for('dashboard.billing'))

    order = get_upi_order(g.current_user['id'], utr)
    if not order:
        flash('Payment order not found.', 'error')
        return redirect(url_for('dashboard.billing'))

    order_dict = dict(order)
    order_dict['vpa'] = UPI_VPA
    order_dict['payee_name'] = UPI_PAYEE_NAME
    # Re-derive upi_uri
    order_dict['upi_uri'] = f"upi://pay?pa={UPI_VPA}&pn={UPI_PAYEE_NAME}&am={float(order['expected_amount']):.2f}&tr={utr}&cu=INR&tn=AddFunds_{utr}"

    return render_template('billing_upi_pay.html', order=order_dict)

@dashboard_bp.route('/billing/purchase-plan', methods=['POST'])
@login_required
def purchase_plan():
    plan_id = int(request.form.get('plan_id'))
    success, message = purchase_subscription(g.current_user['id'], plan_id)

    if success:
        flash(message, 'success')
        record_audit_log('plan_purchased', g.current_user['id'], message, request.remote_addr)
        return redirect(url_for('dashboard.index'))
    else:
        flash(message, 'error')
        return redirect(url_for('dashboard.billing'))

@dashboard_bp.route('/billing/renew-subscription', methods=['POST'])
@login_required
def renew_subscription():
    sub_id = int(request.form.get('subscription_id'))
    # Fetch subscription & plan price
    with get_db_connection() as conn:
        sub = conn.execute(
            "SELECT s.*, p.price_inr, p.billing_days, p.name as plan_name FROM subscriptions s JOIN plans p ON s.plan_id = p.id WHERE s.id = ? AND s.user_id = ?",
            (sub_id, g.current_user['id'])
        ).fetchone()

        if not sub:
            flash('Subscription not found.', 'error')
            return redirect(url_for('dashboard.billing'))

        price = sub['price_inr']
        if g.current_user['wallet_balance'] < price:
            flash(f"Insufficient wallet balance. Please add at least ₹{price - g.current_user['wallet_balance']:.2f}.", 'error')
            return redirect(url_for('dashboard.billing'))

        # Deduct wallet
        conn.execute(
            "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?",
            (price, g.current_user['id'])
        )
        conn.execute(
            """
            INSERT INTO transactions (user_id, amount_inr, type, description, status, transaction_ref)
            VALUES (?, ?, 'plan_renewal', ?, 'success', ?)
            """,
            (g.current_user['id'], price, f"Subscription renewal: {sub['plan_name']}", f"RENEW-{sub_id}-{random.randint(1000, 9999)}")
        )
        conn.execute(
            """
            UPDATE subscriptions 
            SET expiry_date = datetime(expiry_date, '+' || ? || ' days'), status = 'active'
            WHERE id = ?
            """,
            (sub['billing_days'], sub_id)
        )

    flash('Subscription renewed successfully!', 'success')
    return redirect(url_for('dashboard.billing'))

@dashboard_bp.route('/notifications')
@login_required
def notifications():
    user_id = g.current_user['id']
    notifs = get_user_notifications(user_id, limit=50)
    return render_template('notifications.html', notifications=notifs)

@dashboard_bp.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    mark_all_notifications_read(g.current_user['id'])
    flash('All notifications marked as read.', 'info')
    return redirect(url_for('dashboard.notifications'))

@dashboard_bp.route('/account', methods=['GET'])
@dashboard_bp.route('/account/settings', methods=['GET'])
@dashboard_bp.route('/settings', methods=['GET'])
@dashboard_bp.route('/profile', methods=['GET'])
@dashboard_bp.route('/dashboard/profile', methods=['GET'])
@dashboard_bp.route('/dashboard/settings', methods=['GET'])
@login_required
def account():
    return render_template('account.html')

@dashboard_bp.route('/account/update-profile', methods=['POST'])
@login_required
def update_profile():
    new_username = request.form.get('username', '').strip()
    new_email = request.form.get('email', '').strip()

    if not new_username:
        flash('Username cannot be empty.', 'error')
        return redirect(url_for('dashboard.account'))

    import re
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', new_username):
        flash('Username must be 3-32 alphanumeric characters, dashes, or underscores.', 'error')
        return redirect(url_for('dashboard.account'))

    with get_db_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, g.current_user['id'])).fetchone()
        if existing:
            flash('Username is already taken by another user.', 'error')
            return redirect(url_for('dashboard.account'))

        if new_email:
            existing_email = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, g.current_user['id'])).fetchone()
            if existing_email:
                flash('Email is already registered by another user.', 'error')
                return redirect(url_for('dashboard.account'))
            conn.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (new_username, new_email, g.current_user['id']))
        else:
            conn.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, g.current_user['id']))

    record_audit_log('profile_updated', g.current_user['id'], f'Updated profile username={new_username}', request.remote_addr)
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('dashboard.account'))

@dashboard_bp.route('/account/change-password', methods=['POST'])
@login_required
def change_password():
    current_pwd = request.form.get('current_password', '')
    new_pwd = request.form.get('new_password', '')
    confirm_pwd = request.form.get('confirm_password', '')

    if new_pwd != confirm_pwd:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('dashboard.account'))

    if len(new_pwd) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('dashboard.account'))

    with get_db_connection() as conn:
        user = conn.execute("SELECT password_hash, telegram_id FROM users WHERE id = ?", (g.current_user['id'],)).fetchone()
        # If user registered via Telegram and never had a human password, allow setting initial password directly
        if user['telegram_id'] and not current_pwd:
            pass
        elif not verify_password(user['password_hash'], current_pwd):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('dashboard.account'))

        new_hash = hash_password(new_pwd)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, g.current_user['id']))

    record_audit_log('password_changed', g.current_user['id'], 'User updated password', request.remote_addr)
    flash('Password updated successfully.', 'success')
    return redirect(url_for('dashboard.account'))

@dashboard_bp.route('/support')
@login_required
def support():
    user_id = g.current_user['id']
    with get_db_connection() as conn:
        tickets = conn.execute(
            "SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        servers = conn.execute("SELECT id, name, subdomain FROM servers WHERE user_id = ?", (user_id,)).fetchall()

    return render_template('support.html', tickets=tickets, servers=servers)

@dashboard_bp.route('/support/create', methods=['POST'])
@login_required
def create_ticket():
    subject = request.form.get('subject', '').strip()
    message = request.form.get('message', '').strip()
    server_id = request.form.get('server_id') or None
    priority = request.form.get('priority', 'medium')

    if not subject or not message:
        flash('Subject and message are required.', 'error')
        return redirect(url_for('dashboard.support'))

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO support_tickets (user_id, server_id, subject, message, priority, status)
            VALUES (?, ?, ?, ?, ?, 'open')
            """,
            (g.current_user['id'], server_id, subject, message, priority)
        )

    flash('Support ticket opened. Our team will review your inquiry shortly.', 'success')
    return redirect(url_for('dashboard.support'))
