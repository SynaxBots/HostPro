"""
Admin Control Blueprint
Comprehensive administrative capabilities: telemetry, user oversight, global server management,
plan CRUD in INR, broadcasts, audit logs, and database backup snapshots.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, send_file, jsonify
from security import admin_required, record_audit_log
from database import get_db_connection, set_setting, get_setting
from resource_manager import get_vps_node_metrics
from port_manager import get_port_pool_status, allocate_port
from config import BASE_DOMAIN, DB_PATH
from billing import add_wallet_funds, admin_adjust_wallet
from process_manager import start_server_process, stop_server_process, delete_server_instance, create_server_instance
from domain_manager import is_subdomain_available, reserve_subdomain
from notifications import create_notification
import shutil
import random
import secrets
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('')
@admin_bp.route('/')
@admin_required
def index():
    vps = get_vps_node_metrics()
    port_stats = get_port_pool_status()

    with get_db_connection() as conn:
        total_users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
        total_servers = conn.execute("SELECT COUNT(*) as c FROM servers").fetchone()['c']
        running_servers = conn.execute("SELECT COUNT(*) as c FROM servers WHERE status = 'running'").fetchone()['c']
        total_subs = conn.execute("SELECT COUNT(*) as c FROM subscriptions WHERE status = 'active'").fetchone()['c']

        # Total revenue from deposits and subscriptions
        rev_row = conn.execute(
            "SELECT SUM(amount_inr) as s FROM transactions WHERE type IN ('plan_purchase', 'plan_renewal') AND status = 'success'"
        ).fetchone()
        total_revenue = rev_row['s'] or 0.0

        # Live running servers list
        live_servers = conn.execute(
            """
            SELECT s.*, u.username 
            FROM servers s 
            JOIN users u ON s.user_id = u.id 
            WHERE s.status = 'running'
            ORDER BY s.created_at DESC
            """
        ).fetchall()

    return render_template(
        'admin/index.html',
        vps=vps,
        port_stats=port_stats,
        total_users=total_users,
        total_servers=total_servers,
        running_servers=running_servers,
        total_subs=total_subs,
        total_revenue=total_revenue,
        live_servers=live_servers,
        base_domain=BASE_DOMAIN
    )

@admin_bp.route('/users')
@admin_required
def users():
    search = request.args.get('q', '').strip()
    with get_db_connection() as conn:
        if search:
            query = """
                SELECT u.*, COUNT(s.id) as server_count 
                FROM users u 
                LEFT JOIN servers s ON u.id = s.user_id 
                WHERE u.username LIKE ? OR u.email LIKE ?
                GROUP BY u.id 
                ORDER BY u.id DESC
            """
            user_list = conn.execute(query, (f"%{search}%", f"%{search}%")).fetchall()
        else:
            query = """
                SELECT u.*, COUNT(s.id) as server_count 
                FROM users u 
                LEFT JOIN servers s ON u.id = s.user_id 
                GROUP BY u.id 
                ORDER BY u.id DESC
            """
            user_list = conn.execute(query).fetchall()

        plans = conn.execute("SELECT * FROM plans WHERE is_active = 1").fetchall()

    return render_template(
        'admin/users.html',
        users=user_list,
        plans=plans,
        search_query=search
    )

@admin_bp.route('/users/adjust-wallet', methods=['POST'])
@admin_required
def adjust_wallet():
    user_id = int(request.form.get('user_id'))
    action = request.form.get('action')
    amount = float(request.form.get('amount', 0))
    reason = request.form.get('reason', 'Admin adjustment').strip() or 'Admin adjustment'

    if amount <= 0:
        flash('Amount must be greater than zero.', 'error')
        return redirect(url_for('admin.users'))

    success, msg = admin_adjust_wallet(g.current_user['id'], user_id, amount, action=action, reason=reason)
    if success:
        flash(f"Successfully {'added' if action == 'add' else 'deducted'} ₹{amount:.2f} (User #{user_id}).", 'success')
    else:
        flash(f"Wallet adjustment failed: {msg}", 'error')

    return redirect(url_for('admin.users'))

@admin_bp.route('/users/grant-subscription', methods=['POST'])
@admin_required
def grant_subscription():
    user_id = int(request.form.get('user_id'))
    plan_id = int(request.form.get('plan_id'))
    days = int(request.form.get('days', 30))
    custom_ram = request.form.get('custom_ram')
    custom_storage = request.form.get('custom_storage')

    custom_ram_mb = int(custom_ram) if custom_ram else None
    custom_storage_mb = int(custom_storage) if custom_storage else None

    with get_db_connection() as conn:
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        plan = conn.execute("SELECT name FROM plans WHERE id = ?", (plan_id,)).fetchone()

        if not user or not plan:
            flash("User or Plan not found.", "error")
            return redirect(url_for('admin.users'))

        conn.execute(
            """
            INSERT INTO subscriptions 
            (user_id, plan_id, status, start_date, expiry_date, is_admin_granted, custom_ram_mb, custom_storage_mb)
            VALUES (?, ?, 'active', CURRENT_TIMESTAMP, datetime('now', '+' || ? || ' days'), 1, ?, ?)
            """,
            (user_id, plan_id, days, custom_ram_mb, custom_storage_mb)
        )

    record_audit_log('admin_grant_plan', g.current_user['id'], f"Granted {plan['name']} to {user['username']} for {days} days", request.remote_addr)
    flash(f"Granted {plan['name']} subscription to {user['username']} successfully!", 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/create-server', methods=['POST'])
@admin_required
def create_server_for_user():
    """Enables admin to directly provision and assign a server instance to any user."""
    user_id = int(request.form.get('user_id'))
    name = request.form.get('name', '').strip()
    plan_id = request.form.get('plan_id')
    entry_file = request.form.get('entry_file', 'app.py').strip() or 'app.py'
    startup_command = request.form.get('startup_command', '').strip() or None
    auto_restart = 1 if request.form.get('auto_restart') == '1' else 0

    if not name:
        flash("Server name is required.", "error")
        return redirect(url_for('admin.users'))

    with get_db_connection() as conn:
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('admin.users'))

        # Check if user already has an active subscription with available capacity
        sub = conn.execute(
            """
            SELECT sub.*, p.name as plan_name, p.max_servers,
                   (SELECT COUNT(*) FROM servers WHERE subscription_id = sub.id) as used_servers
            FROM subscriptions sub
            JOIN plans p ON sub.plan_id = p.id
            WHERE sub.user_id = ? AND sub.status = 'active'
            ORDER BY sub.id DESC LIMIT 1
            """,
            (user_id,)
        ).fetchone()

        # If no active subscription or capacity full, create a new active subscription for this plan
        subscription_id = None
        if sub and sub['used_servers'] < sub['max_servers']:
            subscription_id = sub['id']
        else:
            # Pick requested plan or fallback to first available plan
            target_plan_id = int(plan_id) if plan_id else None
            if not target_plan_id:
                first_plan = conn.execute("SELECT id FROM plans WHERE is_active = 1 ORDER BY id ASC LIMIT 1").fetchone()
                target_plan_id = first_plan['id'] if first_plan else 1

            cursor = conn.execute(
                """
                INSERT INTO subscriptions 
                (user_id, plan_id, status, start_date, expiry_date, is_admin_granted)
                VALUES (?, ?, 'active', CURRENT_TIMESTAMP, datetime('now', '+30 days'), 1)
                """,
                (user_id, target_plan_id)
            )
            subscription_id = cursor.lastrowid

        # Allocate unique port
        try:
            assigned_port = allocate_port()
        except Exception as e:
            flash(f"Port allocation failed: {str(e)}", "error")
            return redirect(url_for('admin.users'))

        # Generate internal identifier
        candidate = f"app-{secrets.token_hex(4)}"
        while not is_subdomain_available(candidate):
            candidate = f"app-{secrets.token_hex(4)}"
        subdomain = candidate

        # Provision in DB
        cursor = conn.execute(
            """
            INSERT INTO servers 
            (user_id, subscription_id, name, subdomain, assigned_port, status, entry_file, startup_command, auto_restart)
            VALUES (?, ?, ?, ?, ?, 'stopped', ?, ?, ?)
            """,
            (user_id, subscription_id, name, subdomain, assigned_port, entry_file, startup_command, auto_restart)
        )
        server_id = cursor.lastrowid

        reserve_subdomain(subdomain, user_id, server_id)

    # Initialize app filesystem
    create_server_instance(server_id, user_id, assigned_port, subdomain)

    create_notification(user_id, f"New Server Assigned: {name}", f"An administrator created and assigned server '{name}' on port {assigned_port} to your account.", "success", server_id)
    record_audit_log('admin_create_server', g.current_user['id'], f"Admin created server '{name}' (ID #{server_id}, Port {assigned_port}) for user {user['username']}", request.remote_addr)

    flash(f"Server '{name}' (Port {assigned_port}) successfully created and assigned to {user['username']}!", 'success')
    return redirect(url_for('admin.servers'))

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    if user_id == g.current_user['id']:
        flash('Cannot suspend yourself.', 'error')
        return redirect(url_for('admin.users'))

    with get_db_connection() as conn:
        user = conn.execute("SELECT status, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            new_status = 'suspended' if user['status'] == 'active' else 'active'
            conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
            flash(f"User {user['username']} is now {new_status}.", 'info')
            record_audit_log('admin_user_status', g.current_user['id'], f"Changed status of {user['username']} to {new_status}", request.remote_addr)

    return redirect(url_for('admin.users'))

@admin_bp.route('/servers')
@admin_required
def servers():
    with get_db_connection() as conn:
        server_list = conn.execute(
            """
            SELECT s.*, u.username, p.name as plan_name 
            FROM servers s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN subscriptions sub ON s.subscription_id = sub.id
            LEFT JOIN plans p ON sub.plan_id = p.id
            ORDER BY s.created_at DESC
            """
        ).fetchall()

    return render_template('admin/servers.html', servers=server_list, base_domain=BASE_DOMAIN)

@admin_bp.route('/servers/<int:server_id>/start', methods=['POST'])
@admin_required
def start_server(server_id):
    start_server_process(server_id)
    flash(f"Server #{server_id} started by administrator.", 'success')
    return redirect(url_for('admin.servers'))

@admin_bp.route('/servers/<int:server_id>/stop', methods=['POST'])
@admin_required
def stop_server(server_id):
    stop_server_process(server_id)
    flash(f"Server #{server_id} stopped by administrator.", 'info')
    return redirect(url_for('admin.servers'))

@admin_bp.route('/servers/<int:server_id>/delete', methods=['POST'])
@admin_required
def delete_server(server_id):
    delete_server_instance(server_id)
    flash(f"Server #{server_id} permanently deleted.", 'info')
    return redirect(url_for('admin.servers'))

@admin_bp.route('/plans')
@admin_required
def plans():
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM plans ORDER BY price_inr ASC").fetchall()
        all_plans = [dict(r) for r in rows]
    return render_template('admin/plans.html', plans=all_plans)

@admin_bp.route('/plans/save', methods=['POST'])
@admin_required
def save_plan():
    plan_id = request.form.get('plan_id')
    name = request.form.get('name', '').strip()
    price_inr = float(request.form.get('price_inr', 199))
    description = request.form.get('description', '').strip()
    ram_mb = int(request.form.get('ram_mb', 512))
    cpu_cores = float(request.form.get('cpu_cores', 1.0))
    storage_mb = int(request.form.get('storage_mb', 2048))
    bandwidth_mb = int(request.form.get('bandwidth_mb', 20480))
    max_servers = int(request.form.get('max_servers', 1))
    billing_days = int(request.form.get('billing_days', 30))

    with get_db_connection() as conn:
        if plan_id:
            conn.execute(
                """
                UPDATE plans 
                SET name = ?, price_inr = ?, description = ?, ram_mb = ?, cpu_cores = ?,
                    storage_mb = ?, bandwidth_mb = ?, max_servers = ?, billing_days = ?
                WHERE id = ?
                """,
                (name, price_inr, description, ram_mb, cpu_cores, storage_mb, bandwidth_mb, max_servers, billing_days, plan_id)
            )
            flash(f"Plan '{name}' updated successfully.", 'success')
        else:
            conn.execute(
                """
                INSERT INTO plans 
                (name, price_inr, description, ram_mb, cpu_cores, storage_mb, bandwidth_mb, max_servers, billing_days, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (name, price_inr, description, ram_mb, cpu_cores, storage_mb, bandwidth_mb, max_servers, billing_days)
            )
            flash(f"Plan '{name}' created successfully.", 'success')

    return redirect(url_for('admin.plans'))

@admin_bp.route('/broadcast')
@admin_required
def broadcast():
    with get_db_connection() as conn:
        announcements = conn.execute("SELECT * FROM announcements ORDER BY created_at DESC").fetchall()
    return render_template('admin/broadcast.html', announcements=announcements)

@admin_bp.route('/broadcast/create', methods=['POST'])
@admin_required
def create_broadcast():
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    action_text = request.form.get('action_text', '').strip() or None
    action_url = request.form.get('action_url', '').strip() or None

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO announcements (title, message, action_text, action_url, is_published)
            VALUES (?, ?, ?, ?, 1)
            """,
            (title, message, action_text, action_url)
        )

    flash('Announcement broadcasted to all users.', 'success')
    return redirect(url_for('admin.broadcast'))

@admin_bp.route('/broadcast/<int:aid>/delete', methods=['POST'])
@admin_required
def delete_broadcast(aid):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM announcements WHERE id = ?", (aid,))
    flash('Announcement removed.', 'info')
    return redirect(url_for('admin.broadcast'))

@admin_bp.route('/audit')
@admin_required
def audit():
    with get_db_connection() as conn:
        logs = conn.execute(
            """
            SELECT a.*, u.username 
            FROM audit_logs a 
            LEFT JOIN users u ON a.admin_id = u.id 
            ORDER BY a.created_at DESC 
            LIMIT 150
            """
        ).fetchall()
    return render_template('admin/audit.html', logs=logs)

@admin_bp.route('/settings')
@admin_required
def settings():
    m_mode = get_setting('maintenance_mode', '0')
    a_reg = get_setting('allow_registration', '1')
    w_bonus = get_setting('welcome_bonus_inr', '100.0')
    or_key = get_setting('openrouter_api_key', os.environ.get('OPENROUTER_API_KEY', ''))
    tg_token = get_setting('telegram_bot_token', os.environ.get('TELEGRAM_BOT_TOKEN', ''))
    tg_user = get_setting('telegram_bot_username', os.environ.get('TELEGRAM_BOT_USERNAME', 'VesperCloudBot'))

    return render_template(
        'admin/settings.html',
        settings={
            'maintenance_mode': m_mode,
            'allow_registration': a_reg,
            'welcome_bonus_inr': w_bonus,
            'openrouter_api_key': or_key,
            'telegram_bot_token': tg_token,
            'telegram_bot_username': tg_user
        }
    )

@admin_bp.route('/settings/save', methods=['POST'])
@admin_required
def save_settings():
    m_mode = '1' if request.form.get('maintenance_mode') == '1' else '0'
    a_reg = '1' if request.form.get('allow_registration') == '1' else '0'
    w_bonus = request.form.get('welcome_bonus_inr', '100.0')
    or_key = request.form.get('openrouter_api_key', '').strip()
    tg_token = request.form.get('telegram_bot_token', '').strip()
    tg_user = request.form.get('telegram_bot_username', '').strip()

    set_setting('maintenance_mode', m_mode)
    set_setting('allow_registration', a_reg)
    set_setting('welcome_bonus_inr', w_bonus)
    set_setting('openrouter_api_key', or_key)
    set_setting('telegram_bot_token', tg_token)
    set_setting('telegram_bot_username', tg_user)

    flash('Operating settings, Telegram Bot configuration, and AI Inspector updated successfully.', 'success')
    return redirect(url_for('admin.settings'))

@admin_bp.route('/backup/download')
@admin_required
def download_backup():
    if not os.path.exists(DB_PATH):
        flash('Database file not found.', 'error')
        return redirect(url_for('admin.settings'))

    return send_file(
        DB_PATH,
        mimetype='application/x-sqlite3',
        as_attachment=True,
        download_name="vesper-platform-backup.db"
    )
