"""
Server Operations Blueprint
Handles individual server control, starting, stopping, restarting, configuration changes, dependency installs, and deletion.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, g, jsonify
from security import login_required, record_audit_log
from database import get_db_connection
import config
from config import BASE_DOMAIN
from process_manager import (
    start_server_process,
    stop_server_process,
    restart_server_process,
    delete_server_instance,
    get_server_paths,
    install_requirements as pm_install_requirements
)
from resource_manager import get_server_resource_usage
import subprocess
import os

server_bp = Blueprint('server', __name__, url_prefix='/server')

def check_server_access(server_id, user_id, is_admin=False):
    """Verify that the user owns the server or is an admin."""
    with get_db_connection() as conn:
        if is_admin:
            server = conn.execute(
                """
                SELECT s.*, p.ram_mb as plan_ram_mb, p.cpu_cores as plan_cpu_cores,
                       p.storage_mb as plan_storage_mb, p.bandwidth_mb as plan_bandwidth_mb,
                       sub.custom_ram_mb, sub.custom_storage_mb
                FROM servers s
                LEFT JOIN subscriptions sub ON s.subscription_id = sub.id
                LEFT JOIN plans p ON sub.plan_id = p.id
                WHERE s.id = ?
                """,
                (server_id,)
            ).fetchone()
        else:
            server = conn.execute(
                """
                SELECT s.*, p.ram_mb as plan_ram_mb, p.cpu_cores as plan_cpu_cores,
                       p.storage_mb as plan_storage_mb, p.bandwidth_mb as plan_bandwidth_mb,
                       sub.custom_ram_mb, sub.custom_storage_mb
                FROM servers s
                LEFT JOIN subscriptions sub ON s.subscription_id = sub.id
                LEFT JOIN plans p ON sub.plan_id = p.id
                WHERE s.id = ? AND s.user_id = ?
                """,
                (server_id, user_id)
            ).fetchone()
    return server

@server_bp.route('/<int:server_id>')
@login_required
def detail(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)

    if not server:
        flash('Server instance not found or access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    # Calculate limits
    ram_mb = server['custom_ram_mb'] or server['plan_ram_mb'] or 512
    cpu_cores = server['plan_cpu_cores'] or 1
    storage_mb = server['custom_storage_mb'] or server['plan_storage_mb'] or 2048
    bandwidth_mb = server['plan_bandwidth_mb'] or 20480

    used_storage_mb = (server['storage_used_bytes'] or 0) / (1024 * 1024)
    used_bandwidth_mb = (server['bandwidth_used_bytes'] or 0) / (1024 * 1024)

    storage_percent = min(100, round((used_storage_mb / storage_mb) * 100, 1)) if storage_mb > 0 else 0
    bandwidth_percent = min(100, round((used_bandwidth_mb / bandwidth_mb) * 100, 1)) if bandwidth_mb > 0 else 0

    ram_grace_mb = getattr(config, 'RAM_GRACE_MB', 30)
    limits = {
        'ram_mb': ram_mb,
        'ram_grace_mb': ram_grace_mb,
        'max_ram_mb': ram_mb + ram_grace_mb,
        'cpu_cores': cpu_cores,
        'storage_mb': storage_mb,
        'used_storage_mb': round(used_storage_mb, 1),
        'storage_percent': storage_percent,
        'bandwidth_mb': bandwidth_mb,
        'used_bandwidth_mb': round(used_bandwidth_mb, 1),
        'bandwidth_percent': bandwidth_percent
    }

    return render_template(
        'server/detail.html',
        server=server,
        limits=limits,
        base_domain=BASE_DOMAIN
    )

@server_bp.route('/<int:server_id>/start', methods=['POST'])
@login_required
def start(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    success, message = start_server_process(server_id)
    if success:
        flash(f"Server process started successfully: {message}", 'success')
        record_audit_log('server_start', g.current_user['id'], f"Started server {server['name']} (ID: {server_id})", request.remote_addr)
    else:
        flash(f"Failed to start server: {message}", 'error')

    return redirect(url_for('server.detail', server_id=server_id))

@server_bp.route('/<int:server_id>/stop', methods=['POST'])
@login_required
def stop(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    success, message = stop_server_process(server_id)
    if success:
        flash('Server process terminated.', 'info')
        record_audit_log('server_stop', g.current_user['id'], f"Stopped server {server['name']} (ID: {server_id})", request.remote_addr)
    else:
        flash(f"Error stopping server: {message}", 'error')

    return redirect(url_for('server.detail', server_id=server_id))

@server_bp.route('/<int:server_id>/restart', methods=['POST'])
@login_required
def restart(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    success, message = restart_server_process(server_id)
    if success:
        flash('Server process restarted successfully.', 'success')
        record_audit_log('server_restart', g.current_user['id'], f"Restarted server {server['name']} (ID: {server_id})", request.remote_addr)
    else:
        flash(f"Restart failed: {message}", 'error')

    return redirect(url_for('server.detail', server_id=server_id))

@server_bp.route('/<int:server_id>/settings', methods=['POST'])
@login_required
def update_settings(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    entry_file = request.form.get('entry_file', 'app.py').strip()
    startup_command = request.form.get('startup_command', '').strip() or None
    auto_restart = 1 if request.form.get('auto_restart') == '1' else 0

    with get_db_connection() as conn:
        conn.execute(
            """
            UPDATE servers 
            SET entry_file = ?, startup_command = ?, auto_restart = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (entry_file, startup_command, auto_restart, server_id)
        )

    flash('Server configuration updated.', 'success')
    return redirect(url_for('server.detail', server_id=server_id))

@server_bp.route('/<int:server_id>/install-requirements', methods=['POST'])
@login_required
def install_requirements(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    success, message = pm_install_requirements(server['user_id'], server_id)
    if success:
        flash("Dependencies installed directly to the main server successfully!", 'success')
    else:
        flash(f"Installation notice: {message}", 'error')

    return redirect(url_for('server.detail', server_id=server_id))

@server_bp.route('/<int:server_id>/delete', methods=['POST'])
@login_required
def delete(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = check_server_access(server_id, g.current_user['id'], is_admin=is_admin)
    if not server:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard.index'))

    success, message = delete_server_instance(server_id)
    if success:
        flash(f"Server '{server['name']}' was permanently removed.", 'info')
        record_audit_log('server_delete', g.current_user['id'], f"Deleted server {server['name']} (Port {server['assigned_port']})", request.remote_addr)
        return redirect(url_for('dashboard.index'))
    else:
        flash(f"Error deleting server: {message}", 'error')
        return redirect(url_for('server.detail', server_id=server_id))
