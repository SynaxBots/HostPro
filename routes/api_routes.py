"""
API Blueprint for Server Operations
Provides REST endpoints for File Manager, Web Console, Live Logs, Environment Variables, and Metrics.
"""

from flask import Blueprint, request, jsonify, g, send_file, Response
from security import login_required
from database import get_db_connection
from file_manager import (
    list_directory_contents, read_file_content, write_file_content,
    create_item, rename_item, delete_item, save_uploaded_file,
    extract_zip_file, create_zip_archive,
    copy_item, move_item, zip_selected_items, export_selected_items_as_zip,
    get_app_dir
)
from security import resolve_safe_path
from resource_manager import get_server_resource_usage
from process_manager import get_server_paths, execute_console_command, auto_install_server_dependencies
from upi_service import verify_and_credit_upi_payment
import subprocess
import os

api_bp = Blueprint('api', __name__, url_prefix='/api')

def verify_server_owner(server_id, user_id, is_admin=False):
    with get_db_connection() as conn:
        if is_admin:
            row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM servers WHERE id = ? AND user_id = ?", (server_id, user_id)).fetchone()
        return dict(row) if row else None

# ----------------------------------------------------------------------
# FILE MANAGER ENDPOINTS
# ----------------------------------------------------------------------

@api_bp.route('/server/<int:server_id>/files', methods=['GET'])
@login_required
def list_files(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized or server not found'}), 403

    rel_path = request.args.get('path', '')
    success, items, err = list_directory_contents(server_id, rel_path)
    if not success:
        return jsonify({'error': err}), 400

    return jsonify({'items': items, 'path': rel_path})

@api_bp.route('/server/<int:server_id>/files/read', methods=['GET'])
@login_required
def read_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    rel_path = request.args.get('path', '')
    success, content, meta, err = read_file_content(server_id, rel_path)
    if not success:
        return jsonify({'error': err}), 400

    return jsonify({
        'content': content,
        'relative_path': meta.get('relative_path'),
        'size_human': meta.get('size_human'),
        'size_bytes': meta.get('size_bytes'),
        'is_protected': meta.get('is_protected', False)
    })

@api_bp.route('/server/<int:server_id>/files/save', methods=['POST'])
@login_required
def save_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    rel_path = data.get('path', '')
    content = data.get('content', '')

    success, err = write_file_content(server_id, rel_path, content)
    if not success:
        return jsonify({'error': err}), 400

    # If a python file or requirements.txt was saved, trigger auto-scan & install in background
    if rel_path.endswith('.py') or os.path.basename(rel_path) == 'requirements.txt':
        import threading
        paths = get_server_paths(server['user_id'], server_id)
        entry_f = server.get('entry_file') or 'app.py'
        threading.Thread(
            target=auto_install_server_dependencies,
            args=(server_id, server['user_id'], paths, entry_f),
            daemon=True
        ).start()

    return jsonify({'success': True, 'message': 'File saved successfully'})

@api_bp.route('/server/<int:server_id>/files/create', methods=['POST'])
@login_required
def create_file_or_dir(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    rel_path = data.get('path', '')
    is_dir = data.get('is_dir', False)

    success, err = create_item(server_id, rel_path, is_dir)
    if not success:
        return jsonify({'error': err}), 400

    return jsonify({'success': True, 'message': 'Created successfully'})

@api_bp.route('/server/<int:server_id>/files/rename', methods=['POST'])
@login_required
def rename_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    old_path = data.get('old_path', '')
    new_name = data.get('new_name', '')

    success, err = rename_item(server_id, old_path, new_name)
    if not success:
        return jsonify({'error': err}), 400

    return jsonify({'success': True, 'message': 'Renamed successfully'})

@api_bp.route('/server/<int:server_id>/files/delete', methods=['POST'])
@login_required
def delete_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    rel_path = data.get('path', '')

    success, err = delete_item(server_id, rel_path)
    if not success:
        return jsonify({'error': err}), 400

    return jsonify({'success': True, 'message': 'Deleted successfully'})

@api_bp.route('/server/<int:server_id>/files/upload', methods=['POST'])
@login_required
def upload_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    dest_folder = request.form.get('folder', '')
    success, err = save_uploaded_file(server_id, file, dest_folder)
    if not success:
        return jsonify({'error': err}), 400

    # If python file or requirements.txt was uploaded, trigger auto-scan & install in background
    if file.filename.endswith('.py') or file.filename == 'requirements.txt':
        import threading
        paths = get_server_paths(server['user_id'], server_id)
        entry_f = server.get('entry_file') or 'app.py'
        threading.Thread(
            target=auto_install_server_dependencies,
            args=(server_id, server['user_id'], paths, entry_f),
            daemon=True
        ).start()

    return jsonify({'success': True, 'message': f"Uploaded {file.filename}"})

@api_bp.route('/server/<int:server_id>/files/upload-zip', methods=['POST'])
@login_required
def upload_zip(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    file = request.files.get('zip')
    if not file or not file.filename.endswith('.zip'):
        return jsonify({'error': 'Please upload a valid .zip archive'}), 400

    dest_folder = request.form.get('folder', '')
    success, extracted, err = extract_zip_file(server_id, file.read(), dest_folder)
    if not success:
        return jsonify({'error': err}), 400

    # Auto-scan extracted archive files for dependencies in background
    import threading
    paths = get_server_paths(server['user_id'], server_id)
    entry_f = server.get('entry_file') or 'app.py'
    threading.Thread(
        target=auto_install_server_dependencies,
        args=(server_id, server['user_id'], paths, entry_f),
        daemon=True
    ).start()

    return jsonify({'success': True, 'message': f"Extracted {extracted} files successfully"})

@api_bp.route('/server/<int:server_id>/files/download-zip', methods=['GET'])
@login_required
def download_zip(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    success, zip_buffer, err = create_zip_archive(server_id)
    if not success:
        return jsonify({'error': err}), 400

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"server-{server_id}-backup.zip"
    )

@api_bp.route('/server/<int:server_id>/files/download-file', methods=['GET'])
@login_required
def download_single_file(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    rel_path = request.args.get('path', '')
    app_dir = get_app_dir(server['user_id'], server_id)
    file_path = resolve_safe_path(app_dir, rel_path)

    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404

    if os.path.isdir(file_path):
        # If directory, zip it on the fly
        zip_buf = export_selected_items_as_zip(server_id, [rel_path])
        return send_file(
            zip_buf,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{os.path.basename(rel_path)}.zip"
        )

    return send_file(
        file_path,
        as_attachment=True,
        download_name=os.path.basename(file_path)
    )

@api_bp.route('/server/<int:server_id>/files/copy', methods=['POST'])
@login_required
def copy_file_or_dir(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    src_path = data.get('src_path', '')
    dest_folder = data.get('dest_folder', '')

    success, msg = copy_item(server_id, src_path, dest_folder)
    if not success:
        return jsonify({'error': msg}), 400

    return jsonify({'success': True, 'message': msg})

@api_bp.route('/server/<int:server_id>/files/move', methods=['POST'])
@login_required
def move_file_or_dir(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    src_path = data.get('src_path', '')
    dest_folder = data.get('dest_folder', '')

    success, msg = move_item(server_id, src_path, dest_folder)
    if not success:
        return jsonify({'error': msg}), 400

    return jsonify({'success': True, 'message': msg})

@api_bp.route('/server/<int:server_id>/files/zip-selected', methods=['POST'])
@login_required
def zip_selected_files_endpoint(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    paths = data.get('paths', [])
    zip_name = data.get('zip_name', 'archive.zip')
    dest_folder = data.get('dest_folder', '')

    success, msg = zip_selected_items(server_id, paths, zip_name, dest_folder)
    if not success:
        return jsonify({'error': msg}), 400

    return jsonify({'success': True, 'message': msg})

@api_bp.route('/server/<int:server_id>/files/download-selected', methods=['POST'])
@login_required
def download_selected_files_endpoint(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    paths = data.get('paths', [])
    if not paths:
        return jsonify({'error': 'No files selected'}), 400

    zip_buf = export_selected_items_as_zip(server_id, paths)
    return send_file(
        zip_buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"selected_files_{server_id}.zip"
    )

# ----------------------------------------------------------------------
# WEB CONSOLE TERMINAL ENDPOINT
# ----------------------------------------------------------------------

@api_bp.route('/server/<int:server_id>/console', methods=['POST'])
@login_required
def run_console_command(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json() or {}
    cmd = data.get('command', '').strip()
    if not cmd:
        return jsonify({'output': ''})

    paths = get_server_paths(server['user_id'], server_id)
    app_dir = paths["app"]
    if not os.path.exists(app_dir):
        return jsonify({'error': 'Application directory does not exist.'}), 400

    try:
        output = execute_console_command(server['user_id'], server_id, cmd)
        if not output.strip():
            output = "[Command finished with no output]"
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': f"[Execution error: {str(e)}]"}), 500

# ----------------------------------------------------------------------
# LIVE LOGS ENDPOINTS
# ----------------------------------------------------------------------

@api_bp.route('/server/<int:server_id>/logs', methods=['GET'])
@login_required
def get_logs(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    paths = get_server_paths(server['user_id'], server_id)
    log_type = request.args.get('type', 'stdout')
    log_filename = "stdout.log" if log_type == 'stdout' else "stderr.log" if log_type == 'stderr' else "system.log"
    log_path = os.path.join(paths["logs"], log_filename)

    if not os.path.exists(log_path):
        return jsonify({'logs': f"[No {log_filename} entries yet]"})

    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            # Read last 400 lines
            lines = f.readlines()
            tail = ''.join(lines[-400:])
            return jsonify({'logs': tail or f"[{log_filename} is empty]"})
    except Exception as e:
        return jsonify({'logs': f"[Error reading logs: {str(e)}]"})

@api_bp.route('/server/<int:server_id>/logs/clear', methods=['POST'])
@login_required
def clear_logs(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    paths = get_server_paths(server['user_id'], server_id)
    data = request.get_json() or {}
    log_type = data.get('type', 'stdout')
    log_filename = "stdout.log" if log_type == 'stdout' else "stderr.log" if log_type == 'stderr' else "system.log"
    log_path = os.path.join(paths["logs"], log_filename)

    try:
        if os.path.exists(log_path):
            open(log_path, 'w').close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ----------------------------------------------------------------------
# ENVIRONMENT VARIABLES ENDPOINTS
# ----------------------------------------------------------------------

@api_bp.route('/server/<int:server_id>/env', methods=['GET', 'POST'])
@login_required
def handle_env_vars(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        with get_db_connection() as conn:
            vars_list = conn.execute(
                "SELECT id, env_key, env_value FROM environment_variables WHERE server_id = ? ORDER BY env_key ASC",
                (server_id,)
            ).fetchall()
        return jsonify({'variables': [dict(v) for v in vars_list]})

    if request.method == 'POST':
        data = request.get_json() or {}
        key = data.get('key', '').strip()
        value = data.get('value', '').strip()

        if not key:
            return jsonify({'error': 'Variable name (key) is required'}), 400

        with get_db_connection() as conn:
            # Check if key exists
            existing = conn.execute(
                "SELECT id FROM environment_variables WHERE server_id = ? AND env_key = ?",
                (server_id, key)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE environment_variables SET env_value = ? WHERE id = ?",
                    (value, existing['id'])
                )
            else:
                conn.execute(
                    "INSERT INTO environment_variables (server_id, env_key, env_value) VALUES (?, ?, ?)",
                    (server_id, key, value)
                )

        return jsonify({'success': True, 'message': 'Variable saved'})

@api_bp.route('/server/<int:server_id>/env/<int:env_id>', methods=['DELETE'])
@login_required
def delete_env_var(server_id, env_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    with get_db_connection() as conn:
        conn.execute("DELETE FROM environment_variables WHERE id = ? AND server_id = ?", (env_id, server_id))

    return jsonify({'success': True})

# ----------------------------------------------------------------------
# LIVE METRICS ENDPOINT
# ----------------------------------------------------------------------

@api_bp.route('/server/<int:server_id>/metrics', methods=['GET'])
@login_required
def server_metrics(server_id):
    is_admin = (g.current_user['role'] == 'admin')
    server = verify_server_owner(server_id, g.current_user['id'], is_admin)
    if not server:
        return jsonify({'error': 'Unauthorized'}), 403

    usage = get_server_resource_usage(server_id)
    return jsonify({
        'cpu_percent': usage.get('cpu_percent', 0.0),
        'ram_mb': usage.get('ram_mb', 0.0),
        'status': usage.get('status', server['status']),
        'pid': usage.get('pid', server['pid']),
        'ram_exceeded': usage.get('ram_exceeded', False),
        'ram_limit_mb': usage.get('ram_limit_mb'),
        'ram_grace_mb': usage.get('ram_grace_mb', 30),
        'max_ram_mb': usage.get('max_ram_mb')
    })

# ----------------------------------------------------------------------
# UPI PAYMENT VERIFICATION ENDPOINT
# ----------------------------------------------------------------------

@api_bp.route('/billing/verify-upi', methods=['POST'])
@login_required
def verify_upi():
    data = request.get_json() or {}
    utr = data.get('utr', '').strip()
    if not utr:
        return jsonify({'success': False, 'message': 'Missing UTR reference'}), 400

    result = verify_and_credit_upi_payment(g.current_user['id'], utr)
    return jsonify(result)
