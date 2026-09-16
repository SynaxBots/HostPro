import os
import sys
import time
import signal
import subprocess
import threading
import json
import ast
import importlib.util
from datetime import datetime
import psutil
from database import get_db
import config
from security import resolve_safe_path
from ai_inspector import inspect_server_app_directory

# Active running processes dictionary: { server_id: { "popen": Popen, "pid": int, "started_at": float, "last_crash": float } }
_active_processes = {}
_process_lock = threading.Lock()
_monitor_thread = None
_stop_monitor = threading.Event()
RAM_GRACE_MB = getattr(config, "RAM_GRACE_MB", 30)

def get_server_paths(user_id, server_id):
    """Returns directory paths for a specific server instance."""
    server_root = os.path.join(config.APPS_DIR, f"user_{user_id}", f"server_{server_id}")
    app_dir = os.path.join(server_root, "app")
    logs_dir = os.path.join(server_root, "logs")
    venv_dir = os.path.join(server_root, "venv")
    jail_dir = os.path.join(server_root, "jail")
    
    for d in [server_root, app_dir, logs_dir, venv_dir, jail_dir]:
        os.makedirs(d, exist_ok=True)
        
    return {
        "root": server_root,
        "app": app_dir,
        "logs": logs_dir,
        "venv": venv_dir,
        "jail": jail_dir,
        "stdout_log": os.path.join(logs_dir, "stdout.log"),
        "stderr_log": os.path.join(logs_dir, "stderr.log"),
        "system_log": os.path.join(logs_dir, "system.log")
    }

def prepare_sandbox_jail(jail_dir, app_dir):
    """
    Initializes a chroot / namespace jail root for the hosted application.
    Prepares directory mountpoints with safe permissions.
    """
    try:
        os.chmod(jail_dir, 0o755)
        for d in ["usr", "bin", "lib", "lib64", "dev", "proc", "tmp", "etc", "workspace"]:
            target = os.path.join(jail_dir, d)
            os.makedirs(target, exist_ok=True)
            os.chmod(target, 0o777 if d in ["tmp", "workspace"] else 0o755)
        # Ensure user application directory is accessible
        os.chmod(app_dir, 0o777)
    except Exception as e:
        print(f"[ProcessManager] prepare_sandbox_jail notice: {e}")

def log_system_event(logs_dir, message):
    """Appends an event timestamped to system.log."""
    try:
        sys_log = os.path.join(logs_dir, "system.log")
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(sys_log, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception as e:
        print(f"[ProcessManager log error] {e}")

def get_pip_env(app_dir):
    """Generates an isolated, non-root pip installation environment."""
    env = os.environ.copy()
    env["HOME"] = "/tmp"
    env["USER"] = "botuser"
    env["PYTHONUSERBASE"] = os.path.join(app_dir, ".local")
    env["PIP_NO_CACHE_DIR"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    
    local_bin = os.path.join(app_dir, ".local", "bin")
    env["PATH"] = f"{local_bin}:{env.get('PATH', '/usr/local/bin:/usr/bin:/bin')}"
    
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    local_site = os.path.join(app_dir, ".local", "lib", f"python{py_ver}", "site-packages")
    existing_pypath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{app_dir}:{local_site}:{existing_pypath}" if existing_pypath else f"{app_dir}:{local_site}"
    return env

def get_server_env(server_id, assigned_port):
    """Collects safe environment variables for the Python process."""
    env = os.environ.copy()
    env["PORT"] = str(assigned_port)
    env["HOST"] = "0.0.0.0"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = "/tmp"
    env["PIP_NO_CACHE_DIR"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    
    # Remove sensitive database path and secrets from child process
    env.pop("DATABASE_PATH", None)
    for sensitive_env in ["FLASK_SECRET", "SECRET_KEY", "ADMIN_PASSWORD", "DATABASE_URL", "UPI_KEY"]:
        env.pop(sensitive_env, None)

    # Pass RAM limits for process-level enforcement
    try:
        from resource_manager import get_server_limits
        limits = get_server_limits(server_id)
        ram_mb = limits["ram_mb"] if limits else config.DEFAULT_RAM_LIMIT_MB
        env["VESPER_RAM_LIMIT_MB"] = str(ram_mb)
        env["VESPER_RAM_GRACE_MB"] = str(getattr(config, "RAM_GRACE_MB", 30))
    except Exception:
        env["VESPER_RAM_LIMIT_MB"] = str(config.DEFAULT_RAM_LIMIT_MB)
        env["VESPER_RAM_GRACE_MB"] = "30"

    try:
        db = get_db()
        cursor = db.execute("SELECT env_key, env_value FROM environment_variables WHERE server_id = ?", (server_id,))
        for row in cursor.fetchall():
            k = row["env_key"].strip()
            v = row["env_value"]
            if k:
                env[k] = v
    except Exception as e:
        print(f"[ProcessManager] Env fetch error: {e}")

    return env

# Comprehensive mapping from Python import names to pip distribution names
IMPORT_TO_PIP = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",
    "discord": "discord.py",
    "bs4": "beautifulsoup4",
    "PIL": "Pillow",
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "cv2": "opencv-python-headless",
    "google.generativeai": "google-generativeai",
    "genai": "google-genai",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "fitz": "PyMuPDF",
    "sklearn": "scikit-learn",
    "crypto": "pycryptodome",
    "Crypto": "pycryptodome",
    "jwt": "PyJWT",
    "dateutil": "python-dateutil",
    "magic": "python-magic",
    "dns": "dnspython",
    "colorama": "colorama",
    "aiohttp": "aiohttp",
    "websockets": "websockets",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "sqlalchemy": "SQLAlchemy",
    "pymongo": "pymongo",
    "redis": "redis",
    "pydantic": "pydantic",
    "numpy": "numpy",
    "pandas": "pandas",
    "requests": "requests",
    "httpx": "httpx",
    "playwright": "playwright",
    "selenium": "selenium",
    "scrapy": "Scrapy",
    "schedule": "schedule",
    "apscheduler": "APScheduler",
    "pytz": "pytz",
    "qrcode": "qrcode",
    "psutil": "psutil",
    "cowsay": "cowsay",
    "emoji": "emoji",
    "tabulate": "tabulate",
    "rich": "rich",
    "tqdm": "tqdm",
    "tldextract": "tldextract",
    "mutagen": "mutagen",
    "yt_dlp": "yt-dlp",
    "youtube_dl": "youtube-dl",
    "aiogram": "aiogram",
    "disnake": "disnake",
    "nextcord": "nextcord",
    "openpyxl": "openpyxl",
    "xlrd": "xlrd",
    "xlsxwriter": "xlsxwriter",
    "pyserial": "pyserial",
    "serial": "pyserial",
    "git": "GitPython",
    "github": "PyGithub",
    "websocket": "websocket-client",
    "mysql": "mysql-connector-python",
    "pymysql": "pymysql",
    "psycopg2": "psycopg2-binary",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "seaborn": "seaborn",
    "flask_cors": "flask-cors",
    "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_login": "flask-login",
    "flask_socketio": "flask-socketio",
}

def scan_python_imports(file_path):
    """Safely extracts all top-level imported module names from a Python source file using AST + regex."""
    imported_mods = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code_content = f.read()
        try:
            tree = ast.parse(code_content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_mods.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.level == 0:
                        imported_mods.add(node.module.split('.')[0])
        except SyntaxError:
            pass
        # Fallback regular expression to catch dynamic or syntax-impaired imports
        import re
        for m in re.finditer(r'^\s*(?:import|from)\s+([a-zA-Z0-9_]+)', code_content, re.MULTILINE):
            imported_mods.add(m.group(1))
    except Exception:
        pass
    return imported_mods

def is_module_installed_locally(pkg_or_mod, app_dir):
    """Checks if a module or pip package is installed in the server's .local site-packages."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    local_site = os.path.join(app_dir, ".local", "lib", f"python{py_ver}", "site-packages")
    if not os.path.isdir(local_site):
        return False
    
    clean = pkg_or_mod.strip().split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
    candidates = [
        clean,
        clean.lower(),
        clean.replace("-", "_"),
        clean.replace("_", "-"),
    ]
    for c in candidates:
        if os.path.exists(os.path.join(local_site, c)) or os.path.exists(os.path.join(local_site, f"{c}.py")):
            return True
        # Check dist-info or egg-info directories
        import glob
        pattern = os.path.join(local_site, f"{c}-*.dist-info")
        if glob.glob(pattern):
            return True
    return False

def auto_install_server_dependencies(server_id, user_id, paths, entry_file="app.py"):
    """
    Automatically detects all required modules across the user's Python codebase,
    adds any missing dependencies to requirements.txt, and installs all dependencies
    directly into the server's isolated environment.
    """
    app_dir = paths["app"]
    logs_dir = paths["logs"]
    sys_log_path = paths["system_log"]
    pip_bin = sys.executable or "python3"
    pip_env = get_pip_env(app_dir)
    req_path = os.path.join(app_dir, "requirements.txt")
    
    installed_any = False
    
    try:
        # 1. Collect all project Python files
        py_files = []
        entry_path = os.path.join(app_dir, entry_file)
        if os.path.exists(entry_path) and os.path.isfile(entry_path):
            py_files.append(entry_path)
            
        for root, dirs, files in os.walk(app_dir):
            dirs[:] = [d for d in dirs if d not in ('.local', 'venv', '.git', '__pycache__', 'node_modules', 'jail')]
            for f in files:
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    if full_p not in py_files:
                        py_files.append(full_p)

        # 2. Extract all module imports from all Python files
        all_imports = set()
        for py_f in py_files:
            all_imports.update(scan_python_imports(py_f))

        stdlib_names = getattr(sys, 'stdlib_module_names', set())
        known_stdlib = {
            'os', 'sys', 'time', 'datetime', 'json', 're', 'math', 'random', 'subprocess',
            'threading', 'multiprocessing', 'queue', 'socket', 'urllib', 'http', 'email',
            'html', 'xml', 'collections', 'itertools', 'functools', 'operator', 'pathlib',
            'shutil', 'tempfile', 'glob', 'fnmatch', 'io', 'logging', 'argparse', 'optparse',
            'typing', 'types', 'traceback', 'warnings', 'contextlib', 'copy', 'pickle',
            'shelve', 'sqlite3', 'hashlib', 'hmac', 'secrets', 'base64', 'binascii', 'struct',
            'codecs', 'unicodedata', 'string', 'textwrap', 'difflib', 'csv', 'configparser',
            'netrc', 'platform', 'ctypes', 'inspect', 'ast', 'dis', 'gc', 'asyncio', 'concurrent',
            'unittest', 'doctest', 'venv', 'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib',
            'ssl', 'select', 'selectors', 'signal', 'mimetypes', 'uuid', 'pprint', 'enum',
            'weakref', 'calendar', 'decimal', 'fractions', 'numbers', 'array', 'bisect', 'heapq',
            'readline', 'rlcompleter', 'site', 'builtins', 'cProfile', 'profile', 'pstats',
            'pdb', 'timeit', 'trace', 'tracemalloc', 'ipaddress', 'socketserver', 'wsgiref'
        }

        # Determine all required 3rd-party pip packages
        required_packages = []
        for mod in sorted(all_imports):
            if not mod or mod in stdlib_names or mod in known_stdlib:
                continue
            # Ignore local project files and packages
            if os.path.exists(os.path.join(app_dir, f"{mod}.py")) or os.path.isdir(os.path.join(app_dir, mod)):
                continue
            
            pkg_name = IMPORT_TO_PIP.get(mod, mod)
            if pkg_name not in required_packages:
                required_packages.append(pkg_name)

        # 3. Read existing requirements.txt and synchronize missing modules
        existing_lines = []
        normalized_existing = set()
        import re
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        clean = line.strip()
                        if clean:
                            existing_lines.append(clean)
                            if not clean.startswith("#"):
                                base_name = re.split(r'[<>=!~;]', clean)[0].strip().lower().replace("_", "-")
                                if base_name:
                                    normalized_existing.add(base_name)
            except Exception as e:
                log_system_event(logs_dir, f"Notice: Error reading requirements.txt: {e}")

        # Determine which packages need to be added to requirements.txt
        added_to_reqs = []
        for pkg in required_packages:
            norm_pkg = pkg.lower().replace("_", "-")
            if norm_pkg not in normalized_existing:
                existing_lines.append(pkg)
                normalized_existing.add(norm_pkg)
                added_to_reqs.append(pkg)

        # Automatically write updated requirements.txt if any new packages detected
        if added_to_reqs or not os.path.exists(req_path):
            try:
                with open(req_path, "w", encoding="utf-8") as f:
                    for line in existing_lines:
                        f.write(f"{line}\n")
                if added_to_reqs:
                    log_system_event(logs_dir, f"Automatically added to requirements.txt: {', '.join(added_to_reqs)}")
            except Exception as e:
                log_system_event(logs_dir, f"Notice: could not update requirements.txt: {e}")

        # 4. Check whether any requirements in requirements.txt or detected packages need installation
        needs_install = False
        all_active_reqs = [l.strip() for l in existing_lines if l.strip() and not l.strip().startswith("#")]
        
        # Check if local site-packages contains all required packages
        for req in all_active_reqs:
            if not is_module_installed_locally(req, app_dir):
                needs_install = True
                break

        if needs_install or added_to_reqs:
            log_system_event(logs_dir, f"Auto-installing dependencies ({len(all_active_reqs)} package(s)) to server...")
            res = subprocess.run(
                [pip_bin, "-m", "pip", "install", "-r", "requirements.txt", "--break-system-packages", "--no-cache-dir"],
                cwd=app_dir,
                capture_output=True,
                text=True,
                timeout=180,
                env=pip_env
            )
            with open(sys_log_path, "a", encoding="utf-8") as f:
                f.write("\n=== AUTO-INSTALL REQUIREMENTS ON STARTUP ===\n" + (res.stdout or "") + (("\n[ERRORS]\n" + res.stderr) if res.stderr else "") + "\n")
            
            if res.returncode == 0:
                log_system_event(logs_dir, "All dependencies successfully installed to server.")
                installed_any = True
            else:
                log_system_event(logs_dir, f"Notice: Batch install returned code {res.returncode}. Attempting individual package install...")
                # Fallback: install missing packages individually so one failing package doesn't block others
                for req in all_active_reqs:
                    if not is_module_installed_locally(req, app_dir):
                        ind_res = subprocess.run(
                            [pip_bin, "-m", "pip", "install", req, "--break-system-packages", "--no-cache-dir"],
                            cwd=app_dir,
                            capture_output=True,
                            text=True,
                            timeout=90,
                            env=pip_env
                        )
                        if ind_res.returncode == 0:
                            log_system_event(logs_dir, f"Package '{req}' installed successfully.")
                            installed_any = True
                        else:
                            log_system_event(logs_dir, f"Failed to install package '{req}'.")
                            
    except Exception as e:
        log_system_event(logs_dir, f"Warning during dependency auto-sync: {e}")

    return installed_any

def start_server(server_id):
    """Starts a hosted Python application process."""
    with _process_lock:
        db = get_db()
        server = db.execute("""
        SELECT s.*, u.id as user_id, u.status as user_status, sub.status as sub_status 
        FROM servers s
        JOIN users u ON s.user_id = u.id
        JOIN subscriptions sub ON s.subscription_id = sub.id
        WHERE s.id = ?
        """, (server_id,)).fetchone()
        
        if not server:
            return False, "Server not found"
            
        if server["user_status"] == "suspended":
            return False, "User account is suspended"
            
        if server["sub_status"] not in ("active", "grace_period"):
            return False, "Subscription is not active or has expired"
            
        paths = get_server_paths(server["user_id"], server_id)
        
        # Check if already running
        if server["pid"]:
            if psutil.pid_exists(server["pid"]):
                try:
                    proc = psutil.Process(server["pid"])
                    if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                        return True, f"Server is already running on PID {server['pid']}"
                except Exception:
                    pass

        # Verify entry file exists
        entry_file = server["entry_file"] or "app.py"
        entry_path = os.path.join(paths["app"], entry_file)
        
        # If directory is empty, create a starter Flask application template
        if not os.path.exists(entry_path) and len(os.listdir(paths["app"])) == 0:
            with open(entry_path, "w", encoding="utf-8") as f:
                f.write(f'''# Starter Python Web Application
import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
PORT = int(os.environ.get("PORT", {server["assigned_port"]}))

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{server["name"]} - Live</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            background: #09090b;
            color: #fafafa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .badge {{
            display: inline-block;
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }}
        h1 {{ margin: 0 0 10px; font-size: 24px; }}
        p {{ color: #a1a1aa; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }}
        .meta {{
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            color: #38bdf8;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">● Online & Healthy</div>
        <h1>{server["name"]}</h1>
        <p>Your Python application is live and running smoothly on Vesper Cloud infrastructure.</p>
        <div class="meta">Subdomain: {server["subdomain"]} | Port: {server["assigned_port"]}</div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/health")
def health():
    return jsonify({{"status": "ok", "app": "{server["name"]}", "port": PORT}})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
''')
            log_system_event(paths["logs"], f"Created default starter application template '{entry_file}'.")

        if not os.path.exists(entry_path):
            return False, f"Entry file '{entry_file}' does not exist in application root."

        # Prepare execution command
        python_bin = sys.executable or "python3"
        custom_cmd = server["startup_command"]
        if custom_cmd and custom_cmd.strip():
            cmd_parts = custom_cmd.strip().split()
            if cmd_parts[0] in ("python", "python3", "python3.10", "py"):
                cmd_parts[0] = python_bin
        else:
            cmd_parts = [python_bin, entry_file]

        env = get_server_env(server_id, server["assigned_port"])

        # Open log files in append mode
        stdout_f = open(paths["stdout_log"], "a", encoding="utf-8")
        stderr_f = open(paths["stderr_log"], "a", encoding="utf-8")
        
        # Auto-install modules & requirements directly into the main server on start
        try:
            auto_install_server_dependencies(server_id, server["user_id"], paths, entry_file=entry_file)
        except Exception as e:
            log_system_event(paths["logs"], f"Notice: Error during auto-dependency install: {e}")

        # Initialize sandboxed isolation environment
        jail_dir = paths["jail"]
        prepare_sandbox_jail(jail_dir, paths["app"])

        # Construct sandboxed command execution via sandbox_launcher.py
        launcher_script = os.path.join(config.BASE_DIR, "sandbox_launcher.py")
        if os.path.exists(launcher_script):
            sandboxed_cmd = [python_bin, launcher_script, jail_dir, paths["app"]] + cmd_parts
        else:
            sandboxed_cmd = cmd_parts

        log_system_event(paths["logs"], f"Launching application: {' '.join(cmd_parts)} (Port: {server['assigned_port']}) [Sandboxed Isolation Active]")
        
        # Launch sandboxed Python process with independent process group
        try:
            popen = subprocess.Popen(
                sandboxed_cmd,
                cwd=paths["app"],
                env=env,
                stdout=stdout_f,
                stderr=stderr_f,
                preexec_fn=os.setsid if os.name != "nt" else None
            )
        except Exception as e:
            stdout_f.close()
            stderr_f.close()
            log_system_event(paths["logs"], f"Failed to start process: {str(e)}")
            return False, f"Failed to spawn process: {str(e)}"

        pid = popen.pid
        _active_processes[server_id] = {
            "popen": popen,
            "pid": pid,
            "stdout_f": stdout_f,
            "stderr_f": stderr_f,
            "started_at": time.time(),
            "last_crash": 0
        }

        # Update database status
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("""
        UPDATE servers 
        SET status = 'running', pid = ?, last_restart_at = ?, updated_at = ?
        WHERE id = ?
        """, (pid, now_str, now_str, server_id))
        db.commit()

        log_system_event(paths["logs"], f"Process started successfully with PID {pid}.")
        return True, f"Application started with PID {pid}"

def stop_server(server_id, mark_status="stopped"):
    """Stops a running application process cleanly."""
    with _process_lock:
        db = get_db()
        server = db.execute("SELECT id, user_id, pid, status FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not server:
            return False, "Server not found"

        paths = get_server_paths(server["user_id"], server_id)
        pid = server["pid"]
        
        # Check active tracking
        proc_info = _active_processes.pop(server_id, None)
        if proc_info:
            try:
                proc_info["stdout_f"].close()
                proc_info["stderr_f"].close()
            except Exception:
                pass

        if pid and psutil.pid_exists(pid):
            try:
                parent = psutil.Process(pid)
                # Terminate children first
                children = parent.children(recursive=True)
                for child in children:
                    try:
                        child.kill()
                    except Exception:
                        pass
                parent.kill()
                gone, alive = psutil.wait_procs(children + [parent], timeout=1)
                for p in alive:
                    try:
                        p.kill()
                    except Exception:
                        pass
                        
                log_system_event(paths["logs"], f"Process group (PID {pid}) terminated successfully.")
            except Exception as e:
                log_system_event(paths["logs"], f"Error terminating PID {pid}: {str(e)}")

        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("""
        UPDATE servers 
        SET status = ?, pid = NULL, updated_at = ?
        WHERE id = ?
        """, (mark_status, now_str, server_id))
        db.commit()
        
        return True, f"Server stopped (status: {mark_status})"

def stop_server_on_ram_limit_exceeded(server_id, user_id, server_name, used_ram_mb, limit_ram_mb, grace_mb=30):
    """
    Turns off a server instance when it exceeds its allocated RAM limit (+ 30MB grace).
    Logs the termination in system.log and stderr.log, creates an in-app error notification,
    and cleanly stops the process group without auto-restarting.
    """
    paths = get_server_paths(user_id, server_id)
    threshold_mb = limit_ram_mb + grace_mb
    msg = (
        f"[RESOURCE EXCEEDED] Application exceeded RAM limit! "
        f"Memory used: {used_ram_mb:.1f} MB (Allocated Limit: {limit_ram_mb} MB, Grace: {int(grace_mb)} MB, Shutdown Threshold: {threshold_mb} MB). "
        f"The project has been automatically turned off to protect system stability."
    )
    
    # 1. Log to system event log
    log_system_event(paths["logs"], msg)
    
    # 2. Append to stderr log so user sees it in console and log viewer
    try:
        with open(paths["stderr_log"], "a", encoding="utf-8") as f:
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            f.write(f"\n[{ts}] {msg}\n")
    except Exception:
        pass
        
    # 3. Stop server process cleanly and set status = 'stopped'
    stop_server(server_id, mark_status="stopped")
    
    # 4. Insert in-app notification
    try:
        from notifications import create_notification
        create_notification(
            user_id=user_id,
            server_id=server_id,
            title="Server Turned Off: RAM Limit Exceeded",
            message=(
                f"Your project '{server_name}' was automatically turned off because it consumed "
                f"{used_ram_mb:.1f} MB RAM, exceeding your limit of {limit_ram_mb} MB "
                f"(with {int(grace_mb)} MB grace allowance)."
            ),
            notif_type="error"
        )
    except Exception as e:
        print(f"[ProcessManager] Notification creation error: {e}")

def restart_server(server_id):
    """Restarts a server instance."""
    db = get_db()
    db.execute("UPDATE servers SET restart_count = restart_count + 1 WHERE id = ?", (server_id,))
    db.commit()
    stop_server(server_id, mark_status="starting")
    time.sleep(0.5)
    return start_server(server_id)

def get_server_metrics(server_id):
    """Returns live CPU %, RAM MB, and status for a server instance."""
    db = get_db()
    server = db.execute("SELECT id, pid, status, user_id, name FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return {"status": "unknown", "cpu_percent": 0.0, "ram_mb": 0.0, "uptime_seconds": 0}
        
    pid = server["pid"]
    if not pid or not psutil.pid_exists(pid):
        return {
            "status": server["status"] if server["status"] != "running" else "stopped",
            "cpu_percent": 0.0,
            "ram_mb": 0.0,
            "uptime_seconds": 0
        }
        
    try:
        proc = psutil.Process(pid)
        if proc.status() == psutil.STATUS_ZOMBIE:
            return {"status": "zombie", "cpu_percent": 0.0, "ram_mb": 0.0, "uptime_seconds": 0}
            
        # Collect metric information including child processes inside container
        procs = [proc]
        try:
            procs.extend(proc.children(recursive=True))
        except Exception:
            pass

        total_rss = 0
        total_cpu = 0.0
        for p in procs:
            try:
                total_rss += p.memory_info().rss
                total_cpu += p.cpu_percent(interval=0.05)
            except Exception:
                pass

        ram_mb = round(total_rss / (1024 * 1024), 2)
        create_time = proc.create_time()
        uptime = int(time.time() - create_time)

        # Enforce RAM limits (grace is 30MB): if exceeded, turn off the project
        try:
            from resource_manager import get_server_limits
            limits = get_server_limits(server_id)
            limit_ram_mb = limits["ram_mb"] if limits else config.DEFAULT_RAM_LIMIT_MB
            grace_mb = getattr(config, "RAM_GRACE_MB", 30)
            threshold_mb = limit_ram_mb + grace_mb

            if ram_mb > threshold_mb:
                s_name = server["name"] if "name" in server.keys() else f"Server #{server_id}"
                stop_server_on_ram_limit_exceeded(
                    server_id, server["user_id"], s_name, ram_mb, limit_ram_mb, grace_mb
                )
                return {
                    "status": "stopped",
                    "cpu_percent": 0.0,
                    "ram_mb": ram_mb,
                    "uptime_seconds": 0,
                    "ram_exceeded": True,
                    "ram_limit_mb": limit_ram_mb,
                    "ram_grace_mb": grace_mb,
                    "max_ram_mb": threshold_mb
                }
        except Exception as ram_err:
            print(f"[ProcessManager] RAM check error in get_server_metrics: {ram_err}")
        
        return {
            "status": "running",
            "cpu_percent": round(total_cpu, 1),
            "ram_mb": ram_mb,
            "uptime_seconds": uptime
        }
    except Exception:
        return {"status": server["status"], "cpu_percent": 0.0, "ram_mb": 0.0, "uptime_seconds": 0}

def execute_console_command(user_id, server_id, command_str):
    """Executes a console command inside the application directory using pure Python."""
    paths = get_server_paths(user_id, server_id)
    cmd = command_str.strip()
    if not cmd:
        return ""
    
    # Security checks: block destructive system commands
    blocked = ["rm -rf /", "mkfs", "dd if=", "shutdown", "reboot", "init 0", ":(){ :|:& };:"]
    for b in blocked:
        if b in cmd:
            return "Execution Blocked: Destructive or dangerous command prohibited."

    try:
        python_bin = sys.executable or "python3"
        jail_dir = paths["jail"]
        prepare_sandbox_jail(jail_dir, paths["app"])

        launcher_script = os.path.join(config.BASE_DIR, "sandbox_launcher.py")
        if os.path.exists(launcher_script):
            sandboxed_cmd = [python_bin, launcher_script, jail_dir, paths["app"], "/bin/sh", "-c", cmd]
            use_shell = False
        else:
            sandboxed_cmd = cmd
            use_shell = True

        # Dynamic timeout: give package installation commands more time (up to 90s)
        cmd_lower = cmd.lower()
        timeout_val = 90 if ("pip " in cmd_lower or "install" in cmd_lower) else 20

        res = subprocess.run(
            sandboxed_cmd,
            shell=use_shell,
            cwd=paths["app"],
            capture_output=True,
            text=True,
            timeout=timeout_val,
            env=get_server_env(server_id, 0)
        )
        output = res.stdout
        if res.stderr:
            output += ("\n[STDERR]\n" if output else "") + res.stderr
        if not output:
            output = f"[Process exited with return code {res.returncode}]"
        return output
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 15 seconds."
    except Exception as e:
        return f"Execution Error: {str(e)}"

def install_requirements(user_id, server_id):
    """
    Installs dependencies directly into the server. Automatically scans Python
    code to populate requirements.txt with any missing modules before installing.
    """
    paths = get_server_paths(user_id, server_id)
    # First, run auto-detection to discover imports and update requirements.txt
    auto_install_server_dependencies(server_id, user_id, paths)

    req_file = os.path.join(paths["app"], "requirements.txt")
    if not os.path.exists(req_file):
        return False, "No requirements.txt found or required modules detected."

    pip_bin = sys.executable or "python3"
    cmd = [pip_bin, "-m", "pip", "install", "-r", "requirements.txt", "--break-system-packages", "--no-cache-dir"]
    
    log_system_event(paths["logs"], "Starting dependencies installation directly to main server...")
    try:
        res = subprocess.run(
            cmd,
            cwd=paths["app"],
            capture_output=True,
            text=True,
            timeout=180,
            env=get_pip_env(paths["app"])
        )
        with open(paths["system_log"], "a", encoding="utf-8") as f:
            f.write("\n=== PIP INSTALL LOGS ===\n" + (res.stdout or "") + (("\n[ERRORS]\n" + res.stderr) if res.stderr else "") + "\n")
            
        if res.returncode == 0:
            log_system_event(paths["logs"], "Dependencies installed directly to main server successfully.")
            return True, "Dependencies installed directly to main server successfully."
        else:
            log_system_event(paths["logs"], f"Pip install returned error code {res.returncode}")
            return False, f"Pip error: {res.stderr[:200] if res.stderr else 'Installation failed'}"
    except subprocess.TimeoutExpired:
        log_system_event(paths["logs"], "Pip install timed out after 180 seconds.")
        return False, "Installation timed out."
    except Exception as e:
        return False, f"Installation failed: {str(e)}"

def monitor_loop():
    """Background thread loop that monitors running processes, enforces RAM limits (30MB grace), and handles auto-restarts."""
    while not _stop_monitor.is_set():
        try:
            # We connect to database in thread
            conn = get_db()
            cursor = conn.execute("SELECT id, user_id, pid, status, auto_restart, restart_count, name FROM servers WHERE status = 'running'")
            running_servers = cursor.fetchall()
            
            for s in running_servers:
                sid = s["id"]
                pid = s["pid"]
                
                # Check process liveness
                is_alive = False
                p = None
                if pid and psutil.pid_exists(pid):
                    try:
                        p = psutil.Process(pid)
                        if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                            is_alive = True
                    except Exception:
                        is_alive = False
                        p = None

                if is_alive and p:
                    # Enforce RAM limits (grace is 30MB): if exceeded, turn off the project!
                    try:
                        from resource_manager import get_server_limits
                        limits = get_server_limits(sid)
                        limit_ram_mb = limits["ram_mb"] if limits else config.DEFAULT_RAM_LIMIT_MB
                        grace_mb = getattr(config, "RAM_GRACE_MB", 30)
                        threshold_mb = limit_ram_mb + grace_mb

                        procs = [p]
                        try:
                            procs.extend(p.children(recursive=True))
                        except Exception:
                            pass

                        total_rss = 0
                        for pr in procs:
                            try:
                                total_rss += pr.memory_info().rss
                            except Exception:
                                pass

                        current_ram_mb = round(total_rss / (1024 * 1024), 2)
                        if current_ram_mb > threshold_mb:
                            # RAM limit exceeded! Turn off the project immediately!
                            stop_server_on_ram_limit_exceeded(
                                sid, s["user_id"], s["name"], current_ram_mb, limit_ram_mb, grace_mb
                            )
                            continue
                    except Exception as ram_check_err:
                        print(f"[ProcessManager] RAM monitor check error for server {sid}: {ram_check_err}")
                        
                if not is_alive:
                    paths = get_server_paths(s["user_id"], sid)

                    # Check if process exited due to OOM / SIGKILL (exit code 137 or -9)
                    is_oom = False
                    proc_info = _active_processes.get(sid)
                    if proc_info and proc_info.get("popen"):
                        ret = proc_info["popen"].poll()
                        if ret in (137, -9, -signal.SIGKILL):
                            is_oom = True

                    if is_oom:
                        # Process terminated due to OOM / memory limit: turn off project and do NOT auto-restart
                        stop_server(sid, mark_status="stopped")
                        msg = "Application terminated due to Out-Of-Memory (OOM / exit code 137). Server turned off."
                        log_system_event(paths["logs"], msg)
                        conn.execute("""
                        INSERT INTO notifications (user_id, server_id, title, message, type)
                        VALUES (?, ?, ?, ?, ?)
                        """, (s["user_id"], sid, "Server Turned Off: RAM Limit Exceeded", f"Application '{s['name']}' was turned off after exceeding allocated memory limit.", "error"))
                        conn.commit()
                        continue

                    log_system_event(paths["logs"], f"Process crash detected (PID {pid} no longer running).")
                    
                    # Record crash notification
                    conn.execute("""
                    INSERT INTO notifications (user_id, server_id, title, message, type)
                    VALUES (?, ?, ?, ?, ?)
                    """, (s["user_id"], sid, "Application Crashed", f"Application '{s['name']}' exited unexpectedly.", "error"))
                    
                    if s["auto_restart"] == 1 and s["restart_count"] < 15:
                        # Exponential backoff calculation
                        backoff = min(60, 2 ** min(6, s["restart_count"]))
                        log_system_event(paths["logs"], f"Auto-restart triggered (attempt #{s['restart_count'] + 1}, delay: {backoff}s)...")
                        
                        conn.execute("""
                        UPDATE servers SET status = 'starting', restart_count = restart_count + 1 WHERE id = ?
                        """, (sid,))
                        conn.commit()
                        
                        # Trigger restart in thread after backoff
                        threading.Timer(backoff, lambda s_id=sid: start_server(s_id)).start()
                    else:
                        conn.execute("UPDATE servers SET status = 'crashed', pid = NULL WHERE id = ?", (sid,))
                        conn.commit()
                        log_system_event(paths["logs"], "Auto-restart stopped (limit reached or disabled). Status marked as 'crashed'.")
                        
        except Exception as e:
            # Avoid crash in monitor thread
            print(f"[Process Monitor Error] {e}")
            
        time.sleep(1.5)

def start_monitor_thread():
    """Starts the background process monitoring thread."""
    global _monitor_thread
    if _monitor_thread is None or not _monitor_thread.is_alive():
        _stop_monitor.clear()
        _monitor_thread = threading.Thread(target=monitor_loop, daemon=True, name="ProcessMonitorThread")
        _monitor_thread.start()
        print("[ProcessManager] Background monitoring thread active.")

def recover_servers_on_startup():
    """Scans and synchronizes server process states on platform boot."""
    db = get_db()
    cursor = db.execute("SELECT id, user_id, pid, status, auto_restart, name FROM servers")
    servers = cursor.fetchall()
    recovered_count = 0
    
    for s in servers:
        sid = s["id"]
        pid = s["pid"]
        is_alive = False
        if pid and psutil.pid_exists(pid):
            try:
                p = psutil.Process(pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    is_alive = True
            except Exception:
                is_alive = False
                
        if not is_alive:
            if s["status"] == "running":
                db.execute("UPDATE servers SET status = 'stopped', pid = NULL WHERE id = ?", (sid,))
                recovered_count += 1
                
def create_server_instance(server_id, user_id, assigned_port, subdomain, zip_bytes=None):
    """Initializes filesystem directories and starter files for a new server instance."""
    paths = get_server_paths(user_id, server_id)
    app_dir = paths["app"]
    
    if zip_bytes:
        temp_zip = os.path.join(paths["logs"], "init_upload.zip")
        try:
            with open(temp_zip, "wb") as f:
                f.write(zip_bytes)
            safe_extract_zip(temp_zip, app_dir)
            os.remove(temp_zip)
            scan_ok, scan_msg = inspect_server_app_directory(app_dir)
            if not scan_ok:
                log_system_event(paths["logs"], f"[AI SECURITY ALERT] Uploaded project contains violations: {scan_msg}")
        except Exception as e:
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
            log_system_event(paths["logs"], f"Failed to extract uploaded zip template: {e}")
    else:
        # Default starter template
        entry_path = os.path.join(app_dir, "app.py")
        if not os.path.exists(entry_path):
            with open(entry_path, "w", encoding="utf-8") as f:
                f.write(f'''# Starter Python Web Application
import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
PORT = int(os.environ.get("PORT", {assigned_port}))

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{subdomain} - Live Application</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            background: #09090b;
            color: #fafafa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 520px;
            text-align: center;
            backdrop-filter: blur(12px);
        }}
        .badge {{
            display: inline-block;
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }}
        h1 {{ margin: 0 0 10px; font-size: 24px; }}
        p {{ color: #a1a1aa; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }}
        .meta {{
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            color: #38bdf8;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">● Online & Ready</div>
        <h1>{subdomain}</h1>
        <p>Your Python application is live and running smoothly on Vesper Cloud infrastructure.</p>
        <div class="meta">Subdomain: {subdomain} | Internal Port: {assigned_port}</div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/health")
def health():
    return jsonify({{"status": "ok", "subdomain": "{subdomain}", "port": PORT}})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
''')
        req_path = os.path.join(app_dir, "requirements.txt")
        if not os.path.exists(req_path):
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("Flask>=3.0.0\n")

    log_system_event(paths["logs"], f"Server instance initialized (Port {assigned_port}).")
    return True, paths

def delete_server_instance(server_id):
    """Cleanly terminates, deallocates resources, and purges a server instance from DB and disk."""
    stop_server(server_id)
    try:
        db = get_db()
        server = db.execute("SELECT id, user_id, assigned_port, subdomain FROM servers WHERE id = ?", (server_id,)).fetchone()
        if server:
            # Release port
            db.execute("DELETE FROM port_allocations WHERE server_id = ?", (server_id,))
            # Release domain
            db.execute("DELETE FROM domain_allocations WHERE server_id = ?", (server_id,))
            # Delete server record
            db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            db.commit()
            
            # Remove directory tree
            paths = get_server_paths(server["user_id"], server_id)
            if os.path.exists(paths["root"]):
                import shutil
                shutil.rmtree(paths["root"], ignore_errors=True)
                
            return True, "Server deleted successfully"
        return False, "Server not found"
    except Exception as e:
        return False, str(e)

# Aliases for route consistency
start_process_monitor = start_monitor_thread
start_server_process = start_server
stop_server_process = stop_server
restart_server_process = restart_server
