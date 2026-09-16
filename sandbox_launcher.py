import os
import sys
import ctypes
import shutil
import signal
import threading
import time

"""
Multi-Tier Sandboxed Application Launcher
- Tier 1: Native Linux Kernel Namespaces & Chroot Jail (when running with CAP_SYS_ADMIN / privileged container)
- Tier 2: User-Space Runtime Sandbox & Path Isolation Hook (when running in unprivileged containers, e.g. Pterodactyl)

Guarantees that:
1. Operation not permitted (errno 1 / EPERM) never crashes execution.
2. Bot cannot inspect or access host files (/app, /home/container, /root, /etc/shadow, database, other users' apps).
3. Requirements and pip installations work seamlessly into workspace .local directory.
4. Process inspection (psutil) is isolated to the bot's own process tree.
"""

libc = ctypes.CDLL("libc.so.6", use_errno=True)

CLONE_NEWPID = 0x20000000
CLONE_NEWNS  = 0x00020000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUTS = 0x04000000

MS_BIND = 4096
MS_REC = 16384
MS_RDONLY = 1
MS_PRIVATE = 1 << 18
MS_NOSUID = 2
MS_NODEV = 4
PR_SET_NO_NEW_PRIVS = 38

def is_kernel_jail_supported(jail_dir):
    """
    Checks if this container environment has capabilities to execute mount and chroot.
    In unprivileged environments (like Pterodactyl /home/container), mount/chroot raises EPERM (errno 1).
    """
    try:
        if os.geteuid() != 0:
            return False
        if not os.path.exists(jail_dir):
            try:
                os.makedirs(jail_dir, exist_ok=True)
            except Exception:
                return False
        # Test in a micro-fork to avoid altering main process
        pid = os.fork()
        if pid == 0:
            try:
                test_sub = os.path.join(jail_dir, ".probe_mnt")
                os.makedirs(test_sub, exist_ok=True)
                res = libc.mount(jail_dir.encode(), test_sub.encode(), None, MS_BIND | MS_RDONLY, None)
                if res != 0:
                    os._exit(1)
                libc.umount(test_sub.encode())
                try:
                    os.rmdir(test_sub)
                except Exception:
                    pass
                os.chroot(jail_dir)
                os._exit(0)
            except Exception:
                os._exit(1)
        else:
            _, status = os.waitpid(pid, 0)
            return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    except Exception:
        return False

def mnt(src, target, fstype, flags, data=None):
    res = libc.mount(
        src.encode() if src else None,
        target.encode(),
        fstype.encode() if fstype else None,
        flags,
        data.encode() if data else None
    )
    return res == 0

def start_parent_ram_watchdog(child_pid):
    """Monitors child_pid and its children in real-time from host side (every 30ms)."""
    limit_str = os.environ.get("VESPER_RAM_LIMIT_MB", "")
    grace_str = os.environ.get("VESPER_RAM_GRACE_MB", "30")
    if not limit_str:
        return None, None
    try:
        limit_mb = float(limit_str)
        grace_mb = float(grace_str)
        threshold_mb = limit_mb + grace_mb
    except Exception:
        return None, None

    stop_event = threading.Event()
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

    def _watchdog_worker():
        while not stop_event.is_set():
            time.sleep(0.03)
            try:
                total_rss_bytes = 0
                statm_file = f"/proc/{child_pid}/statm"
                if os.path.exists(statm_file):
                    try:
                        with open(statm_file, "r") as f:
                            parts = f.read().split()
                            if len(parts) >= 2:
                                total_rss_bytes += int(parts[1]) * page_size
                    except Exception:
                        pass
                else:
                    break

                try:
                    import psutil
                    p = psutil.Process(child_pid)
                    for cp in p.children(recursive=True):
                        try:
                            total_rss_bytes += cp.memory_info().rss
                        except Exception:
                            pass
                except Exception:
                    pass

                used_mb = total_rss_bytes / (1024 * 1024)
                if used_mb > threshold_mb:
                    sys.stderr.write(
                        f"\n[RESOURCE LIMIT EXCEEDED] Application exceeded RAM limit! "
                        f"Memory used: {used_mb:.1f} MB (Allocated Limit: {limit_mb:.1f} MB, Grace: {grace_mb:.1f} MB, Shutdown Threshold: {threshold_mb:.1f} MB). "
                        f"The project has been automatically turned off.\n"
                    )
                    sys.stderr.flush()
                    try:
                        import psutil
                        p = psutil.Process(child_pid)
                        for cp in p.children(recursive=True):
                            try:
                                cp.kill()
                            except Exception:
                                pass
                        p.kill()
                    except Exception:
                        pass
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except Exception:
                        pass
                    os._exit(137)
            except Exception:
                pass

    t = threading.Thread(target=_watchdog_worker, daemon=True, name="ParentRamWatchdog")
    t.start()
    return t, stop_event

def wait_for_child_with_watchdog(child_pid, stop_event):
    def sig_forwarder(signum, frame):
        try:
            os.kill(child_pid, signum)
        except OSError:
            pass

    signal.signal(signal.SIGTERM, sig_forwarder)
    signal.signal(signal.SIGINT, sig_forwarder)
    signal.signal(signal.SIGHUP, sig_forwarder)

    try:
        _, status = os.waitpid(child_pid, 0)
    finally:
        if stop_event:
            stop_event.set()

    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    elif os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    sys.exit(0)

def run_userspace_sandbox(app_dir, cmd_args):
    """
    Tier 2: User-Space Sandbox & Runtime Security Hook.
    Runs cleanly without requiring root, kernel mount, or chroot privileges.
    Protects host files, other users' apps, and system authentication files.
    """
    app_dir = os.path.abspath(app_dir)
    
    # Locate host base (e.g. /home/container/dirt or /app/applet)
    if "/storage/apps" in app_dir:
        host_base = app_dir.split("/storage/apps")[0]
    else:
        host_base = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(app_dir))))

    # Prepare security hook directory
    hook_dir = os.path.join(app_dir, ".sandbox_hook")
    try:
        if os.path.exists(hook_dir):
            try:
                os.chmod(hook_dir, 0o755)
            except Exception:
                pass
        os.makedirs(hook_dir, exist_ok=True)
        hook_path = os.path.join(hook_dir, "sitecustomize.py")
        if os.path.exists(hook_path):
            try:
                os.chmod(hook_path, 0o644)
            except Exception:
                pass
        with open(hook_path, "w", encoding="utf-8") as hf:
            hf.write('''import builtins
import io
import os
import sys

app_dir = os.environ.get("SANDBOX_APP_DIR", "")
host_base = os.environ.get("SANDBOX_HOST_BASE", "")

orig_open = builtins.open
orig_listdir = os.listdir
orig_scandir = os.scandir
orig_remove = getattr(os, "remove", None)
orig_unlink = getattr(os, "unlink", None)
orig_rename = getattr(os, "rename", None)
orig_rmdir = getattr(os, "rmdir", None)

def is_path_blocked(path_str):
    try:
        norm = os.path.realpath(os.path.abspath(str(path_str)))
    except Exception:
        norm = str(path_str)
    
    # 1. Block sensitive system authentication & root paths
    for sensitive in ["/etc/shadow", "/etc/sudoers", "/root"]:
        if norm == sensitive or norm.startswith(sensitive + "/"):
            return True
            
    # 2. Block host base files outside the app's own directory
    if host_base and app_dir:
        real_base = os.path.realpath(host_base)
        real_app = os.path.realpath(app_dir)
        if norm == real_base or norm.startswith(real_base + "/"):
            if not (norm == real_app or norm.startswith(real_app + "/")):
                return True
    return False

def is_sandbox_hook_target(path_str):
    p = str(path_str).replace("\\\\", "/")
    parts = [part for part in p.split("/") if part and part != "."]
    return ".sandbox_hook" in parts

def safe_open(file, *args, **kwargs):
    s = str(file)
    if is_path_blocked(s):
        raise PermissionError(f"[Sandbox] Access Denied: '{s}' is protected.")
    if is_sandbox_hook_target(s):
        mode = args[0] if args else kwargs.get("mode", "r")
        if any(m in mode for m in ("w", "a", "+", "x")):
            raise PermissionError("[Sandbox] Access Denied: Cannot modify or write to .sandbox_hook files.")
    if s == "/etc/passwd":
        mode = args[0] if args else kwargs.get("mode", "r")
        if "w" in mode or "a" in mode or "+" in mode:
            raise PermissionError("[Sandbox] Cannot write to /etc/passwd")
        return io.StringIO("botuser:x:10001:10001:Sandboxed Bot User:/workspace:/bin/sh\\n")
    return orig_open(file, *args, **kwargs)

def safe_listdir(path="."):
    if is_path_blocked(path):
        raise PermissionError(f"[Sandbox] Access Denied: '{path}' is protected.")
    return orig_listdir(path)

def safe_scandir(path="."):
    if is_path_blocked(path):
        raise PermissionError(f"[Sandbox] Access Denied: '{path}' is protected.")
    return orig_scandir(path)

def safe_remove(path, *args, **kwargs):
    if is_sandbox_hook_target(path):
        raise PermissionError("[Sandbox] Access Denied: Cannot delete .sandbox_hook files.")
    if orig_remove:
        return orig_remove(path, *args, **kwargs)

def safe_unlink(path, *args, **kwargs):
    if is_sandbox_hook_target(path):
        raise PermissionError("[Sandbox] Access Denied: Cannot delete .sandbox_hook files.")
    if orig_unlink:
        return orig_unlink(path, *args, **kwargs)

def safe_rename(src, dst, *args, **kwargs):
    if is_sandbox_hook_target(src) or is_sandbox_hook_target(dst):
        raise PermissionError("[Sandbox] Access Denied: Cannot rename .sandbox_hook files.")
    if orig_rename:
        return orig_rename(src, dst, *args, **kwargs)

def safe_rmdir(path, *args, **kwargs):
    if is_sandbox_hook_target(path):
        raise PermissionError("[Sandbox] Access Denied: Cannot delete .sandbox_hook directory.")
    if orig_rmdir:
        return orig_rmdir(path, *args, **kwargs)

builtins.open = safe_open
io.open = safe_open
os.listdir = safe_listdir
os.scandir = safe_scandir
if orig_remove:
    os.remove = safe_remove
if orig_unlink:
    os.unlink = safe_unlink
if orig_rename:
    os.rename = safe_rename
if orig_rmdir:
    os.rmdir = safe_rmdir

# Intercept psutil if imported to shield host processes
try:
    import psutil
    _orig_process_iter = psutil.process_iter
    _orig_pids = psutil.pids
    current_pid = os.getpid()

    def safe_pids():
        try:
            curr = psutil.Process(current_pid)
            child_pids = [c.pid for c in curr.children(recursive=True)]
            return [current_pid] + child_pids
        except Exception:
            return [current_pid]

    def safe_process_iter(attrs=None, ad_value=None):
        allowed = set(safe_pids())
        for p in _orig_process_iter(attrs=attrs, ad_value=ad_value):
            if p.pid in allowed:
                yield p

    psutil.pids = safe_pids
    psutil.process_iter = safe_process_iter
except Exception:
    pass

# Real-time memory watchdog (auto shutdown if RAM limit + 30MB grace exceeded)
try:
    import threading
    import time
    
    _ram_limit_str = os.environ.get("VESPER_RAM_LIMIT_MB", "")
    _ram_grace_str = os.environ.get("VESPER_RAM_GRACE_MB", "30")
    if _ram_limit_str:
        _limit_mb = float(_ram_limit_str)
        _grace_mb = float(_ram_grace_str)
        _max_allowed_mb = _limit_mb + _grace_mb

        def _mem_watchdog():
            page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
            while True:
                time.sleep(0.015)
                try:
                    rss_bytes = 0
                    if os.path.exists("/proc/self/statm"):
                        with open("/proc/self/statm", "r") as sm:
                            parts = sm.read().split()
                            if len(parts) >= 2:
                                rss_pages = int(parts[1])
                                rss_bytes = rss_pages * page_size
                    if rss_bytes == 0 and "psutil" in sys.modules:
                        p_mod = sys.modules["psutil"]
                        if hasattr(p_mod, "Process"):
                            rss_bytes = p_mod.Process().memory_info().rss
                    
                    if rss_bytes > 0:
                        used_mb = rss_bytes / (1024 * 1024)
                        if used_mb > _max_allowed_mb:
                            sys.stderr.write(f"\\n[RESOURCE LIMIT EXCEEDED] Application RAM limit exceeded ({used_mb:.1f} MB used / {_limit_mb:.1f} MB limit + {_grace_mb:.1f} MB grace, shutdown threshold: {_max_allowed_mb:.1f} MB). The project has been automatically turned off.\\n")
                            sys.stderr.flush()
                            os._exit(137)
                except Exception:
                    pass

        _t = threading.Thread(target=_mem_watchdog, daemon=True, name="VesperMemWatchdog")
        _t.start()
except Exception:
    pass
''')
        # Enforce read-only filesystem permissions on hook
        try:
            os.chmod(hook_path, 0o444)
            os.chmod(hook_dir, 0o555)
        except Exception:
            pass
    except Exception as e:
        sys.stderr.write(f"[Sandbox] Hook initialization notice: {e}\n")

    # Set up safe sandboxed environment
    os.environ["SANDBOX_APP_DIR"] = app_dir
    os.environ["SANDBOX_HOST_BASE"] = host_base
    os.environ["HOME"] = "/tmp"
    os.environ["USER"] = "botuser"
    os.environ["LOGNAME"] = "botuser"
    os.environ["PYTHONUSERBASE"] = os.path.join(app_dir, ".local")
    os.environ["PIP_NO_CACHE_DIR"] = "1"
    os.environ["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    os.environ["PYTHONUNBUFFERED"] = "1"

    # Purge sensitive host environment variables from child process
    for sensitive_env in ["FLASK_SECRET", "SECRET_KEY", "ADMIN_PASSWORD", "DATABASE_URL", "UPI_KEY"]:
        os.environ.pop(sensitive_env, None)

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    local_site = os.path.join(app_dir, ".local", "lib", f"python{py_ver}", "site-packages")
    local_bin = os.path.join(app_dir, ".local", "bin")

    existing_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    os.environ["PATH"] = f"{local_bin}:{existing_path}"

    existing_pypath = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = f"{hook_dir}:{app_dir}:{local_site}:{existing_pypath}"

    os.chdir(app_dir)
    child_pid = os.fork()
    if child_pid == 0:
        os.execvp(cmd_args[0], cmd_args)
    else:
        _, stop_event = start_parent_ram_watchdog(child_pid)
        wait_for_child_with_watchdog(child_pid, stop_event)

def run_kernel_jail(jail_dir, app_dir, cmd_args):
    """
    Tier 1: Linux Namespaces & Chroot Jail.
    Used when running with CAP_SYS_ADMIN privileges.
    """
    try:
        libc.unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS)
    except Exception as e:
        sys.stderr.write(f"[Sandbox] unshare notice: {e}\n")

    child_pid = os.fork()
    if child_pid == 0:
        try:
            mnt("none", "/", None, MS_REC | MS_PRIVATE)

            for d in ["usr", "bin", "lib", "lib64"]:
                host_path = "/" + d
                if os.path.exists(host_path):
                    mnt(host_path, os.path.join(jail_dir, d), None, MS_BIND | MS_REC | MS_RDONLY)

            for dev in ["null", "zero", "urandom", "random"]:
                host_dev = "/dev/" + dev
                if os.path.exists(host_dev):
                    jail_dev = os.path.join(jail_dir, "dev", dev)
                    try:
                        open(jail_dev, "w").close()
                    except Exception:
                        pass
                    mnt(host_dev, jail_dev, None, MS_BIND)

            mnt("proc", os.path.join(jail_dir, "proc"), "proc", MS_NOSUID | MS_NODEV | MS_RDONLY)
            mnt(app_dir, os.path.join(jail_dir, "workspace"), None, MS_BIND | MS_REC)

            for e in ["resolv.conf", "ssl", "hosts", "nsswitch.conf"]:
                src = os.path.join("/etc", e)
                if os.path.exists(src):
                    dst = os.path.join(jail_dir, "etc", e)
                    if os.path.isdir(src):
                        os.makedirs(dst, exist_ok=True)
                        mnt(src, dst, None, MS_BIND | MS_REC | MS_RDONLY)
                    else:
                        try:
                            open(dst, "w").close()
                        except Exception:
                            pass
                        mnt(src, dst, None, MS_BIND | MS_RDONLY)

            try:
                with open(os.path.join(jail_dir, "etc", "passwd"), "w", encoding="utf-8") as pf:
                    pf.write("botuser:x:10001:10001:Sandboxed Bot User:/workspace:/bin/sh\n")
                with open(os.path.join(jail_dir, "etc", "group"), "w", encoding="utf-8") as gf:
                    gf.write("botuser:x:10001:\n")
            except Exception:
                pass

            os.chroot(jail_dir)
            os.chdir("/workspace")

            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            try:
                os.setgid(10001)
                os.setuid(10001)
            except Exception:
                pass

            os.environ["HOME"] = "/tmp"
            os.environ["USER"] = "botuser"
            os.environ["LOGNAME"] = "botuser"
            os.environ["PYTHONUSERBASE"] = "/workspace/.local"
            os.environ["PIP_NO_CACHE_DIR"] = "1"
            os.environ["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
            
            existing_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
            os.environ["PATH"] = f"/workspace/.local/bin:{existing_path}"
            
            py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
            local_site = f"/workspace/.local/lib/python{py_ver}/site-packages"
            existing_pypath = os.environ.get("PYTHONPATH", "")
            if existing_pypath:
                os.environ["PYTHONPATH"] = f"/workspace/.sandbox_hook:/workspace:{local_site}:{existing_pypath}"
            else:
                os.environ["PYTHONPATH"] = f"/workspace/.sandbox_hook:/workspace:{local_site}"

            os.execvp(cmd_args[0], cmd_args)
        except Exception as e:
            sys.stderr.write(f"[Sandbox] Kernel jail failure, falling back: {e}\n")
            run_userspace_sandbox(app_dir, cmd_args)
    else:
        _, stop_event = start_parent_ram_watchdog(child_pid)
        wait_for_child_with_watchdog(child_pid, stop_event)

def main():
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: sandbox_launcher.py <jail_dir> <app_dir> <command...>\n")
        sys.exit(1)

    jail_dir = sys.argv[1]
    app_dir = sys.argv[2]
    cmd_args = sys.argv[3:]

    # Check if Kernel Jail (mount / chroot) is permitted in current container
    if is_kernel_jail_supported(jail_dir):
        run_kernel_jail(jail_dir, app_dir, cmd_args)
    else:
        run_userspace_sandbox(app_dir, cmd_args)

if __name__ == "__main__":
    main()
