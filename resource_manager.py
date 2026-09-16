import os
import psutil
from database import get_db
import config

def get_vps_system_metrics():
    """Retrieves VPS-level CPU, Memory, Disk, and Load averages."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count(logical=True)
        
        mem = psutil.virtual_memory()
        ram_total_mb = round(mem.total / (1024 * 1024), 1)
        ram_used_mb = round(mem.used / (1024 * 1024), 1)
        ram_available_mb = round(mem.available / (1024 * 1024), 1)
        ram_percent = mem.percent
        
        disk = psutil.disk_usage(config.STORAGE_DIR)
        disk_total_gb = round(disk.total / (1024 * 1024 * 1024), 2)
        disk_used_gb = round(disk.used / (1024 * 1024 * 1024), 2)
        disk_free_gb = round(disk.free / (1024 * 1024 * 1024), 2)
        disk_percent = disk.percent
        
        try:
            load_avg = [round(x, 2) for x in os.getloadavg()]
        except (AttributeError, OSError):
            load_avg = [0.0, 0.0, 0.0]
            
        return {
            "cpu_percent": cpu_percent,
            "cpu_count": cpu_count,
            "ram_total_mb": ram_total_mb,
            "ram_used_mb": ram_used_mb,
            "ram_available_mb": ram_available_mb,
            "ram_percent": ram_percent,
            "disk_total_gb": disk_total_gb,
            "disk_used_gb": disk_used_gb,
            "disk_free_gb": disk_free_gb,
            "disk_percent": disk_percent,
            "load_avg": load_avg
        }
    except Exception as e:
        print(f"[Resource Manager Error] {e}")
        return {
            "cpu_percent": 0, "cpu_count": 1, "ram_total_mb": 0, "ram_used_mb": 0,
            "ram_available_mb": 0, "ram_percent": 0, "disk_total_gb": 0, "disk_used_gb": 0,
            "disk_free_gb": 0, "disk_percent": 0, "load_avg": [0, 0, 0]
        }

def calculate_directory_size(directory):
    """Calculates recursive size in bytes of a directory."""
    total = 0
    if not os.path.exists(directory):
        return 0
    for root, dirs, files in os.walk(directory):
        for f in files:
            fp = os.path.join(root, f)
            try:
                if not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total

def update_server_storage(user_id, server_id):
    """Calculates and stores actual disk usage for a server."""
    server_dir = os.path.join(config.APPS_DIR, f"user_{user_id}", f"server_{server_id}")
    total_bytes = calculate_directory_size(server_dir)
    db = get_db()
    db.execute("UPDATE servers SET storage_used_bytes = ? WHERE id = ?", (total_bytes, server_id))
    db.commit()
    return total_bytes

def get_server_limits(server_id):
    """Returns effective resource limits (RAM, Storage, Bandwidth, CPU) considering custom admin overrides."""
    db = get_db()
    row = db.execute("""
    SELECT s.id, s.storage_used_bytes, s.bandwidth_used_bytes,
           sub.custom_ram_mb, sub.custom_storage_mb, sub.custom_bandwidth_mb, sub.custom_cpu_cores,
           p.ram_mb as plan_ram_mb, p.storage_mb as plan_storage_mb, p.bandwidth_mb as plan_bandwidth_mb,
           p.cpu_cores as plan_cpu_cores
    FROM servers s
    LEFT JOIN subscriptions sub ON s.subscription_id = sub.id
    LEFT JOIN plans p ON sub.plan_id = p.id
    WHERE s.id = ?
    """, (server_id,)).fetchone()
    
    if not row:
        return None
        
    ram_mb = row["custom_ram_mb"] if row["custom_ram_mb"] is not None else (row["plan_ram_mb"] or config.DEFAULT_RAM_LIMIT_MB)
    storage_mb = row["custom_storage_mb"] if row["custom_storage_mb"] is not None else (row["plan_storage_mb"] or config.DEFAULT_STORAGE_LIMIT_MB)
    bandwidth_mb = row["custom_bandwidth_mb"] if row["custom_bandwidth_mb"] is not None else (row["plan_bandwidth_mb"] or config.DEFAULT_BANDWIDTH_LIMIT_MB)
    cpu_cores = row["custom_cpu_cores"] if row["custom_cpu_cores"] is not None else (row["plan_cpu_cores"] or 1)
    
    ram_grace_mb = getattr(config, "RAM_GRACE_MB", 30)
    max_ram_mb = ram_mb + ram_grace_mb

    storage_used = row["storage_used_bytes"] or 0
    bandwidth_used = row["bandwidth_used_bytes"] or 0
    used_storage_mb = round(storage_used / (1024 * 1024), 2)
    used_bandwidth_mb = round(bandwidth_used / (1024 * 1024), 2)
    
    return {
        "ram_mb": ram_mb,
        "ram_grace_mb": ram_grace_mb,
        "max_ram_mb": max_ram_mb,
        "storage_mb": storage_mb,
        "bandwidth_mb": bandwidth_mb,
        "cpu_cores": cpu_cores,
        "used_storage_mb": used_storage_mb,
        "used_bandwidth_mb": used_bandwidth_mb,
        "storage_percent": min(100.0, round((used_storage_mb / max(1, storage_mb)) * 100, 1)),
        "bandwidth_percent": min(100.0, round((used_bandwidth_mb / max(1, bandwidth_mb)) * 100, 1))
    }

def check_storage_quota(user_id, server_id, additional_bytes=0):
    """
    Checks if adding 'additional_bytes' will breach the server's storage quota.
    Returns (is_allowed, current_mb, limit_mb).
    """
    current_bytes = update_server_storage(user_id, server_id)
    limits = get_server_limits(server_id)
    if not limits:
        return False, 0, 0
        
    limit_bytes = limits["storage_mb"] * 1024 * 1024
    new_total = current_bytes + additional_bytes
    
    is_allowed = new_total <= limit_bytes
    return is_allowed, round(current_bytes / (1024 * 1024), 2), limits["storage_mb"]

def record_bandwidth(server_id, byte_count):
    """Records HTTP request/response transfer bytes against server bandwidth."""
    if byte_count <= 0:
        return
    try:
        db = get_db()
        db.execute("UPDATE servers SET bandwidth_used_bytes = bandwidth_used_bytes + ? WHERE id = ?", (byte_count, server_id))
        db.commit()
    except Exception as e:
        print(f"[Bandwidth Record Error] {e}")

def get_server_resource_usage(server_id):
    """Fetches CPU and RAM for server process."""
    from process_manager import get_server_metrics
    return get_server_metrics(server_id)

# Alias
get_vps_node_metrics = get_vps_system_metrics
