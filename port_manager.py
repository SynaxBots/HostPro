import socket
import sqlite3
from database import get_db
import config

def is_port_in_use(port, host="127.0.0.1"):
    """Checks if a port is currently listening or bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        return result == 0

def allocate_port(server_id=None):
    """
    Finds and allocates an unused port from the configured range.
    Locks allocation in SQLite database.
    """
    db = get_db()
    
    # Get all currently active allocated ports from database
    cursor = db.execute("SELECT port FROM port_allocations WHERE status = 'allocated'")
    allocated_ports = {row["port"] for row in cursor.fetchall()}
    
    for port in range(config.PORT_START, config.PORT_END + 1):
        if port not in allocated_ports:
            # Verify system port availability
            if not is_port_in_use(port):
                try:
                    db.execute("""
                    INSERT INTO port_allocations (port, server_id, status)
                    VALUES (?, ?, 'allocated')
                    """, (port, server_id))
                    db.commit()
                    return port
                except sqlite3.IntegrityError:
                    # Race condition safety: port was allocated by concurrent request
                    continue
                    
    raise RuntimeError(f"Port pool exhausted! No free ports between {config.PORT_START} and {config.PORT_END}")

def release_port(port):
    """Releases a previously allocated port."""
    if not port:
        return
    db = get_db()
    db.execute("UPDATE port_allocations SET status = 'released', server_id = NULL WHERE port = ?", (port,))
    db.commit()

def recover_orphan_ports():
    """Scans port allocations against active server records and frees dead reservations."""
    db = get_db()
    cursor = db.execute("""
    SELECT p.port, p.server_id, s.status, s.assigned_port 
    FROM port_allocations p
    LEFT JOIN servers s ON p.server_id = s.id
    WHERE p.status = 'allocated'
    """)
    rows = cursor.fetchall()
    recovered = 0
    for row in rows:
        # If server was deleted or server assigned_port doesn't match
        if row["server_id"] is None or row["status"] is None or row["assigned_port"] != row["port"]:
            db.execute("UPDATE port_allocations SET status = 'released', server_id = NULL WHERE port = ?", (row["port"],))
            recovered += 1
    if recovered > 0:
        db.commit()
        print(f"[PortManager] Recovered {recovered} orphaned port allocations.")

def get_port_pool_stats():
    """Returns total, allocated, and free port counts."""
    db = get_db()
    total_ports = max(1, config.PORT_END - config.PORT_START + 1)
    allocated = db.execute("SELECT COUNT(*) FROM port_allocations WHERE status = 'allocated'").fetchone()[0]
    free_ports = total_ports - allocated
    utilization_pct = round((allocated / total_ports) * 100, 1)
    return {
        "start": config.PORT_START,
        "end": config.PORT_END,
        "total": total_ports,
        "allocated": allocated,
        "free": free_ports,
        "utilization_pct": utilization_pct
    }

get_port_pool_status = get_port_pool_stats
