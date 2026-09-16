import secrets
import string
from database import get_db
from security import validate_subdomain
import config

def generate_unique_subdomain(prefix="app"):
    """Generates an available unique subdomain."""
    db = get_db()
    clean_prefix = "".join(c for c in prefix.lower() if c.isalnum())[:12] or "py"
    
    for _ in range(50):
        random_suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        candidate = f"{clean_prefix}-{random_suffix}"
        
        # Check if already in domain allocations or servers
        existing = db.execute("SELECT id FROM servers WHERE subdomain = ? UNION SELECT id FROM domain_allocations WHERE subdomain = ?", (candidate, candidate)).fetchone()
        if not existing:
            return candidate
            
    # Fallback with timestamp hash
    return f"{clean_prefix}-{secrets.token_hex(4)}"

def reserve_subdomain(subdomain, user_id, server_id=None):
    """Validates and reserves a subdomain for a user."""
    is_valid, err_or_sub = validate_subdomain(subdomain)
    if not is_valid:
        return False, err_or_sub
        
    subdomain = err_or_sub
    db = get_db()
    
    # Check if claimed by another active server or user
    existing = db.execute("""
    SELECT id, user_id, server_id FROM domain_allocations 
    WHERE subdomain = ? AND status = 'active'
    """, (subdomain,)).fetchone()
    
    if existing:
        if existing["user_id"] != user_id or (server_id and existing["server_id"] and existing["server_id"] != server_id):
            return False, f"Subdomain '{subdomain}' is already claimed by another user/instance"
            
    # Allocate or update
    db.execute("""
    INSERT INTO domain_allocations (subdomain, server_id, user_id, status)
    VALUES (?, ?, ?, 'active')
    ON CONFLICT(subdomain) DO UPDATE SET server_id = excluded.server_id, status = 'active'
    """, (subdomain, server_id, user_id))
    db.commit()
    return True, subdomain

def release_subdomain(subdomain):
    """Releases a subdomain so it can be claimed again."""
    if not subdomain:
        return
    db = get_db()
    db.execute("UPDATE domain_allocations SET status = 'released', server_id = NULL WHERE subdomain = ?", (subdomain,))
    db.commit()

def is_subdomain_available(subdomain):
    """Checks if a subdomain is available for reservation."""
    is_valid, err_or_sub = validate_subdomain(subdomain)
    if not is_valid:
        return False, err_or_sub
    db = get_db()
    existing = db.execute(
        "SELECT id FROM servers WHERE subdomain = ? UNION SELECT id FROM domain_allocations WHERE subdomain = ? AND status = 'active'",
        (subdomain, subdomain)
    ).fetchone()
    if existing:
        return False, "Subdomain already taken."
    return True, None

def get_full_domain(subdomain):
    """Returns the full FQDN for a given subdomain."""
    return f"{subdomain}.{config.BASE_DOMAIN}"
