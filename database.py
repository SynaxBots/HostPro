import sqlite3
import os
import threading
from werkzeug.security import generate_password_hash
import config

_local = threading.local()

def get_db():
    """Returns a thread-local SQLite connection with dictionary row factory and WAL mode."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(config.DATABASE_PATH, timeout=30.0, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA foreign_keys = ON;")
        _local.conn.execute("PRAGMA journal_mode = WAL;")
        _local.conn.execute("PRAGMA synchronous = NORMAL;")
    return _local.conn

def get_db_connection():
    """Alias for get_db to return an active connection."""
    return get_db()

def get_setting(key, default=None):
    """Retrieve platform configuration setting by key."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT setting_value FROM settings WHERE setting_key = ? LIMIT 1;", (key,))
    row = cursor.fetchone()
    if row:
        return row["setting_value"]
    return default

def set_setting(key, value):
    """Set or update platform configuration setting."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO settings (setting_key, setting_value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP;",
        (key, str(value))
    )
    conn.commit()

def init_db():
    """Initializes the database schema and default records."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    cursor = conn.cursor()

    # 1. Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        telegram_id TEXT UNIQUE,
        role TEXT NOT NULL DEFAULT 'user', -- 'user', 'admin', 'moderator', 'support'
        status TEXT NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'pending'
        wallet_balance REAL NOT NULL DEFAULT 0.0,
        avatar_url TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
    );
    """)

    # Ensure telegram_id column exists if table already created previously
    cursor.execute("PRAGMA table_info(users);")
    user_cols = [col[1] for col in cursor.fetchall()]
    if "telegram_id" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN telegram_id TEXT;")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id) WHERE telegram_id IS NOT NULL;")

    # Telegram OTP Verifications
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telegram_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id TEXT NOT NULL,
        otp_code TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0, -- 0=pending, 1=verified, 2=invalidated/expired
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telegram_otps_tid ON telegram_otps(telegram_id, verified);")

    # 2. Plans (Prices strictly in INR)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price_inr REAL NOT NULL,
        billing_days INTEGER NOT NULL DEFAULT 30,
        ram_mb INTEGER NOT NULL,
        cpu_cores REAL NOT NULL DEFAULT 1.0,
        storage_mb INTEGER NOT NULL,
        bandwidth_mb INTEGER NOT NULL,
        max_servers INTEGER NOT NULL DEFAULT 1,
        max_processes INTEGER NOT NULL DEFAULT 3,
        max_file_size_mb INTEGER NOT NULL DEFAULT 50,
        auto_restart_allowed INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Subscriptions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'expired', 'cancelled'
        start_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiry_date DATETIME NOT NULL,
        is_admin_granted INTEGER NOT NULL DEFAULT 0,
        custom_ram_mb INTEGER,
        custom_storage_mb INTEGER,
        custom_bandwidth_mb INTEGER,
        custom_cpu_cores REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(plan_id) REFERENCES plans(id) ON DELETE RESTRICT
    );
    """)

    # 4. Servers (Hosted Python Applications)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subscription_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        subdomain TEXT UNIQUE NOT NULL,
        assigned_port INTEGER UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'stopped', -- 'running', 'stopped', 'crashed', 'starting', 'stopping', 'error', 'suspended', 'expired'
        entry_file TEXT NOT NULL DEFAULT 'app.py',
        startup_command TEXT DEFAULT '',
        pid INTEGER,
        auto_restart INTEGER NOT NULL DEFAULT 1,
        restart_count INTEGER NOT NULL DEFAULT 0,
        last_restart_at DATETIME,
        storage_used_bytes INTEGER NOT NULL DEFAULT 0,
        bandwidth_used_bytes INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
    );
    """)

    # 5. Environment Variables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS environment_variables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        env_key TEXT NOT NULL,
        env_value TEXT NOT NULL,
        is_secret INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(server_id, env_key),
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
    );
    """)

    # 6. Port Allocations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS port_allocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        port INTEGER UNIQUE NOT NULL,
        server_id INTEGER,
        status TEXT NOT NULL DEFAULT 'allocated', -- 'allocated', 'reserved', 'released'
        allocated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL
    );
    """)

    # 7. Domain Allocations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domain_allocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subdomain TEXT UNIQUE NOT NULL,
        server_id INTEGER,
        user_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 8. Transactions (INR Wallet & Subscriptions Ledger)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_ref TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL, -- 'deposit', 'plan_purchase', 'plan_renewal', 'refund', 'admin_grant', 'admin_deduct'
        amount_inr REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'success', -- 'success', 'pending', 'failed', 'cancelled'
        description TEXT NOT NULL,
        metadata_json TEXT DEFAULT '{}',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 9. Announcements & Broadcasts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'announcement', -- 'announcement', 'maintenance', 'feature', 'notice', 'promotion', 'alert'
        priority TEXT NOT NULL DEFAULT 'normal', -- 'low', 'normal', 'high', 'urgent'
        action_url TEXT DEFAULT '',
        action_text TEXT DEFAULT '',
        is_published INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 10. User Announcement Reads
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_announcement_reads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        announcement_id INTEGER NOT NULL,
        read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, announcement_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(announcement_id) REFERENCES announcements(id) ON DELETE CASCADE
    );
    """)

    # 11. Notifications
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_id INTEGER,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'info', -- 'info', 'success', 'warning', 'error'
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL
    );
    """)

    # 12. Activity Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_id INTEGER,
        action TEXT NOT NULL,
        details TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 13. Audit Logs (Admin actions)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        target_user_id INTEGER,
        target_server_id INTEGER,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 14. Support Tickets
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_id INTEGER,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
        status TEXT NOT NULL DEFAULT 'open', -- 'open', 'in_progress', 'resolved', 'closed'
        admin_reply TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL
    );
    """)

    # 15. UPI Orders & Verification Ledger
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS upi_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        utr TEXT UNIQUE NOT NULL,
        expected_amount REAL NOT NULL,
        actual_amount REAL DEFAULT 0.0,
        status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'success', 'failed'
        response_json TEXT DEFAULT '{}',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # 16. Platform Settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_servers_user ON servers(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_servers_subdomain ON servers(subdomain);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_servers_port ON servers(assigned_port);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_subs_user ON subscriptions(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_admin ON audit_logs(admin_id);")

    # Seed Default Admin if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin' LIMIT 1;")
    admin = cursor.fetchone()
    if not admin:
        default_pwd_hash = generate_password_hash("admin123")
        cursor.execute("""
        INSERT INTO users (username, email, password_hash, role, status, wallet_balance)
        VALUES ('admin', 'admin@pythonhost.local', ?, 'admin', 'active', 5000.0)
        """, (default_pwd_hash,))
        admin_id = cursor.lastrowid
        print(f"[Database] Default admin created: admin / admin123 (ID: {admin_id})")

    # Seed Default Plans in INR
    cursor.execute("SELECT COUNT(*) FROM plans;")
    plan_count = cursor.fetchone()[0]
    if plan_count == 0:
        default_plans = [
            (
                "Starter Python",
                "Ideal for microservices, Telegram/Discord bots, webhook handlers, and lightweight automation scripts.",
                49.0, 30, 256, 0.5, 1024, 10240, 1, 2, 25, 1, 1
            ),
            (
                "Pro Python",
                "Perfect for Flask/FastAPI REST APIs, data scrapers, scheduled cron workers, and medium workloads.",
                149.0, 30, 512, 1.0, 5120, 51200, 3, 5, 50, 1, 2
            ),
            (
                "Business Cloud",
                "High-performance allocation for high-traffic web applications, background queue consumers, and async workers.",
                399.0, 30, 2048, 2.0, 20480, 204800, 10, 15, 100, 1, 3
            ),
            (
                "Enterprise AI & Compute",
                "Maximum dedicated resources for heavy data processing, multi-service architectures, and continuous pipelines.",
                799.0, 30, 4096, 4.0, 51200, 512000, 25, 30, 250, 1, 4
            )
        ]
        cursor.executemany("""
        INSERT INTO plans (name, description, price_inr, billing_days, ram_mb, cpu_cores, storage_mb, bandwidth_mb, max_servers, max_processes, max_file_size_mb, auto_restart_allowed, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_plans)
        print("[Database] Seeded 4 default INR hosting plans.")

    # Seed Default Settings
    default_settings = [
        ("site_name", "Vesper Python Cloud"),
        ("base_domain", config.BASE_DOMAIN),
        ("port_start", str(config.PORT_START)),
        ("port_end", str(config.PORT_END)),
        ("maintenance_mode", "0"),
        ("allow_registration", "1"),
        ("default_grace_period_days", "7"),
        ("currency", "INR"),
        ("max_upload_size_mb", "100"),
        ("telegram_bot_token", os.environ.get("TELEGRAM_BOT_TOKEN", "")),
        ("telegram_bot_username", os.environ.get("TELEGRAM_BOT_USERNAME", "VesperCloudBot"))
    ]
    for key, val in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)", (key, val))

    # Seed initial announcement
    cursor.execute("SELECT COUNT(*) FROM announcements;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO announcements (title, message, type, priority, action_url, action_text, is_published)
        VALUES (
            'Welcome to Vesper Python Cloud Hosting',
            'Deploy your Python scripts, Flask web applications, and background workers with isolated ports, auto-restarts, live console, and lightning performance. Billed purely in INR.',
            'announcement', 'high', '/plans', 'Explore Plans', 1
        )
        """)

    conn.commit()
    conn.close()
    print("[Database] Initialized and verified successfully.")
