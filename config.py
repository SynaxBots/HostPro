import os

# Base Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
APPS_DIR = os.path.join(STORAGE_DIR, "apps")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")

# Ensure required directories exist
for directory in [DATA_DIR, STORAGE_DIR, APPS_DIR, LOGS_DIR, BACKUP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Database
DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(DATA_DIR, "platform.sqlite3"))

# Platform Settings
SECRET_KEY = os.environ.get("SECRET_KEY", "vesper-py-platform-secret-key-prod-2026-secure-inr-hosting")
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "pythonhost.local")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 5000))
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")

# Port Pool for Hosted Applications
PORT_START = int(os.environ.get("PORT_START", 10000))
PORT_END = int(os.environ.get("PORT_END", 20000))
DEFAULT_PORT_START = PORT_START
DEFAULT_PORT_END = PORT_END
DB_PATH = DATABASE_PATH

# Upload & Resource Limits
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 100))
MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024
DEFAULT_STORAGE_LIMIT_MB = int(os.environ.get("DEFAULT_STORAGE_LIMIT_MB", 1024))
DEFAULT_RAM_LIMIT_MB = int(os.environ.get("DEFAULT_RAM_LIMIT_MB", 512))
RAM_GRACE_MB = int(os.environ.get("RAM_GRACE_MB", 30))
DEFAULT_BANDWIDTH_LIMIT_MB = int(os.environ.get("DEFAULT_BANDWIDTH_LIMIT_MB", 20480))
DEFAULT_GRACE_PERIOD_DAYS = int(os.environ.get("DEFAULT_GRACE_PERIOD_DAYS", 7))
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", 24))

# Currency
CURRENCY = "INR"
CURRENCY_SYMBOL = "₹"

# App Branding
PLATFORM_NAME = os.environ.get("PLATFORM_NAME", "Vesper Python Cloud")
TAGLINE = "High-Performance Python Hosting & Script Orchestration"
