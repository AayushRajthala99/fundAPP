import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()


# Configuration
class CONFIG:
    APP_PORT = int(os.getenv("APP_PORT", 5000))
    SESSION_TYPE = os.getenv("SESSION_TYPE", "filesystem")
    SESSION_DIR = os.getenv("SESSION_DIR", "flask_session")
    CACHE_TYPE = os.getenv("CACHE_TYPE", "FileSystemCache")
    CACHE_DIR = os.getenv("CACHE_DIR", "cache")
    CACHE_DEFAULT_TIMEOUT = int(os.getenv("CACHE_DEFAULT_TIMEOUT", 300))
    CACHE_THRESHOLD = int(os.getenv("CACHE_THRESHOLD", 100))
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("PERMANENT_SESSION_LIFETIME", 10))
    )

    # Email Config
    MAIL_SERVER = os.getenv("MAIL_SERVER", "your-mail-server")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_EMAIL = os.getenv("MAIL_EMAIL", "your-mail-email")
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_APP_KEY = os.getenv("MAIL_APP_KEY", "your-mail-app-key")

    # Security keys
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-string")

    # Database settings
    DATABASE_URI = os.getenv("DATABASE_URI", "database/fundAPP.db")

    # Logging and migrations
    FUNDAPP_LOG_PATH = os.getenv("FUNDAPP_LOG_PATH", "fundAPP.log")
    DB_MIGRATIONS_FILE = os.getenv("DB_MIGRATIONS_FILE", "database/migrations.sql")
