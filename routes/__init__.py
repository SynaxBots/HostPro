"""
Routes package initialization.
"""

from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.server_routes import server_bp
from routes.api_routes import api_bp
from routes.admin_routes import admin_bp

__all__ = ['auth_bp', 'dashboard_bp', 'server_bp', 'api_bp', 'admin_bp']
