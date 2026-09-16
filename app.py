"""
Vesper Python Application Hosting Platform
Production-grade, self-hosted Python PaaS with isolated process management,
port and subdomain routing, live console, file manager, wallet and INR billing,
and comprehensive admin controls.
"""

import os
import sys
import logging
from flask import Flask, render_template, request, redirect, url_for, g, session, jsonify, flash
from config import SECRET_KEY, PLATFORM_NAME, BASE_DOMAIN, DATA_DIR, PORT
from database import init_db, get_db, get_db_connection, get_setting
from security import get_user_by_session_token, generate_csrf_token, validate_csrf_token
from process_manager import start_process_monitor
from proxy_manager import handle_proxy_request, handle_host_header_proxy
from notifications import get_unread_count
from routes import auth_bp, dashboard_bp, server_bp, api_bp, admin_bp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("vesper")

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max upload
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    from datetime import timedelta
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_COOKIE_MAX_SIZE'] = 4096

    # Initialize Database Schema
    init_db()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(server_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)

    # ------------------------------------------------------------------
    # REQUEST HOOKS & MIDDLEWARE
    # ------------------------------------------------------------------

    @app.before_request
    def before_request_hook():
        # 1. Check for transparent Host-header subdomain proxying
        host_resp = handle_host_header_proxy()
        if host_resp is not None:
            return host_resp

        # 2. Populate authenticated user
        g.current_user = None
        user_id = session.get('user_id')
        session_token = session.get('session_token') or session.get('_session_token')
        if user_id:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,)).fetchone()
            if user and user['status'] != 'suspended':
                user_dict = dict(user)
                user_dict.pop('password_hash', None)
                g.current_user = user_dict
            else:
                session.clear()
        elif session_token:
            user = get_user_by_session_token(session_token)
            if user:
                user_dict = dict(user)
                user_dict.pop('password_hash', None)
                g.current_user = user_dict
            else:
                session.clear()

        # 3. Check maintenance mode
        maintenance = get_setting('maintenance_mode', '0')
        if maintenance == '1':
            # Allow static files, auth endpoints, and admin users
            path = request.path
            is_auth_route = path.startswith('/auth')
            is_static = path.startswith('/static')
            is_admin = g.current_user and g.current_user.get('role') == 'admin'

            if not (is_auth_route or is_static or is_admin):
                return render_template('errors/maintenance.html'), 503

        # 4. Enforce CSRF on state-changing requests (exclude proxy endpoints and OTP dispatch)
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if not request.path.startswith('/app/') and not request.path.startswith('/static') and request.path != '/auth/send-otp':
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not validate_csrf_token(token):
                    if request.headers.get('Accept') == 'application/json' or request.is_json:
                        return jsonify({'error': 'Invalid or missing CSRF token.'}), 400
                    flash('Invalid or expired security token. Please try again.', 'error')
                    return redirect(request.referrer or url_for('dashboard.index'))

    @app.context_processor
    def inject_template_globals():
        unread_notifs = 0
        if g.get('current_user'):
            unread_notifs = get_unread_count(g.current_user['id'])

        return {
            'platform_name': PLATFORM_NAME,
            'base_domain': BASE_DOMAIN,
            'current_user': g.get('current_user'),
            'unread_notifs': unread_notifs,
            'csrf_token': generate_csrf_token
        }

    # ------------------------------------------------------------------
    # LANDING PAGE & PROXY ROUTING
    # ------------------------------------------------------------------

    @app.route('/')
    def landing():
        if g.get('current_user'):
            return redirect(url_for('dashboard.index'))

        with get_db_connection() as conn:
            plans = conn.execute("SELECT * FROM plans WHERE is_active = 1 ORDER BY price_inr ASC").fetchall()
            server_count = conn.execute("SELECT COUNT(*) as c FROM servers").fetchone()['c']
            running_count = conn.execute("SELECT COUNT(*) as c FROM servers WHERE status = 'running'").fetchone()['c']
            user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']

        from port_manager import get_port_pool_status
        port_stats = get_port_pool_status()

        stats = {
            'total_servers': server_count,
            'running_servers': running_count,
            'user_count': user_count,
            'port_pool': port_stats
        }

        return render_template(
            'landing.html',
            plans=plans,
            stats=stats,
            server_count=server_count,
            user_count=user_count,
            base_domain=BASE_DOMAIN
        )

    # Reverse proxy route: /app/<subdomain>/<path>
    @app.route('/app/<subdomain>/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
    @app.route('/app/<subdomain>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
    def proxy_app(subdomain, path):
        return handle_proxy_request(subdomain, path)

    # ------------------------------------------------------------------
    # ERROR HANDLERS
    # ------------------------------------------------------------------

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'error': 'Resource or API route not found'}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def handle_403(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'error': 'Access forbidden'}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def handle_500(e):
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('errors/500.html'), 500

    # Start background process crash recovery and monitoring thread
    start_process_monitor()

    return app

app = create_app()

if __name__ == '__main__':
    logger.info(f"Starting {PLATFORM_NAME} PaaS server on 0.0.0.0:{PORT}...")
    app.run(host='0.0.0.0', port=PORT, debug=False)
