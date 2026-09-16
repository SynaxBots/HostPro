import urllib.request
import urllib.error
import urllib.parse
from flask import request, Response, render_template_string
from database import get_db
from resource_manager import record_bandwidth
import config

APP_OFFLINE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Application Offline | {{ platform_name }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            background: #000000;
            color: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 480px;
            text-align: center;
            backdrop-filter: blur(12px);
        }
        .icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.1);
            color: #f87171;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 24px;
        }
        h1 { font-size: 20px; margin: 0 0 10px; font-weight: 600; }
        p { color: #a1a1aa; font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
        .details {
            background: rgba(0,0,0,0.4);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 8px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
            color: #94a3b8;
            margin-bottom: 20px;
            text-align: left;
        }
        .btn {
            display: inline-block;
            background: #ffffff;
            color: #000000;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
        </div>
        <h1>Application Not Responding</h1>
        <p>The hosted Python application on <strong>{{ subdomain }}</strong> is currently {{ status }}.</p>
        <div class="details">
            <div>Target Port: {{ port }}</div>
            <div>Subdomain: {{ subdomain }}.{{ base_domain }}</div>
            <div>Status: {{ status }}</div>
        </div>
        <a href="/dashboard" class="btn">Go to Dashboard</a>
    </div>
</body>
</html>
"""

def proxy_request_to_port(port, server_id, subdomain, subpath=""):
    """
    Forwards incoming HTTP request to internal localhost:<port>
    and streams the response back, tracking bandwidth.
    """
    target_url = f"http://127.0.0.1:{port}/{subpath.lstrip('/')}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    # Prepare forwarding headers
    excluded_headers = {"host", "content-length"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    headers["X-Forwarded-For"] = request.remote_addr or "127.0.0.1"
    headers["X-Forwarded-Proto"] = request.scheme
    headers["X-Forwarded-Host"] = request.host

    body_data = request.get_data()
    req_bytes = len(body_data) if body_data else 0

    req = urllib.request.Request(
        url=target_url,
        data=body_data if request.method in ("POST", "PUT", "PATCH", "DELETE") and body_data else None,
        headers=headers,
        method=request.method
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_body = response.read()
            resp_bytes = len(resp_body)
            
            # Record total bandwidth transferred
            record_bandwidth(server_id, req_bytes + resp_bytes)
            
            resp_headers = {}
            for k, v in response.headers.items():
                if k.lower() not in ("transfer-encoding", "content-length", "connection"):
                    resp_headers[k] = v
                    
            return Response(resp_body, status=response.status, headers=resp_headers)
            
    except urllib.error.HTTPError as e:
        resp_body = e.read()
        record_bandwidth(server_id, req_bytes + len(resp_body))
        resp_headers = {k: v for k, v in e.headers.items() if k.lower() not in ("transfer-encoding", "content-length")}
        return Response(resp_body, status=e.code, headers=resp_headers)
        
    except (urllib.error.URLError, ConnectionRefusedError, TimeoutError, OSError):
        # Application not running / listening on port
        db = get_db()
        server = db.execute("SELECT status FROM servers WHERE id = ?", (server_id,)).fetchone()
        status = server["status"] if server else "stopped"
        
        return render_template_string(
            APP_OFFLINE_HTML,
            platform_name=config.PLATFORM_NAME,
            subdomain=subdomain,
            base_domain=config.BASE_DOMAIN,
            port=port,
            status=status
        ), 502

def handle_subdomain_or_proxy():
    """
    Inspects incoming request Host header to check if it matches <subdomain>.<BASE_DOMAIN>.
    If matched, transparently proxies to that server's assigned port.
    """
    host = request.host.split(":")[0].lower()
    base_domain = config.BASE_DOMAIN.lower()
    
    if host.endswith("." + base_domain) and host != base_domain:
        subdomain = host[: - (len(base_domain) + 1)]
        db = get_db()
        server = db.execute("SELECT id, assigned_port, status, subdomain FROM servers WHERE subdomain = ?", (subdomain,)).fetchone()
        if server:
            return proxy_request_to_port(server["assigned_port"], server["id"], subdomain, request.path)
            
    return None

def handle_proxy_request(subdomain, path=""):
    """Handles path-based /app/<subdomain>/<path> reverse proxy requests."""
    db = get_db()
    server = db.execute("SELECT id, assigned_port, status, subdomain FROM servers WHERE subdomain = ?", (subdomain,)).fetchone()
    if not server:
        return render_template_string(
            APP_OFFLINE_HTML,
            platform_name=config.PLATFORM_NAME,
            subdomain=subdomain,
            base_domain=config.BASE_DOMAIN,
            port="N/A",
            status="Not Found"
        ), 404
        
    return proxy_request_to_port(server["assigned_port"], server["id"], subdomain, path)

# Alias
handle_host_header_proxy = handle_subdomain_or_proxy
