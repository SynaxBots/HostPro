# Starter Python Web Application
import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 12346))

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>user3-bot - Live Application</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            background: #09090b;
            color: #fafafa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .card {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            max-width: 520px;
            text-align: center;
            backdrop-filter: blur(12px);
        }
        .badge {
            display: inline-block;
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        h1 { margin: 0 0 10px; font-size: 24px; }
        p { color: #a1a1aa; font-size: 15px; line-height: 1.5; margin-bottom: 24px; }
        .meta {
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            color: #38bdf8;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">● Online & Ready</div>
        <h1>user3-bot</h1>
        <p>Your Python application is live and running smoothly on Vesper Cloud infrastructure.</p>
        <div class="meta">Subdomain: user3-bot | Internal Port: 12346</div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "subdomain": "user3-bot", "port": PORT})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
