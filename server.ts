import express from "express";
import http from "http";
import { spawn, execSync, ChildProcess } from "child_process";
import path from "path";

const app = express();
const PORT = 3000;
const PYTHON_PORT = 5000;

let pythonProcess: ChildProcess | null = null;
let isShuttingDown = false;

function ensurePythonDependencies() {
  try {
    execSync('python3 -c "import flask, requests, psutil"', { stdio: "ignore" });
  } catch {
    console.log("[Host Server] Python packages missing. Installing via get-pip.py...");
    try {
      execSync("python3 get-pip.py", { stdio: "inherit" });
      execSync("python3 -m pip install flask requests psutil", { stdio: "inherit" });
      console.log("[Host Server] Python dependencies installed successfully.");
    } catch (err) {
      console.error("[Host Server] Warning: Could not complete auto-installation of Python dependencies:", err);
    }
  }
}

function startPythonBackend() {
  if (isShuttingDown) return;

  ensurePythonDependencies();

  console.log(`[Host Server] Spawning Python Vesper PaaS Backend on port ${PYTHON_PORT}...`);

  const env = {
    ...process.env,
    PORT: String(PYTHON_PORT),
    FLASK_PORT: String(PYTHON_PORT),
    PYTHONUNBUFFERED: "1",
  };

  pythonProcess = spawn("python3", ["app.py"], {
    env,
    stdio: ["pipe", "inherit", "inherit"],
  });

  pythonProcess.on("exit", (code, signal) => {
    console.log(`[Host Server] Python backend exited with code ${code}, signal ${signal}`);
    pythonProcess = null;
    if (!isShuttingDown) {
      console.log("[Host Server] Restarting Python backend in 2 seconds...");
      setTimeout(startPythonBackend, 2000);
    }
  });

  pythonProcess.on("error", (err) => {
    console.error("[Host Server] Failed to spawn Python backend:", err);
  });
}

// Start Python subprocess
startPythonBackend();

// Transparent Reverse Proxy to Python Backend
app.use((req, res) => {
  const options: http.RequestOptions = {
    hostname: "127.0.0.1",
    port: PYTHON_PORT,
    path: req.url,
    method: req.method,
    headers: {
      ...req.headers,
      host: req.headers.host || `localhost:${PORT}`,
      "x-forwarded-for": req.socket.remoteAddress || "127.0.0.1",
      "x-forwarded-proto": req.protocol,
      "x-forwarded-port": String(PORT),
    },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 500, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Starting Vesper Cloud Platform...</title>
          <meta http-equiv="refresh" content="2">
          <style>
            body { background: #09090b; color: #fafafa; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 32px; text-align: center; max-width: 400px; }
            .spinner { width: 36px; height: 36px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #38bdf8; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 16px; }
            @keyframes spin { to { transform: rotate(360deg); } }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="spinner"></div>
            <h2 style="margin: 0 0 8px; font-size: 18px;">Initializing Platform Engine</h2>
            <p style="color: #a1a1aa; font-size: 14px; margin: 0;">Booting Python core processes & database schema. Refreshing in a moment...</p>
          </div>
        </body>
        </html>
      `);
    }
  });

  req.pipe(proxyReq);
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Host Server] Vesper Python PaaS ingress gateway listening on http://0.0.0.0:${PORT}`);
});

function gracefulShutdown() {
  isShuttingDown = true;
  console.log("[Host Server] Graceful shutdown initiated...");
  if (pythonProcess) {
    pythonProcess.kill("SIGTERM");
  }
  server.close(() => {
    process.exit(0);
  });
}

process.on("SIGINT", gracefulShutdown);
process.on("SIGTERM", gracefulShutdown);
