"""
Server Monitor Hub - one web page for all your servers.

Every server running Server Monitor connects OUT to the hub (HTTPS), so no port has
to be opened on the servers - like AnyDesk / UltraViewer. Only the hub itself needs
one reachable address (a small cloud server, or an office PC behind Cloudflare Tunnel).

First run:   python hub.py --set-password
Then:        python hub.py
On each server: Server Monitor -> Update tab -> Cloud monitoring -> hub address + hub key.
"""
import argparse
import base64
import getpass
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, Response, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "hub_config.json")
SERVERS_PATH = os.path.join(BASE_DIR, "servers.json")
AUDIT_PATH = os.path.join(BASE_DIR, "hub_audit.log")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 30090,
    "username": "admin",
    "password_hash": "",
    "secret_key": "",
    # Servers prove they belong to you with this key (shown in the hub under "Add server").
    "agent_key": "",
    "session_minutes": 240,
    # Each connected server keeps one request open, so allow enough threads for all servers + browsers.
    "threads": 120,
    "ssl_cert": "",
    "ssl_key": "",
}

ONLINE_SECONDS = 30   # servers report every 10 s; nothing for this long = offline
POLL_SECONDS = 25     # how long a server's poll waits for work
JOB_SECONDS = 130     # how long a browser request waits for the server's answer (terminal runs up to 120 s)


# --------------------------------------------------------------------------- config
def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if not cfg["secret_key"] or not cfg["agent_key"]:
        cfg["secret_key"] = cfg["secret_key"] or secrets.token_hex(32)
        cfg["agent_key"] = cfg["agent_key"] or secrets.token_urlsafe(24)
        save_json(CONFIG_PATH, cfg)
    return cfg


def set_password():
    cfg = load_config()
    user = input(f"Hub username [{cfg['username']}]: ").strip() or cfg["username"]
    while True:
        p1 = getpass.getpass("New password (min 10 chars): ")
        if len(p1) < 10:
            print("Too short - the hub can control every server, use a strong password.")
            continue
        if p1 != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            continue
        break
    cfg["username"], cfg["password_hash"] = user, generate_password_hash(p1)
    save_json(CONFIG_PATH, cfg)
    print("Saved. Start the hub with:  python hub.py")


CFG = load_config()
app = Flask(__name__, static_folder=None)
app.secret_key = CFG["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(CFG["ssl_cert"]),
    PERMANENT_SESSION_LIFETIME=CFG["session_minutes"] * 60,
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
)


def client_ip():
    # behind Cloudflare Tunnel / a reverse proxy the real address is in these headers
    return (request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr)


def audit(action, target, detail=""):
    line = {"time": datetime.now().isoformat(timespec="seconds"), "user": session.get("user", "-"),
            "ip": client_ip(), "action": action, "target": target, "detail": detail[:300]}
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


# --------------------------------------------------------------------------- servers
_lock = threading.Lock()
_servers = {}   # agent id -> {"id", "report", "last_seen", "ip", "first_seen", "name"}
_queues = {}    # agent id -> queue of jobs waiting for that server
_waiting = {}   # job id -> {"event", "result"}

if os.path.exists(SERVERS_PATH):
    with open(SERVERS_PATH, encoding="utf-8") as f:
        _servers = {s["id"]: dict(s, last_seen=0) for s in json.load(f)}
_saved_at = 0.0


def save_servers(force=False):
    global _saved_at
    if force or time.time() - _saved_at > 60:
        _saved_at = time.time()
        with _lock:
            data = [{k: v for k, v in s.items() if k != "last_seen"} for s in _servers.values()]
        save_json(SERVERS_PATH, data)


def is_online(s):
    return time.time() - s.get("last_seen", 0) < ONLINE_SECONDS


def agent_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        key, aid = request.headers.get("X-Agent-Key", ""), request.headers.get("X-Agent-Id", "")
        if not secrets.compare_digest(key.encode(), CFG["agent_key"].encode()):
            return jsonify(error="wrong hub key"), 403
        if not aid or len(aid) > 40 or not aid.isalnum():
            return jsonify(error="bad agent id"), 400
        with _lock:
            s = _servers.setdefault(aid, {"id": aid, "report": {}, "first_seen": time.time(), "name": ""})
            new = "ip" not in s
            # "run" changes each time Server Monitor restarts on that server
            s.update(last_seen=time.time(), ip=client_ip(), run=request.headers.get("X-Agent-Run", ""))
            _queues.setdefault(aid, queue.Queue())
        if new:
            save_servers(force=True)
        return fn(aid, *a, **kw)
    return wrapper


@app.post("/agent/report")
@agent_required
def agent_report(aid):
    with _lock:
        _servers[aid]["report"] = request.get_json(silent=True) or {}
        _servers[aid]["report_time"] = time.time()
    save_servers()
    return jsonify(ok=True)


@app.get("/agent/poll")
@agent_required
def agent_poll(aid):
    q, s = _queues[aid], _servers[aid]
    run = s["run"]
    jobs = []
    deadline = time.time() + POLL_SECONDS
    # Wait in short steps: when the server restarts, the poll of the old (dead) process is
    # still open here and must stop taking jobs as soon as the new process shows up.
    while not jobs and time.time() < deadline and s.get("run") == run:
        try:
            jobs.append(q.get(timeout=1))
            while True:
                jobs.append(q.get_nowait())
        except queue.Empty:
            pass
    with _lock:
        s["last_seen"] = time.time()
    # a job whose browser request already gave up must not run any more (e.g. a late "restart")
    jobs = [j for j in jobs if time.time() - j["created"] < JOB_SECONDS - 5]
    for j in jobs:
        w = _waiting.get(j["id"])
        if w:
            w["run"] = run  # remember which process took it, to resend it if that process dies
    return jsonify(jobs=jobs)


@app.post("/agent/result")
@agent_required
def agent_result(aid):
    r = request.get_json(silent=True) or {}
    w = _waiting.get(r.get("id"))
    if w and w["agent"] == aid:
        w["result"] = r
        w["event"].set()
    return jsonify(ok=True)


# --------------------------------------------------------------------------- browser: auth
_failed = {}
LOCK_WINDOW, LOCK_MAX = 300, 5


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return jsonify(error="login required"), 401
        if request.method != "GET" and request.headers.get("X-Requested-With") != "fetch":
            return jsonify(error="bad request"), 400  # basic CSRF guard
        return fn(*a, **kw)
    return wrapper


@app.post("/api/login")
def api_login():
    ip = client_ip()
    now = time.time()
    _failed[ip] = [t for t in _failed.get(ip, []) if now - t < LOCK_WINDOW]
    if len(_failed[ip]) >= LOCK_MAX:
        return jsonify(error="Too many attempts, try again in 5 minutes"), 429
    d = request.get_json(silent=True) or {}
    if CFG["password_hash"] and d.get("username") == CFG["username"] and \
            check_password_hash(CFG["password_hash"], d.get("password", "")):
        session.clear()
        session.permanent = True
        session["user"] = CFG["username"]
        audit("login", "hub")
        return jsonify(ok=True, user=CFG["username"])
    _failed[ip].append(now)
    time.sleep(1)
    return jsonify(error="Wrong username or password"), 401


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def api_me():
    return jsonify(user=session.get("user"))


# --------------------------------------------------------------------------- browser: servers
def server_view(s):
    r = s.get("report") or {}
    return {"id": s["id"], "name": s.get("name") or r.get("hostname") or s["id"], "hostname": r.get("hostname", ""),
            "online": is_online(s), "last_seen": s.get("last_seen") or s.get("report_time") or 0,
            "first_seen": s.get("first_seen", 0), "public_ip": s.get("ip", ""), "report": r}


@app.get("/api/servers")
@login_required
def api_servers():
    with _lock:
        out = [server_view(s) for s in _servers.values()]
    out.sort(key=lambda s: (not s["online"], s["name"].lower()))
    return jsonify(servers=out, now=time.time())


@app.post("/api/servers/<aid>")
@login_required
def api_server_edit(aid):
    d = request.get_json(silent=True) or {}
    with _lock:
        s = _servers.get(aid) or abort(404)
        if "name" in d:
            s["name"] = str(d["name"]).strip()[:60]
    save_servers(force=True)
    audit("rename", aid, s["name"])
    return jsonify(ok=True)


@app.delete("/api/servers/<aid>")
@login_required
def api_server_delete(aid):
    with _lock:
        s = _servers.get(aid) or abort(404)
        if is_online(s):
            return jsonify(error="The server is online - disconnect it from the hub on the server first"), 400
        _servers.pop(aid, None)
        _queues.pop(aid, None)
    save_servers(force=True)
    audit("remove server", aid)
    return jsonify(ok=True)


@app.get("/api/info")
@login_required
def api_info():
    return jsonify(agent_key=CFG["agent_key"], hub_url=request.host_url.rstrip("/"))


@app.get("/api/audit")
@login_required
def api_audit():
    if not os.path.exists(AUDIT_PATH):
        return jsonify([])
    with open(AUDIT_PATH, encoding="utf-8") as f:
        lines = f.readlines()[-300:]
    return jsonify([json.loads(l) for l in reversed(lines) if l.strip()])


# --------------------------------------------------------------------------- browser: open one server
@app.route("/s/<aid>", methods=["GET"])
def server_root(aid):
    return redirect(f"/s/{aid}/")


@app.route("/s/<aid>/", defaults={"path": ""}, methods=["GET", "POST", "DELETE"])
@app.route("/s/<aid>/<path:path>", methods=["GET", "POST", "DELETE"])
def relay(aid, path):
    """Forward a browser request to one server through its outgoing connection."""
    page = path == ""
    if not session.get("user"):
        return redirect("/") if page else (jsonify(error="login required"), 401)
    if request.method != "GET" and request.headers.get("X-Requested-With") != "fetch":
        return jsonify(error="bad request"), 400
    with _lock:
        s = _servers.get(aid)
    if not s:
        abort(404)
    name = server_view(s)["name"]
    if not is_online(s):
        if page:
            return Response(f"<!doctype html><meta charset=utf-8><title>{name} - offline</title>"
                            f"<body style='font:16px system-ui;padding:40px'><h2>{name} is offline</h2>"
                            f"<p>The server has not contacted the hub for a while. <a href='/'>Back to all servers</a></p>",
                            status=503, mimetype="text/html")
        return jsonify(error=f"{name} is offline"), 503

    job = {"id": uuid.uuid4().hex, "created": time.time(), "method": request.method, "path": "/" + path,
           "query": request.query_string.decode("latin-1"), "content_type": request.content_type or "",
           "body": base64.b64encode(request.get_data()).decode(), "xrw": request.headers.get("X-Requested-With", ""),
           "user": f"{session['user']}@hub", "ip": client_ip()}
    w = {"event": threading.Event(), "result": None, "agent": aid, "run": None, "resent": False}
    _waiting[job["id"]] = w
    try:
        _queues[aid].put(job)
        deadline = time.time() + JOB_SECONDS
        while not w["event"].wait(1) and time.time() < deadline:
            # taken by a process that has since restarted (e.g. right after an update): send it again once
            if w["run"] and w["run"] != s.get("run") and not w["resent"]:
                w.update(run=None, resent=True)
                _queues[aid].put(job)
            if not w["run"] and not is_online(s):
                break  # nobody took it and the server has gone offline - don't keep the browser waiting
    finally:
        _waiting.pop(job["id"], None)
    r = w["result"]
    if not r:
        if not is_online(s):
            return jsonify(error=f"{name} is offline"), 503
        return jsonify(error=f"{name} did not answer in time"), 504
    if request.method != "GET":
        audit(request.method, f"{name}: /{path}", (request.get_data(as_text=True) or "")[:200])
    resp = Response(base64.b64decode(r.get("body") or ""), status=r.get("status", 502),
                    content_type=r.get("content_type") or "application/octet-stream")
    if r.get("disposition"):
        resp.headers["Content-Disposition"] = r["disposition"]
    return resp


# --------------------------------------------------------------------------- page
@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "hub.html")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-password", action="store_true", help="set the hub login username/password")
    ap.add_argument("--show-key", action="store_true", help="print the key servers use to connect")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()
    if args.set_password:
        set_password()
        return
    if args.show_key:
        print(CFG["agent_key"])
        return
    if not CFG["password_hash"]:
        print("No password set yet. Run:  python hub.py --set-password")
        sys.exit(1)
    port = args.port or CFG["port"]
    ssl = (CFG["ssl_cert"], CFG["ssl_key"]) if CFG["ssl_cert"] else None
    print(f"Server Monitor Hub running on http{'s' if ssl else ''}://{socket.gethostname()}:{port}")
    print(f"Hub key for the servers: {CFG['agent_key']}")
    if ssl:
        app.run(host=CFG["host"], port=port, ssl_context=ssl, threaded=True)
    else:
        from waitress import serve
        serve(app, host=CFG["host"], port=port, threads=CFG["threads"], channel_timeout=POLL_SECONDS + 60)


if __name__ == "__main__":
    main()
