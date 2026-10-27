"""
Server Monitor - a small web utility that runs ON the server.

Open http://<server-ip>:30081 from any computer's browser to:
  * watch CPU / memory / disk / network / uptime / top processes
  * read the Windows Event Log (or the Linux journal)
  * start / stop / restart services - without RDP or SSH

First run:   python app.py --set-password
Then:        python app.py
"""
import argparse
import base64
import getpass
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from functools import wraps

import psutil
from flask import Flask, jsonify, request, session, send_from_directory, abort
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
AUDIT_PATH = os.path.join(BASE_DIR, "audit.log")
IS_WINDOWS = platform.system() == "Windows"

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 30081,
    "username": "admin",
    "password_hash": "",
    "secret_key": "",
    # Empty list = every service may be controlled.
    # Otherwise only these service names get Start/Stop/Restart buttons.
    "allowed_services": [],
    # These can never be stopped/restarted from the web page.
    "protected_services": ["RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs",
                           "EventLog", "WinRM", "TermService", "sshd", "systemd-journald"],
    # These processes can never be ended from the web page.
    "protected_processes": ["System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
                            "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                            "dwm.exe", "fontdrvhost.exe", "MsMpEng.exe",
                            "systemd", "init", "sshd", "kthreadd"],
    "session_minutes": 60,
    # Terminal tab: run Command Prompt / PowerShell commands on the server from the web page.
    "terminal_enabled": True,
    "ssl_cert": "",
    "ssl_key": "",
}


# --------------------------------------------------------------------------- config
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if not cfg["secret_key"]:
        cfg["secret_key"] = secrets.token_hex(32)
        save_config(cfg)
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def set_password():
    cfg = load_config()
    user = input(f"Username [{cfg['username']}]: ").strip() or cfg["username"]
    while True:
        p1 = getpass.getpass("New password (min 8 chars): ")
        if len(p1) < 8:
            print("Too short.")
            continue
        if p1 != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            continue
        break
    cfg["username"] = user
    cfg["password_hash"] = generate_password_hash(p1)
    save_config(cfg)
    print("Saved. Start the utility with:  python app.py")


CFG = load_config()
app = Flask(__name__, static_folder=None)
app.secret_key = CFG["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=bool(CFG["ssl_cert"]),
    PERMANENT_SESSION_LIFETIME=CFG["session_minutes"] * 60,
)


# --------------------------------------------------------------------------- helpers
def run(cmd, timeout=30, cwd=None, merge_stderr=False, encoding="utf-8"):
    """Run a command, return (ok, output)."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        p = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, timeout=timeout, cwd=cwd,
                           stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                           stdin=subprocess.DEVNULL, creationflags=flags,
                           encoding=encoding, errors="replace")
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode == 0, out.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def powershell(script, timeout=30):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def audit(action, target, ok, detail=""):
    line = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "user": session.get("user", "-"),
        "ip": request.remote_addr,
        "action": action,
        "target": target,
        "ok": ok,
        "detail": detail[:300],
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


# --------------------------------------------------------------------------- auth
_failed = {}  # ip -> [timestamps]
LOCK_WINDOW, LOCK_MAX = 300, 5


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return jsonify(error="login required"), 401
        if request.method == "POST" and request.headers.get("X-Requested-With") != "fetch":
            return jsonify(error="bad request"), 400  # basic CSRF guard
        return fn(*a, **kw)
    return wrapper


@app.post("/api/login")
def api_login():
    ip = request.remote_addr
    now = time.time()
    attempts = [t for t in _failed.get(ip, []) if now - t < LOCK_WINDOW]
    _failed[ip] = attempts
    if len(attempts) >= LOCK_MAX:
        return jsonify(error="Too many failed attempts. Try again in 5 minutes."), 429

    data = request.get_json(silent=True) or {}
    user, pw = data.get("username", ""), data.get("password", "")
    if (CFG["password_hash"] and secrets.compare_digest(user, CFG["username"])
            and check_password_hash(CFG["password_hash"], pw)):
        session.clear()
        session.permanent = True
        session["user"] = user
        _failed.pop(ip, None)
        audit("login", "-", True)
        return jsonify(ok=True, user=user)
    attempts.append(now)
    time.sleep(1)
    return jsonify(error="Invalid username or password"), 401


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def api_me():
    return jsonify(user=session.get("user"))


# --------------------------------------------------------------------------- metrics
_history = deque(maxlen=120)  # ~6 minutes at 3s
_last_net = {"t": time.time(), "c": psutil.net_io_counters()}


def sampler():
    psutil.cpu_percent(None)
    while True:
        time.sleep(3)
        now, c = time.time(), psutil.net_io_counters()
        dt = max(now - _last_net["t"], 0.001)
        rx = (c.bytes_recv - _last_net["c"].bytes_recv) / dt
        tx = (c.bytes_sent - _last_net["c"].bytes_sent) / dt
        _last_net.update(t=now, c=c)
        _history.append({
            "t": int(now),
            "cpu": psutil.cpu_percent(None),
            "mem": psutil.virtual_memory().percent,
            "rx": rx,
            "tx": tx,
        })


@app.get("/api/stats")
@login_required
def api_stats():
    vm = psutil.virtual_memory()
    disks = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({"mount": p.mountpoint, "fs": p.fstype, "total": u.total,
                          "used": u.used, "percent": u.percent})
        except (PermissionError, OSError):
            pass
    boot = psutil.boot_time()
    release = platform.release()
    if IS_WINDOWS and release == "10" and int(platform.version().split(".")[-1]) >= 22000:
        release = "11"  # Python reports Windows 11 as "10"
    return jsonify(
        host=socket.gethostname(),
        os=f"{platform.system()} {release} ({platform.version()})",
        cpu_count=psutil.cpu_count(),
        cpu=_history[-1]["cpu"] if _history else psutil.cpu_percent(0.2),
        mem={"total": vm.total, "used": vm.used, "percent": vm.percent},
        swap=psutil.swap_memory().percent,
        disks=disks,
        uptime=int(time.time() - boot),
        boot=datetime.fromtimestamp(boot).isoformat(timespec="seconds"),
        history=list(_history),
    )


# Reading every process is slow on busy servers (and with antivirus), so one
# background thread takes a snapshot every few seconds and all pages share it.
_procs = {"t": 0.0, "list": []}
_procs_lock = threading.Lock()


def take_process_snapshot():
    ncpu = psutil.cpu_count() or 1
    snap = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "create_time"]):
        i = p.info
        if i["pid"] == 0:
            continue  # "System Idle Process" is just free CPU
        snap.append({
            "pid": i["pid"], "name": i["name"] or "", "user": i["username"] or "",
            "cpu": (i["cpu_percent"] or 0) / ncpu,  # 0-100 % of the whole machine, like Task Manager
            "mem": i["memory_info"].rss if i["memory_info"] else 0,
            "started": datetime.fromtimestamp(i["create_time"]).isoformat(timespec="seconds")
                       if i["create_time"] else "",
            "session": _session_of(i["pid"]) if IS_WINDOWS else None,
        })
    with _procs_lock:
        _procs.update(t=time.time(), list=snap)


def process_snapshot():
    if time.time() - _procs["t"] > 15:  # sampler not running yet / stalled
        take_process_snapshot()
    return [dict(p) for p in _procs["list"]]


def process_sampler():
    while True:
        try:
            take_process_snapshot()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(3)


@app.get("/api/processes")
@login_required
def api_processes():
    procs = process_snapshot()
    key = request.args.get("sort", "mem")
    procs.sort(key=lambda x: x.get(key, 0), reverse=True)
    for p in procs[:50]:
        p["killable"] = process_killable(p["pid"], p["name"])
    return jsonify(procs[:50])


def process_killable(pid, name):
    protected = {s.lower() for s in CFG["protected_processes"]}
    return pid > 4 and pid != os.getpid() and (name or "").lower() not in protected


@app.post("/api/processes/<int:pid>/kill")
@login_required
def api_process_kill(pid):
    # the page sends the name it showed, so a reused PID is never killed by mistake
    name = (request.get_json(silent=True) or {}).get("name", "")
    target = f"{name} ({pid})"
    try:
        p = psutil.Process(pid)
        if p.name() != name:
            return jsonify(error="Process has already exited"), 404
    except psutil.NoSuchProcess:
        return jsonify(error="Process has already exited"), 404
    if not process_killable(pid, name):
        audit("end task", target, False, "protected process")
        return jsonify(error="This process is protected"), 403
    try:
        p.terminate()
        p.wait(timeout=5)
        ok, out = True, ""
    except psutil.NoSuchProcess:
        ok, out = True, ""
    except psutil.TimeoutExpired:
        ok, out = False, "Process did not exit within 5 seconds"
    except psutil.AccessDenied:
        ok, out = False, "Access denied - run Server Monitor as Administrator"
    audit("end task", target, ok, out)
    if not ok:
        return jsonify(error=out), 500
    with _procs_lock:
        _procs["list"] = [x for x in _procs["list"] if x["pid"] != pid]
    return jsonify(ok=True)


# --------------------------------------------------------------------------- user sessions (RDP)
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _WTS_SESSION_INFO(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR),
                    ("State", ctypes.c_int)]

    class _WTSINFO(ctypes.Structure):
        _fields_ = [("State", ctypes.c_int), ("SessionId", wintypes.DWORD)] + \
                   [(n, wintypes.DWORD) for n in ("InB", "OutB", "InF", "OutF", "InC", "OutC")] + \
                   [("WinStationName", wintypes.WCHAR * 32), ("Domain", wintypes.WCHAR * 17),
                    ("UserName", wintypes.WCHAR * 21)] + \
                   [(n, ctypes.c_int64) for n in ("ConnectTime", "DisconnectTime", "LastInputTime",
                                                  "LogonTime", "CurrentTime")]

    WTS_STATES = ["Active", "Connected", "ConnectQuery", "Shadow", "Disconnected",
                  "Idle", "Listen", "Reset", "Down", "Init"]
    WTS_USER_NAME, WTS_DOMAIN_NAME, WTS_CLIENT_NAME = 5, 7, 10
    WTS_CLIENT_ADDRESS, WTS_CLIENT_PROTOCOL, WTS_SESSION_INFO = 14, 16, 24
    WTS_PROTOCOLS = {0: "Console", 1: "Citrix ICA", 2: "RDP"}


# Parts of Windows that run in every user's session (shown greyed out under the user's programs)
WINDOWS_BACKGROUND = {n.lower() for n in (
    "csrss.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "LogonUI.exe", "explorer.exe",
    "sihost.exe", "taskhostw.exe", "ctfmon.exe", "RuntimeBroker.exe", "dllhost.exe", "conhost.exe",
    "svchost.exe", "rdpclip.exe", "rdpinput.exe", "smartscreen.exe", "TextInputHost.exe",
    "SearchHost.exe", "SearchApp.exe", "StartMenuExperienceHost.exe", "ShellExperienceHost.exe",
    "ShellHost.exe", "ApplicationFrameHost.exe", "SystemSettingsBroker.exe", "UserOOBEBroker.exe",
    "backgroundTaskHost.exe", "SecurityHealthSystray.exe", "Widgets.exe", "WidgetService.exe",
    "LockApp.exe", "CrossDeviceResume.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
    "WmiPrvSE.exe", "audiodg.exe", "MoUsoCoreWorker.exe", "PhoneExperienceHost.exe")}


def _wts_query(sid, info_class):
    buf, size = ctypes.c_void_p(), wintypes.DWORD()
    if not _wts.WTSQuerySessionInformationW(None, sid, info_class, ctypes.byref(buf), ctypes.byref(size)):
        return None
    try:
        if info_class in (WTS_USER_NAME, WTS_DOMAIN_NAME, WTS_CLIENT_NAME):
            return ctypes.wstring_at(buf.value)
        if info_class == WTS_CLIENT_PROTOCOL:
            return int.from_bytes(ctypes.string_at(buf.value, 2), "little")
        if info_class == WTS_CLIENT_ADDRESS:
            raw = ctypes.string_at(buf.value, size.value)
            family = int.from_bytes(raw[:4], "little")
            return ".".join(str(b) for b in raw[6:10]) if family == socket.AF_INET else ""
        return _WTSINFO.from_buffer_copy(ctypes.string_at(buf.value, ctypes.sizeof(_WTSINFO)))
    finally:
        _wts.WTSFreeMemory(buf)


def _filetime(v):
    return datetime.fromtimestamp((v - 116444736000000000) / 1e7) if v > 0 else None


def _session_of(pid):
    sid = wintypes.DWORD()
    return sid.value if _k32.ProcessIdToSessionId(pid, ctypes.byref(sid)) else None


def _quser_idle():
    """session id -> idle text from quser (not present on Windows Home)."""
    ok, out = run(["quser"])
    idle = {}
    for line in out.splitlines()[1:]:
        m = re.match(r"^\s*>?(\S+)\s+(\S*)\s+(\d+)\s+(\S+)\s+(\S+)\s+", line)
        if m:
            idle[int(m.group(3))] = "" if m.group(5) in (".", "none") else m.group(5)
    return idle


def list_sessions():
    if not IS_WINDOWS:
        return [{"id": i, "user": u.name, "session": u.terminal or "", "state": "Active",
                 "client": "", "ip": u.host or "", "logon": datetime.fromtimestamp(u.started).isoformat(timespec="seconds"),
                 "idle": "", "procs": 0, "cpu": 0, "mem": 0} for i, u in enumerate(psutil.users())]
    ptr, count = ctypes.POINTER(_WTS_SESSION_INFO)(), wintypes.DWORD()
    if not _wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(ptr), ctypes.byref(count)):
        return []
    ids = [ptr[i].SessionId for i in range(count.value)]
    _wts.WTSFreeMemory(ptr)

    usage = {}  # session id -> [processes, cpu, mem]
    for p in process_snapshot():
        u = usage.setdefault(p["session"], [0, 0.0, 0])
        u[0] += 1
        u[1] += p["cpu"]
        u[2] += p["mem"]
    quser = None

    # Some thin-client systems run user sessions that WTSEnumerateSessions does not
    # list, so also take every session that has a real user's programs running.
    owners = {}  # session id -> {user: process count}
    for p in process_snapshot():
        if p["session"] and p["user"] and not _is_system_account(p["user"]):
            c = owners.setdefault(p["session"], {})
            c[p["user"]] = c.get(p["user"], 0) + 1
    ids += [sid for sid in sorted(owners) if sid not in ids]

    own_sid = _session_of(os.getpid())
    out = []
    for sid in ids:
        if sid == 0:
            continue  # services session
        info = _wts_query(sid, WTS_SESSION_INFO)
        user = _wts_query(sid, WTS_USER_NAME) or (info.UserName if info else "")
        domain = _wts_query(sid, WTS_DOMAIN_NAME) or (info.Domain if info else "")
        if not user and sid in owners:
            user, domain = max(owners[sid], key=owners[sid].get), ""
        client = _wts_query(sid, WTS_CLIENT_NAME) or ""
        state = (WTS_STATES[info.State] if info.State < len(WTS_STATES) else str(info.State)) if info else "Active"
        if not user and (state in ("Listen", "Down", "Init") or not client):
            continue  # RDP listener or an empty local sign-in screen
        idle, logon = "", None
        if info:
            now = _filetime(info.CurrentTime) or datetime.now()
            since = _filetime(info.DisconnectTime) if state == "Disconnected" else _filetime(info.LastInputTime)
            if since:
                idle = int((now - since).total_seconds())
            else:
                quser = _quser_idle() if quser is None else quser
                idle = quser.get(sid, "")
            logon = _filetime(info.LogonTime)
        procs, cpu, mem = usage.get(sid, [0, 0, 0])
        proto = _wts_query(sid, WTS_CLIENT_PROTOCOL)
        out.append({
            "id": sid, "user": f"{domain}\\{user}" if domain and "\\" not in user else user,
            "signed_in": bool(user),
            "session": info.WinStationName if info else "", "state": state,
            "protocol": WTS_PROTOCOLS.get(proto, "Other") if proto is not None else "",
            "client": client, "ip": _wts_query(sid, WTS_CLIENT_ADDRESS) or "",
            "logon": logon.isoformat(timespec="seconds") if logon else "",
            "idle": idle, "procs": procs, "cpu": cpu, "mem": mem,
            "own": sid == own_sid,
        })
    return out


def _is_system_account(user):
    u = user.upper()
    return u.startswith(("NT AUTHORITY\\", "FONT DRIVER HOST\\", "WINDOW MANAGER\\")) or \
        u.split("\\")[-1] in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")


@app.get("/api/sessions")
@login_required
def api_sessions():
    return jsonify(sessions=list_sessions(), supported=IS_WINDOWS)


@app.get("/api/sessions/<int:sid>/processes")
@login_required
def api_session_processes(sid):
    if IS_WINDOWS:
        procs = [p for p in process_snapshot() if p["session"] == sid]
    else:
        users = psutil.users()
        if sid >= len(users):
            abort(404)
        procs = [p for p in process_snapshot() if p["user"] == users[sid].name]
    for p in procs:
        p["killable"] = process_killable(p["pid"], p["name"])
        p["system"] = p["name"].lower() in WINDOWS_BACKGROUND
    # the user's own programs first, then by memory
    procs.sort(key=lambda p: (p["system"], -p["mem"]))
    return jsonify(procs)


@app.post("/api/sessions/<int:sid>/<action>")
@login_required
def api_session_action(sid, action):
    if action not in ("logoff", "disconnect"):
        abort(400)
    if not IS_WINDOWS:
        return jsonify(error="Only supported on Windows"), 400
    s = next((s for s in list_sessions() if s["id"] == sid), None)
    if not s:
        return jsonify(error="Session not found"), 404
    target = f"{s['user']} (session {sid})"
    if s["own"]:
        audit(action, target, False, "Server Monitor runs in this session")
        return jsonify(error="Server Monitor itself runs in this session - it cannot log itself off"), 403
    fn = _wts.WTSLogoffSession if action == "logoff" else _wts.WTSDisconnectSession
    ok = bool(fn(None, sid, False))
    out = "" if ok else ctypes.FormatError(ctypes.get_last_error())
    audit("log off" if action == "logoff" else "disconnect", target, ok, out)
    if not ok:
        return jsonify(error=out or "Failed"), 500
    return jsonify(ok=True)


def _rdp_port():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as k:
            return int(winreg.QueryValueEx(k, "PortNumber")[0])
    except (OSError, ImportError, ValueError):
        return 3389


@app.get("/api/rdp-file")
@login_required
def api_rdp_file():
    """A .rdp file that opens Windows Remote Desktop to this server."""
    user = re.sub(r"[\r\n]", "", request.args.get("user", ""))[:100]
    host = request.host.rsplit(":", 1)[0] if request.host.count(":") == 1 else request.host
    port = _rdp_port()
    lines = [
        f"full address:s:{host}" + (f":{port}" if port != 3389 else ""),
        f"username:s:{user}" if user else "",
        "prompt for credentials:i:1",
        "screen mode id:i:2",
        "use multimon:i:0",
        "redirectclipboard:i:1",
        "redirectprinters:i:1",
        "authentication level:i:2",
        "autoreconnection enabled:i:1",
    ]
    body = "\r\n".join(l for l in lines if l) + "\r\n"
    name = re.sub(r"[^A-Za-z0-9.-]", "_", socket.gethostname() + (("-" + user.split("\\")[-1]) if user else ""))
    return app.response_class(body, mimetype="application/x-rdp",
                              headers={"Content-Disposition": f'attachment; filename="{name}.rdp"'})


# --------------------------------------------------------------------------- terminal
TERM_SHELLS = ["cmd", "powershell"] if IS_WINDOWS else ["bash"]
TERM_MARK = "__SERVER_MONITOR_CWD__"
TERM_TIMEOUT = 120


def _term_home():
    return os.environ.get("SystemDrive", "C:") + "\\" if IS_WINDOWS else "/"


@app.get("/api/terminal")
@login_required
def api_terminal_info():
    try:
        user = psutil.Process().username()
    except psutil.Error:
        user = getpass.getuser()
    return jsonify(enabled=CFG["terminal_enabled"], shells=TERM_SHELLS, user=user,
                   cwd={s: session.get("cwd_" + s) or _term_home() for s in TERM_SHELLS},
                   timeout=TERM_TIMEOUT)


@app.post("/api/terminal")
@login_required
def api_terminal():
    if not CFG["terminal_enabled"]:
        return jsonify(error='The terminal is turned off ("terminal_enabled" in config.json)'), 403
    d = request.get_json(silent=True) or {}
    shell, command = d.get("shell"), (d.get("command") or "").strip()
    if shell not in TERM_SHELLS:
        abort(400)
    cwd = session.get("cwd_" + shell) or _term_home()
    if not os.path.isdir(cwd):
        cwd = _term_home()
    if not command:
        return jsonify(output="", cwd=cwd)

    # every command runs in a fresh shell started in the remembered folder;
    # after it we print a marker and the new folder, so "cd" keeps working
    if shell == "cmd":
        # cmd writes in the console code page ("oem"), not UTF-8
        ok, out = run(f'cmd /d /s /c "{command} & echo {TERM_MARK}& cd"',
                      timeout=TERM_TIMEOUT, cwd=cwd, merge_stderr=True, encoding="oem")
    elif shell == "powershell":
        script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue';"
                  f"try {{ . {{ {command}\n}} 2>&1 | Out-String -Width 250 }} catch {{ $_ | Out-String }};"
                  f"'{TERM_MARK}'; (Get-Location).ProviderPath")
        enc = base64.b64encode(script.encode("utf-16-le")).decode()
        ok, out = run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                      timeout=TERM_TIMEOUT, cwd=cwd, merge_stderr=True)
    else:
        ok, out = run(["bash", "-c", f"{command}\necho {TERM_MARK}; pwd"], timeout=TERM_TIMEOUT, cwd=cwd, merge_stderr=True)

    if TERM_MARK in out:
        out, _, new_cwd = out.rpartition(TERM_MARK)
        new_cwd = new_cwd.strip().splitlines()[0] if new_cwd.strip() else cwd
        if os.path.isdir(new_cwd):
            cwd = new_cwd
    elif out == "Command timed out":
        out = f"Stopped: the command ran longer than {TERM_TIMEOUT} seconds."
    session["cwd_" + shell] = cwd
    audit(shell, command[:300], ok)
    out = out.rstrip()
    if len(out) > 200_000:
        out = out[:200_000] + "\n… output cut at 200 KB"
    return jsonify(output=out, cwd=cwd)


# --------------------------------------------------------------------------- network
_last_nic = {}  # nic -> (time, bytes_sent, bytes_recv)


@app.get("/api/network")
@login_required
def api_network():
    now = time.time()
    stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
    counters = psutil.net_io_counters(pernic=True)
    nics = []
    for name, st in stats.items():
        a = addrs.get(name, [])
        c = counters.get(name)
        rx = tx = None
        if c and name in _last_nic:
            t0, s0, r0 = _last_nic[name]
            dt = max(now - t0, 0.001)
            rx, tx = (c.bytes_recv - r0) / dt, (c.bytes_sent - s0) / dt
        if c:
            _last_nic[name] = (now, c.bytes_sent, c.bytes_recv)
        nics.append({
            "name": name, "up": st.isup, "speed": st.speed, "mtu": st.mtu,
            "ipv4": [x.address for x in a if x.family == socket.AF_INET],
            "ipv6": [x.address.split("%")[0] for x in a if x.family == socket.AF_INET6][:2],
            "mac": next((x.address for x in a if x.family == psutil.AF_LINK), ""),
            "sent": c.bytes_sent if c else 0, "recv": c.bytes_recv if c else 0,
            "errors": (c.errin + c.errout) if c else 0, "drops": (c.dropin + c.dropout) if c else 0,
            "rx": rx, "tx": tx,
        })
    nics.sort(key=lambda n: (not n["up"], not n["ipv4"], n["name"].lower()))

    names = {}
    def pname(pid):
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else ""
            except psutil.Error:
                names[pid] = ""
        return names[pid]

    summary, listening, conns = {}, [], []
    for c in psutil.net_connections("inet"):
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        status = c.status if proto == "TCP" else "UDP"
        summary[status] = summary.get(status, 0) + 1
        if status == "LISTEN":
            listening.append({"proto": proto, "addr": c.laddr.ip, "port": c.laddr.port,
                              "pid": c.pid, "process": pname(c.pid)})
        elif c.raddr:
            conns.append({"proto": proto, "local": f"{c.laddr.ip}:{c.laddr.port}",
                          "remote": c.raddr.ip, "rport": c.raddr.port, "status": status,
                          "pid": c.pid, "process": pname(c.pid)})
    listening = sorted({(l["port"], l["proto"], l["addr"]): l for l in listening}.values(),
                       key=lambda l: l["port"])
    conns.sort(key=lambda c: (c["status"] != "ESTABLISHED", c["remote"]))
    return jsonify(nics=nics, summary=summary, listening=listening, conns=conns[:500],
                   total_conns=len(conns))


def _ping(host, count=3):
    cmd = ["ping", "-n", str(count), "-w", "1000", host] if IS_WINDOWS else ["ping", "-c", str(count), "-W", "1", host]
    ok, out = run(cmd, timeout=count * 2 + 5)
    replies = [l for l in out.splitlines() if "ttl=" in l.lower()]
    times = [float(m.group(1)) for l in replies for m in [re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", l)] if m]
    return {"host": host, "ok": bool(replies), "sent": count, "received": len(replies),
            "ms": round(sum(times) / len(times), 1) if times else None}


def _gateway_and_dns():
    if IS_WINDOWS:
        ok, out = powershell(
            "$g=(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop;"
            "$d=Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object ServerAddresses | Select-Object -Unique;"
            "@{gateway=$g; dns=@($d)} | ConvertTo-Json -Compress")
        try:
            j = json.loads(out)
            return j.get("gateway") or "", [d for d in (j.get("dns") or []) if d]
        except json.JSONDecodeError:
            return "", []
    ok, out = run(["ip", "route", "show", "default"])
    m = re.search(r"via (\S+)", out)
    dns = []
    if os.path.exists("/etc/resolv.conf"):
        with open("/etc/resolv.conf") as f:
            dns = [l.split()[1] for l in f if l.startswith("nameserver") and len(l.split()) > 1]
    return (m.group(1) if m else ""), dns


@app.get("/api/network/check")
@login_required
def api_network_check():
    from concurrent.futures import ThreadPoolExecutor
    custom = request.args.get("host", "").strip()
    if custom and not re.fullmatch(r"[A-Za-z0-9.\-:]{1,253}", custom):
        return jsonify(error="Invalid host name"), 400
    gateway, dns = _gateway_and_dns()

    def dns_lookup():
        t = time.time()
        try:
            ip = socket.gethostbyname("www.google.com")
            return {"ok": True, "ms": round((time.time() - t) * 1000, 1), "ip": ip}
        except OSError as e:
            return {"ok": False, "ms": None, "ip": "", "error": str(e)}

    checks = [("Gateway", gateway)] if gateway else []
    checks += [("DNS server", d) for d in dns[:2]] + [("Internet (Google DNS)", "8.8.8.8"),
                                                     ("Internet (Cloudflare)", "1.1.1.1")]
    if custom:
        checks = [("Custom", custom)]
    with ThreadPoolExecutor(8) as ex:
        lookup = ex.submit(dns_lookup) if not custom else None
        results = [dict(r, label=lbl) for (lbl, _), r in zip(checks, ex.map(lambda c: _ping(c[1]), checks))]
    return jsonify(gateway=gateway, dns=dns, pings=results,
                   lookup=lookup.result() if lookup else None)


# --------------------------------------------------------------------------- services
def list_services():
    out = []
    if IS_WINDOWS:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
            except Exception:  # noqa: BLE001
                continue
            out.append({"name": d["name"], "display": d["display_name"],
                        "status": d["status"], "start": d["start_type"],
                        "pid": d["pid"], "desc": (d.get("description") or "")[:200]})
    else:
        ok, txt = run(["systemctl", "list-units", "--type=service", "--all",
                       "--no-pager", "--plain", "--no-legend"])
        for line in txt.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            name = parts[0].removesuffix(".service")
            out.append({"name": name, "display": name, "status": parts[3],
                        "start": parts[1], "pid": None,
                        "desc": parts[4] if len(parts) > 4 else ""})
    allowed = {s.lower() for s in CFG["allowed_services"]}
    protected = {s.lower() for s in CFG["protected_services"]}
    for s in out:
        n = s["name"].lower()
        s["controllable"] = n not in protected and (not allowed or n in allowed)
    out.sort(key=lambda s: s["display"].lower())
    return out


@app.get("/api/services")
@login_required
def api_services():
    return jsonify(list_services())


@app.post("/api/services/<name>/<action>")
@login_required
def api_service_action(name, action):
    if action not in ("start", "stop", "restart"):
        abort(400)
    svc = next((s for s in list_services() if s["name"] == name), None)
    if not svc:
        return jsonify(error="Service not found"), 404
    if not svc["controllable"]:
        audit(action, name, False, "blocked by config")
        return jsonify(error="This service is protected / not in allowed list"), 403

    if IS_WINDOWS:
        verb = {"start": "Start-Service", "stop": "Stop-Service -Force",
                "restart": "Restart-Service -Force"}[action]
        # name comes from the real service list above, still quote it safely
        safe = name.replace("'", "''")
        ok, out = powershell(f"{verb} -Name '{safe}' -ErrorAction Stop", timeout=90)
    else:
        ok, out = run(["systemctl", action, name + ".service"], timeout=90)

    audit(action, name, ok, out)
    new = next((s for s in list_services() if s["name"] == name), svc)
    if not ok:
        return jsonify(error=out or "Failed", service=new), 500
    return jsonify(ok=True, service=new)


# --------------------------------------------------------------------------- events
WIN_LOGS = ["System", "Application", "Security", "Setup"]
LEVEL_NAMES = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 0: "Information", 5: "Verbose"}


@app.get("/api/events")
@login_required
def api_events():
    count = max(1, min(int(request.args.get("count", 100)), 500))
    level = request.args.get("level", "warning")  # critical|error|warning|all
    if IS_WINDOWS:
        log = request.args.get("log", "System")
        if log not in WIN_LOGS:
            abort(400)
        levels = {"critical": "1", "error": "1,2", "warning": "1,2,3"}.get(level)
        flt = f"@{{LogName='{log}'" + (f"; Level={levels}" if levels else "") + "}"
        script = (
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            f"Get-WinEvent -FilterHashtable {flt} -MaxEvents {count} -ErrorAction SilentlyContinue | "
            "Select-Object @{n='time';e={$_.TimeCreated.ToString('s')}},"
            "@{n='level';e={$_.Level}},@{n='source';e={$_.ProviderName}},"
            "@{n='id';e={$_.Id}},@{n='message';e={$m=([string]$_.Message -replace '\\s+',' ').Trim(); "
            "if($m.Length -gt 400){$m.Substring(0,400)+'...'}else{$m}}} | "
            "ConvertTo-Json -Compress"
        )
        ok, out = powershell(script, timeout=60)
        if not out:
            return jsonify(events=[], logs=WIN_LOGS)
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return jsonify(error=out[:500], events=[], logs=WIN_LOGS), 500
        if isinstance(data, dict):
            data = [data]
        for e in data:
            e["level"] = LEVEL_NAMES.get(e["level"], str(e["level"]))
        return jsonify(events=data, logs=WIN_LOGS)

    prio = {"critical": "2", "error": "3", "warning": "4"}.get(level, "7")
    ok, out = run(["journalctl", "-n", str(count), "-p", prio, "-o", "json", "--no-pager", "-r"])
    events, names = [], {0: "Critical", 1: "Critical", 2: "Critical", 3: "Error",
                         4: "Warning", 5: "Information", 6: "Information", 7: "Verbose"}
    for line in out.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = int(j.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        events.append({"time": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
                       "level": names.get(int(j.get("PRIORITY", 6)), "Information"),
                       "source": j.get("SYSLOG_IDENTIFIER") or j.get("_SYSTEMD_UNIT", ""),
                       "id": "", "message": str(j.get("MESSAGE", ""))[:400]})
    return jsonify(events=events, logs=["journal"])


# --------------------------------------------------------------------------- audit
@app.get("/api/audit")
@login_required
def api_audit():
    if not os.path.exists(AUDIT_PATH):
        return jsonify([])
    with open(AUDIT_PATH, encoding="utf-8") as f:
        lines = f.readlines()[-200:]
    return jsonify([json.loads(l) for l in reversed(lines) if l.strip()])


# --------------------------------------------------------------------------- updates from GitHub
REPO_URL = "https://github.com/voyagerinc/Servermanager.git"
RESTART_CODE = 3  # app exits with this code to ask the supervisor for a restart
SUPERVISED = os.environ.get("SERVER_MONITOR_SUPERVISED") == "1"


def _git_exe():
    import shutil
    found = shutil.which("git")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramW6432", "")):
        p = os.path.join(base, "Git", "cmd", "git.exe")
        if base and os.path.exists(p):
            return p
    return None


def git(*args, timeout=60):
    exe = _git_exe()
    if not exe:
        return False, "Git is not installed - run start.bat once to install it"
    # safe.directory: the folder may belong to another account (e.g. when running as SYSTEM)
    return run([exe, "-c", "safe.directory=*", "-C", BASE_DIR, *args], timeout=timeout)


def _branch():
    ok, out = git("rev-parse", "--abbrev-ref", "HEAD")
    return out if ok and out and out != "HEAD" else "main"


def update_status(fetch=True):
    if not _git_exe():
        return {"git": False, "error": "Git is not installed - run start.bat once to install it"}
    if not os.path.isdir(os.path.join(BASE_DIR, ".git")):
        return {"git": True, "repo": False, "behind": None,
                "error": "This folder is not linked to GitHub yet - click Pull update to link it"}
    branch = _branch()
    st = {"git": True, "repo": True, "branch": branch, "error": ""}
    ok, out = git("log", "-1", "--format=%h%x1f%cI%x1f%s")
    if ok and "\x1f" in out:
        st["commit"], st["date"], st["message"] = out.split("\x1f", 2)
    if fetch:
        ok, out = git("fetch", "--quiet", "origin", branch, timeout=60)
        if not ok:
            st["error"] = "Could not reach GitHub: " + out[-300:]
    ok, out = git("log", "--format=%h%x1f%cI%x1f%s", f"HEAD..origin/{branch}")
    st["incoming"] = [dict(zip(("commit", "date", "message"), l.split("\x1f", 2)))
                      for l in out.splitlines() if ok and "\x1f" in l]
    st["behind"] = len(st["incoming"]) if ok else None
    return st


def apply_update():
    """Bring the program files to the latest GitHub version.
    Returns (ok, changed, log). config.json, audit.log and venv are not in git, so they are kept."""
    log = []
    if not os.path.isdir(os.path.join(BASE_DIR, ".git")):
        for args in (("init", "--quiet"), ("remote", "add", "origin", REPO_URL)):
            ok, out = git(*args)
            log.append(out)
            if not ok:
                return False, False, "\n".join(log)
        old = ""
    else:
        old = git("rev-parse", "HEAD")[1]
    branch = _branch()
    ok, out = git("fetch", "--quiet", "origin", branch, timeout=120)
    if not ok:
        return False, False, "Could not download from GitHub: " + out
    # servers never have their own edits to the program files, so take GitHub's version as-is
    ok, out = git("reset", "--hard", f"origin/{branch}")
    log.append(out)
    if not ok:
        return False, False, "\n".join(log)
    git("branch", f"--set-upstream-to=origin/{branch}")
    new = git("rev-parse", "HEAD")[1]
    changed = new != old
    if changed:
        ok, out = run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                       "-r", os.path.join(BASE_DIR, "requirements.txt")], timeout=600)
        log.append(out)
        if not ok:
            return False, True, "Updated, but installing packages failed:\n" + out
    return True, changed, "\n".join(l for l in log if l)


def restart_soon(delay=1.5):
    # leave time for the HTTP response to reach the browser, then exit for the supervisor
    threading.Timer(delay, lambda: os._exit(RESTART_CODE)).start()


@app.get("/api/update")
@login_required
def api_update_status():
    st = update_status(fetch=request.args.get("fetch") != "0")
    st["supervised"] = SUPERVISED
    st["repo_url"] = REPO_URL
    return jsonify(st)


@app.post("/api/update/<action>")
@login_required
def api_update(action):
    if action not in ("pull", "restart"):
        abort(400)
    if not SUPERVISED:
        return jsonify(error="Server Monitor was not started by start.bat / the service, so it cannot "
                             "restart itself. Close it and run start.bat again."), 400
    if action == "restart":
        audit("restart", "Server Monitor", True)
        restart_soon()
        return jsonify(ok=True, restarting=True)
    ok, changed, out = apply_update()
    audit("update", git("log", "-1", "--format=%h %s")[1] if ok else "-", ok, out)
    if not ok:
        return jsonify(error=out or "Update failed"), 500
    if changed:
        restart_soon()
    return jsonify(ok=True, changed=changed, restarting=changed)


def supervise(port=None):
    """Keep the web app running: restart it after an update (exit code 3) or a crash."""
    if not CFG["password_hash"]:
        print("No password set yet. Run:  python app.py --set-password")
        sys.exit(1)
    env = dict(os.environ, SERVER_MONITOR_SUPERVISED="1")
    cmd = [sys.executable, os.path.join(BASE_DIR, "app.py")] + (["--port", str(port)] if port else [])
    while True:
        try:
            code = subprocess.call(cmd, env=env, cwd=BASE_DIR)
        except KeyboardInterrupt:
            break
        if code == RESTART_CODE:
            print(f"{datetime.now():%H:%M:%S}  Restarting Server Monitor...")
            continue
        print(f"{datetime.now():%H:%M:%S}  Server Monitor stopped (exit code {code}) - restarting in 5 seconds. "
              "Press Ctrl+C to quit.")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            break


# --------------------------------------------------------------------------- page
@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "index.html")


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-password", action="store_true", help="set login username/password")
    ap.add_argument("--port", type=int)
    ap.add_argument("--update", action="store_true",
                    help="pull the latest version from GitHub (exit code 10 = files changed)")
    ap.add_argument("--supervise", action="store_true",
                    help="run the web app and restart it after updates or crashes")
    args = ap.parse_args()
    if args.set_password:
        set_password()
        return
    if args.update:
        ok, changed, out = apply_update()
        if not ok:
            print(out)
        sys.exit(1 if not ok else 10 if changed else 0)
    if args.supervise:
        supervise(args.port)
        return
    if not CFG["password_hash"]:
        print("No password set yet. Run:  python app.py --set-password")
        sys.exit(1)

    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=process_sampler, daemon=True).start()
    port = args.port or CFG["port"]
    ssl = (CFG["ssl_cert"], CFG["ssl_key"]) if CFG["ssl_cert"] else None
    print(f"Server Monitor running on http{'s' if ssl else ''}://{socket.gethostname()}:{port}")
    if ssl:
        app.run(host=CFG["host"], port=port, ssl_context=ssl, threaded=True)
    else:
        from waitress import serve
        serve(app, host=CFG["host"], port=port, threads=8)


if __name__ == "__main__":
    main()
