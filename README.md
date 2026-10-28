# Server Monitor

A small web utility you install **on the server**. Then from any computer on the
network, open `http://<server-ip>:30081` in a browser to:

- **Overview** – CPU, memory, network, uptime, disk space, a 6-minute chart, latest errors
- **Services** – search all services, Start / Stop / Restart with one click (no RDP needed)
- **Events** – Windows Event Log (System / Application / Security / Setup), filter by level and text
- **Processes** – every process, sorted by memory or CPU, search by name / PID / user, with **End task**
- **Users** – everyone signed in (RDP and console): status, client PC/IP, sign-in time, idle time,
  CPU/memory per user. See each user's programs, end a program, **Disconnect** or **Log off** a user.
  **Open Remote Desktop** / **Connect** downloads a `.rdp` file that opens Windows Remote Desktop to the server
- **Terminal** – run Command Prompt or PowerShell commands on the server (each command is logged)
- **Network** – gateway / DNS / internet test, ping any host, adapters with live speed,
  active connections per program, listening ports
- **Update** – check GitHub for a newer version, **Pull update & restart**, or just restart
- **Activity log** – who signed in, services restarted, tasks ended, users logged off,
  terminal commands and updates – with the IP they came from

Works on Windows Server (Event Log + Windows services) and on Linux (journalctl + systemd).

## Install on a Windows server

1. Download the code to the server, e.g. into `C:\ServerMonitor`:
   - with Git: `git clone https://github.com/voyagerinc/Servermanager.git C:\ServerMonitor`
   - or without Git: on GitHub click **Code → Download ZIP** and unzip it
2. Double-click **`start.bat`**. It asks for Administrator rights, then checks everything and
   installs whatever is missing – Python, the packages, Git – links the folder to GitHub,
   pulls the latest version, asks once for the web page username/password, opens port 30081
   in the firewall and starts Server Monitor.
3. From any PC, open `http://<server-ip>:30081` and sign in.

`start.bat` keeps running in its window. To start Server Monitor automatically with Windows
instead (as SYSTEM, so it can restart services), after step 2 run once in an Administrator PowerShell:

```
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

To remove the auto-start: `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`

## Updating every server

1. Make the change on your PC and push it to GitHub (`git commit` + `git push`).
2. On each server, either
   - open its web page → **Update** tab → **Pull update & restart**, or
   - just restart `start.bat` – it pulls the latest version every time it starts.

The update replaces the program files with the GitHub version. Each server's own
`config.json` (login, port, settings), `audit.log` and `venv` are not in Git and are kept.
Server Monitor runs under a small watchdog (`app.py --supervise`) that restarts it after an
update and if it ever crashes.

## Monitor all servers from one page – without opening ports (Hub)

The **Hub** (`hub/` folder) shows every server on one page: online/offline, CPU, memory,
disk, signed-in users and stopped services, with **Open** (that server's full Server Monitor),
**Update** and **Update all servers**.

The servers connect **out** to the hub over HTTPS – like AnyDesk/UltraViewer – so **no port
is opened on any server or customer router**. Only the hub needs one address the servers can reach.

```
 Server A ─┐   outgoing HTTPS only          ┌─ your laptop / phone
 Server B ─┼──►  Server Monitor HUB   ◄─────┤  https://hub.yourcompany.com
 Server C ─┘                                └─
```

**1. Start the hub** on one machine: double-click `hub\start-hub.bat` (or `python hub/hub.py`
on Linux). It asks for the hub username/password and listens on port 30090.

**2. Give the hub an address** the servers can reach – pick one:

- **Office PC + Cloudflare Tunnel (free, no port opened anywhere):** in a free Cloudflare
  account with your domain, go to *Zero Trust → Networks → Tunnels → Create tunnel*, install the
  connector on the hub PC with the command Cloudflare shows, and add a public hostname, e.g.
  `hub.voyager.co.in` → `http://localhost:30090`. Cloudflare provides the HTTPS certificate.
  To just try it without a domain: `cloudflared tunnel --url http://localhost:30090` prints a
  temporary `https://….trycloudflare.com` address (it changes on every restart).
- **A small cloud server** (Azure, AWS Lightsail, DigitalOcean, Hetzner…): run the hub there and
  put HTTPS in front of it, e.g. `caddy reverse-proxy --from hub.yourcompany.com --to localhost:30090`.

Always use an **https://** address on the internet – the hub can run commands on every server.

**3. Connect each server:** open the hub → **Add server** to see the hub address and hub key.
On the server open Server Monitor → **Update** tab → **Cloud monitoring**, paste both, click
**Connect**. The server appears in the hub within seconds and reconnects by itself after restarts.

The hub key is in `hub/hub_config.json` (`agent_key`); change it there and restart the hub to
lock out every server that used the old key. The hub's activity log records every action
done through it, and each server's own Activity log shows them as `<hub user>@hub`.

## Install on Linux

```
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python app.py --set-password
sudo venv/bin/python app.py      # root is needed to restart services
```

## Settings (`config.json`, created on first run)

| Key | Meaning |
|---|---|
| `port` | Web port (default 30081) |
| `allowed_services` | If not empty, **only** these services can be controlled, e.g. `["MSSQLSERVER","W3SVC","Tally"]` |
| `protected_services` | Never controllable from the web page (RPC, EventLog, RDP, WinRM… by default) |
| `session_minutes` | Auto sign-out time |
| `terminal_enabled` | `true` = Terminal tab can run commands on the server, `false` = turned off |
| `hub_url`, `hub_key` | Cloud monitoring hub this server connects to (set from the Update tab); empty = off |
| `ssl_cert`, `ssl_key` | Paths to a certificate to serve over HTTPS |

Change the password any time: `venv\Scripts\python app.py --set-password`, then restart the
`ServerMonitor` scheduled task.

## Security notes

- Anyone with the password can restart services, so use a strong password.
- After 5 wrong passwords an IP is blocked for 5 minutes.
- Keep it on your office LAN/VPN. **Do not** port-forward 30081 to the internet unless you
  set `ssl_cert`/`ssl_key` (HTTPS) and ideally restrict the firewall rule to known IPs.
- Use `allowed_services` to limit control to just the services your team needs.
