import socket
import threading
import logging
import os
import re
import secrets
from datetime import datetime, timezone
import ipinfo
import time
from urllib.parse import urlsplit, parse_qs, unquote_plus
from typing import Optional
from app import log_attack
from mitigation import get_policy

# Import shared EventBus instance
from shared_bus import bus

# Configure logging (stdout only; no file writes)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# IPinfo API token (prefer environment variable to avoid committing secrets)
ipinfo_token = os.getenv('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default


# Services to simulate
# NOTE: Ports <1024 require elevated privileges on many systems.
# Defaults are chosen to work without sudo. Override via env vars.
SERVICES = {
    'HTTP': {'port': _env_int('HONEYPOT_HTTP_PORT', 8080), 'handler': 'handle_http'},
    'SSH': {'port': _env_int('HONEYPOT_SSH_PORT', 2222), 'handler': 'handle_ssh'},
    'MySQL': {'port': _env_int('HONEYPOT_MYSQL_PORT', 33060), 'handler': 'handle_mysql'},
    'FTP': {'port': _env_int('HONEYPOT_FTP_PORT', 2121), 'handler': 'handle_ftp'},
    'Telnet': {'port': _env_int('HONEYPOT_TELNET_PORT', 2323), 'handler': 'handle_telnet'},
    'SMTP': {'port': _env_int('HONEYPOT_SMTP_PORT', 2525), 'handler': 'handle_smtp'}
}


_SESSIONS_LOCK = threading.Lock()
_SESSIONS = {}


def _now() -> float:
    return time.time()


def _get_session(client_ip: str) -> dict:
    """Lightweight per-IP state to make interactions feel stateful."""
    with _SESSIONS_LOCK:
        s = _SESSIONS.get(client_ip)
        if not s:
            s = {
                'session_id': secrets.token_hex(8),
                'created_at': _now(),
                'last_seen': _now(),
                'http': {
                    'authed': False,
                    'username': None,
                    'visits': 0,
                },
                'ssh': {
                    'username': None,
                    'authed': False,
                    'failed_logins': 0,
                    'cwd': '/home',
                    'history': [],
                    'files': {
                        '/home/README.txt': 'Welcome. Maintenance window: Sun 02:00 UTC\n',
                        '/home/important_data.txt': 'finance_q2.xlsx\ncustomers.csv\n',
                        '/var/log/auth.log': 'Apr  3 00:12:41 sshd[1211]: Failed password for root\n',
                        '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n',
                    },
                    'dirs': {'/': ['home', 'var', 'etc', 'tmp'], '/home': ['README.txt', 'important_data.txt'], '/tmp': [], '/var': ['log'], '/var/log': ['auth.log'], '/etc': ['passwd']},
                },
                'signals': {
                    'suspicion': 0,
                    'fakedb': False,
                    'deeppacketlog': False,
                }
            }
            _SESSIONS[client_ip] = s
        s['last_seen'] = _now()
        return s


def _read_http_request(sock: socket.socket, max_bytes: int = 64 * 1024) -> bytes:
    sock.settimeout(2.0)
    data = b''
    while b'\r\n\r\n' not in data and len(data) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if b'\r\n\r\n' not in data:
        return data
    header_part, body = data.split(b'\r\n\r\n', 1)
    headers_text = header_part.decode('iso-8859-1', errors='replace')
    m = re.search(r'\r\ncontent-length:\s*(\d+)\s*\r\n', '\r\n' + headers_text.lower() + '\r\n')
    if m:
        need = int(m.group(1)) - len(body)
        while need > 0 and len(data) < max_bytes:
            chunk = sock.recv(min(4096, need))
            if not chunk:
                break
            body += chunk
            need -= len(chunk)
        return header_part + b'\r\n\r\n' + body
    return data


def _parse_http_request(raw: bytes) -> dict:
    try:
        text = raw.decode('iso-8859-1', errors='replace')
    except Exception:
        text = ''
    if not text:
        return {'method': 'GET', 'path': '/', 'version': 'HTTP/1.1', 'headers': {}, 'body': ''}
    head, _, body = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    request_line = lines[0] if lines else ''
    parts = request_line.split(' ')
    method = parts[0].upper() if len(parts) >= 1 else 'GET'
    target = parts[1] if len(parts) >= 2 else '/'
    version = parts[2] if len(parts) >= 3 else 'HTTP/1.1'
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()

    u = urlsplit(target)
    path = u.path or '/'
    query = parse_qs(u.query)
    return {
        'method': method,
        'target': target,
        'path': path,
        'query': query,
        'version': version,
        'headers': headers,
        'body': body,
        'request_line': request_line,
    }


def _http_detect_signals(req: dict) -> dict:
    raw_target = req.get('target', '')
    raw_body = req.get('body', '')
    decoded = (unquote_plus(raw_target) + ' ' + unquote_plus(raw_body)).lower()
    traversal = ('../' in decoded) or ('..\\' in decoded) or ('%2e%2e' in decoded)
    sqli = any(p in decoded for p in ["' or 1=1", 'union select', 'information_schema', 'sleep(', 'benchmark(', 'xp_cmdshell'])
    cmdi = any(p in decoded for p in [';','&&','|','`','$(', '>/dev', 'curl ', 'wget ']) and ('http' in decoded or 'bin/' in decoded or 'sh' in decoded)
    brute = any(k in decoded for k in ['wp-login', 'xmlrpc.php', 'login', 'password='])
    return {
        'traversal': traversal,
        'sqli': sqli,
        'cmdi': cmdi,
        'brute': brute,
    }


def _http_category(req: dict, signals: dict) -> str:
    path = (req.get('path') or '/').lower()
    method = (req.get('method') or 'GET').upper()
    if signals.get('traversal'):
        return 'Directory Traversal'
    if signals.get('sqli'):
        return 'SQL Injection'
    if signals.get('cmdi'):
        return 'Command Injection'
    if method == 'POST' and path in ['/upload', '/api/v1/upload']:
        return 'Malware Upload'
    if method == 'POST' and ('login' in path or path in ['/wp-login.php', '/admin/login']):
        return 'Brute Force'
    if path in ['/robots.txt', '/phpmyadmin', '/wp-login.php', '/.env', '/config.php', '/backup.zip', '/db.sql']:
        return 'Reconnaissance'
    return 'Reconnaissance' if method == 'GET' else 'Exploitation'


def _http_response(status: str, content_type: str, body: str, headers: Optional[dict] = None) -> bytes:
    hdrs = {
        'Content-Type': content_type,
        'Content-Length': str(len(body.encode('utf-8', errors='ignore'))),
        'Connection': 'close',
        'Server': 'nginx/1.18.0',
    }
    if headers:
        hdrs.update(headers)
    header_lines = ''.join([f"{k}: {v}\r\n" for k, v in hdrs.items()])
    return (f"HTTP/1.1 {status}\r\n" + header_lines + "\r\n" + body).encode('utf-8', errors='ignore')

# Service handlers
def log_attack_internal(ip, service, payload, category, duration=0.0, src_bytes=0, dst_bytes=0, flag='SF', logged_in=False, failed_logins=0):
    session = _get_session(ip)
    try:
        if not ipinfo_handler:
            raise RuntimeError('IPINFO_TOKEN not configured')
        details = ipinfo_handler.getDetails(ip)
        geolocation = f"{details.lat},{details.lon}"
    except Exception as e:
        geolocation = "13.0878,80.2785"  # Default fallback
        logging.error(f"IPinfo lookup error for IP {ip}: {e}")
    timestamp = datetime.now(timezone.utc).isoformat()

    # Log to database/dashboard first so we can correlate with ML enrichment.
    attack_id = log_attack(ip, geolocation, timestamp, service, str(payload), category)
    
    # Emit event to ML pipeline
    connection_event = {
        'attack_id': attack_id,
        'session_id': session.get('session_id'),
        'src_ip': ip,
        'dst_port': SERVICES.get(service, {}).get('port', 0),
        'protocol': 'tcp',  # Default, can be updated based on service
        'service': service.lower(),
        'geolocation': geolocation,
        'duration': duration,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'flag': flag,
        'logged_in': logged_in,
        'failed_logins': failed_logins,
        'payload': payload.encode() if isinstance(payload, str) else payload,
        'timestamp': time.time(),
    }
    
    bus.emit(connection_event)

def handle_http(client_socket, client_ip):
    start_time = time.time()
    session = _get_session(client_ip)

    try:
        raw = _read_http_request(client_socket)
    except Exception as e:
        logging.error(f"HTTP read error from {client_ip}: {e}")
        client_socket.close()
        return

    req = _parse_http_request(raw)
    session['http']['visits'] += 1
    signals = _http_detect_signals(req)
    category = _http_category(req, signals)

    method = req.get('method', 'GET')
    path = req.get('path', '/')
    headers = req.get('headers', {})
    body = req.get('body', '')
    cookie = headers.get('cookie', '')
    authed_cookie = (f"session={session['session_id']}" in cookie)
    authed = bool(session['http'].get('authed')) or authed_cookie

    # Basic lures + common paths attackers probe
    if method == 'GET' and path == '/':
        page = (
            "<html><head><title>Acme Intranet</title></head><body>"
            "<h1>Acme Intranet</h1>"
            "<p>Internal services:</p>"
            "<ul>"
            "<li><a href='/admin'>Admin Console</a></li>"
            "<li><a href='/phpmyadmin'>Database Admin</a></li>"
            "<li><a href='/api/v1/status'>API Status</a></li>"
            "</ul>"
            "</body></html>"
        )
        resp = _http_response('200 OK', 'text/html; charset=utf-8', page)

    elif method == 'GET' and path == '/robots.txt':
        robots = "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\nDisallow: /db.sql\n"
        resp = _http_response('200 OK', 'text/plain; charset=utf-8', robots)

    elif method == 'GET' and path in ['/wp-login.php', '/login']:
        page = (
            "<html><body><h1>Log In</h1>"
            "<form method='POST' action='/admin/login'>"
            "<input name='username' placeholder='Username'/>"
            "<input name='password' type='password' placeholder='Password'/>"
            "<button type='submit'>Sign in</button>"
            "</form></body></html>"
        )
        resp = _http_response('200 OK', 'text/html; charset=utf-8', page)

    elif method == 'GET' and path in ['/phpmyadmin', '/pma']:
        page = (
            "<html><body><h1>phpMyAdmin</h1>"
            "<p>Version 4.9.7</p>"
            "<form method='POST' action='/admin/login'>"
            "<input name='username' placeholder='User'/>"
            "<input name='password' type='password' placeholder='Password'/>"
            "<button type='submit'>Go</button>"
            "</form></body></html>"
        )
        resp = _http_response('200 OK', 'text/html; charset=utf-8', page)

    elif method == 'GET' and path == '/api/v1/status':
        resp = _http_response('200 OK', 'application/json', '{"status":"ok","version":"1.12.3","uptime":%d}' % int(_now()))

    elif method == 'GET' and path == '/status':
        resp = _http_response('200 OK', 'application/json', '{"status":"ok"}')

    elif method == 'GET' and path in ['/.env', '/config.php', '/backup.zip', '/db.sql']:
        # Fake "sensitive" files to keep attackers engaged (never real secrets).
        if path == '/.env':
            fake = "APP_ENV=prod\nDB_HOST=127.0.0.1\nDB_USER=app\nDB_PASS=changeme\n"
        elif path == '/config.php':
            fake = "<?php\n$DB_USER='app';\n$DB_PASS='changeme';\n?>\n"
        elif path == '/backup.zip':
            fake = "PK\x03\x04\n(fake zip placeholder)\n"
        else:
            fake = "-- MySQL dump\n-- (fake)\nCREATE TABLE users(id int);\n"
        resp = _http_response('200 OK', 'text/plain; charset=utf-8', fake)

    elif method == 'GET' and path == '/admin':
        if authed:
            page = (
                "<html><body><h1>Admin Console</h1>"
                "<p>Welcome.</p>"
                "<ul><li><a href='/admin/logs'>View Logs</a></li><li><a href='/admin/users'>Users</a></li></ul>"
                "</body></html>"
            )
        else:
            page = (
                "<html><body><h1>Admin Console</h1>"
                "<form method='POST' action='/admin/login'>"
                "<input name='username'/> <input name='password' type='password'/>"
                "<button type='submit'>Login</button>"
                "</form></body></html>"
            )
        resp = _http_response('200 OK', 'text/html; charset=utf-8', page)

    elif method == 'POST' and path == '/admin/login':
        # Accept a few common weak credentials to allow engagement.
        lowered = body.lower()
        username = None
        m = re.search(r'(?:^|&)(?:username|user|login)=([^&]+)', lowered)
        if m:
            username = unquote_plus(m.group(1))
        ok = any(p in lowered for p in ['password=admin', 'password=admin123', 'password=toor', 'password=honeypot'])
        if ok:
            session['http']['authed'] = True
            session['http']['username'] = username or 'admin'
            page = "<html><body><h1>Welcome</h1><p>Redirecting...</p></body></html>"
            resp = _http_response('302 Found', 'text/html; charset=utf-8', page, headers={
                'Location': '/admin',
                'Set-Cookie': f"session={session['session_id']}; HttpOnly",
            })
        else:
            page = "<html><body><h1>Login Failed</h1><p>Invalid credentials.</p></body></html>"
            resp = _http_response('401 Unauthorized', 'text/html; charset=utf-8', page)

    elif method == 'POST' and path == '/login':
        # Backward-compatible alias for the login flow
        req['path'] = '/admin/login'
        # Re-enter via the same logic by pretending this was /admin/login
        lowered = body.lower()
        username = None
        m = re.search(r'(?:^|&)(?:username|user|login)=([^&]+)', lowered)
        if m:
            username = unquote_plus(m.group(1))
        ok = any(p in lowered for p in ['password=admin', 'password=admin123', 'password=toor', 'password=honeypot'])
        if ok:
            session['http']['authed'] = True
            session['http']['username'] = username or 'admin'
            page = "<html><body><h1>Welcome</h1><p>Redirecting...</p></body></html>"
            resp = _http_response('302 Found', 'text/html; charset=utf-8', page, headers={
                'Location': '/admin',
                'Set-Cookie': f"session={session['session_id']}; HttpOnly",
            })
        else:
            page = "<html><body><h1>Login Failed</h1><p>Invalid credentials.</p></body></html>"
            resp = _http_response('401 Unauthorized', 'text/html; charset=utf-8', page)

    elif method == 'POST' and path in ['/upload', '/api/v1/upload']:
        # Simulate accepting an upload and returning a token
        token = secrets.token_hex(12)
        resp = _http_response('201 Created', 'application/json', '{"ok":true,"id":"%s"}' % token)

    else:
        # Special-case a traversal attempt for /etc/passwd to keep attacker engaged.
        decoded_target = unquote_plus(req.get('target', ''))
        if signals.get('traversal') and ('etc/passwd' in decoded_target.lower()):
            resp = _http_response('200 OK', 'text/plain; charset=utf-8', session['ssh']['files'].get('/etc/passwd', ''))
        elif signals.get('sqli'):
            resp = _http_response('500 Internal Server Error', 'text/plain; charset=utf-8', "SQLSTATE[42000]: Syntax error or access violation")
        elif signals.get('cmdi'):
            # Tarpit slightly on command injection
            time.sleep(0.6)
            resp = _http_response('500 Internal Server Error', 'text/plain; charset=utf-8', "sh: 1: syntax error: unexpected token")
        else:
            resp = _http_response('404 Not Found', 'text/html; charset=utf-8', "<html><body><h1>404 Not Found</h1></body></html>")

    try:
        client_socket.sendall(resp)
    except Exception as e:
        logging.error(f"HTTP send error to {client_ip}: {e}")

    duration = time.time() - start_time
    request_preview = (req.get('request_line', '') + "\n" + (body[:512] if body else '')).strip()
    log_attack_internal(
        client_ip,
        'HTTP',
        request_preview,
        category,
        duration=duration,
        src_bytes=len(raw),
        dst_bytes=len(resp),
        flag='SF',
        logged_in=bool(session['http'].get('authed')),
        failed_logins=0,
    )
    client_socket.close()


def handle_ssh(client_socket, client_ip):
    start_time = time.time()
    session = _get_session(client_ip)
    ssh_state = session['ssh']
    total_bytes_sent = 0
    total_bytes_received = 0

    def send(b: bytes):
        nonlocal total_bytes_sent
        client_socket.sendall(b)
        total_bytes_sent += len(b)

    def recv_line(max_len: int = 1024) -> str:
        nonlocal total_bytes_received
        client_socket.settimeout(10.0)
        data = client_socket.recv(max_len)
        total_bytes_received += len(data)
        return data.decode('utf-8', errors='replace').strip()

    # Banner exchange (not a real SSH implementation; just enough to look alive to basic probes)
    try:
        send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        _ = client_socket.recv(1024)
        total_bytes_received += 1024
        send(b"Username: ")
        username = recv_line()
        send(b"Password: ")
        password = recv_line()
    except Exception as e:
        logging.error(f"SSH handshake error from {client_ip}: {e}")
        client_socket.close()
        return

    ssh_state['username'] = username
    redacted_pw = '<redacted>'
    logging.info(f"SSH login attempt from {client_ip} username={username} password={redacted_pw}")

    weak_ok = {
        ('root', 'toor'),
        ('admin', 'admin'),
        ('admin', 'admin123'),
        ('honeypot', 'honeypot'),
        ('user', 'honeypot'),
    }

    logged_in = (username, password) in weak_ok
    if not logged_in:
        ssh_state['failed_logins'] += 1
        send(b"Access denied\r\n")
        log_attack_internal(
            client_ip,
            'SSH',
            f"Failed login username={username}",
            'Brute Force',
            duration=time.time() - start_time,
            src_bytes=len(username) + len(password),
            dst_bytes=total_bytes_sent,
            flag='S0',
            logged_in=False,
            failed_logins=1,
        )
        client_socket.close()
        return

    ssh_state['authed'] = True
    ssh_state['failed_logins'] = 0
    # Session banner + prompt
    banner = (
        "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "Last login: Fri Apr  3 00:12:41 2026 from 10.0.0.12\r\n"
    ).encode('utf-8')
    send(banner)
    send(b"$ ")

    def list_dir(path: str) -> str:
        items = ssh_state['dirs'].get(path, [])
        return '  '.join(items) + "\r\n"

    def resolve_path(cwd: str, arg: str) -> str:
        if not arg:
            return cwd
        if arg.startswith('/'):
            return arg
        if arg == '..':
            if cwd == '/':
                return '/'
            return '/'.join(cwd.rstrip('/').split('/')[:-1]) or '/'
        if cwd.endswith('/'):
            return cwd + arg
        return cwd + '/' + arg

    while True:
        try:
            command = recv_line()
        except socket.timeout:
            break
        except Exception:
            break

        if not command:
            send(b"$ ")
            continue

        ssh_state['history'].append(command)
        logging.info(f"SSH command from {client_ip}: {command}")

        cmd = command.strip()
        lower = cmd.lower()
        category = 'Post-Exploitation'
        response = ""

        if lower in ['exit', 'logout', 'quit']:
            response = "logout\r\n"
            send(response.encode('utf-8'))
            break

        elif lower in ['whoami']:
            response = f"{username}\r\n"

        elif lower in ['pwd']:
            response = f"{ssh_state['cwd']}\r\n"

        elif lower.startswith('cd '):
            target = cmd.split(' ', 1)[1].strip()
            new_path = resolve_path(ssh_state['cwd'], target)
            if new_path in ssh_state['dirs']:
                ssh_state['cwd'] = new_path
            else:
                response = f"bash: cd: {target}: No such file or directory\r\n"

        elif lower == 'ls' or lower.startswith('ls '):
            response = list_dir(ssh_state['cwd'])

        elif lower.startswith('uname'):
            response = "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"

        elif lower == 'id':
            response = f"uid=1001({username}) gid=1001({username}) groups=1001({username})\r\n"

        elif lower.startswith('cat '):
            path = cmd.split(' ', 1)[1].strip()
            full = resolve_path(ssh_state['cwd'], path)
            content = ssh_state['files'].get(full)
            if content is None:
                response = f"cat: {path}: No such file or directory\r\n"
            else:
                response = content.replace('\n', '\r\n') + "\r\n"

        elif lower == 'ps' or lower.startswith('ps '):
            response = "  PID TTY      TIME CMD\r\n  812 ?        00:00:00 nginx\r\n  901 ?        00:00:01 sshd\r\n"

        elif lower.startswith('wget ') or lower.startswith('curl '):
            category = 'Malware Download'
            url = cmd.split(' ', 1)[1].strip()
            fname = f"/tmp/{secrets.token_hex(4)}.bin"
            ssh_state['files'][fname] = f"Downloaded from {url}\n"
            ssh_state['dirs'].setdefault('/tmp', []).append(fname.split('/')[-1])
            response = f"Saving to: '{fname}'\r\n100%[===================>]  12.3K  --.-KB/s\r\n\r\n"

        elif lower.startswith('chmod '):
            response = ""

        elif lower.startswith('./') or lower.startswith('sh ') or lower.startswith('bash '):
            category = 'Execution'
            time.sleep(0.4)
            response = "Segmentation fault (core dumped)\r\n"

        elif lower == 'history':
            response = "\r\n".join([f"{i+1}  {c}" for i, c in enumerate(ssh_state['history'][-20:])]) + "\r\n"

        else:
            # Many attackers try common enumeration commands
            if any(k in lower for k in ['netstat', 'ifconfig', 'ip a', 'ss ', 'who', 'last', 'sudo', 'passwd']):
                category = 'Reconnaissance'
            response = f"bash: {cmd.split(' ',1)[0]}: command not found\r\n"

        if response:
            send(response.encode('utf-8', errors='ignore'))
        send(b"$ ")

        log_attack_internal(
            client_ip,
            'SSH',
            cmd,
            category,
            duration=time.time() - start_time,
            src_bytes=len(cmd),
            dst_bytes=len(response.encode('utf-8', errors='ignore')),
            flag='SF',
            logged_in=True,
            failed_logins=0,
        )

    client_socket.close()


def handle_mysql(client_socket, client_ip):
    start_time = time.time()
    session = _get_session(client_ip)
    total_bytes_sent = 0
    total_bytes_received = 0
    failed_logins = 0
    logged_in = False
    
    greeting = b"\x0a5.7.36-0ubuntu0.20.04.1\x00\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    client_socket.sendall(greeting)
    total_bytes_sent += len(greeting)
    login_attempt = client_socket.recv(1024).decode()
    total_bytes_received += len(login_attempt)
    logging.info(f"MySQL login attempt from {client_ip}: {login_attempt}")

    if "password" in login_attempt:
        response = b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00"
        client_socket.sendall(response)
        total_bytes_sent += len(response)
        sql_query = client_socket.recv(1024).decode()
        total_bytes_received += len(sql_query)
        logging.info(f"MySQL query from {client_ip}: {sql_query}")

        if session.get('signals', {}).get('deeppacketlog'):
            logging.info(f"Deep packet log: mysql_query={sql_query}")

        if session.get('signals', {}).get('fakedb'):
            # Fake a successful response to keep the attacker engaged.
            response = b"\x00\x00\x00\x01\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        else:
            if "SELECT * FROM users" in sql_query:
                response = b"\x00\x00\x00\x01\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            else:
                response = b"Access Denied\x00"
                client_socket.sendall(response)
                total_bytes_sent += len(response)

        log_attack_internal(client_ip, 'MySQL', sql_query, 'Exploitation', 
                          duration=time.time()-start_time, src_bytes=len(sql_query), dst_bytes=len(response), 
                          flag='SF', logged_in=True, failed_logins=failed_logins)
    else:
        response = b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00"
        client_socket.sendall(response)
        total_bytes_sent += len(response)
        failed_logins = 1
        log_attack_internal(client_ip, 'MySQL', login_attempt, 'Reconnaissance', 
                          duration=time.time()-start_time, src_bytes=len(login_attempt), 
                          dst_bytes=total_bytes_sent, flag='S0', logged_in=logged_in, failed_logins=failed_logins)
    
    client_socket.close()


def handle_ftp(client_socket, client_ip):
    start_time = time.time()
    total_bytes_sent = 0
    total_bytes_received = 0
    failed_logins = 0
    logged_in = False
    
    welcome_msg = b"220 Welcome to Honeypot FTP Server\r\n"
    client_socket.sendall(welcome_msg)
    total_bytes_sent += len(welcome_msg)
    
    while True:
        command = client_socket.recv(1024).decode().strip()
        total_bytes_received += len(command)
        logging.info(f"FTP command from {client_ip}: {command}")

        if command.upper() == "QUIT":
            goodbye_msg = b"221 Goodbye.\r\n"
            client_socket.sendall(goodbye_msg)
            total_bytes_sent += len(goodbye_msg)
            break
        elif command.upper().startswith("USER"):
            response = b"331 Password required.\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        elif command.upper().startswith("PASS"):
            response = b"230 Login successful.\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
            logged_in = True
        elif command.upper() == "LIST":
            response = b"150 Here comes the directory listing.\r\nfile1.txt\r\nfile2.log\r\n226 Directory send OK.\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        elif command.upper().startswith("RETR"):
            response = b"550 Permission denied.\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        else:
            response = b"502 Command not implemented.\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)

        log_attack_internal(client_ip, 'FTP', command, 'Exploitation', 
                          duration=time.time()-start_time, src_bytes=len(command), dst_bytes=len(response), 
                          flag='SF', logged_in=logged_in, failed_logins=failed_logins)

    client_socket.close()


def handle_telnet(client_socket, client_ip):
    start_time = time.time()
    total_bytes_sent = 0
    total_bytes_received = 0
    failed_logins = 0
    logged_in = False
    
    welcome_msg = b"Welcome to Honeypot Telnet Server\r\n"
    client_socket.sendall(welcome_msg)
    total_bytes_sent += len(welcome_msg)
    
    while True:
        prompt = b"$ "
        client_socket.sendall(prompt)
        total_bytes_sent += len(prompt)
        
        command = client_socket.recv(1024).decode().strip()
        total_bytes_received += len(command)
        logging.info(f"Telnet command from {client_ip}: {command}")
        
        if command.lower() == "exit":
            goodbye_msg = b"Goodbye.\r\n"
            client_socket.sendall(goodbye_msg)
            total_bytes_sent += len(goodbye_msg)
            break
        else:
            response = f"{command}: command not found\r\n".encode()
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        
        log_attack_internal(client_ip, 'Telnet', command, 'Exploitation', 
                          duration=time.time()-start_time, src_bytes=len(command), dst_bytes=len(response), 
                          flag='SF', logged_in=logged_in, failed_logins=failed_logins)
    
    client_socket.close()

def handle_smtp(client_socket, client_ip):
    start_time = time.time()
    total_bytes_sent = 0
    total_bytes_received = 0
    failed_logins = 0
    logged_in = False
    sender = None
    recipient = None
    
    welcome_msg = b"220 honeypot.local ESMTP Honeypot\r\n"
    client_socket.sendall(welcome_msg)
    total_bytes_sent += len(welcome_msg)

    while True:
        command = client_socket.recv(1024).decode().strip()
        total_bytes_received += len(command)
        logging.info(f"SMTP command from {client_ip}: {command}")

        if command.upper().startswith("HELO") or command.upper().startswith("EHLO"):
            response = b"250-honeypot.local Hello\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250 AUTH LOGIN PLAIN\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        
        elif command.upper().startswith("AUTH LOGIN"):
            response = b"334 VXNlcm5hbWU6\r\n"  # Base64 for "Username:"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        
        elif command.upper().startswith("MAIL FROM"):
            sender = command.split(":")[-1].strip()
            response = b"250 OK\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)

        elif command.upper().startswith("RCPT TO"):
            recipient = command.split(":")[-1].strip()
            response = b"250 OK\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
        
        elif command.upper() == "DATA":
            response = b"354 End data with <CR><LF>.<CR><LF>\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
            email_data = client_socket.recv(4096).decode().strip()
            total_bytes_received += len(email_data)
            if email_data.endswith("."):
                logging.info(f"SMTP Email from {client_ip} | Sender: {sender} | Recipient: {recipient} | Data: {email_data}")
                response = b"250 OK\r\n"
                client_socket.sendall(response)
                total_bytes_sent += len(response)
                log_attack_internal(client_ip, 'SMTP', email_data, 'Exploitation', 
                                  duration=time.time()-start_time, src_bytes=len(email_data), dst_bytes=len(response), 
                                  flag='SF', logged_in=logged_in, failed_logins=failed_logins)

        elif command.upper() == "QUIT":
            response = b"221 Bye\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)
            break

        else:
            response = b"502 Command not implemented\r\n"
            client_socket.sendall(response)
            total_bytes_sent += len(response)

        log_attack_internal(client_ip, 'SMTP', command, 'Reconnaissance', 
                          duration=time.time()-start_time, src_bytes=len(command), dst_bytes=len(response), 
                          flag='SF', logged_in=logged_in, failed_logins=failed_logins)

    client_socket.close()


# Honeypot Engine
class HoneypotEngine:
    def __init__(self):
        self.active_services = {}

    def activate_service(self, service_name):
        if (service_name in SERVICES) and (service_name not in self.active_services):
            port = SERVICES[service_name]['port']
            handler = getattr(self, SERVICES[service_name]['handler'])
            thread = threading.Thread(target=self.run_service, args=(port, handler))
            self.active_services[service_name] = thread
            thread.start()
            logging.info(f"{service_name} service activated on port {port}")
        else:
            logging.warning(f"{service_name} service already active or not defined")

    def run_service(self, port, handler):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            logging.info(f"Service running on port {port}")
            while True:
                client_socket, client_address = server_socket.accept()
                client_ip = client_address[0]
                pol = get_policy(client_ip)
                if pol.active():
                    if pol.mode == 'drop':
                        try:
                            client_socket.close()
                        except Exception:
                            pass
                        continue
                    if pol.mode == 'tarpit' and pol.delay_seconds:
                        time.sleep(pol.delay_seconds)
                    if pol.mode == 'deeppacketlog':
                        session = _get_session(client_ip)
                        session['signals']['deeppacketlog'] = True
                        if pol.delay_seconds:
                            time.sleep(pol.delay_seconds)
                        logging.info(f"Deep packet log enabled for {client_ip} on port {port}")
                    if pol.mode == 'fakedb':
                        session = _get_session(client_ip)
                        session['signals']['fakedb'] = True
                        if pol.delay_seconds:
                            time.sleep(pol.delay_seconds)

                handler(client_socket, client_ip)
        except Exception as e:
            logging.error(f"Failed to bind to port {port}: {e}")

    def handle_http(self, client_socket, client_ip):
        handle_http(client_socket, client_ip)

    def handle_ssh(self, client_socket, client_ip):
        handle_ssh(client_socket, client_ip)

    def handle_mysql(self, client_socket, client_ip):
        handle_mysql(client_socket, client_ip)

    def handle_ftp(self, client_socket, client_ip):
        handle_ftp(client_socket, client_ip)

    def handle_telnet(self, client_socket, client_ip):
        handle_telnet(client_socket, client_ip)

    def handle_smtp(self, client_socket, client_ip):
        handle_smtp(client_socket, client_ip)

# Create an instance of the HoneypotEngine
honeypot_engine = HoneypotEngine()


def start_all_services():
    """Start all configured honeypot services."""
    for service_name in SERVICES.keys():
        honeypot_engine.activate_service(service_name)


if __name__ == '__main__':
    start_all_services()