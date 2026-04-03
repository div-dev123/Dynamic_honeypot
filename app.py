from flask import Flask, render_template, jsonify, request, redirect, url_for, abort, make_response
from flask_socketio import SocketIO
import sqlite3
import secrets
from datetime import datetime, timezone
from typing import Any
# Import shared EventBus instance
from shared_bus import bus
from mitigation import apply_rl_action

app = Flask(__name__)
socketio = SocketIO(app)

DATABASE = 'honeypot.db'


def ensure_attacks_table(conn: sqlite3.Connection) -> None:
    # Create table (new DB) with enrichment columns.
    conn.execute('''CREATE TABLE IF NOT EXISTS attacks (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     geolocation TEXT,
                     timestamp TEXT,
                     service TEXT,
                     payload TEXT,
                     category TEXT,

                     -- ML enrichment
                     ml_attack_type TEXT,
                     ml_confidence REAL,
                     ml_is_anomaly INTEGER,
                     ml_zero_day INTEGER,
                     ml_ae_error REAL,
                     ml_iso_score REAL,

                     -- RL enrichment
                     rl_action TEXT,
                     rl_des REAL,
                     rl_q_value REAL,
                     rl_aggressiveness TEXT,
                     rl_time_bucket TEXT
                 )''')

    # Migrate older DBs missing these columns.
    existing_cols = {
        row['name']
        for row in conn.execute("PRAGMA table_info(attacks)").fetchall()
    }
    desired_cols = {
        'ml_attack_type': 'TEXT',
        'ml_confidence': 'REAL',
        'ml_is_anomaly': 'INTEGER',
        'ml_zero_day': 'INTEGER',
        'ml_ae_error': 'REAL',
        'ml_iso_score': 'REAL',
        'rl_action': 'TEXT',
        'rl_des': 'REAL',
        'rl_q_value': 'REAL',
        'rl_aggressiveness': 'TEXT',
        'rl_time_bucket': 'TEXT',
    }
    for col_name, col_type in desired_cols.items():
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE attacks ADD COLUMN {col_name} {col_type}")
    conn.commit()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_webapp_tables(conn: sqlite3.Connection) -> None:
    conn.execute('''CREATE TABLE IF NOT EXISTS honeytokens (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     token_type TEXT,
                     token_value TEXT UNIQUE,
                     created_at TEXT,
                     used_at TEXT,
                     used_ip TEXT,
                     context TEXT
                 )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS webapp_audit (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts TEXT,
                     ip TEXT,
                     action TEXT,
                     detail TEXT
                 )''')
    conn.commit()


def add_audit(conn: sqlite3.Connection, ip: str, action: str, detail: str) -> None:
    ensure_webapp_tables(conn)
    conn.execute(
        'INSERT INTO webapp_audit (ts, ip, action, detail) VALUES (?, ?, ?, ?)',
        (utc_now_iso(), ip, action, detail),
    )
    conn.commit()


def create_honeytoken(conn: sqlite3.Connection, token_type: str, context: str = '') -> str:
    ensure_webapp_tables(conn)
    token_value = secrets.token_urlsafe(18)
    conn.execute(
        'INSERT INTO honeytokens (token_type, token_value, created_at, context) VALUES (?, ?, ?, ?)',
        (token_type, token_value, utc_now_iso(), context),
    )
    conn.commit()
    return token_value


def mark_honeytoken_used(conn: sqlite3.Connection, token_value: str, ip: str) -> None:
    ensure_webapp_tables(conn)
    conn.execute(
        'UPDATE honeytokens SET used_at=?, used_ip=? WHERE token_value=? AND used_at IS NULL',
        (utc_now_iso(), ip, token_value),
    )
    conn.commit()


def emit_bus_for_attack(attack_id: int, ip: str, service: str, payload: str) -> None:
    # Keep this lightweight: FeatureExtractor will map unknown values to defaults.
    try:
        bus.emit({
            'attack_id': int(attack_id),
            'src_ip': ip,
            'dst_port': 0,
            'protocol': 'tcp',
            'service': str(service).lower(),
            'duration': 0.05,
            'src_bytes': len(payload.encode('utf-8', errors='ignore')),
            'dst_bytes': 0,
            'flag': 'SF',
            'logged_in': False,
            'failed_logins': 0,
            'payload': payload.encode('utf-8', errors='ignore'),
            'timestamp': datetime.now(timezone.utc).timestamp(),
        })
    except Exception:
        # Never break the web app on ML enrichment.
        return


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack_summary')
def attack_summary():
    return render_template('attack_summary.html')

@app.route('/map')
def map_page():
    return render_template('map.html')


@app.route('/apply_action', methods=['POST'])
def apply_action():
    """Apply a mitigation policy for an attacker IP.

    Expected JSON:
      {"id": <attack_id>} OR {"ip": "1.2.3.4", "rl_action": "..."}
    """
    payload: Any = request.get_json(silent=True) or {}
    attack_id = payload.get('id')
    ip = payload.get('ip')
    rl_action = payload.get('rl_action')

    if attack_id and not ip:
        conn = get_db()
        ensure_attacks_table(conn)
        row = conn.execute('SELECT ip, rl_action FROM attacks WHERE id=?', (attack_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'ok': False, 'error': 'attack_not_found'}), 404
        ip = row['ip']
        rl_action = rl_action or row['rl_action']

    if not ip:
        return jsonify({'ok': False, 'error': 'ip_required'}), 400

    pol = apply_rl_action(str(ip), str(rl_action or ''))
    socketio.emit('action_applied', {
        'ip': ip,
        'mode': pol.mode,
        'delay_seconds': pol.delay_seconds,
        'expires_at': pol.expires_at,
        'rl_action': rl_action,
        'id': attack_id,
    })
    return jsonify({'ok': True, 'ip': ip, 'mode': pol.mode, 'delay_seconds': pol.delay_seconds, 'expires_at': pol.expires_at})

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')


# ─────────────────────────────────────────────────────────────────────────────
# Decoy Web App + Honeytokens

@app.route('/webapp')
def webapp_home():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        # Create a passive honeytoken (tracking pixel) if none exist.
        row = conn.execute(
            "SELECT token_value FROM honeytokens WHERE token_type='pixel' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            pixel_token = row['token_value']
        else:
            pixel_token = create_honeytoken(conn, 'pixel', context='webapp_home')

        add_audit(conn, ip, 'visit', 'Visited decoy web app home')
        return render_template('webapp_home.html', pixel_token=pixel_token)
    finally:
        conn.close()


@app.route('/webapp/password-reset', methods=['GET', 'POST'])
def webapp_password_reset():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    if request.method == 'GET':
        return render_template('webapp_password_reset.html')

    email = (request.form.get('email') or '').strip()
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        token = create_honeytoken(conn, 'reset_link', context=f'email={email}')
        add_audit(conn, ip, 'password_reset_requested', f'Password reset requested for {email or "(blank)"}')
        reset_url = url_for('webapp_reset_token', token=token, _external=True)
        return render_template('webapp_password_reset_sent.html', email=email, reset_url=reset_url)
    finally:
        conn.close()


@app.route('/webapp/reset/<token>', methods=['GET', 'POST'])
def webapp_reset_token(token: str):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        row = conn.execute('SELECT * FROM honeytokens WHERE token_value=? AND token_type=?', (token, 'reset_link')).fetchone()
        if not row:
            abort(404)

        # Visiting the link is already a "phone home" signal.
        if not row['used_at']:
            mark_honeytoken_used(conn, token, ip)
            add_audit(conn, ip, 'reset_link_opened', 'Password reset link opened')

            attack_id = log_attack(ip, None, utc_now_iso(), 'WEBAPP', f'Reset link opened token={token}', 'Honeytoken Used')
            emit_bus_for_attack(attack_id, ip, 'webapp', f'Reset link opened token={token}')

        if request.method == 'GET':
            return render_template('webapp_reset_token.html', token=token, used_at=row['used_at'])

        # Fake completion step
        new_password = request.form.get('password') or ''
        add_audit(conn, ip, 'password_reset_completed', f'Password reset completed (len={len(new_password)})')
        return render_template('webapp_reset_token.html', token=token, completed=True)
    finally:
        conn.close()


@app.route('/webapp/api-keys', methods=['GET', 'POST'])
def webapp_api_keys():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        if request.method == 'POST':
            token = create_honeytoken(conn, 'api_key', context='generated_via_webapp')
            # Make it look like a real API key format
            api_key = f"nhp_live_{token}"

            add_audit(conn, ip, 'api_key_generated', 'Generated a new API key')
            return render_template('webapp_api_key_created.html', api_key=api_key)

        keys = conn.execute(
            "SELECT token_value, created_at, used_at, used_ip FROM honeytokens WHERE token_type='api_key' ORDER BY id DESC LIMIT 20"
        ).fetchall()
        return render_template('webapp_api_keys.html', keys=[dict(r) for r in keys])
    finally:
        conn.close()


@app.route('/api/v1/profile')
def api_profile():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    api_key = (request.headers.get('X-API-Key') or '').strip()
    auth = (request.headers.get('Authorization') or '').strip()
    if not api_key and auth.lower().startswith('bearer '):
        api_key = auth.split(' ', 1)[1].strip()

    if not api_key:
        conn = get_db()
        try:
            add_audit(conn, ip, 'api_probe', 'API called without key')
        finally:
            conn.close()
        return jsonify({'ok': False, 'error': 'missing_api_key'}), 401

    raw_token = api_key
    if api_key.startswith('nhp_live_'):
        raw_token = api_key.replace('nhp_live_', '', 1)

    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        row = conn.execute(
            "SELECT * FROM honeytokens WHERE token_type='api_key' AND token_value=?",
            (raw_token,),
        ).fetchone()

        if row:
            if not row['used_at']:
                mark_honeytoken_used(conn, raw_token, ip)
            add_audit(conn, ip, 'api_key_used', 'Honeytoken API key used on /api/v1/profile')

            attack_id = log_attack(ip, None, utc_now_iso(), 'WEBAPP_API', f'X-API-Key={api_key}', 'Honeytoken Used')
            emit_bus_for_attack(attack_id, ip, 'http', f'API key used token={raw_token}')

            return jsonify({
                'ok': True,
                'user': {'id': 'u_1024', 'email': 'admin@acme.internal', 'role': 'admin'},
                'note': 'profile served'
            })

        add_audit(conn, ip, 'api_key_invalid', 'Invalid API key used on /api/v1/profile')
        attack_id = log_attack(ip, None, utc_now_iso(), 'WEBAPP_API', f'Invalid key={api_key}', 'API Probe')
        emit_bus_for_attack(attack_id, ip, 'http', f'Invalid API key used')
        return jsonify({'ok': False, 'error': 'invalid_api_key'}), 401
    finally:
        conn.close()


@app.route('/webapp/audit')
def webapp_audit():
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        rows = conn.execute('SELECT * FROM webapp_audit ORDER BY id DESC LIMIT 100').fetchall()
        return render_template('webapp_audit.html', rows=[dict(r) for r in rows])
    finally:
        conn.close()


@app.route('/honey/<token>.png')
def honey_pixel(token: str):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
    conn = get_db()
    try:
        ensure_webapp_tables(conn)
        row = conn.execute(
            "SELECT * FROM honeytokens WHERE token_type='pixel' AND token_value=?",
            (token,),
        ).fetchone()
        if row:
            if not row['used_at']:
                mark_honeytoken_used(conn, token, ip)
            add_audit(conn, ip, 'pixel_fired', 'Honeytoken tracking pixel requested')

            attack_id = log_attack(ip, None, utc_now_iso(), 'WEBAPP', f'Pixel requested token={token}', 'Honeytoken Used')
            emit_bus_for_attack(attack_id, ip, 'http', f'Pixel requested token={token}')
    finally:
        conn.close()

    # 1x1 transparent PNG
    pixel = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
             b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0bIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
             b'\x0d\n\x2d\xb4\x00\x00\x00\x00IEND\xaeB`\x82')
    resp = make_response(pixel)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp

@app.route('/data')
def get_data():
    conn = get_db()
    try:
        ensure_attacks_table(conn)
        attacks = conn.execute('SELECT * FROM attacks').fetchall()
        attack_data = [dict(row) for row in attacks]
        return jsonify(attack_data)
    finally:
        conn.close()

@socketio.on('connect')
def handle_connect(auth):
    # When a client connects, send the initial data
    conn = get_db()
    try:
        ensure_attacks_table(conn)
        attacks = conn.execute('SELECT * FROM attacks').fetchall()
        attack_data = [dict(row) for row in attacks]
        socketio.emit('initial_data', attack_data)
    finally:
        conn.close()

def log_attack(ip, geolocation, timestamp, service, payload, category):
    conn = get_db()
    try:
        ensure_attacks_table(conn)
        cur = conn.execute(
            'INSERT INTO attacks (ip, geolocation, timestamp, service, payload, category) VALUES (?, ?, ?, ?, ?, ?)',
            (ip, geolocation, timestamp, service, payload, category),
        )
        conn.commit()
        attack_id = cur.lastrowid
    finally:
        conn.close()

    # Send real-time update to clients
    attack_data = {
        'id': attack_id,
        'ip': ip,
        'geolocation': geolocation,
        'timestamp': timestamp,
        'service': service,
        'payload': payload,
        'category': category
    }
    socketio.emit('new_attack', attack_data)

    return attack_id

# Subscribe to EventBus for enriched events

def handle_enriched_event(enriched_event):
    # Extract ML and RL results
    ml_result = enriched_event.get('ml', {})
    rl_result = enriched_event.get('rl', {})
    
    # Ensure all values are JSON serializable.
    # Socket.IO uses JSON encoding; numpy/scikit-learn types (e.g. numpy.bool_)
    # are a common source of "not JSON serializable" errors.
    def make_serializable(obj):
        if obj is None:
            return None

        # Native JSON types
        if isinstance(obj, (str, int, float, bool)):
            return obj

        # bytes-like (payloads, packets)
        if isinstance(obj, (bytes, bytearray, memoryview)):
            try:
                return bytes(obj).decode('utf-8', errors='replace')
            except Exception:
                return str(obj)

        # numpy scalars / arrays
        try:
            import numpy as np

            if isinstance(obj, np.generic):
                # Includes numpy.bool_, numpy.float32, etc.
                return obj.item()
            if isinstance(obj, np.ndarray):
                return obj.tolist()
        except Exception:
            pass

        if isinstance(obj, dict):
            return {str(k): make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [make_serializable(item) for item in obj]

        # Fallback
        return str(obj)
    
    # Send enriched event to dashboard
    attack_id = enriched_event.get('attack_id')

    # Persist enrichment back into DB if we can correlate.
    if attack_id is not None:
        try:
            conn = get_db()
            try:
                ensure_attacks_table(conn)
                conn.execute(
                    '''UPDATE attacks
                       SET ml_attack_type=?,
                           ml_confidence=?,
                           ml_is_anomaly=?,
                           ml_zero_day=?,
                           ml_ae_error=?,
                           ml_iso_score=?,
                           rl_action=?,
                           rl_des=?,
                           rl_q_value=?,
                           rl_aggressiveness=?,
                           rl_time_bucket=?
                     WHERE id=?''',
                    (
                        ml_result.get('attack_type'),
                        ml_result.get('confidence'),
                        int(bool(ml_result.get('is_anomaly'))) if ml_result.get('is_anomaly') is not None else None,
                        int(bool(ml_result.get('zero_day'))) if ml_result.get('zero_day') is not None else None,
                        ml_result.get('ae_error'),
                        ml_result.get('iso_score'),
                        rl_result.get('action'),
                        rl_result.get('des'),
                        rl_result.get('q_value'),
                        rl_result.get('aggressiveness'),
                        rl_result.get('time_bucket'),
                        int(attack_id),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            # Don't take down the pipeline if persistence fails.
            print(f'Enrichment persistence error: {e}')

    socketio.emit('enriched_attack', {
        'id': int(attack_id) if attack_id is not None else None,
        'ip': str(enriched_event.get('src_ip', 'unknown')),
        'geolocation': str(enriched_event.get('geolocation', '')),
        'timestamp': str(enriched_event.get('timestamp', '')),
        'service': str(enriched_event.get('service', 'unknown')),
        'payload': make_serializable(enriched_event.get('payload', '')),
        'ml_result': make_serializable(ml_result),
        'rl_result': make_serializable(rl_result)
    })

# Subscribe to event bus
bus.subscribe(handle_enriched_event)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)