from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import sqlite3
from typing import Any
# Import shared EventBus instance
from shared_bus import bus

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


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack_summary')
def attack_summary():
    return render_template('attack_summary.html')

@app.route('/map')
def map_page():
    return render_template('map.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

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