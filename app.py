from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import sqlite3
# Import shared EventBus instance
from shared_bus import bus

app = Flask(__name__)
socketio = SocketIO(app)

DATABASE = 'honeypot.db'


def ensure_attacks_table(conn: sqlite3.Connection) -> None:
    conn.execute('''CREATE TABLE IF NOT EXISTS attacks (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     geolocation TEXT,
                     timestamp TEXT,
                     service TEXT,
                     payload TEXT,
                     category TEXT
                 )''')
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
        conn.execute(
            'INSERT INTO attacks (ip, geolocation, timestamp, service, payload, category) VALUES (?, ?, ?, ?, ?, ?)',
            (ip, geolocation, timestamp, service, payload, category),
        )
        conn.commit()
    finally:
        conn.close()

    # Send real-time update to clients
    attack_data = {
        'ip': ip,
        'geolocation': geolocation,
        'timestamp': timestamp,
        'service': service,
        'payload': payload,
        'category': category
    }
    socketio.emit('new_attack', attack_data)

# Subscribe to EventBus for enriched events

def handle_enriched_event(enriched_event):
    # Extract ML and RL results
    ml_result = enriched_event.get('ml', {})
    rl_result = enriched_event.get('rl', {})
    
    # Ensure all values are JSON serializable
    def make_serializable(obj):
        if isinstance(obj, bool):
            return bool(obj)
        elif isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(item) for item in obj]
        elif obj is None:
            return None
        else:
            return obj
    
    # Send enriched event to dashboard
    socketio.emit('enriched_attack', {
        'ip': str(enriched_event.get('src_ip', 'unknown')),
        'timestamp': str(enriched_event.get('timestamp', '')),
        'service': str(enriched_event.get('service', 'unknown')),
        'payload': str(enriched_event.get('payload', '')),
        'ml_result': make_serializable(ml_result),
        'rl_result': make_serializable(rl_result)
    })

# Subscribe to event bus
bus.subscribe(handle_enriched_event)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)