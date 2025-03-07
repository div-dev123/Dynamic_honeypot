from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import sqlite3
import json

app = Flask(__name__)
socketio = SocketIO(app)

DATABASE = 'honeypot.db'

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
    cur = conn.cursor()
    
    # Ensure the attacks table exists
    cur.execute('''CREATE TABLE IF NOT EXISTS attacks (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     geolocation TEXT,
                     timestamp TEXT,
                     service TEXT,
                     payload TEXT,
                     category TEXT
                 )''')
    
    # Fetch attack data
    cur.execute('SELECT * FROM attacks')
    attacks = cur.fetchall()

    attack_data = [dict(row) for row in attacks]
    return jsonify(attack_data)

@socketio.on('connect')
def handle_connect(auth):
    # When a client connects, send the initial data
    conn = get_db()
    cur = conn.cursor()
    
    # Ensure the attacks table exists
    cur.execute('''CREATE TABLE IF NOT EXISTS attacks (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     geolocation TEXT,
                     timestamp TEXT,
                     service TEXT,
                     payload TEXT,
                     category TEXT
                 )''')
    
    cur.execute('SELECT * FROM attacks')
    attacks = cur.fetchall()

    attack_data = [dict(row) for row in attacks]
    socketio.emit('initial_data', attack_data)

def log_attack(ip, geolocation, timestamp, service, payload, category):
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('INSERT INTO attacks (ip, geolocation, timestamp, service, payload, category) VALUES (?, ?, ?, ?, ?, ?)',
                (ip, geolocation, timestamp, service, payload, category))
    conn.commit()

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

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)