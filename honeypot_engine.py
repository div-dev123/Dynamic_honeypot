import socket
import threading
import logging
import sqlite3
import json
from datetime import datetime
import ipinfo
from app import log_attack

# Configure logging
logging.basicConfig(filename='honeypot.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
DATABASE = 'honeypot.db'
conn = sqlite3.connect(DATABASE, check_same_thread=False)
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS attacks (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip TEXT,
                 geolocation TEXT,
                 timestamp TEXT,
                 service TEXT,
                 payload TEXT,
                 category TEXT
             )''')
conn.commit()

# IPinfo API token
ipinfo_token = '62eb1b14b915c1'  # Replace with your IPinfo API token
ipinfo_handler = ipinfo.getHandler(ipinfo_token)

# Services to simulate
SERVICES = {
    'HTTP': {'port': 8080, 'handler': 'handle_http'},
    'SSH': {'port': 2222, 'handler': 'handle_ssh'},
    'MySQL': {'port': 33060, 'handler': 'handle_mysql'},
    'FTP': {'port': 21, 'handler': 'handle_ftp'},
    'Telnet': {'port': 23, 'handler': 'handle_telnet'},
    'SMTP': {'port': 25, 'handler': 'handle_smtp'}
}

# Service handlers
def log_attack_internal(ip, service, payload, category):
    try:
        details = ipinfo_handler.getDetails('223.187.115.191')
        geolocation = "13.0878,80.2785"
    except Exception as e:
        geolocation = "13.0878,80.2785"
        logging.error(f"IPinfo lookup error for IP {ip}: {e}")
    timestamp = str(datetime.utcnow())
    log_attack(ip, geolocation, timestamp, service, payload, category)

def handle_http(client_socket, client_ip):
    request = client_socket.recv(1024).decode()
    logging.info(f"HTTP request from {client_ip}: {request}")

    if "GET / " in request:
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the Honeypot HTTP Server</h1>"
    elif "GET /status" in request:
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\": \"ok\"}"
    elif "POST /data" in request:
        response = "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\nData received"
    else:
        response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>"

    client_socket.sendall(response.encode())
    log_attack_internal(client_ip, 'HTTP', request, 'Exploitation' if "POST" in request else 'Reconnaissance')
    client_socket.close()

def handle_ssh(client_socket, client_ip):
    client_socket.sendall(b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n")
    client_socket.recv(1024)  # Receive client's SSH protocol version
    client_socket.sendall(b"Password: ")
    password = client_socket.recv(1024).decode().strip()
    logging.info(f"SSH login attempt from {client_ip} with password: {password}")

    if password == "honeypot":
        client_socket.sendall(b"Welcome to the Honeypot SSH Server\r\n$ ")
        while True:
            command = client_socket.recv(1024).decode().strip()
            logging.info(f"SSH command from {client_ip}: {command}")
            if command.lower() == "exit":
                break
            client_socket.sendall(b"Command not found\r\n$ ")
            log_attack_internal(client_ip, 'SSH', command, 'Exploitation')
    else:
        client_socket.sendall(b"Access denied\r\n")
        log_attack_internal(client_ip, 'SSH', password, 'Reconnaissance')
    
    client_socket.close()

def handle_mysql(client_socket, client_ip):
    greeting = b"\x0a5.7.29-0ubuntu0.18.04.1\x00\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    client_socket.sendall(greeting)
    login_attempt = client_socket.recv(1024).decode()
    logging.info(f"MySQL login attempt from {client_ip}: {login_attempt}")

    if "password" in login_attempt:
        client_socket.sendall(b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00")
        sql_query = client_socket.recv(1024).decode()
        logging.info(f"MySQL query from {client_ip}: {sql_query}")
        response = b"\x00\x00\x00\x01\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
        client_socket.sendall(response)
        log_attack_internal(client_ip, 'MySQL', sql_query, 'Exploitation')
    else:
        client_socket.sendall(b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00")
        log_attack_internal(client_ip, 'MySQL', login_attempt, 'Reconnaissance')
    
    client_socket.close()

def handle_ftp(client_socket, client_ip):
    client_socket.sendall(b"220 Welcome to Honeypot FTP Server\r\n")
    while True:
        command = client_socket.recv(1024).decode().strip()
        logging.info(f"FTP command from {client_ip}: {command}")
        if command.upper() == "QUIT":
            client_socket.sendall(b"221 Goodbye.\r\n")
            break
        elif command.upper().startswith("USER"):
            client_socket.sendall(b"331 Please specify the password.\r\n")
        elif command.upper().startswith("PASS"):
            client_socket.sendall(b"230 Login successful.\r\n")
        else:
            client_socket.sendall(b"502 Command not implemented.\r\n")
        log_attack_internal(client_ip, 'FTP', command, 'Exploitation')
    client_socket.close()

def handle_telnet(client_socket, client_ip):
    client_socket.sendall(b"Welcome to Honeypot Telnet Server\r\n")
    while True:
        client_socket.sendall(b"$ ")
        command = client_socket.recv(1024).decode().strip()
        logging.info(f"Telnet command from {client_ip}: {command}")
        if command.lower() == "exit":
            client_socket.sendall(b"Goodbye.\r\n")
            break
        else:
            client_socket.sendall(f"{command}: command not found\r\n".encode())
        log_attack_internal(client_ip, 'Telnet', command, 'Exploitation')
    client_socket.close()

def handle_smtp(client_socket, client_ip):
    client_socket.sendall(b"220 honeypot.local ESMTP Honeypot\r\n")
    while True:
        command = client_socket.recv(1024).decode().strip()
        logging.info(f"SMTP command from {client_ip}: {command}")
        if command.upper() == "QUIT":
            client_socket.sendall(b"221 Bye\r\n")
            break
        else:
            client_socket.sendall(b"250 OK\r\n")
        log_attack_internal(client_ip, 'SMTP', command, 'Exploitation')
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

# Activate desired services
honeypot_engine.activate_service('HTTP')
honeypot_engine.activate_service('SSH')
honeypot_engine.activate_service('MySQL')
honeypot_engine.activate_service('FTP')
honeypot_engine.activate_service('Telnet')
honeypot_engine.activate_service('SMTP')