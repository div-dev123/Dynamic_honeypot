import socket
import threading
import logging
import os
from datetime import datetime
import ipinfo
import time
from app import log_attack

# Import shared EventBus instance
from shared_bus import bus

# Configure logging
logging.basicConfig(filename='honeypot.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# IPinfo API token (prefer environment variable to avoid committing secrets)
ipinfo_token = os.getenv('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None

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
def log_attack_internal(ip, service, payload, category, duration=0.0, src_bytes=0, dst_bytes=0, flag='SF', logged_in=False, failed_logins=0):
    try:
        if not ipinfo_handler:
            raise RuntimeError('IPINFO_TOKEN not configured')
        details = ipinfo_handler.getDetails(ip)
        geolocation = f"{details.lat},{details.lon}"
    except Exception as e:
        geolocation = "13.0878,80.2785"  # Default fallback
        logging.error(f"IPinfo lookup error for IP {ip}: {e}")
    timestamp = str(datetime.utcnow())
    
    # Emit event to ML pipeline
    connection_event = {
        'src_ip': ip,
        'dst_port': SERVICES.get(service, {}).get('port', 0),
        'protocol': 'tcp',  # Default, can be updated based on service
        'service': service.lower(),
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
    
    # Also log to database for dashboard
    log_attack(ip, geolocation, timestamp, service, str(payload), category)

def handle_http(client_socket, client_ip):
    start_time = time.time()
    request = client_socket.recv(1024).decode()
    request_len = len(request)
    logging.info(f"HTTP request from {client_ip}: {request}")

    if "GET / " in request:
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the Honeypot HTTP Server</h1>"
    elif "GET /status" in request:
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\": \"ok\"}"
    elif "POST /data" in request:
        response = "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\nData received"
    elif "POST /login" in request:
        response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>Login Failed</h1>"
    elif "GET /admin" in request:
        response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>Access Denied</h1>"
    else:
        response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>"

    response_len = len(response)
    client_socket.sendall(response.encode())
    duration = time.time() - start_time
    
    log_attack_internal(client_ip, 'HTTP', request, 'Reconnaissance' if "GET" in request else 'Exploitation', 
                        duration=duration, src_bytes=request_len, dst_bytes=response_len, flag='SF', 
                        logged_in=False, failed_logins=0)
    client_socket.close()


def handle_ssh(client_socket, client_ip):
    start_time = time.time()
    total_bytes_sent = 0
    total_bytes_received = 0
    failed_logins = 0
    logged_in = False
    
    client_socket.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
    total_bytes_sent += 49
    client_socket.recv(1024)  
    total_bytes_received += 1024
    client_socket.sendall(b"Username: ")
    total_bytes_sent += 10
    username = client_socket.recv(1024).decode().strip()
    total_bytes_received += len(username)
    client_socket.sendall(b"Password: ")
    total_bytes_sent += 11
    password = client_socket.recv(1024).decode().strip()
    total_bytes_received += len(password)

    logging.info(f"SSH login attempt from {client_ip} with username: {username} and password: {password}")

    if password == "honeypot":
        logged_in = True
        client_socket.sendall(b"Welcome to the Honeypot SSH Server\r\n$ ")
        total_bytes_sent += 42
        while True:
            command = client_socket.recv(1024).decode().strip()
            total_bytes_received += len(command)
            logging.info(f"SSH command from {client_ip}: {command}")

            if command.lower() == "exit":
                break
            elif command.lower() == "ls":
                response = b"important_data.txt  secrets  logs\r\n$ "
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            elif command.lower() == "whoami":
                response = f"{username}\r\n$ ".encode()
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            elif command.lower() == "pwd":
                response = b"/home/user\r\n$ "
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            elif command.startswith("cat "):
                response = b"Access Denied\r\n$ "
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            else:
                response = b"Command not found\r\n$ "
                client_socket.sendall(response)
                total_bytes_sent += len(response)
            log_attack_internal(client_ip, 'SSH', command, 'Exploitation', 
                              duration=time.time()-start_time, src_bytes=len(command), dst_bytes=len(response), 
                              flag='SF', logged_in=logged_in, failed_logins=failed_logins)
    else:
        failed_logins = 1
        client_socket.sendall(b"Access denied\r\n")
        total_bytes_sent += 14
        log_attack_internal(client_ip, 'SSH', f"Failed login for {username}", 'Reconnaissance', 
                          duration=time.time()-start_time, src_bytes=len(username)+len(password), 
                          dst_bytes=total_bytes_sent, flag='S0', logged_in=logged_in, failed_logins=failed_logins)
    
    client_socket.close()


def handle_mysql(client_socket, client_ip):
    start_time = time.time()
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