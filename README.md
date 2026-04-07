# Dynamic Honeypot System

A sophisticated network deception system designed to detect, analyze, and visualize cyber attacks in real-time. This honeypot system combines active defense mechanisms with passive monitoring to provide deep insights into attacker behavior and techniques.

## 🎯 Features

- **Real-time Attack Detection**: Monitors network traffic for suspicious activities
- **Multi-Service Simulation**: Simulates 6 common services (HTTP, SSH, MySQL, FTP, Telnet, SMTP)
- **Interactive Dashboard**: Web-based interface with live attack visualization
- **Geolocation Tracking**: Maps attack origins using IP geolocation
- **Statistical Analysis**: Trend analysis and attack pattern recognition
- **Comprehensive Logging**: Detailed attack records with timestamps and payloads
- **ML/RL Enrichment**: Events are enriched with ML anomaly/type signals and RL response recommendations (may appear shortly after the base attack is logged)
- **Decoy Web App + Honeytokens**: A realistic multi-step decoy app that issues trackable reset links/API keys/pixels that “phone home” when used

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Network        │    │  Honeypot        │    │  Web Dashboard   │
│  Sniffer        │───▶│  Engine          │───▶│  (Flask)         │
│  (Scapy)        │    │  (Services)      │    │  Real-time UI    │
└─────────────────┘    └──────────────────┘    └──────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
  Traffic Analysis        Attack Simulation        Data Visualization
  Threat Detection        Intelligence Gathering   Live Monitoring
```

## 🛠️ Technology Stack

**Backend**: Python 3.9+
- `scapy` - Network packet analysis
- `flask` - Web framework
- `flask-socketio` - Real-time WebSocket communication
- `ipinfo` - IP geolocation API

**Frontend**: 
- HTML5/CSS3 with Bootstrap 4.5
- JavaScript with Chart.js and Leaflet.js
- Jinja2 templating

**Database**: SQLite

**Containerization**: Docker

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd dynamic_honeypot
```

2. **Install dependencies**
```bash
pip install flask flask-socketio scapy ipinfo
```

Optional (recommended): configure IP geolocation token
```bash
export IPINFO_TOKEN="your_token_here"
```

3. **Start the system**

Recommended (starts honeypot services + sniffer + dashboard together):
```bash
python3 main.py
```

Or run components separately:
```bash
python3 honeypot_engine.py
python3 network_sniffer.py
python3 app.py
```

4. **Access the dashboard**
Open your browser to: `http://localhost:5001`

## 📊 System Components

### 1. Network Sniffer (`network_sniffer.py`)
- Captures and analyzes network packets using Scapy
- Detects port scanning and DoS attacks
- Triggers honeypot service activation
- Logs to console output (no log file)

### 2. Honeypot Engine (`honeypot_engine.py`)
- Simulates vulnerable services:
  - **HTTP** (default port 8080): Web app simulation with realistic endpoints (e.g., `/admin`, `/robots.txt`, `/wp-login.php`, `/phpmyadmin`) and common exploit paths (SQLi/traversal/cmd-injection)
  - **SSH** (default port 2222): Stateful pseudo-shell with a small fake filesystem and common attacker commands (`ls`, `cat`, `wget`, etc.)
  - **MySQL** (default port 33060): Database connection simulation
  - **FTP** (default port 2121): File transfer protocol simulation
  - **Telnet** (default port 2323): Command-line interface simulation
  - **SMTP** (default port 2525): Email server simulation
- Logs interactions to console (no log file)
- Provides geolocation data for each attack

Note: Ports are configurable via environment variables like `HONEYPOT_FTP_PORT`, `HONEYPOT_TELNET_PORT`, `HONEYPOT_SMTP_PORT`.

### 3. Web Dashboard (`app.py`)
- Flask application with real-time WebSocket updates
- Multiple visualization views:
  - Attack Summary Table
  - Geographic Attack Map
  - Statistical Analysis Charts
- RESTful API for data access

Note: ML/RL enrichment is computed asynchronously via the event bus. On first load, some `ml_*` / `rl_*` fields may be `NULL` and then populate within ~1–2 seconds via WebSocket updates.

### 4. Database (`honeypot.db`)
- SQLite database storing attack records
- Schema includes: IP, geolocation, timestamp, service, payload, category
- Also includes ML/RL enrichment columns (e.g., `ml_attack_type`, `ml_confidence`, `ml_is_anomaly`, `rl_action`, `rl_des`)

## 🎮 Usage Examples

### Testing the System

**Connect to HTTP Service:**
```bash
curl http://localhost:8080
curl http://localhost:8080/status
curl -X POST http://localhost:8080/login
```

More realistic probes:
```bash
curl http://localhost:8080/robots.txt
curl http://localhost:8080/wp-login.php
curl http://localhost:8080/phpmyadmin
curl "http://localhost:8080/admin?user=admin'%20OR%201=1--"
curl "http://localhost:8080/index.php?page=../../../../etc/passwd"
```

**Connect to SSH Service:**
```bash
ssh -p 2222 localhost
# Try username: honeypot, password: honeypot
```

If you want a deterministic login for testing, try:
- `admin` / `admin123`
- `root` / `toor`

**Test with Nmap (reconnaissance):**
```bash
nmap -p 21-25,23,8080,2222,33060 localhost
```

### Docker Deployment

**Build and run honeypot container:**
```bash
docker build -f Dockerfile.honeypot -t honeypot .
docker run -p 5001:5001 -p 8080:8080 -p 2222:2222 honeypot
```

**Build attacker testing container:**
```bash
docker build -f Dockerfile.attacker -t attacker .
docker run -it attacker
```

## 🔍 Data Analysis

### View Attack Statistics
```bash
python3 insights.py
```

### Check IP Geolocation
```bash
python3 view.py
```

### Logs
- Console output - Runtime logs (services, sniffer, and detection)
- `honeypot.db` - Structured attack data

## 📈 Dashboard Features

### Attack Summary (`/attack_summary`)
- Real-time table of all detected attacks
- Detailed information including IP, location, timestamp, and payload

### Geographic Map (`/map`)
- Interactive world map showing attack origins
- Clickable markers with attack details
- Powered by Leaflet.js

### Analysis (`/analysis`)
- Live trend charts showing attack frequency over time
- Service-specific attack distribution
- Powered by Chart.js

## 🔧 Configuration

### Adjust Detection Thresholds
In `network_sniffer.py`:
```python
PORT_SCAN_THRESHOLD = 100  # Ports scanned before detection
DOS_THRESHOLD = 1000       # Packets per IP threshold
```

### IPinfo API Configuration
In `honeypot_engine.py`:
```python
ipinfo_token = 'your_api_token_here'
```

## 🧪 Attack Simulation

To quickly generate realistic traffic (recon + exploit patterns + SSH commands):
```bash
python3 tools/simulate_attacks.py --host 127.0.0.1
```

If you changed ports via env vars:
```bash
python3 tools/simulate_attacks.py --host 127.0.0.1 --http-port 8080 --ssh-port 2222
```

To smoke-test the decoy web app honeytoken paths (API key + reset link + pixel):
```bash
python3 tools/smoke_honeytokens.py
```

Prefer no-terminal demos? Use the web UI Attack Lab:
- `http://localhost:5001/lab` (HTTP probe, SSH session, port scan)

## 🎓 Teacher Demo (5–10 minutes)

This is a clean “story” you can narrate live: an attacker touches the honeypot, the dashboard logs it immediately, ML/RL enrichment arrives shortly after, and you can apply a mitigation response.

### 1) Start the system
```bash
python3 main.py
```

Open:
- `http://localhost:5001/` (Home)
- `http://localhost:5001/attack_summary` (Attack Summary)
- `http://localhost:5001/map` (Geographic Map)
- `http://localhost:5001/analysis` (Analysis)
- `http://localhost:5001/webapp` (Decoy Web App)

### 2) Explain what the dashboard is showing
In `/attack_summary`, every row is a single “attack event” stored in SQLite (`honeypot.db`).

Key idea to say out loud:
- The base event is logged immediately.
- ML/RL enrichment is asynchronous: you may see `ml_*` / `rl_*` fields appear 1–2 seconds later via a WebSocket “enriched update”.

### 3) Generate a realistic attack on-demand
Run the built-in simulator (recon + exploit-like HTTP probes + a pseudo-SSH session):
```bash
python3 tools/simulate_attacks.py --host 127.0.0.1
```

Now refresh `/attack_summary` (or just watch it) and point out:
- Multiple services: HTTP + SSH (and whatever else is enabled)
- Payload examples: SQL injection probes, path traversal probes, suspicious commands
- ML variety: events can be classified as `Probe`, `DoS`, `R2L`, `U2R`, etc.
- Zero-day is a separate flag (`ml_zero_day`) rather than the only label

### 4) Show the “response” (mitigation) loop
In `/attack_summary`, use the Actions column to apply a response for an IP (e.g., `drop` or `tarpit`).

Then rerun the simulator again and explain:
- The system is stateful per source IP.
- “Drop” immediately cuts new connections.
- “Tarpit” slows the attacker down (artificial delay).

### 5) Demonstrate honeytokens that “phone home”
Open the decoy web app:
- `http://localhost:5001/webapp`

Do one of these live:
- Password reset flow: submit an email, then click the reset link that appears (this is the honeytoken).
- API key flow: generate a key and use it.

Each of these triggers a `Honeytoken Used` event that is:
- written to `honeypot.db` (so it persists)
- pushed into the same event bus so ML/RL enrichment also applies

You can also show the internal audit trail at:
- `http://localhost:5001/webapp/audit`

## 🧭 Website Flow (end-to-end)

Use this as your “how it works” explanation:

1. A connection or request hits a honeypot surface (HTTP/SSH/etc) or the decoy web app.
2. The handler logs a base event into SQLite (`attacks` table).
3. The app immediately emits a `new_attack` WebSocket event so the UI updates in real time.
4. In parallel, the EventBus extracts features and runs ML inference (classification + anomaly), then runs the RL policy to pick a recommended response.
5. When enrichment finishes, the system updates the same DB row and emits an `enriched_attack` WebSocket event.
6. The dashboard merges the enrichment into the existing row (so you see fields “fill in” without duplicates).
7. If you apply an action from the UI, the honeypot engine consults that policy per IP and enforces it on future connections.

### Service Ports
Modify service ports in `honeypot_engine.py`:
```python
SERVICES = {
    'HTTP': {'port': 8080, 'handler': 'handle_http'},
    'SSH': {'port': 2222, 'handler': 'handle_ssh'},
    # ... other services
}
```

## 🛡️ Security Considerations

- **Network Isolation**: Run in isolated network environment
- **Port Restrictions**: Only expose necessary ports
- **Log Management**: Regular log rotation and backup
- **API Keys**: Secure IPinfo API token storage
- **Access Control**: Restrict dashboard access in production

## 📚 Development

### Project Structure
```
.
├── app.py                 # Web dashboard server
├── network_sniffer.py     # Network traffic monitor
├── honeypot_engine.py     # Attack simulation engine
├── insights.py           # Statistical analysis
├── view.py               # IP geolocation utility
├── templates/            # HTML templates
│   ├── index.html
│   ├── attack_summary.html
│   ├── map.html
│   └── analysis.html
├── static/
│   └── style.css         # Dashboard styling
├── Dockerfile.honeypot   # Honeypot container
├── Dockerfile.attacker   # Attacker testing container
├── honeypot.db           # Attack database
└── README.md
```

### Adding New Services
1. Add service definition in `SERVICES` dictionary
2. Create handler function for the service
3. Register handler in `HoneypotEngine` class
4. Update port mappings as needed

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and research purposes.

## 🆘 Support

For issues and questions:
- Check the existing documentation
- Review log files for error details
- Ensure all dependencies are properly installed
- Verify network permissions for packet capture

---

**Note**: This honeypot system is designed for legitimate security research and educational purposes only. Always ensure you have proper authorization before deploying on any network.
