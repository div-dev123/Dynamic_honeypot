#!/usr/bin/env python3
"""
Main entry point for the ML-powered Honeypot System
Starts all services: web dashboard, network sniffer, and honeypot engine
"""

import threading
import sys
import time

def run_dashboard():
    """Run the Flask web dashboard"""
    from app import app, socketio
    print("🚀 Starting Web Dashboard on http://localhost:5001")
    socketio.run(app, debug=False, port=5001, use_reloader=False)

def run_network_sniffer():
    """Run the network sniffer"""
    import network_sniffer
    print("👂 Starting Network Sniffer...")
    network_sniffer.main()

def run_honeypot_engine():
    """Run the honeypot engine with all services"""
    from honeypot_engine import start_all_services
    print("🛡️ Starting Honeypot Engine with all services...")
    start_all_services()
    # Keep the thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

def main():
    print("🛡️ Starting ML-Powered Honeypot System...")
    print("   Press Ctrl+C to stop")
    print()

    # Import the shared bus to initialize it first
    from shared_bus import bus
    
    # Start services in separate threads
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    sniffer_thread = threading.Thread(target=run_network_sniffer, daemon=True)
    engine_thread = threading.Thread(target=run_honeypot_engine, daemon=True)

    # Start all threads
    engine_thread.start()
    time.sleep(2)  # Give engine time to start
    sniffer_thread.start()
    time.sleep(2)  # Give sniffer time to start
    dashboard_thread.start()

    print()
    print("🔗 Services started:")
    print("   Dashboard: http://localhost:5001")
    try:
        from honeypot_engine import SERVICES as HP_SERVICES
        ports = ", ".join([f"{name}:{cfg['port']}" for name, cfg in HP_SERVICES.items()])
        print(f"   Honeypot Services: {ports}")
        print("   (Ports are configurable via HONEYPOT_*_PORT env vars)")
    except Exception:
        print("   Honeypot Services: HTTP:8080, SSH:2222, MySQL:33060, FTP:2121, Telnet:2323, SMTP:2525")
    print("   Network Sniffer: Listening on all interfaces")
    print()
    print("📊 Dashboard Views:")
    print("   Home: http://localhost:5001/")
    print("   Attack Summary: http://localhost:5001/attack_summary")
    print("   Geographic Map: http://localhost:5001/map")
    print("   Analysis: http://localhost:5001/analysis")
    print("   Attack Lab: http://localhost:5001/lab")
    print("   Decoy Web App: http://localhost:5001/webapp")
    print("   Web App Audit: http://localhost:5001/webapp/audit")
    print()

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down honeypot system...")
        sys.exit(0)

if __name__ == "__main__":
    main()