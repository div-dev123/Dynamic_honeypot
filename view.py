import os
import sys
import ipinfo

access_token = os.getenv('IPINFO_TOKEN')
if not access_token:
    raise SystemExit('Error: Missing IPINFO_TOKEN environment variable. Set it using: export IPINFO_TOKEN="your_token"')

handler = ipinfo.getHandler(access_token)
ip_address = sys.argv[1] if len(sys.argv) > 1 else '8.8.8.8'

try:
    details = handler.getDetails(ip_address)
    print(f"IP: {ip_address}")
    print(f"City: {getattr(details, 'city', 'Unknown')}")
    print(f"Region: {getattr(details, 'region', 'Unknown')}")
    print(f"Country: {getattr(details, 'country_name', getattr(details, 'country', 'Unknown'))}")
    print(f"Location: {getattr(details, 'loc', 'Unknown')}")
    print(f"Org: {getattr(details, 'org', 'Unknown')}")
except Exception as e:
    print(f"Lookup error for IP {ip_address}: {e}")

