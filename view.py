import ipinfo
import os

access_token = os.getenv('IPINFO_TOKEN')
if not access_token:
	raise SystemExit('Missing IPINFO_TOKEN environment variable')

handler = ipinfo.getHandler(access_token)
ip_address = '223.187.115.191'
details = handler.getDetails(ip_address)
print(details.city)
