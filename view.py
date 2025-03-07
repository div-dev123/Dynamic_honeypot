import ipinfo
access_token = '62eb1b14b915c1'
handler = ipinfo.getHandler(access_token)
ip_address = '223.187.115.191'
details = handler.getDetails(ip_address)
print(details.city)
