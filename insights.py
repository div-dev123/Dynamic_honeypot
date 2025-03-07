import sqlite3
import json

conn = sqlite3.connect('honeypot.db')
c = conn.cursor()

# Most targeted services
print("Most Targeted Services:")
c.execute('SELECT service, COUNT(*) as count FROM attacks GROUP BY service ORDER BY count DESC')
for row in c.fetchall():
    print(f"Service: {row[0]}, Count: {row[1]}")

# Common attack types
print("\nCommon Attack Types:")
c.execute('SELECT category, COUNT(*) as count FROM attacks GROUP BY category ORDER BY count DESC')
for row in c.fetchall():
    print(f"Category: {row[0]}, Count: {row[1]}")

# Frequent IPs
print("\nFrequent IPs:")
c.execute('SELECT ip, COUNT(*) as count FROM attacks GROUP BY ip ORDER BY count DESC')
for row in c.fetchall():
    print(f"IP: {row[0]}, Count: {row[1]}")

# Geolocation distribution
print("\nGeolocation Distribution:")
c.execute('SELECT geolocation, COUNT(*) as count FROM attacks GROUP BY geolocation ORDER BY count DESC')
for row in c.fetchall():
    print(f"Geolocation: {row[0]}, Count: {row[1]}")

conn.close()