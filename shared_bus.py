"""
Shared EventBus instance for the entire honeypot system
"""
from ml.core.event_bus import EventBus

# Create a single shared instance
bus = EventBus()
bus.start()