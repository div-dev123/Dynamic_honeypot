# core/event_bus.py
# Central hub — your honeypot services emit events here

import queue
import threading
import time
from ml.feature_extractor import FeatureExtractor
from ml.ml_pipeline import MLPipeline
from ml.rl_agent import HoneypotRLAgent

class EventBus:
    def __init__(self):
        self.queue      = queue.Queue()
        self.ml         = MLPipeline()
        self.rl         = HoneypotRLAgent()
        self.extractor  = FeatureExtractor()
        self.listeners  = []   # dashboard callbacks
        self.running    = False

    def emit(self, connection_event):
        """Your honeypot services call this for every connection."""
        self.queue.put(connection_event)

    def subscribe(self, callback):
        """Dashboard subscribes to get enriched results."""
        self.listeners.append(callback)

    def _process(self, event):
        try:
            # Extract features
            features = self.extractor.extract(event)

            # ML classification
            ml_result = self.ml.predict(features)

            # RL decision
            rl_result = self.rl.get_action(
                event.get('src_ip', 'unknown'), ml_result)

            # Enrich event
            enriched = {
                **event,
                'ml'        : ml_result,
                'rl'        : rl_result,
                'timestamp' : time.time(),
            }

            # Notify all listeners (dashboard)
            for listener in self.listeners:
                try:
                    listener(enriched)
                except Exception as e:
                    print(f'Listener error: {e}')

            return enriched

        except Exception as e:
            print(f'EventBus processing error: {e}')
            return None

    def start(self):
        self.running = True
        def worker():
            while self.running:
                try:
                    event = self.queue.get(timeout=1)
                    self._process(event)
                except queue.Empty:
                    continue
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        print('✅ EventBus started')

    def stop(self):
        self.running = False