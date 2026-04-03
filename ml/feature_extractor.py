# ml/feature_extractor.py
# Converts raw connection data → ML feature vector

import numpy as np
import pickle
import time
from collections import defaultdict

class FeatureExtractor:
    def __init__(self, artifacts_path='ml/models/artifacts.pkl'):
        with open(artifacts_path, 'rb') as f:
            self.artifacts = pickle.load(f)

        self.scaler        = self.artifacts['scaler']
        self.selector      = self.artifacts['selector']
        self.encoders      = self.artifacts['encoders']
        self.feature_names = self.artifacts['feature_names']

        # Connection tracker for behavioral features
        self.connection_history = defaultdict(list)
        self.failed_logins      = defaultdict(int)
        self.request_counts     = defaultdict(int)

    def extract(self, connection_event):
        """
        connection_event: dict from your honeypot services
        {
            'src_ip'       : '192.168.1.100',
            'dst_port'     : 22,
            'protocol'     : 'tcp',
            'service'      : 'ssh',
            'duration'     : 2.3,
            'src_bytes'    : 1024,
            'dst_bytes'    : 512,
            'flag'         : 'SF',
            'logged_in'    : False,
            'failed_logins': 3,
            'payload'      : b'...',
            'timestamp'    : time.time(),
        }
        """
        src_ip = connection_event.get('src_ip', '0.0.0.0')

        # Update behavioral trackers
        self.request_counts[src_ip]  += 1
        self.connection_history[src_ip].append(
            connection_event.get('timestamp', time.time())
        )
        if not connection_event.get('logged_in', False):
            self.failed_logins[src_ip] += \
                connection_event.get('failed_logins', 0)

        # Build feature dict matching NSL-KDD feature space
        payload      = connection_event.get('payload', b'')
        payload_size = len(payload) if payload else 0

        features = {
            'duration'                  : connection_event.get('duration', 0),
            'protocol_type'             : connection_event.get('protocol', 'tcp'),
            'service'                   : connection_event.get('service', 'http'),
            'flag'                      : connection_event.get('flag', 'SF'),
            'src_bytes'                 : connection_event.get('src_bytes', 0),
            'dst_bytes'                 : connection_event.get('dst_bytes', 0),
            'land'                      : 0,
            'wrong_fragment'            : 0,
            'urgent'                    : 0,
            'hot'                       : self._compute_hot(connection_event),
            'num_failed_logins'         : connection_event.get('failed_logins', 0),
            'logged_in'                 : int(connection_event.get('logged_in', False)),
            'num_compromised'           : 0,
            'root_shell'                : 0,
            'su_attempted'              : 0,
            'num_root'                  : 0,
            'num_file_creations'        : 0,
            'num_shells'                : 0,
            'num_access_files'          : 0,
            'num_outbound_cmds'         : 0,
            'is_host_login'             : 0,
            'is_guest_login'            : 0,
            'count'                     : self.request_counts[src_ip],
            'srv_count'                 : self._srv_count(src_ip,
                                          connection_event.get('service')),
            'serror_rate'               : self._serror_rate(src_ip),
            'srv_serror_rate'           : 0.0,
            'rerror_rate'               : self._rerror_rate(src_ip),
            'srv_rerror_rate'           : 0.0,
            'same_srv_rate'             : self._same_srv_rate(src_ip,
                                          connection_event.get('service')),
            'diff_srv_rate'             : 0.0,
            'srv_diff_host_rate'        : 0.0,
            'dst_host_count'            : self.request_counts[src_ip],
            'dst_host_srv_count'        : self._srv_count(src_ip,
                                          connection_event.get('service')),
            'dst_host_same_srv_rate'    : self._same_srv_rate(src_ip,
                                          connection_event.get('service')),
            'dst_host_diff_srv_rate'    : 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate'      : self._serror_rate(src_ip),
            'dst_host_srv_serror_rate'  : 0.0,
            'dst_host_rerror_rate'      : self._rerror_rate(src_ip),
            'dst_host_srv_rerror_rate'  : 0.0,
        }

        # Encode categoricals
        for col in ['protocol_type', 'service', 'flag']:
            le  = self.encoders[col]
            val = str(features[col]).lower()
            if val not in le.classes_:
                val = le.classes_[0]
            features[col] = le.transform([val])[0]

        # Build vector in correct order
        vector = np.array([features.get(f, 0.0)
                          for f in self.feature_names],
                         dtype=np.float32)

        # Scale + select
        vector = self.scaler.transform(vector.reshape(1, -1))
        vector = self.selector.transform(vector)
        return vector

    def _compute_hot(self, event):
        hot = 0
        if event.get('failed_logins', 0) > 3:
            hot += 1
        if event.get('src_bytes', 0) > 10000:
            hot += 1
        if event.get('duration', 0) > 10:
            hot += 1
        return hot

    def _srv_count(self, src_ip, service):
        history = self.connection_history.get(src_ip, [])
        return min(len(history), 511)

    def _serror_rate(self, src_ip):
        logins = self.failed_logins.get(src_ip, 0)
        total  = max(self.request_counts.get(src_ip, 1), 1)
        return min(logins / total, 1.0)

    def _rerror_rate(self, src_ip):
        return 0.0

    def _same_srv_rate(self, src_ip, service):
        return 1.0

    def reset_ip(self, src_ip):
        self.connection_history.pop(src_ip, None)
        self.failed_logins.pop(src_ip, None)
        self.request_counts.pop(src_ip, None)