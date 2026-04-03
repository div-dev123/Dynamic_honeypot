# ml/rl_agent.py

import numpy as np
import pickle
from itertools import product

class HoneypotRLAgent:
    def __init__(self, model_path='ml/models/rl_agent.pkl'):
        with open(model_path, 'rb') as f:
            data = pickle.load(f)

        self.q_table        = data['q_table']
        self.states         = data['states']
        self.actions        = data['actions']
        self.attack_types   = data['attack_types']
        self.aggressiveness = data['aggressiveness']
        self.time_buckets   = data['time_buckets']

        # Track active sessions
        self.sessions = {}   # ip → session info

        print('✅ RL Agent loaded')

    def _classify_aggressiveness(self, ml_result, session):
        confidence    = ml_result['confidence']
        request_count = session.get('request_count', 1)
        ae_error      = ml_result.get('ae_error', 0)

        score = 0
        if confidence > 80:
            score += 1
        if request_count > 20:
            score += 1
        if ae_error > 0.5:
            score += 1
        if ml_result.get('zero_day'):
            score += 1

        if score >= 3:
            return 'high'
        elif score >= 1:
            return 'medium'
        return 'low'

    def _get_time_bucket(self, session):
        t = session.get('time_spent', 0)
        if t >= 3:
            return 'deep_in'
        elif t >= 1:
            return 'exploring'
        return 'just_arrived'

    def get_action(self, src_ip, ml_result):
        """
        Given ML prediction result, decide honeypot response.
        Returns action name + full decision info.
        """
        # Init session
        if src_ip not in self.sessions:
            self.sessions[src_ip] = {
                'request_count': 0,
                'time_spent'   : 0,
                'payload_count': 0,
                'des_history'  : [],
            }

        session = self.sessions[src_ip]
        session['request_count'] += 1

        attack_type    = ml_result['attack_type']
        if attack_type not in self.attack_types:
            attack_type = 'ZeroDay'

        aggressiveness = self._classify_aggressiveness(ml_result, session)
        time_bucket    = self._get_time_bucket(session)

        state      = self.states.get(
            (attack_type, aggressiveness, time_bucket), 0)
        action_idx = int(np.argmax(self.q_table[state]))
        action     = self.actions[action_idx]
        q_value    = float(self.q_table[state, action_idx])

        # Update session
        session['time_spent'] += 1

        # Compute DES
        des = self._compute_des(session)
        session['des_history'].append(des)

        return {
            'action'         : action,
            'action_idx'     : action_idx,
            'q_value'        : round(q_value, 3),
            'attack_type'    : attack_type,
            'aggressiveness' : aggressiveness,
            'time_bucket'    : time_bucket,
            'des'            : round(des, 3),
            'session'        : session,
        }

    def _compute_des(self, session):
        time_score    = min(session['time_spent'], 10) / 10
        payload_score = min(session['payload_count'], 5) / 5
        depth         = min(session['time_spent'] / 3, 1.0)
        return (time_score * 0.4) + (payload_score * 0.4) + (depth * 0.2)

    def record_payload(self, src_ip):
        if src_ip in self.sessions:
            self.sessions[src_ip]['payload_count'] += 1

    def end_session(self, src_ip):
        return self.sessions.pop(src_ip, None)