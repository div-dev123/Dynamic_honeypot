# ml/rl_agent.py
# Reinforcement Learning Adaptive Deception Agent (Tabular Q-Learning)

import numpy as np
import pickle
import os

class HoneypotRLAgent:
    def __init__(self, model_path='ml/models/rl_agent.pkl'):
        self.model_path = model_path
        with open(model_path, 'rb') as f:
            data = pickle.load(f)

        self.q_table        = data['q_table']
        self.states         = data['states']
        self.actions        = data['actions']
        self.attack_types   = data['attack_types']
        self.aggressiveness = data['aggressiveness']
        self.time_buckets   = data['time_buckets']

        # Ensure actions is a dict mapping index -> name
        if isinstance(self.actions, (list, tuple)):
            self.actions = {i: name for i, name in enumerate(self.actions)}

        self.alpha = 0.15   # Learning rate
        self.gamma = 0.85   # Discount factor
        self.updates_count = 0

        # Track active sessions per IP
        self.sessions = {}   # ip -> session state & history

        print('✅ RL Agent loaded (Tabular Q-Learning with 54 states, 6 actions)')

    def _classify_aggressiveness(self, ml_result, session):
        confidence    = ml_result.get('confidence', 50)
        request_count = session.get('request_count', 1)
        ae_error      = ml_result.get('ae_error', 0)

        score = 0
        if confidence > 80:
            score += 1
        if request_count > 15:
            score += 1
        if ae_error > 0.4:
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
        if t >= 4:
            return 'deep_in'
        elif t >= 1:
            return 'exploring'
        return 'just_arrived'

    def get_action(self, src_ip, ml_result):
        """
        Given ML prediction result and attacker IP, select the optimal deception action
        using the trained Q-table policy, compute DES, and update Q-values across transitions.
        """
        # Initialize or retrieve attacker session
        if src_ip not in self.sessions:
            self.sessions[src_ip] = {
                'request_count': 0,
                'time_spent'   : 0,
                'payload_count': 0,
                'prev_state'   : None,
                'prev_action'  : None,
                'des_history'  : [],
            }

        session = self.sessions[src_ip]
        session['request_count'] += 1

        # Track payload if present
        payload = ml_result.get('payload') or b''
        if payload and len(payload) > 0:
            session['payload_count'] += 1

        # Determine current state tuple: (attack_type, aggressiveness, time_bucket)
        attack_type = ml_result.get('attack_type', 'Normal')
        if attack_type not in self.attack_types:
            attack_type = 'ZeroDay'

        aggressiveness = self._classify_aggressiveness(ml_result, session)
        time_bucket    = self._get_time_bucket(session)

        current_state = self.states.get(
            (attack_type, aggressiveness, time_bucket), 0)

        # ── Q-Table Policy Selection ──────────────────────────────────────────
        # Best action = argmax_a Q(s, a)
        action_idx  = int(np.argmax(self.q_table[current_state]))
        action_name = self.actions.get(action_idx, 'deep_packet_log')
        q_value     = float(self.q_table[current_state, action_idx])

        # ── State Transition & Q-Learning Update ──────────────────────────────
        # If this attacker had a previous interaction, observe reward for (prev_state, prev_action)
        # based on whether the attacker stayed, explored deeper, or revealed more payload.
        last_reward = 0.0
        if session['prev_state'] is not None and session['prev_action'] is not None:
            prev_s = session['prev_state']
            prev_a = session['prev_action']

            # Reward calculation:
            # +0.5 base reward (attacker stayed for another request)
            # +1.5 bonus if attacker submitted a payload
            # +1.0 bonus if reached deeper exploration
            # -1.0 penalty if DoS flooding
            r = 0.5
            if payload and len(payload) > 0:
                r += 1.5
            if time_bucket == 'deep_in':
                r += 1.0
            if attack_type == 'DoS':
                r -= 1.0

            last_reward = r

            # Bellman equation: Q(s, a) <- Q(s, a) + alpha * [r + gamma * max_a' Q(s', a') - Q(s, a)]
            max_next_q = float(np.max(self.q_table[current_state]))
            old_q = float(self.q_table[prev_s, prev_a])
            td_target = r + self.gamma * max_next_q
            self.q_table[prev_s, prev_a] = old_q + self.alpha * (td_target - old_q)

            self.updates_count += 1
            if self.updates_count % 25 == 0:
                self._persist()

        # Update session memory for the next transition
        session['prev_state']  = current_state
        session['prev_action'] = action_idx
        session['time_spent'] += 1

        # Compute Deception Effectiveness Score (DES)
        des = self._compute_des(session)
        session['des_history'].append(des)

        return {
            'action'         : action_name,
            'action_idx'     : action_idx,
            'q_value'        : round(q_value, 3),
            'state'          : int(current_state),
            'attack_type'    : attack_type,
            'aggressiveness' : aggressiveness,
            'time_bucket'    : time_bucket,
            'des'            : round(des, 3),
            'session'        : session,
            'reward'         : round(last_reward, 2),
        }

    def _compute_des(self, session):
        """
        Deception Effectiveness Score (DES):
          DES = (time_spent * 0.4) + (payload_count * 0.4) + (depth * 0.2)
        Normalized to [0.0, 1.0].
        """
        time_score    = min(session.get('time_spent', 1), 10) / 10.0
        payload_score = min(session.get('payload_count', 0), 5) / 5.0
        depth         = min(session.get('time_spent', 1) / 4.0, 1.0)
        des = (time_score * 0.4) + (payload_score * 0.4) + (depth * 0.2)
        return min(max(des, 0.0), 1.0)

    def record_payload(self, src_ip):
        if src_ip in self.sessions:
            self.sessions[src_ip]['payload_count'] += 1

    def end_session(self, src_ip):
        return self.sessions.pop(src_ip, None)

    def _persist(self) -> None:
        try:
            data = {
                'q_table'       : self.q_table,
                'states'        : self.states,
                'actions'       : self.actions,
                'attack_types'  : self.attack_types,
                'aggressiveness': self.aggressiveness,
                'time_buckets'  : self.time_buckets,
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(data, f)
        except Exception:
            pass