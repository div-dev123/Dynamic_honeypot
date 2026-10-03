"""Lightweight, in-process mitigation controls.

This module is intentionally simple:
- Stores per-IP policies in memory.
- Meant to be used when the dashboard + honeypot run in the same Python process
  (recommended: `python3 main.py`).

If you run `app.py` and `honeypot_engine.py` as separate processes,
these policies will not be shared.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class MitigationPolicy:
    mode: str  # 'none' | 'drop' | 'tarpit' | 'fakedb' | 'fakedirs' | 'fake_error' | 'deeppacketlog'
    delay_seconds: float = 0.0
    expires_at: Optional[float] = None

    def active(self, now: Optional[float] = None) -> bool:
        if self.mode == 'none':
            return False
        now = time.time() if now is None else now
        if self.expires_at is None:
            return True
        return now < self.expires_at


_LOCK = threading.Lock()
_POLICIES: Dict[str, MitigationPolicy] = {}


def _clean_expired(now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    expired = [ip for ip, pol in _POLICIES.items() if pol.expires_at is not None and now >= pol.expires_at]
    for ip in expired:
        _POLICIES.pop(ip, None)


def set_policy(ip: str, mode: str, *, delay_seconds: float = 0.0, ttl_seconds: Optional[float] = 900) -> MitigationPolicy:
    """Set an in-memory mitigation policy for an IP."""
    if not ip:
        raise ValueError('ip is required')
    valid_modes = {'none', 'drop', 'tarpit', 'fakedb', 'fakedirs', 'fake_error', 'deeppacketlog'}
    if mode not in valid_modes:
        raise ValueError(f'unsupported mode: {mode}')

    expires_at = None
    if ttl_seconds is not None and ttl_seconds > 0:
        expires_at = time.time() + float(ttl_seconds)

    pol = MitigationPolicy(mode=mode, delay_seconds=float(delay_seconds or 0.0), expires_at=expires_at)
    with _LOCK:
        _POLICIES[ip] = pol
        _clean_expired()
    return pol


def clear_policy(ip: str) -> None:
    with _LOCK:
        _POLICIES.pop(ip, None)


def get_policy(ip: str) -> MitigationPolicy:
    with _LOCK:
        _clean_expired()
        return _POLICIES.get(ip, MitigationPolicy(mode='none'))


def apply_rl_action(ip: str, rl_action: str, *, ttl_seconds: Optional[float] = 900) -> MitigationPolicy:
    """Map the 6 RL deception actions directly to honeypot mitigation policies."""
    action = str(rl_action or '').lower().strip()

    # 1. redirect_sandbox -> isolate / drop
    if any(k in action for k in ['redirect_sandbox', 'sandbox', 'block', 'drop', 'deny', 'reset', 'isolate']):
        return set_policy(ip, 'drop', ttl_seconds=ttl_seconds)

    # 2. slow_response -> tarpit delay
    if any(k in action for k in ['slow_response', 'tarpit', 'slow', 'delay', 'throttle']):
        return set_policy(ip, 'tarpit', delay_seconds=1.2, ttl_seconds=ttl_seconds)

    # 3. expose_fake_db -> fakedb lure
    if any(k in action for k in ['expose_fake_db', 'fakedb', 'fake_db']):
        return set_policy(ip, 'fakedb', delay_seconds=0.3, ttl_seconds=ttl_seconds)

    # 4. expose_fake_dirs -> fakedirs lure
    if any(k in action for k in ['expose_fake_dirs', 'fakedirs', 'fake_dirs']):
        return set_policy(ip, 'fakedirs', delay_seconds=0.2, ttl_seconds=ttl_seconds)

    # 5. fake_error -> simulate error / confusion
    if any(k in action for k in ['fake_error', 'error']):
        return set_policy(ip, 'fake_error', delay_seconds=0.2, ttl_seconds=ttl_seconds)

    # 6. deep_packet_log -> comprehensive monitoring with light delay
    if any(k in action for k in ['deep_packet_log', 'deeppacketlog', 'monitor', 'trace']):
        return set_policy(ip, 'deeppacketlog', delay_seconds=0.1, ttl_seconds=ttl_seconds)

    return set_policy(ip, 'none', ttl_seconds=ttl_seconds)

