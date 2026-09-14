# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import ipaddress
from datetime import datetime
from functools import lru_cache
from typing import Optional, Tuple, Dict, Any

from backend.config import Config


# Suspicious-username pattern compiled once. Anchored at the start to match the
# original re.match semantics; combined into a single alternation so we only
# evaluate the regex engine once per call.
_SUSPICIOUS_USERNAME_RE = re.compile(
    r'^(user_\d+$|[a-f0-9]{8,}$|test|temp|guest)'
)

# IPv4 quick-shape pattern — used only inside cached helpers, but kept here.
_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


@lru_cache(maxsize=65536)
def _check_ip_reputation_cached(ip_str: str) -> Tuple[str, str, bool]:
    """Inner cached worker — only takes hashable str inputs."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return 'UNKNOWN', 'Invalid IP', False

    if ip.is_private:
        return 'LOW', 'Private', True
    if ip_str in Config.PUBLIC_DNS_IPS:
        return 'LOW', 'Public DNS', False
    for net in Config.VPN_RANGES:
        if ip in net:
            return 'HIGH', 'VPN/Datacenter', False
    return 'LOW', 'Clean', False


def check_ip_reputation(ip_str: Optional[str]) -> Tuple[str, str, bool]:
    """Analyze IP address risk.

    Cached on the normalized string so repeated IPs (extremely common in fraud
    datasets) skip the ipaddress parse + VPN-range scan after the first hit.
    """
    if ip_str is None or ip_str == '':
        return 'UNKNOWN', 'Invalid IP', False
    return _check_ip_reputation_cached(str(ip_str).strip())


@lru_cache(maxsize=8192)
def _device_category_cached(ds: str) -> str:
    if 'iphone' in ds or 'ipad' in ds or 'ipod' in ds:
        return 'ios'
    if 'android' in ds:
        return 'android'
    if 'windows' in ds:
        return 'windows'
    if 'macintosh' in ds or 'mac os' in ds:
        return 'mac'
    if 'linux' in ds:
        return 'linux'
    return 'other'


def get_device_category(device_str: Optional[str]) -> str:
    """Extract device category from user agent string. Cached."""
    if device_str is None:
        return 'unknown'
    return _device_category_cached(str(device_str).lower())


# Use a plain dict cache here because we return a fresh dict each call to
# preserve the original API (callers may mutate it). The inner immutable tuple
# lookup is the actual hot path.
@lru_cache(maxsize=16384)
def _analyze_email_inner(email: str) -> Tuple[bool, str, int, bool]:
    if '@' not in email:
        return (False, '', 0, True)
    local_part, domain = email.split('@', 1)
    is_disposable = domain in Config.DISPOSABLE_DOMAINS
    if domain in Config.REPUTABLE_DOMAINS:
        reputation = 10
    elif is_disposable:
        reputation = 0
    else:
        reputation = 5
    is_suspicious = bool(_SUSPICIOUS_USERNAME_RE.match(local_part))
    return (is_disposable, domain, reputation, is_suspicious)


def analyze_email(email: Optional[str]) -> Dict[str, Any]:
    """Analyze email address for risk indicators. Cached on normalized form."""
    if email is None:
        return {'is_disposable': False, 'domain': '', 'reputation_score': 5, 'is_suspicious_username': False}
    norm = str(email).lower().strip()
    is_disposable, domain, reputation, is_suspicious = _analyze_email_inner(norm)
    return {
        'is_disposable': is_disposable,
        'domain': domain,
        'reputation_score': reputation,
        'is_suspicious_username': is_suspicious,
    }


def normalize_timestamp(ts: Any) -> Optional[datetime]:
    """Convert various timestamp formats to datetime."""
    if ts is None:
        return None
    try:
        if isinstance(ts, datetime):
            return ts
        return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    except Exception:
        return None
