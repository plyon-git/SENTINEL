# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Central configuration for Ledgewell SENTINEL.

This file is extracted 1:1 from the original single-file app so the
runtime values and defaults remain unchanged.
"""

import os
import ipaddress


class Config:
    """Central configuration with environment variable support."""

    # Chunking configuration for large files
    CHUNK_SIZE = int(os.getenv('CHUNK_SIZE', '50000'))  # Process 50k rows at a time
    MAX_MEMORY_MB = int(os.getenv('MAX_MEMORY_MB', '1024'))

    # VPN / Hosting IP ranges (CIDR blocks)
    VPN_RANGES = [
        ipaddress.ip_network('104.16.0.0/12'),    # Cloudflare
        ipaddress.ip_network('172.64.0.0/13'),    # Cloudflare
        ipaddress.ip_network('185.222.0.0/16'),   # Known VPN provider
        ipaddress.ip_network('198.54.0.0/16'),    # Datacenter range
        ipaddress.ip_network('45.138.0.0/16'),    # VPN
        ipaddress.ip_network('76.76.0.0/16'),     # VPN
        ipaddress.ip_network('146.112.0.0/16'),   # OpenDNS/VPN
        ipaddress.ip_network('151.101.0.0/16'),   # Fastly CDN
        ipaddress.ip_network('162.158.0.0/15'),   # Cloudflare
    ]

    PUBLIC_DNS_IPS = {'1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222', '8.8.4.4'}

    DISPOSABLE_DOMAINS = {
        'temp-mail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        '10minute.net', 'yopmail.com', 'throwawaymail.com', 'dispostable.com',
        'trashmail.com', 'getnada.com', 'tempmail.com', 'maildrop.cc',
        'harakirimail.com', 'sharklasers.com', 'guerrillamail.org', 'guerrillamail.net'
    }

    REPUTABLE_DOMAINS = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'icloud.com', 'protonmail.com',
        'hotmail.com', 'aol.com', 'live.com', 'me.com', 'mac.com',
        'msn.com', 'comcast.net', 'verizon.net', 'att.net'
    }

    # Detection thresholds (tunable)
    VELOCITY_WINDOW_MINUTES = int(os.getenv('VELOCITY_WINDOW_MINUTES', '10'))
    VELOCITY_MIN_ATTEMPTS = int(os.getenv('VELOCITY_MIN_ATTEMPTS', '5'))
    VELOCITY_MAX_AVG_VALUE = float(os.getenv('VELOCITY_MAX_AVG_VALUE', '20.0'))

    ATO_WINDOW_HOURS = int(os.getenv('ATO_WINDOW_HOURS', '1'))

    BIN_ATTACK_IP_MIN = int(os.getenv('BIN_ATTACK_IP_MIN', '10'))
    BIN_ATTACK_CARD_MIN = int(os.getenv('BIN_ATTACK_CARD_MIN', '8'))
    BIN_ATTACK_VELOCITY_MULTIPLIER = float(os.getenv('BIN_ATTACK_VELOCITY_MULTIPLIER', '2.0'))

    DEVICE_MANY_USERS_THRESHOLD = int(os.getenv('DEVICE_MANY_USERS_THRESHOLD', '20'))
    DEVICE_MIN_USERS_FOR_FLAG = int(os.getenv('DEVICE_MIN_USERS_FOR_FLAG', '15'))

    # Risk weights
    RISK_WEIGHTS = {
        'very_large_amount': 2,
        'large_amount': 1,
        'card_testing': 4,
        'ato_attempt': 3,
        'bin_attack': 2,
        'synthetic_email': 1,
        'vpn_ip': 1,
        'device_shared': 1,
        'critical_cluster': 3,
        'high_cluster': 1,
        'velocity_anomaly': 2,
        'geolocation_mismatch': 2,
        'shipping_billing_mismatch': 1,
    }

    GRADE_THRESHOLDS = {
        'CRITICAL RISK': 6,
        'INVESTIGATE': 4,
        'HIGH RISK': 2,
        'LOW RISK': 0
    }

    CLUSTER_TIME_WINDOW_HOURS = int(os.getenv('CLUSTER_TIME_WINDOW_HOURS', '2'))
    IP_CLUSTER_MIN_TXNS = int(os.getenv('IP_CLUSTER_MIN_TXNS', '3'))
    IP_CLUSTER_MIN_USERS = int(os.getenv('IP_CLUSTER_MIN_USERS', '2'))
    CARD_CLUSTER_MIN_TXNS = int(os.getenv('CARD_CLUSTER_MIN_TXNS', '8'))

    # Column mapping confidence threshold
    MAPPING_CONFIDENCE_THRESHOLD = 0.7