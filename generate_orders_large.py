#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SENTINEL | Parrish Lyon | PL-SENTINEL-20260914
# Copyright (c) 2026 Parrish Lyon. All rights reserved.

"""
Realistic E‑commerce Transaction Generator
Version 2.0 – Production‑Grade Synthetic Data

This script generates a CSV file of ~200,000 orders with a realistic
fraud rate of ~1.8%. The patterns are designed to mimic the complexity
of real‑world fintech / Shopify / crypto exchange data.

Usage:
    python generate_realistic_orders.py

Output:
    realistic_orders.csv  (approx 200,000 rows, ~25 MB)

Author: Ledgewell Data Team
"""

import csv
import random
import math
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
TOTAL_ORDERS = 200_000
OUTPUT_FILE = "realistic_orders.csv"

# Time window: last 90 days
END_DATE = datetime.now()
START_DATE = END_DATE - timedelta(days=90)

# ----------------------------------------------------------------------
# Realistic Distributions
# ----------------------------------------------------------------------
# Order value: log‑normal distribution (most orders $20–$200, some large)
# Parameters derived from real e‑commerce data
ORDER_VALUE_MU = 4.0      # mean of log(value)
ORDER_VALUE_SIGMA = 1.2   # std of log(value)

# Countries with realistic weights (based on global e‑commerce)
COUNTRIES = {
    "US": 0.35, "GB": 0.08, "DE": 0.07, "FR": 0.06, "JP": 0.05,
    "AU": 0.04, "CA": 0.04, "BR": 0.03, "IN": 0.03, "NL": 0.02,
    "SE": 0.02, "SG": 0.02, "IT": 0.02, "ES": 0.02, "MX": 0.02,
    "other": 0.13
}

# Device types with market share
DEVICES = {
    "iPhone; CPU iPhone OS 17_2": 0.25,
    "Android 14": 0.30,
    "Windows NT 10.0": 0.25,
    "Macintosh; Intel Mac OS X 10_15_7": 0.10,
    "iPad; CPU OS 17_2": 0.05,
    "Linux x86_64": 0.05
}

# Email domains (reputation weighted)
EMAIL_DOMAINS = {
    "gmail.com": 0.45,
    "yahoo.com": 0.12,
    "outlook.com": 0.10,
    "icloud.com": 0.08,
    "protonmail.com": 0.03,
    "hotmail.com": 0.05,
    "aol.com": 0.02,
    "live.com": 0.03,
    "company.com": 0.07,   # business domains
    "other": 0.05
}

# Disposable domains (low probability but present)
DISPOSABLE_DOMAINS = [
    "temp-mail.org", "10minutemail.com", "mailinator.com", "guerrillamail.com"
]

# IP ranges: residential ISPs vs datacenter
RESIDENTIAL_IP_PREFIXES = [
    ("192.168.", 0.6),   # internal/demo
    ("10.0.", 0.1),
    ("172.16.", 0.1),
    ("203.0.113.", 0.05),  # TEST-NET-3
]
DATACENTER_IP_RANGES = [
    "104.16.", "172.64.", "185.222.", "198.54.", "45.138.", "76.76."
]
VPN_PROB = 0.005      # 0.5% of orders use VPN/datacenter IP

# Fraud base rate
FRAUD_RATE = 0.018    # 1.8% overall fraud

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def weighted_choice(choices_dict):
    """Select a key from a dict based on weights."""
    items = list(choices_dict.items())
    keys = [k for k, w in items]
    weights = [w for k, w in items]
    return random.choices(keys, weights=weights)[0]

def generate_order_value():
    """Log‑normal distribution for order amounts."""
    return round(math.exp(random.gauss(ORDER_VALUE_MU, ORDER_VALUE_SIGMA)), 2)

def generate_timestamp():
    """Random timestamp within the 90‑day window, with more activity during business hours."""
    # Base random time
    total_seconds = (END_DATE - START_DATE).total_seconds()
    random_seconds = random.randint(0, int(total_seconds))
    ts = START_DATE + timedelta(seconds=random_seconds)

    # Adjust for day/night pattern: more orders during daytime (8am–10pm)
    hour = ts.hour
    if 2 <= hour <= 7:  # early morning: reduce probability
        if random.random() > 0.3:
            ts += timedelta(hours=random.randint(1, 6))
    return ts.strftime("%Y-%m-%d %H:%M:%S")

def generate_device():
    """Return a device string based on market share."""
    return weighted_choice(DEVICES)

def generate_email(user_id, is_fraud=False):
    """Generate email with occasional disposable domain for fraud."""
    domain = weighted_choice(EMAIL_DOMAINS)
    if is_fraud and random.random() < 0.2:
        domain = random.choice(DISPOSABLE_DOMAINS)
    if domain == "other":
        domain = f"example{random.randint(1,100)}.com"
    # Username patterns
    if random.random() < 0.3:
        username = f"{user_id}"
    elif random.random() < 0.5:
        username = f"{user_id}{random.randint(10,99)}"
    else:
        username = f"user_{user_id.split('_')[1] if '_' in user_id else user_id}"
    return f"{username}@{domain}"

def generate_ip(is_fraud=False, country=None):
    """Generate an IP address. Fraud sometimes uses datacenter/VPN."""
    if is_fraud and random.random() < 0.4:
        # Datacenter/VPN IP
        prefix = random.choice(DATACENTER_IP_RANGES)
        return f"{prefix}{random.randint(1,254)}.{random.randint(1,254)}"
    else:
        # Residential or internal
        if random.random() < 0.7:
            return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        else:
            # Fake public residential
            return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def generate_card_fingerprint():
    """Create a realistic card fingerprint (hashed PAN)."""
    # Simulate BIN ranges (first 6 digits) common for credit/debit
    bins = ["4", "5", "3", "6"]  # Visa, MC, Amex, Discover
    bin_num = random.choice(bins) + ''.join([str(random.randint(0,9)) for _ in range(5)])
    pan = bin_num + ''.join([str(random.randint(0,9)) for _ in range(10)])
    return hashlib.sha256(pan.encode()).hexdigest()[:12]

def generate_item_id():
    """SKU format with realistic categories."""
    categories = ["ELEC", "CLTH", "HOME", "SPRT", "BOOK", "TOYS"]
    cat = random.choice(categories)
    num = random.randint(1000, 9999)
    return f"{cat}-{num}"

# ----------------------------------------------------------------------
# User Profile Generation (for consistent behavior)
# ----------------------------------------------------------------------
class UserProfile:
    def __init__(self, user_id):
        self.user_id = user_id
        self.country = weighted_choice(COUNTRIES)
        # Preferred device (users tend to use same device)
        self.primary_device = generate_device()
        # Typical order value range
        self.avg_order_value = generate_order_value()
        self.value_std = self.avg_order_value * 0.3
        # Email domain (consistent per user)
        self.email_domain = weighted_choice(EMAIL_DOMAINS)
        if self.email_domain == "other":
            self.email_domain = f"company{random.randint(1,50)}.com"
        # IP geolocation consistency (for legitimate users)
        self.home_ip_prefix = f"192.168.{random.randint(1,254)}."
        # Fraud flag (some users are fraudsters)
        self.is_fraudster = random.random() < 0.01  # 1% of users are fraudsters

    def generate_order(self, order_id, is_fraud=False):
        """Create an order for this user."""
        # Timestamp
        ts = generate_timestamp()

        # Order value (correlated with user's typical spending)
        if is_fraud:
            # Fraudulent orders tend to be higher value
            value = max(50, self.avg_order_value * random.uniform(1.5, 5.0))
        else:
            value = max(1.0, random.gauss(self.avg_order_value, self.value_std))
        value = round(value, 2)

        # Device (usually primary, sometimes different)
        if random.random() < 0.85:
            device = self.primary_device
        else:
            device = generate_device()

        # IP address
        if is_fraud and random.random() < 0.5:
            # Fraud may use datacenter IP
            ip = generate_ip(is_fraud=True)
        else:
            # Legitimate: consistent IP prefix
            if random.random() < 0.8:
                ip = self.home_ip_prefix + str(random.randint(1,254))
            else:
                ip = generate_ip()

        # Email
        email = f"{self.user_id.split('_')[1] if '_' in self.user_id else self.user_id}@{self.email_domain}"
        if is_fraud and random.random() < 0.15:
            email = generate_email(self.user_id, is_fraud=True)

        # Card fingerprint (users may have multiple cards)
        card = generate_card_fingerprint()

        # Item
        item = generate_item_id()

        # Country (consistent with profile)
        country = self.country

        return {
            "order_id": f"ORD-{order_id:06d}",
            "timestamp": ts,
            "user_id": self.user_id,
            "order_value": value,
            "ip_address": ip,
            "card_fingerprint": card,
            "item_id": item,
            "country": country,
            "device_info": device,
            "email": email,
            "is_fraud": is_fraud
        }

# ----------------------------------------------------------------------
# Fraud Pattern Injector
# ----------------------------------------------------------------------
class FraudInjector:
    """Adds sophisticated fraud patterns to the dataset."""

    def __init__(self, user_profiles):
        self.user_profiles = user_profiles
        self.fraud_orders = []

    def inject_card_testing(self, count=100):
        """Rapid low‑value attempts on same card."""
        for _ in range(count):
            card = generate_card_fingerprint()
            base_ts = datetime.strptime(generate_timestamp(), "%Y-%m-%d %H:%M:%S")
            for i in range(random.randint(5, 12)):
                ts = base_ts + timedelta(minutes=random.randint(1, 5))
                user = random.choice(list(self.user_profiles.keys()))
                order = self.user_profiles[user].generate_order(
                    order_id=0,  # will be reassigned
                    is_fraud=True
                )
                order["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
                order["order_value"] = round(random.uniform(1.0, 15.0), 2)
                order["card_fingerprint"] = card
                order["ip_address"] = generate_ip(is_fraud=True)
                self.fraud_orders.append(order)

    def inject_account_takeover(self, count=80):
        """Legit user credentials stolen, different IP/device."""
        for _ in range(count):
            user_id = random.choice([uid for uid, prof in self.user_profiles.items() if not prof.is_fraudster])
            prof = self.user_profiles[user_id]
            # Two transactions close in time with different IP/device
            ts1 = datetime.strptime(generate_timestamp(), "%Y-%m-%d %H:%M:%S")
            ts2 = ts1 + timedelta(minutes=random.randint(5, 30))

            order1 = prof.generate_order(0, is_fraud=False)
            order1["timestamp"] = ts1.strftime("%Y-%m-%d %H:%M:%S")

            order2 = prof.generate_order(0, is_fraud=True)
            order2["timestamp"] = ts2.strftime("%Y-%m-%d %H:%M:%S")
            order2["ip_address"] = generate_ip(is_fraud=True)
            order2["device_info"] = generate_device()
            order2["order_value"] = round(prof.avg_order_value * random.uniform(2, 4), 2)

            self.fraud_orders.extend([order1, order2])

    def inject_triangulation_fraud(self, count=50):
        """Fraudster uses stolen card, ships to different address (not in CSV but simulated)."""
        for _ in range(count):
            user = random.choice([uid for uid, prof in self.user_profiles.items() if prof.is_fraudster])
            prof = self.user_profiles[user]
            order = prof.generate_order(0, is_fraud=True)
            # High value, often electronics
            order["order_value"] = round(random.uniform(800, 3000), 2)
            order["item_id"] = f"ELEC-{random.randint(5000,9999)}"
            order["ip_address"] = generate_ip(is_fraud=True)
            order["country"] = random.choice(["US", "GB", "DE"])  # common reship destinations
            self.fraud_orders.append(order)

    def inject_friendly_fraud(self, count=120):
        """Customer disputes legitimate charge after receiving goods."""
        for _ in range(count):
            user = random.choice([uid for uid, prof in self.user_profiles.items() if not prof.is_fraudster])
            prof = self.user_profiles[user]
            order = prof.generate_order(0, is_fraud=False)
            # These are legitimate transactions but later disputed
            # We mark them as fraud for detection challenge
            order["is_fraud"] = True
            # Indicators: high value, digital goods (hard to prove delivery)
            order["item_id"] = f"GIFT-{random.randint(1000,9999)}"
            order["order_value"] = round(random.uniform(200, 800), 2)
            self.fraud_orders.append(order)

    def get_fraud_orders(self):
        return self.fraud_orders

# ----------------------------------------------------------------------
# Main Generator
# ----------------------------------------------------------------------
def generate_dataset():
    print("Creating user profiles...")
    # Generate 2000 users (each makes ~100 orders on average)
    num_users = 2000
    user_ids = [f"user_{i:04d}" for i in range(1, num_users+1)]
    user_profiles = {uid: UserProfile(uid) for uid in user_ids}

    orders = []
    fraud_injector = FraudInjector(user_profiles)

    # Generate legitimate orders (98.2% of total)
    legit_count = int(TOTAL_ORDERS * (1 - FRAUD_RATE))
    print(f"Generating {legit_count} legitimate orders...")
    for i in range(legit_count):
        user_id = random.choice(user_ids)
        order = user_profiles[user_id].generate_order(i, is_fraud=False)
        orders.append(order)

    # Inject fraud patterns (1.8%)
    fraud_count = TOTAL_ORDERS - legit_count
    print(f"Injecting {fraud_count} fraudulent orders with realistic patterns...")

    # Distribute fraud across patterns
    fraud_injector.inject_card_testing(int(fraud_count * 0.25))
    fraud_injector.inject_account_takeover(int(fraud_count * 0.30))
    fraud_injector.inject_triangulation_fraud(int(fraud_count * 0.20))
    fraud_injector.inject_friendly_fraud(int(fraud_count * 0.25))

    fraud_orders = fraud_injector.get_fraud_orders()
    # If we have more fraud orders than needed, sample
    if len(fraud_orders) > fraud_count:
        fraud_orders = random.sample(fraud_orders, fraud_count)
    else:
        # Fill remaining with random fraud from fraudster users
        while len(fraud_orders) < fraud_count:
            uid = random.choice([u for u, p in user_profiles.items() if p.is_fraudster])
            order = user_profiles[uid].generate_order(len(orders)+len(fraud_orders), is_fraud=True)
            fraud_orders.append(order)

    orders.extend(fraud_orders)

    # Shuffle to intermix fraud and legit
    random.shuffle(orders)

    # Reassign order IDs
    for idx, order in enumerate(orders):
        order["order_id"] = f"ORD-{idx+1:06d}"
        # Remove internal fraud flag (not in output)
        del order["is_fraud"]

    print(f"Generated {len(orders)} orders.")
    print(f"Fraud injection target: {FRAUD_RATE*100:.1f}%")

    return orders

# ----------------------------------------------------------------------
# Write CSV
# ----------------------------------------------------------------------
def main():
    orders = generate_dataset()

    print(f"Writing to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "order_id", "timestamp", "user_id", "order_value", "ip_address",
            "card_fingerprint", "item_id", "country", "device_info", "email"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(orders)

    print("Done.")

if __name__ == "__main__":
    main()
