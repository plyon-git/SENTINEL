# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

import polars as pl

from backend.config import Config


logger = logging.getLogger('ledgewell-sentinel')


class SchemaMapper:
    """
    Intelligently maps arbitrary CSV columns to the internal schema.
    """

    TEMPLATES = {
        'shopify_orders': {
            'timestamp': ['Created at', 'created_at', 'Order Date', 'order_date'],
            'user_id': ['Email', 'Customer Email', 'customer_email', 'Billing Email'],
            'order_value': ['Total', 'total', 'Order Total', 'order_total', 'Total Price'],
            'ip_address': ['Browser Ip', 'browser_ip', 'IP Address', 'ip_address'],
            'payment_method': ['Payment Method', 'payment_method', 'Gateway'],
            'email': ['Email', 'Customer Email', 'customer_email', 'Billing Email'],
            'device_info': ['Browser User Agent', 'user_agent'],
            'country': ['Billing Country', 'billing_country', 'Shipping Country'],
            'order_id': ['Name', 'Order Name', 'order_name', 'Order ID', 'order_id']
        },
        'stripe_payments': {
            'timestamp': ['created', 'Created (UTC)', 'created_utc'],
            'user_id': ['customer_email', 'Customer Email', 'email'],
            'order_value': ['amount', 'Amount', 'amount_total'],
            'ip_address': ['ip_address', 'client_ip', 'IP Address'],
            'payment_method': ['payment_method', 'card_fingerprint', 'source_id'],
            'email': ['customer_email', 'receipt_email', 'Email'],
            'device_info': ['user_agent', 'client_user_agent'],
            'country': ['customer_country', 'Country'],
            'order_id': ['id', 'payment_intent_id', 'charge_id']
        },
        'generic_ecommerce': {
            'timestamp': ['timestamp', 'date', 'created', 'order_date', 'time', 'datetime'],
            'user_id': ['user_id', 'customer_id', 'email', 'username', 'account'],
            'order_value': ['amount', 'total', 'value', 'price', 'order_value', 'subtotal'],
            'ip_address': ['ip', 'ip_address', 'client_ip', 'remote_addr'],
            'payment_method': ['card', 'fingerprint', 'payment_token', 'payment_method', 'pan'],
            'email': ['email', 'customer_email', 'user_email', 'contact'],
            'device_info': ['device', 'user_agent', 'browser', 'os'],
            'country': ['country', 'nation', 'billing_country', 'location'],
            'order_id': ['order_id', 'id', 'transaction_id', 'reference']
        }
    }

    REQUIRED_FIELDS = ['timestamp', 'user_id', 'order_value', 'ip_address', 'payment_method']
    OPTIONAL_FIELDS = ['email', 'device_info', 'country', 'order_id']

    def __init__(self, df: pl.DataFrame):
        self.original_df = df
        self.mapped_df = None
        self.mapping_report = {}

    def detect_template(self) -> Optional[str]:
        columns = set(col.lower() for col in self.original_df.columns)

        scores = {}
        for template_name, mapping in self.TEMPLATES.items():
            score = 0
            total_possible = 0
            for field, candidates in mapping.items():
                if field in self.REQUIRED_FIELDS or field in self.OPTIONAL_FIELDS:
                    total_possible += 1
                    if any(cand.lower() in columns for cand in candidates):
                        score += 1
            if total_possible > 0:
                scores[template_name] = score / total_possible

        if scores:
            best = max(scores, key=scores.get)
            if scores[best] >= Config.MAPPING_CONFIDENCE_THRESHOLD:
                logger.info(f"Detected template: {best} (confidence: {scores[best]:.2f})")
                return best
        return None

    def fuzzy_match(self, col_name: str, candidates: List[str]) -> float:
        col_lower = col_name.lower().strip()
        best = 0.0
        for cand in candidates:
            cand_lower = cand.lower()
            if col_lower == cand_lower:
                return 1.0
            if cand_lower in col_lower or col_lower in cand_lower:
                best = max(best, 0.8)
            col_tokens = set(re.findall(r'\w+', col_lower))
            cand_tokens = set(re.findall(r'\w+', cand_lower))
            if col_tokens and cand_tokens:
                overlap = len(col_tokens & cand_tokens) / max(len(col_tokens), len(cand_tokens))
                best = max(best, overlap)
        return best

    def auto_map(self) -> Dict[str, str]:
        columns = self.original_df.columns
        mapping = {}

        all_candidates = defaultdict(list)
        for template in self.TEMPLATES.values():
            for field, candidates in template.items():
                all_candidates[field].extend(candidates)

        for field in self.REQUIRED_FIELDS + self.OPTIONAL_FIELDS:
            best_col = None
            best_score = 0.0
            for col in columns:
                score = self.fuzzy_match(col, all_candidates[field])
                if score > best_score:
                    best_score = score
                    best_col = col
            if best_score >= 0.6:
                mapping[field] = best_col
            else:
                if field == 'timestamp':
                    for col in columns:
                        if self.original_df[col].dtype in [pl.Datetime, pl.Date]:
                            mapping[field] = col
                            break
                elif field == 'order_value':
                    for col in columns:
                        if self.original_df[col].dtype in pl.NUMERIC_DTYPES:
                            if any(word in col.lower() for word in ['amount', 'total', 'value', 'price']):
                                mapping[field] = col
                                break
                    if field not in mapping:
                        num_cols = [c for c in columns if self.original_df[c].dtype in pl.NUMERIC_DTYPES]
                        if num_cols:
                            mapping[field] = num_cols[0]
                elif field == 'ip_address':
                    for col in columns:
                        sample = self.original_df[col].drop_nulls().cast(pl.Utf8).head(100).to_list()
                        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
                        matches = sum(1 for s in sample if ip_pattern.match(str(s)))
                        if matches / max(len(sample), 1) > 0.8:
                            mapping[field] = col
                            break
                elif field == 'email':
                    for col in columns:
                        sample = self.original_df[col].drop_nulls().cast(pl.Utf8).head(100).to_list()
                        matches = sum(1 for s in sample if '@' in str(s))
                        if matches / max(len(sample), 1) > 0.8:
                            mapping[field] = col
                            break
                elif field == 'payment_method':
                    for col in columns:
                        if 'card' in col.lower() or 'fingerprint' in col.lower() or 'token' in col.lower():
                            mapping[field] = col
                            break
                    if field not in mapping:
                        str_cols = [c for c in columns if self.original_df[c].dtype == pl.Utf8]
                        for col in str_cols:
                            if self.original_df[col].n_unique() > 10:
                                mapping[field] = col
                                break
                elif field == 'user_id':
                    for col in columns:
                        if any(word in col.lower() for word in ['user', 'customer', 'email', 'account', 'id']):
                            if self.original_df[col].n_unique() > 1:
                                mapping[field] = col
                                break
                    if field not in mapping:
                        for col in columns:
                            if self.original_df[col].n_unique() > 5:
                                mapping[field] = col
                                break
        return mapping

    def apply_mapping(self, mapping: Dict[str, str]) -> pl.DataFrame:
        select_exprs = []
        for internal_field, original_col in mapping.items():
            if original_col in self.original_df.columns:
                select_exprs.append(pl.col(original_col).alias(internal_field))

        df_mapped = self.original_df.select(select_exprs) if select_exprs else pl.DataFrame()

        for req in self.REQUIRED_FIELDS:
            if req not in df_mapped.columns:
                if req == 'ip_address':
                    df_mapped = df_mapped.with_columns(pl.lit('0.0.0.0').alias('ip_address'))
                elif req == 'user_id':
                    df_mapped = df_mapped.with_columns(pl.lit('unknown_user').alias('user_id'))
                elif req == 'payment_method':
                    df_mapped = df_mapped.with_columns(pl.lit('unknown_card').alias('payment_method'))
                elif req == 'timestamp':
                    from datetime import datetime, timezone
                    df_mapped = df_mapped.with_columns(
                        pl.lit(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')).alias('timestamp')
                    )
                elif req == 'order_value':
                    df_mapped = df_mapped.with_columns(pl.lit(0.0).alias('order_value'))
                logger.warning(f"Required field '{req}' missing, using placeholder.")

        if 'payment_method' in df_mapped.columns:
            df_mapped = df_mapped.rename({'payment_method': 'card_fingerprint'})

        df_mapped = df_mapped.with_columns(
            pl.col('order_value').cast(pl.Float64, strict=False).fill_null(0.0)
        )

        return df_mapped

    def map(self) -> Tuple[pl.DataFrame, Dict]:
        template = self.detect_template()
        if template:
            mapping = {}
            for field, candidates in self.TEMPLATES[template].items():
                for col in self.original_df.columns:
                    if col.lower() in [c.lower() for c in candidates]:
                        mapping[field] = col
                        break
        else:
            logger.info("No template matched; using auto-mapping heuristics.")
            mapping = self.auto_map()

        self.mapping_report = {
            'detected_template': template,
            'mapping': mapping,
            'original_columns': list(self.original_df.columns)
        }

        df_mapped = self.apply_mapping(mapping)
        return df_mapped, self.mapping_report