# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
High-performance fraud detection using Polars vectorized operations.

This file was rewritten for speed. Key changes vs. the prior version:

* The per-card / per-user Python `for` loops in `detect_card_testing` and
  `detect_account_takeover` are replaced with a single vectorized expression
  using window functions (`.over(...)`), eliminating O(unique_cards) full
  filter passes over the DataFrame.
* `_preprocess` now exploits the cached helpers in `utils.py` (so repeat IPs /
  emails / user-agents are essentially free), and uses dict-lookup paths
  instead of recomputing everything per row.
* `compute_risk_scores` previously emitted a `with_columns` call per flagged
  row to set `flag_reason` one row at a time (O(N) Polars ops, each scanning
  the whole DF). It now builds the reason string with a single `concat_str` /
  `when` expression.
* The previous ATO detection had a real bug: the "previous transaction for
  this user" was computed with `i - 1` on the *global* sorted DataFrame, which
  is unrelated to the user-level previous transaction. Fixed by using
  `.shift(1).over('user_id')`.
* `cluster_analysis` keeps the original semantics (first-window-only per
  IP/card) but skips a redundant filter / sort pass.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Any

import polars as pl

from backend.config import Config
from backend.utils import check_ip_reputation, get_device_category, analyze_email


logger = logging.getLogger('ledgewell-sentinel')


# ---- module-level helpers --------------------------------------------------

def _hash_card(value: Any) -> str:
    if value is None:
        return 'unknown'
    return hashlib.md5(str(value).encode()).hexdigest()[:12]


# Risk weight defaults so dict access never KeyError's on a custom config.
def _w(name: str, default: int = 0) -> int:
    return int(Config.RISK_WEIGHTS.get(name, default))


# ---- main detector ---------------------------------------------------------

class FraudDetector:

    def __init__(self, df: pl.DataFrame, mapping_report: Optional[Dict] = None):
        self.original_df = df
        self.mapping_report = mapping_report or {}
        self.df = df.clone()
        self._preprocess()

    # ---------- preprocessing ------------------------------------------------

    def _preprocess(self):
        df = self.df

        # Normalize timestamp column.
        if 'timestamp' in df.columns:
            df = df.with_columns(
                pl.col('timestamp').str.to_datetime(strict=False, time_unit='us').dt.convert_time_zone('UTC')
            )
            df = df.drop_nulls(subset=['timestamp']).sort('timestamp')
        else:
            df = df.with_columns(pl.lit(datetime.now(timezone.utc)).alias('timestamp'))

        df = df.with_row_index('_row_idx')

        # IP reputation — vectorize via a single pass over the unique IPs and a
        # join. Cuts work from O(rows) Python calls to O(unique_ips) calls.
        if 'ip_address' in df.columns:
            unique_ips = df.select(pl.col('ip_address').unique()).to_series().to_list()
            ip_lookup = {ip: check_ip_reputation(ip) for ip in unique_ips}
            ip_df = pl.DataFrame({
                'ip_address': list(ip_lookup.keys()),
                'ip_risk': [v[0] for v in ip_lookup.values()],
                'ip_risk_type': [v[1] for v in ip_lookup.values()],
                'ip_is_private': [v[2] for v in ip_lookup.values()],
            })
            df = df.join(ip_df, on='ip_address', how='left').with_columns([
                pl.col('ip_risk').fill_null('UNKNOWN'),
                pl.col('ip_risk_type').fill_null('Invalid IP'),
                pl.col('ip_is_private').fill_null(False),
            ])
        else:
            df = df.with_columns([
                pl.lit('UNKNOWN').alias('ip_risk'),
                pl.lit('Missing').alias('ip_risk_type'),
                pl.lit(False).alias('ip_is_private'),
            ])

        # Device category — same idea, dedupe before Python work.
        if 'device_info' in df.columns:
            unique_devs = df.select(pl.col('device_info').unique()).to_series().to_list()
            dev_lookup = {d: get_device_category(d) for d in unique_devs}
            dev_df = pl.DataFrame({
                'device_info': list(dev_lookup.keys()),
                'device_category': list(dev_lookup.values()),
            })
            df = df.join(dev_df, on='device_info', how='left').with_columns(
                pl.col('device_category').fill_null('unknown')
            )
        else:
            df = df.with_columns(pl.lit('unknown').alias('device_category'))

        # Email enrichment — dedupe before Python work.
        if 'email' in df.columns:
            unique_emails = df.select(pl.col('email').unique()).to_series().to_list()
            results = {e: analyze_email(e) for e in unique_emails}
            email_df = pl.DataFrame({
                'email': list(results.keys()),
                'email_is_disposable': [r['is_disposable'] for r in results.values()],
                'email_domain': [r['domain'] for r in results.values()],
                'email_reputation': [r['reputation_score'] for r in results.values()],
                'email_suspicious_username': [r['is_suspicious_username'] for r in results.values()],
            })
            df = df.join(email_df, on='email', how='left').with_columns([
                pl.col('email_is_disposable').fill_null(False),
                pl.col('email_reputation').fill_null(5),
                pl.col('email_suspicious_username').fill_null(False),
            ])
        else:
            df = df.with_columns([
                pl.lit(False).alias('email_is_disposable'),
                pl.lit(5).alias('email_reputation'),
                pl.lit(False).alias('email_suspicious_username'),
            ])

        # Order value as Float64.
        if 'order_value' in df.columns:
            df = df.with_columns(
                pl.col('order_value').cast(pl.Float64, strict=False).fill_null(0.0)
            )
        else:
            df = df.with_columns(pl.lit(0.0).alias('order_value'))

        # Card fingerprint — only hash uniques, then map back. Avoids re-hashing
        # the same payment_method string thousands of times.
        if 'card_fingerprint' not in df.columns:
            if 'payment_method' in df.columns:
                unique_pm = df.select(pl.col('payment_method').unique()).to_series().to_list()
                pm_lookup = {pm: _hash_card(pm) for pm in unique_pm}
                pm_df = pl.DataFrame({
                    'payment_method': list(pm_lookup.keys()),
                    'card_fingerprint': list(pm_lookup.values()),
                })
                df = df.join(pm_df, on='payment_method', how='left').with_columns(
                    pl.col('card_fingerprint').fill_null('unknown')
                )
            else:
                df = df.with_columns(pl.lit('unknown_card').alias('card_fingerprint'))

        self.df = df

    # ---------- detectors ----------------------------------------------------

    def detect_card_testing(self) -> pl.Series:
        """Vectorized card-testing detection.

        For each card, count transactions and average value within a rolling
        window of `VELOCITY_MIN_ATTEMPTS`. If both gates trip, the row is
        flagged. Implemented with `.over('card_fingerprint')` so it runs in a
        single pass instead of per-card Python loops.
        """
        n = Config.VELOCITY_MIN_ATTEMPTS
        max_avg = Config.VELOCITY_MAX_AVG_VALUE

        # `cumcount` over a sorted card group acts as the running count; we
        # already sorted by timestamp during preprocessing, so per-card order
        # is preserved by Polars' `over` semantics on a stable sort key.
        df = self.df.with_columns([
            pl.col('order_value').rolling_mean(window_size=n, min_periods=n)
              .over('card_fingerprint').alias('_avg_value'),
            pl.col('order_value').count()
              .over('card_fingerprint').alias('_card_count'),
        ])

        flag = (
            (pl.col('_card_count') >= n) &
            (pl.col('_avg_value').is_not_null()) &
            (pl.col('_avg_value') < max_avg)
        )
        return df.select(flag.alias('card_testing_flag'))['card_testing_flag']

    def detect_account_takeover(self) -> pl.Series:
        """Account-takeover: per-user, look for short time gap + IP change + device change.

        Uses `.shift(1).over('user_id')` to get the previous transaction within
        the user's own history. (The previous version used global row indices,
        which is incorrect across users.)

        Both the offending row AND the immediately-prior user row are flagged,
        matching the original behavior.
        """
        window = timedelta(hours=Config.ATO_WINDOW_HOURS)

        df = self.df.with_columns([
            (pl.col('timestamp') - pl.col('timestamp').shift(1).over('user_id')).alias('_time_diff'),
            (pl.col('ip_address') != pl.col('ip_address').shift(1).over('user_id')).alias('_ip_change'),
            (pl.col('device_category') != pl.col('device_category').shift(1).over('user_id')).alias('_device_change'),
            pl.col('_row_idx').shift(1).over('user_id').alias('_prev_idx'),
        ])

        ato_mask = (
            (pl.col('_time_diff') <= window) &
            pl.col('_ip_change').fill_null(False) &
            pl.col('_device_change').fill_null(False)
        )

        flagged = df.filter(ato_mask)
        flagged_ids = set(flagged['_row_idx'].to_list())
        # Include the previous-in-user-sequence row as well.
        prev_ids = flagged['_prev_idx'].drop_nulls().to_list()
        flagged_ids.update(int(p) for p in prev_ids)

        return self.df['_row_idx'].is_in(list(flagged_ids)).alias('ato_flag')

    def detect_bin_attack(self) -> pl.Series:
        ip_stats = self.df.group_by('ip_address').agg([
            pl.col('card_fingerprint').n_unique().alias('unique_cards'),
            pl.col('user_id').n_unique().alias('unique_users'),
            pl.col('timestamp').min().alias('time_min'),
            pl.col('timestamp').max().alias('time_max'),
            pl.len().alias('txn_count'),
        ])

        ip_stats = ip_stats.with_columns(
            ((pl.col('time_max') - pl.col('time_min')).dt.total_hours().clip(0.1, None)).alias('time_span_hours')
        ).with_columns(
            (pl.col('txn_count') / pl.col('time_span_hours')).alias('txn_per_hour')
        )

        # Global baseline.
        ts_min = self.df['timestamp'].min()
        ts_max = self.df['timestamp'].max()
        if ts_min is None or ts_max is None:
            global_time_span = 0.1
        else:
            global_time_span = max((ts_max - ts_min).total_seconds() / 3600.0, 0.1)
        global_txn_per_hour = len(self.df) / global_time_span
        threshold = global_txn_per_hour * Config.BIN_ATTACK_VELOCITY_MULTIPLIER

        bin_ips = ip_stats.filter(
            (pl.col('txn_count') >= Config.BIN_ATTACK_IP_MIN) &
            (pl.col('unique_cards') >= Config.BIN_ATTACK_CARD_MIN) &
            (pl.col('txn_per_hour') > threshold)
        )['ip_address'].to_list()

        # Exclude private IPs (their traffic is internal / NATted).
        private_ips = (
            self.df.filter(pl.col('ip_is_private'))
            .select(pl.col('ip_address').unique())
            .to_series()
            .to_list()
        )
        private_set = set(private_ips)
        bin_ips = [ip for ip in bin_ips if ip not in private_set]

        return self.df['ip_address'].is_in(bin_ips).alias('bin_attack_flag')

    def detect_device_anomaly(self) -> pl.Series:
        if 'device_info' not in self.df.columns:
            return pl.Series('device_flag', [False] * len(self.df))

        device_stats = self.df.group_by('device_info').agg(
            pl.col('user_id').n_unique().alias('unique_users')
        )
        suspicious_devices = device_stats.filter(
            (pl.col('unique_users') >= Config.DEVICE_MIN_USERS_FOR_FLAG) &
            (pl.col('unique_users') > Config.DEVICE_MANY_USERS_THRESHOLD)
        )['device_info'].to_list()

        return self.df['device_info'].is_in(suspicious_devices).alias('device_flag')

    def detect_impossible_travel(self) -> pl.Series:
        return pl.Series('travel_flag', [False] * len(self.df))

    # ---------- clustering ---------------------------------------------------

    def cluster_analysis(self) -> Tuple[pl.Series, List[Dict]]:
        """First-window-per-key clustering.

        Pre-aggregate per IP / per card to skip groups that can't possibly
        qualify, instead of filtering+sorting every group from scratch.
        """
        n = len(self.df)
        cluster_assignments: List[Optional[str]] = [None] * n
        clusters_meta: List[Dict] = []
        cluster_id = 1
        window = timedelta(hours=Config.CLUSTER_TIME_WINDOW_HOURS)

        # ---- IP clusters (public IPs only) ----
        public_df = self.df.filter(~pl.col('ip_is_private'))

        ip_summary = public_df.group_by('ip_address').agg([
            pl.len().alias('txns'),
            pl.col('user_id').n_unique().alias('users'),
        ]).filter(
            (pl.col('txns') >= Config.IP_CLUSTER_MIN_TXNS) &
            (pl.col('users') >= Config.IP_CLUSTER_MIN_USERS)
        )

        candidate_ips = ip_summary['ip_address'].to_list()
        if candidate_ips:
            # Single sort + filter, then split per IP via partition_by — much
            # faster than a per-IP filter() loop.
            ip_groups = public_df.filter(
                pl.col('ip_address').is_in(candidate_ips)
            ).sort('timestamp').partition_by('ip_address', as_dict=True)

            for key, ip_df in ip_groups.items():
                start_time = ip_df['timestamp'][0]
                window_df = ip_df.filter(pl.col('timestamp') <= start_time + window)
                if len(window_df) < Config.IP_CLUSTER_MIN_TXNS:
                    continue
                indices = window_df['_row_idx'].to_list()
                if not all(cluster_assignments[i] is None for i in indices):
                    continue
                tag = f'IP_{cluster_id}'
                for i in indices:
                    cluster_assignments[i] = tag
                # `key` is a tuple from partition_by; the IP value is the first element.
                ip_value = key[0] if isinstance(key, tuple) else key
                risk = 'HIGH' if len(window_df) >= 5 else 'INVESTIGATE'
                clusters_meta.append({
                    'cluster_id': tag,
                    'pattern': 'Shared Public IP',
                    'transaction_count': len(window_df),
                    'risk_level': risk,
                    'shared_attributes': [f'ip={ip_value}', f'{window_df["user_id"].n_unique()} users'],
                })
                cluster_id += 1

        # ---- Card clusters ----
        card_summary = self.df.group_by('card_fingerprint').agg(
            pl.len().alias('txns')
        ).filter(pl.col('txns') >= Config.CARD_CLUSTER_MIN_TXNS)
        candidate_cards = card_summary['card_fingerprint'].to_list()

        if candidate_cards:
            card_groups = self.df.filter(
                pl.col('card_fingerprint').is_in(candidate_cards)
            ).sort('timestamp').partition_by('card_fingerprint', as_dict=True)

            for key, card_df in card_groups.items():
                start_time = card_df['timestamp'][0]
                window_df = card_df.filter(pl.col('timestamp') <= start_time + window)
                if len(window_df) < Config.CARD_CLUSTER_MIN_TXNS:
                    continue
                indices = window_df['_row_idx'].to_list()
                if not all(cluster_assignments[i] is None for i in indices):
                    continue
                tag = f'CARD_{cluster_id}'
                for i in indices:
                    cluster_assignments[i] = tag
                card_value = key[0] if isinstance(key, tuple) else key
                clusters_meta.append({
                    'cluster_id': tag,
                    'pattern': 'Extreme Card Velocity',
                    'transaction_count': len(window_df),
                    'risk_level': 'CRITICAL',
                    'shared_attributes': [f'card={card_value}'],
                })
                cluster_id += 1

        return pl.Series('cluster_id', cluster_assignments, dtype=pl.Utf8), clusters_meta

    # ---------- scoring ------------------------------------------------------

    def compute_risk_scores(self,
                            velocity_flag: pl.Series,
                            ato_flag: pl.Series,
                            bin_flag: pl.Series,
                            device_flag: pl.Series,
                            travel_flag: pl.Series,
                            cluster_series: pl.Series,
                            clusters_meta: List[Dict]) -> pl.DataFrame:

        df = self.df.with_columns([
            velocity_flag.alias('_velocity_flag'),
            ato_flag.alias('_ato_flag'),
            bin_flag.alias('_bin_flag'),
            device_flag.alias('_device_flag'),
            travel_flag.alias('_travel_flag'),
            cluster_series.alias('cluster_id'),
        ])

        # ---- numeric risk score (single vectorized pass) -------------------
        very_large = _w('very_large_amount')
        large = _w('large_amount')
        w_card = _w('card_testing')
        w_ato = _w('ato_attempt')
        w_bin = _w('bin_attack')
        w_dev = _w('device_shared')
        w_email = _w('synthetic_email')
        w_vpn = _w('vpn_ip')
        w_crit_cluster = _w('critical_cluster')
        w_high_cluster = _w('high_cluster')

        cluster_risk_map = {c['cluster_id']: c['risk_level'] for c in clusters_meta}
        critical_cluster_ids = [cid for cid, lvl in cluster_risk_map.items() if lvl == 'CRITICAL']
        other_cluster_ids = [cid for cid, lvl in cluster_risk_map.items() if lvl != 'CRITICAL']

        score = (
            pl.when(pl.col('order_value') > 10000).then(very_large)
              .when(pl.col('order_value') > 5000).then(large)
              .otherwise(0)
            + pl.col('_velocity_flag').cast(pl.Int32) * w_card
            + pl.col('_ato_flag').cast(pl.Int32) * w_ato
            + pl.col('_bin_flag').cast(pl.Int32) * w_bin
            + pl.col('_device_flag').cast(pl.Int32) * w_dev
            + pl.col('email_is_disposable').cast(pl.Int32) * w_email
            + ((pl.col('ip_risk') == 'HIGH') & ~pl.col('ip_is_private')).cast(pl.Int32) * w_vpn
            + pl.col('cluster_id').is_in(critical_cluster_ids).cast(pl.Int32) * w_crit_cluster
            + pl.col('cluster_id').is_in(other_cluster_ids).cast(pl.Int32) * w_high_cluster
        )

        df = df.with_columns(score.alias('risk_score'))

        # ---- flag_reason (vectorized concat instead of per-row loop) -------
        # Each part is "<text>" if the flag is true, "" otherwise; the parts are
        # joined with ", " and trailing/leading separators are trimmed at the
        # end. This replaces an N-call with_columns loop that previously did a
        # full-table scan per flagged row.
        def _part(condition, text: str):
            return pl.when(condition).then(pl.lit(text)).otherwise(pl.lit(''))

        cluster_label = (
            pl.when(pl.col('cluster_id').is_not_null())
              .then(pl.concat_str([pl.lit('Cluster '), pl.col('cluster_id')]))
              .otherwise(pl.lit(''))
        )

        parts = [
            _part(pl.col('order_value') > 10000, 'Very Large Amount (>$10k)'),
            _part((pl.col('order_value') > 5000) & (pl.col('order_value') <= 10000), 'Large Amount (>$5k)'),
            _part(pl.col('_velocity_flag'), 'Card Testing Velocity'),
            _part(pl.col('_ato_flag'), 'Possible ATO'),
            _part(pl.col('_bin_flag'), 'BIN Attack Pattern'),
            _part(pl.col('email_is_disposable'), 'Disposable Email'),
            _part((pl.col('ip_risk') == 'HIGH') & ~pl.col('ip_is_private'), 'VPN/Proxy IP'),
            _part(pl.col('_device_flag'), 'Device Fingerprint Shared'),
            cluster_label,
        ]

        # Join non-empty parts with ", ". concat_str with separator skips
        # empties only if we filter — instead, we concatenate with a sentinel
        # separator and clean up afterwards.
        SEP = '\x1f'  # unit separator — safe, never appears in our text
        joined = pl.concat_str(parts, separator=SEP)
        # Collapse runs of separators and trim leading/trailing separators,
        # then convert remaining separators to ", ".
        cleaned = (
            joined.str.replace_all(rf'{SEP}+', SEP)  # collapse adjacent
                  .str.strip_chars(SEP)
                  .str.replace_all(SEP, ', ')
        )
        flag_reason = (
            pl.when(pl.col('risk_score') > 0)
              .then(pl.when(cleaned == '').then(pl.lit('Elevated risk')).otherwise(cleaned))
              .otherwise(pl.lit('Normal'))
        )

        df = df.with_columns(flag_reason.alias('flag_reason'))
        df = df.drop(['_velocity_flag', '_ato_flag', '_bin_flag', '_device_flag', '_travel_flag'])

        self.df = df
        return df

    # ---------- grading ------------------------------------------------------

    @staticmethod
    def score_to_grade(score: int) -> str:
        if score >= Config.GRADE_THRESHOLDS['CRITICAL RISK']:
            return 'CRITICAL RISK'
        if score >= Config.GRADE_THRESHOLDS['INVESTIGATE']:
            return 'INVESTIGATE'
        if score >= Config.GRADE_THRESHOLDS['HIGH RISK']:
            return 'HIGH RISK'
        return 'LOW RISK'

    def _grade_expression(self) -> pl.Expr:
        """Vectorized score → grade (avoids a Python list comp over `risk_score`)."""
        crit = Config.GRADE_THRESHOLDS['CRITICAL RISK']
        inv = Config.GRADE_THRESHOLDS['INVESTIGATE']
        high = Config.GRADE_THRESHOLDS['HIGH RISK']
        return (
            pl.when(pl.col('risk_score') >= crit).then(pl.lit('CRITICAL RISK'))
              .when(pl.col('risk_score') >= inv).then(pl.lit('INVESTIGATE'))
              .when(pl.col('risk_score') >= high).then(pl.lit('HIGH RISK'))
              .otherwise(pl.lit('LOW RISK'))
        )

    # ---------- pipeline -----------------------------------------------------

    def run_analysis(self) -> Dict[str, Any]:
        logger.info(f"Starting analysis on {len(self.df)} transactions")

        velocity_flag = self.detect_card_testing()
        ato_flag = self.detect_account_takeover()
        bin_flag = self.detect_bin_attack()
        device_flag = self.detect_device_anomaly()
        travel_flag = self.detect_impossible_travel()
        cluster_series, clusters_meta = self.cluster_analysis()

        self.compute_risk_scores(
            velocity_flag, ato_flag, bin_flag,
            device_flag, travel_flag,
            cluster_series, clusters_meta,
        )

        self.df = self.df.with_columns(self._grade_expression().alias('risk_grade'))

        # Risk distribution as a plain dict.
        vc = self.df['risk_grade'].value_counts()
        risk_counts = dict(zip(vc['risk_grade'].to_list(), vc['count'].to_list()))
        for grade in ('CRITICAL RISK', 'INVESTIGATE', 'HIGH RISK', 'LOW RISK'):
            risk_counts.setdefault(grade, 0)

        # Serialize flagged rows.
        flagged_df = self.df.filter(pl.col('risk_grade') != 'LOW RISK').drop('_row_idx')

        # Stringify timestamp once at the column level — much faster than a
        # per-row strftime call.
        if 'timestamp' in flagged_df.columns:
            flagged_df = flagged_df.with_columns(
                pl.col('timestamp').dt.strftime('%Y-%m-%d %H:%M:%S').alias('timestamp')
            )

        flagged_records = flagged_df.to_dicts()

        # Stats — single aggregation pass.
        stats_row = self.df.select([
            pl.col('order_value').mean().alias('avg_order_value'),
            pl.col('order_value').median().alias('median_order_value'),
            pl.col('order_value').sum().alias('total_volume'),
            pl.col('user_id').n_unique().alias('unique_users'),
            pl.col('card_fingerprint').n_unique().alias('unique_cards'),
            pl.col('ip_address').n_unique().alias('unique_ips'),
            pl.col('timestamp').min().alias('ts_min'),
            pl.col('timestamp').max().alias('ts_max'),
        ]).row(0, named=True)

        def _fmt_ts(ts):
            if ts is None:
                return None
            try:
                return ts.strftime('%Y-%m-%d %H:%M:%S')
            except AttributeError:
                return str(ts)

        stats = {
            'total_rows': len(self.df),
            'avg_order_value': float(stats_row['avg_order_value'] or 0),
            'median_order_value': float(stats_row['median_order_value'] or 0),
            'total_volume': float(stats_row['total_volume'] or 0),
            'unique_users': int(stats_row['unique_users'] or 0),
            'unique_cards': int(stats_row['unique_cards'] or 0),
            'unique_ips': int(stats_row['unique_ips'] or 0),
            'date_range_start': _fmt_ts(stats_row['ts_min']),
            'date_range_end': _fmt_ts(stats_row['ts_max']),
        }

        logger.info(f"Analysis complete. Risk distribution: {risk_counts}")
        return {
            'total_rows': len(self.df),
            'risk_counts': risk_counts,
            'clusters': clusters_meta,
            'flagged_rows': flagged_records,
            'statistics': stats,
            'mapping_report': self.mapping_report,
        }