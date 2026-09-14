# SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
# Copyright (c) 2026 Parrish Lyon. All rights reserved.
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging

import polars as pl


logger = logging.getLogger('ledgewell-sentinel')


def read_csv_chunked(filepath: str, chunk_size: int = 50000) -> pl.DataFrame:
    """Read a CSV file efficiently with Polars.

    Polars' streaming engine reads large CSVs without loading the whole file into
    Python memory at once, and a single `collect(streaming=True)` is dramatically
    faster than the previous per-chunk slice/collect loop, which re-parsed the
    file from byte zero on every iteration.

    The `chunk_size` argument is preserved for API compatibility but no longer
    drives a Python-level loop; it is only used to control logging behavior.
    """
    lazy_df = pl.scan_csv(filepath, infer_schema_length=10000)

    # Try the streaming collect first; fall back to a normal collect if the
    # installed Polars version doesn't support that kwarg.
    try:
        df = lazy_df.collect(streaming=True)
    except TypeError:
        df = lazy_df.collect()

    if len(df) > chunk_size:
        logger.info(f"Read {len(df)} rows (streaming)")

    return df
