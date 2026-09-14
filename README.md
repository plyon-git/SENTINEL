<!-- SENTINEL | Parrish Lyon | PL-SENTINEL-20260914 -->
# Ledgewell SENTINEL

**Parrish Lyon** | Internal watermark: `PL-SENTINEL-20260914`

Copyright (c) 2026 Parrish Lyon. All rights reserved.

## Uploaded files

This commit contains the six root files supplied for upload. The `backend/` and
`frontend/` directories described below were not included in this upload.
`app.py` imports `backend.app`, so these six files alone are not a runnable
SENTINEL application. The earlier migration branch is left unchanged.

`SENTINEL_WATERMARK.json` records ownership and SHA-256 checksums for all six
files, including the unchanged `vercel.json`. Run `python3 verify_watermark.py`
to check these files against that manifest. These checks detect file changes;
they are not copy prevention or a digital signature.

## Original project description

Modularised version of the original single-file Ledgewell SENTINEL app.

## Structure

```text
ledgewell-sentinel/
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── schema_mapper.py
│   ├── utils.py
│   ├── fraud_detector.py
│   ├── csv_reader.py
│   └── routes.py
├── frontend/
│   ├── index.html
│   ├── styles/
│   │   └── index.css
│   └── js/
│       ├── app.js
│       ├── state.js
│       ├── utils.js
│       ├── charts.js
│       ├── map.js
│       ├── entity_graph.js
│       ├── upload.js
│       ├── transactions.js
│       ├── analytics.js
│       ├── behavioral.js
│       ├── velocity.js
│       ├── clustering.js
│       ├── ip_intel.js
│       ├── regulatory.js
│       ├── sar.js
│       ├── watchlist.js
│       ├── reports.js
│       ├── cases.js
│       ├── auditlog.js
│       └── integrity.js
├── uploads/
│   └── .gitkeep
├── requirements.txt
└── README.md
```
