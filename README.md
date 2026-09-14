# SENTINEL

**Parrish Lyon** | `PARRISH-LYON-SENTINEL-2026`

Fraud-analysis application imported from source snapshot `33b0697a47ecdaf2cc152f39c1d37e50e87f2917`, with file-level attribution, local SHA-256 integrity checking, and validation tests.

## Run locally

Use Python 3.12. From a terminal:

```sh
git clone https://github.com/plyon-git/SENTINEL.git
cd SENTINEL
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python sentinel_guard.py check
python app.py
```

On Windows PowerShell, use `py -3.12 -m venv .venv` and `.\.venv\Scripts\Activate.ps1` instead of the two virtual-environment commands above.

Open `http://127.0.0.1:5000`. The development server defaults to loopback and has debug mode disabled. Opening the HTML file directly is not supported; the UI needs its Flask routes and static server.

## Ownership and safeguards

Python, JavaScript, HTML, and CSS files carry Parrish Lyon source headers. `OWNERSHIP.json`, HTML metadata, `window.SENTINEL_IDENTITY`, API response headers, `/identity`, and successful `/upload` results carry the distribution identity. `integrity.sha256.json` records the approved file hashes.

```sh
python sentinel_guard.py check
python sentinel_guard.py secrets
python -m unittest discover -s tests -v
```

Startup refuses missing or changed baselines in the default `enforce` mode. Verification never silently repairs a baseline. It performs no network call, telemetry, deletion, or remote shutdown.

After an intentional change, inspect the diff and run:

```sh
python sentinel_guard.py baseline --approve
python sentinel_guard.py check
```

Commit the reviewed changes and the new manifest together. Do not rebaseline unexplained modifications. `SENTINEL_INTEGRITY_MODE=off` is an explicit development-only override. Re-enable enforcement before distribution.

## Repository controls

`.github/CODEOWNERS` assigns all files to `@plyon-git`. The read-only GitHub Actions workflow checks credentials/private-data filenames, Python and JavaScript syntax, regression tests, and the committed integrity baseline. Action versions are pinned to commit SHAs.

CODEOWNERS alone does not enforce approval. Configure a rule for `main` in GitHub Settings requiring pull-request review, code-owner review, and the `integrity-and-tests` check, with an appropriate owner bypass for a sole-maintainer repository. Repository protection settings are not changed by this code migration.

## Important limits

Public source can be copied. These markers and hashes provide attribution and change detection; they are not unremovable DRM, a cryptographic ownership determination, or a substitute for access control. Someone who controls a copy can modify both the code and its verifier. Trust a reviewed commit or an independently retained manifest, not an arbitrary copy's self-reported identity.

This is a source migration, not production-deployment approval or a validation of fraud-model accuracy. The inherited API has no authentication and includes mutable runtime configuration; the UI can persist analysis data in browser storage and loads third-party assets. Keep it local unless you add appropriate authentication, authorization, TLS, data controls, and dependency review. Never commit transaction data, generated reports, credentials, or private keys.

See `PROVENANCE.md`, `SECURITY.md`, and `NOTICE` for the source record, operating limits, and ownership notice.
