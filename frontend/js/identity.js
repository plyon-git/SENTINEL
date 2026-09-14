// SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// Public attribution metadata only. No tracking, telemetry, or remote controls.
export const SENTINEL_IDENTITY = Object.freeze({
    project: 'SENTINEL',
    owner: 'Parrish Lyon',
    watermark_id: 'PARRISH-LYON-SENTINEL-2026',
    build_id: 'PL-SENTINEL-20260914-33b0697a',
    source_commit: '33b0697a47ecdaf2cc152f39c1d37e50e87f2917'
});
Object.defineProperty(globalThis, 'SENTINEL_IDENTITY', {
    value: SENTINEL_IDENTITY, writable: false, configurable: false, enumerable: true
});
document.documentElement.dataset.sentinelOwner = SENTINEL_IDENTITY.owner;
document.documentElement.dataset.sentinelWatermark = SENTINEL_IDENTITY.watermark_id;
