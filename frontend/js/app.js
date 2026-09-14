// SENTINEL | Parrish Lyon | PARRISH-LYON-SENTINEL-2026
// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// APP - Main application entry point

import './state.js';
import './utils.js';
import './router.js';
import './upload.js';
import './dashboard.js';
import './transactions.js';
import './charts.js';
import './modal.js';
import './behavioral.js';
import './velocity.js';
import './clustering.js';
import './entity_graph.js';
import './ipintel.js';
import './regulatory.js';
import './sar.js';
import './watchlist.js';
import './reports.js';
import './cases.js';
import './auditlog.js';
import './integrity.js';

import { loadComponents, initApp } from './router.js';
import { initClustering, renderClusters } from './clustering.js';
import { initUpload } from './upload.js';
import { initDashboard } from './dashboard.js';
import { initTransactions } from './transactions.js';
import { initModal } from './modal.js';
import { initIPIntel } from './ipintel.js';
import { initSAR } from './sar.js';
import { initWatchlist } from './watchlist.js';
import { initReports } from './reports.js';
import { initCases } from './cases.js';
import { initAuditLog } from './auditlog.js';

// Initialize everything when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    console.log('SENTINEL · Initializing...');

    // Initialize all modules
    initUpload();
    initDashboard();
    initClustering();
    initTransactions();
    initModal();
    initIPIntel();
    initSAR();
    initWatchlist();
    initReports();
    initCases();
    initAuditLog();

    console.log('SENTINEL · Ready');
});

// Export for global access
export { loadComponents, initApp };