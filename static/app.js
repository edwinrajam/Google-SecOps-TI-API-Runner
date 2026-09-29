/**
 * Google SecOps Chronicle v1alpha API Runner
 * Client-side Controller & Interactive Workbench
 */

// Application State
const state = {
  user: null,
  config: {},
  activePlatform: 'secops',
  secopsCatalog: null,
  gtiCatalog: null,
  catalog: { endpoints: [], presets: [] },
  filteredEndpoints: [],
  filteredPresets: [],
  selectedEndpoint: null,
  favorites: new Set(),
  history: [],
  auditLogs: [],
  filteredAuditLogs: [],
  activeSidebarTab: 'presets',
  activeReqTab: 'params',
  activeResTab: 'json',
  lastResponse: null,
  activeLro: null,
  activeSearchSession: null,
  renderedEndpointCount: 60,
  queryParams: [],
  customHeaders: [
    { key: 'Accept', value: 'application/json' },
    { key: 'Content-Type', value: 'application/json' }
  ]
};

// Initialization on DOM Load
document.addEventListener('DOMContentLoaded', async () => {
  initKeyboardShortcuts();
  initMethodGuide();
  await checkAuthUser();
  await loadConfig();
  const urlParams = new URLSearchParams(window.location.search);
  const initialTab = (urlParams.get('tab') === 'gti' || window.location.hash === '#gti') ? 'gti' : 'secops';
  await loadFavorites();
  await loadHistory();
  renderQueryParamsTable();
  renderHeadersTable();
  await switchPlatform(initialTab);
});

// Keyboard Shortcuts
function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Cmd/Ctrl + Enter to send request
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      sendApiRequest();
    }
  });
}

// -----------------------------------------------------------------------------
// PLATFORM SWITCHER: GOOGLE SECOPS (CHRONICLE) <-> GOOGLE THREAT INTEL (GTI v3)
// -----------------------------------------------------------------------------

async function switchPlatform(platform) {
  if (platform !== 'secops' && platform !== 'gti') return;
  state.activePlatform = platform;

  const btnSecops = document.getElementById('platform-tab-secops');
  const btnGti = document.getElementById('platform-tab-gti');
  const headerTitle = document.getElementById('app-header-title');
  const searchInput = document.getElementById('endpoint-search');

  const presetsHeader = document.getElementById('presets-header-label');
  const footerBadge = document.getElementById('sidebar-footer-badge');
  const chronicleChips = document.getElementById('chronicle-helper-chips');
  const gtiChips = document.getElementById('gti-helper-chips');
  const emptyTitle = document.getElementById('res-empty-title');
  const gtiSummaryCard = document.getElementById('gti-summary-card');
  const secopsCredPill = document.getElementById('auth-status-pill');
  const gtiCredPill = document.getElementById('gti-auth-status-pill');

  if (platform === 'secops') {
    if (btnSecops) {
      btnSecops.className = 'px-3.5 py-1.5 rounded-md text-xs font-bold flex items-center space-x-2 bg-blue-600 text-white shadow transition';
    }
    if (btnGti) {
      btnGti.className = 'px-3.5 py-1.5 rounded-md text-xs font-bold flex items-center space-x-2 text-gray-400 hover:text-gray-200 transition';
    }
    if (secopsCredPill) secopsCredPill.classList.remove('hidden');
    if (gtiCredPill) gtiCredPill.classList.add('hidden');
    if (headerTitle) {
      headerTitle.innerHTML = 'Google SecOps (Chronicle) <span class="text-blue-400 font-semibold">API Runner</span>';
    }
    if (searchInput) {
      const count = state.secopsCatalog?.endpoints?.length || 1352;
      searchInput.placeholder = `Search ${count.toLocaleString()} Chronicle endpoints (e.g. feeds, search, rules, cases)...`;
      searchInput.value = '';
    }
    if (presetsHeader) presetsHeader.textContent = 'Featured Chronicle Actions';
    if (footerBadge) footerBadge.innerHTML = '<i class="fa-solid fa-shield-halved text-blue-400 text-xs"></i><span>Chronicle v1alpha REST</span>';
    if (chronicleChips) { chronicleChips.classList.remove('hidden'); chronicleChips.classList.add('flex'); }
    if (gtiChips) { gtiChips.classList.add('hidden'); gtiChips.classList.remove('flex'); }
    if (emptyTitle) emptyTitle.textContent = 'Ready to execute live Chronicle v1alpha API request';
    if (gtiSummaryCard) gtiSummaryCard.classList.add('hidden');
  } else {
    if (btnGti) {
      btnGti.className = 'px-3.5 py-1.5 rounded-md text-xs font-bold flex items-center space-x-2 bg-cyan-600 text-white shadow transition';
    }
    if (btnSecops) {
      btnSecops.className = 'px-3.5 py-1.5 rounded-md text-xs font-bold flex items-center space-x-2 text-gray-400 hover:text-gray-200 transition';
    }
    if (gtiCredPill) gtiCredPill.classList.remove('hidden');
    if (secopsCredPill) secopsCredPill.classList.add('hidden');
    if (headerTitle) {
      headerTitle.innerHTML = 'Google Threat Intelligence <span class="text-cyan-400 font-semibold">API Runner (GTI v3)</span>';
    }
    if (searchInput) {
      const count = state.gtiCatalog?.endpoints?.length || 381;
      searchInput.placeholder = `Search ${count.toLocaleString()} GTI v3 endpoints (e.g. files, ip_addresses, collections, livehunt, dtm)...`;
      searchInput.value = '';
    }
    if (presetsHeader) presetsHeader.textContent = 'Featured GTI v3 Actions';
    if (footerBadge) footerBadge.innerHTML = '<i class="fa-solid fa-radar text-cyan-400 text-xs"></i><span>GTI / VirusTotal v3 REST</span>';
    if (chronicleChips) { chronicleChips.classList.add('hidden'); chronicleChips.classList.remove('flex'); }
    if (gtiChips) { gtiChips.classList.remove('hidden'); gtiChips.classList.add('flex'); }
    if (emptyTitle) emptyTitle.textContent = 'Ready to execute live Google Threat Intelligence (GTI v3) API request';
  }

  updatePlatformAuthBanner();
  await loadCatalog(platform);

  if (state.catalog.presets && state.catalog.presets.length > 0) {
    selectPreset(state.catalog.presets[0].id);
  } else if (state.catalog.endpoints && state.catalog.endpoints.length > 0) {
    selectEndpoint(state.catalog.endpoints[0]);
  }
}

function updatePlatformAuthBanner() {
  const noSaBanner = document.getElementById('no-sa-banner');
  if (!noSaBanner) return;

  if (state.activePlatform === 'gti') {
    if (state.config && state.config.has_gti_key) {
      noSaBanner.classList.add('hidden');
    } else {
      noSaBanner.classList.remove('hidden');
      noSaBanner.innerHTML = `
        <div class="flex items-center space-x-3">
          <div class="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 flex-shrink-0">
            <i class="fa-solid fa-virus-covid"></i>
          </div>
          <div>
            <div class="text-xs font-bold text-cyan-200">Google Threat Intelligence (VirusTotal v3) Credentials Required</div>
            <div class="text-[11px] text-cyan-300/80">Upload or enter your GTI <code class="text-cyan-200 font-mono">x-apikey</code> to run live Threat Intelligence v3 calls against <code class="text-cyan-200 font-mono">https://www.virustotal.com/api/v3</code>. Credentials are encrypted at rest with AES-256.</div>
          </div>
        </div>
        <button onclick="openConfigModal('gti')" class="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow transition whitespace-nowrap flex-shrink-0">
          <i class="fa-solid fa-key mr-1.5"></i>Credentials
        </button>
      `;
    }
  } else {
    if (state.config && state.config.has_service_account) {
      noSaBanner.classList.add('hidden');
    } else {
      noSaBanner.classList.remove('hidden');
      noSaBanner.innerHTML = `
        <div class="flex items-center space-x-3">
          <div class="w-8 h-8 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 flex-shrink-0">
            <i class="fa-solid fa-key"></i>
          </div>
          <div>
            <div class="text-xs font-bold text-amber-200">Chronicle Service Account Credentials Required</div>
            <div class="text-[11px] text-amber-300/80">Upload your Google Cloud Service Account JSON file (<code class="text-amber-200 font-mono">roles/chronicle.viewer</code> or <code class="text-amber-200 font-mono">roles/chronicle.admin</code>) to execute live Chronicle v1alpha API requests. Credentials are encrypted at rest with AES-256.</div>
          </div>
        </div>
        <button onclick="openConfigModal('secops')" class="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-lg shadow transition whitespace-nowrap flex-shrink-0">
          <i class="fa-solid fa-key mr-1.5"></i>Credentials
        </button>
      `;
    }
  }
}

// -----------------------------------------------------------------------------
// CONFIGURATION & AUTHENTICATION
// -----------------------------------------------------------------------------

async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const data = await res.json();
    state.config = data;

    // Update Topbar Display (if present)
    const navProject = document.getElementById('nav-project');
    if (navProject) navProject.textContent = data.project_id || 'Not set';
    const navLocation = document.getElementById('nav-location');
    if (navLocation) navLocation.textContent = data.location || 'us';
    const navInstance = document.getElementById('nav-instance');
    if (navInstance) {
      navInstance.textContent = data.customer_id || 'Not set';
      navInstance.title = data.customer_id || 'Not set';
    }

    // Update Modal Inputs
    document.getElementById('cfg-project-id').value = data.project_id || '';
    document.getElementById('cfg-customer-id').value = data.customer_id || '';
    document.getElementById('cfg-location').value = data.location || 'us';
    document.getElementById('cfg-endpoint').value = data.endpoint || `https://${data.location || 'us'}-chronicle.googleapis.com`;
    const gtiEndpointInput = document.getElementById('cfg-gti-endpoint');
    if (gtiEndpointInput) {
      gtiEndpointInput.value = data.gti_endpoint || 'https://www.virustotal.com';
    }

    // Update SecOps Credentials Pill & Modal Visual Indicators
    const pill = document.getElementById('auth-status-pill');
    const dot = document.getElementById('auth-status-dot');
    const icon = document.getElementById('auth-status-icon');
    const text = document.getElementById('auth-status-text');
    const badge = document.getElementById('auth-status-badge');
    const modalTabBadgeSecops = document.getElementById('cfg-tab-badge-secops');
    const stepCreatedSecops = document.getElementById('secops-step-created');
    const stepCreatedIconSecops = document.getElementById('secops-step-created-icon');
    const stepCreatedSubSecops = document.getElementById('secops-step-created-sub');
    const stepValidatedSecops = document.getElementById('secops-step-validated');
    const stepValidatedIconSecops = document.getElementById('secops-step-validated-icon');
    const stepValidatedSubSecops = document.getElementById('secops-step-validated-sub');

    const saStatusLabel = document.getElementById('sa-status-label');
    const btnRemoveKey = document.getElementById('btn-remove-key');
    const dropzone = document.getElementById('sa-dropzone');
    const dropzoneIcon = document.getElementById('sa-dropzone-icon');
    const dropzoneTitle = document.getElementById('sa-dropzone-title');
    const identifiedCard = document.getElementById('sa-identified-card');
    const identifiedEmail = document.getElementById('sa-identified-email');
    const identifiedProject = document.getElementById('sa-identified-project');
    const identifiedStatus = document.getElementById('sa-identified-status');

    const maskedEmail = data.client_email_masked || data.client_email || 'Encrypted Key';
    const isSecopsTab = state.activePlatform !== 'gti';

    if (data.has_service_account) {
      if (btnRemoveKey) btnRemoveKey.classList.remove('hidden');
      if (identifiedCard) identifiedCard.classList.remove('hidden');
      if (identifiedEmail) identifiedEmail.textContent = maskedEmail;
      if (identifiedProject) identifiedProject.textContent = data.project_id || 'From SA Key';

      if (stepCreatedSecops) stepCreatedSecops.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-500/40 text-emerald-200';
      if (stepCreatedIconSecops) stepCreatedIconSecops.className = 'fa-solid fa-circle-check text-sm text-emerald-400';
      if (stepCreatedSubSecops) stepCreatedSubSecops.textContent = `AES-256 Encrypted (${maskedEmail.split('@')[0]})`;

      if (data.is_authenticated) {
        if (pill) pill.className = `${isSecopsTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-emerald-500/15 border border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/25 cursor-pointer whitespace-nowrap flex-shrink-0 transition shadow-[0_0_12px_rgba(16,185,129,0.18)]`;
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399] flex-shrink-0';
        if (icon) icon.className = 'fa-solid fa-circle-check text-emerald-400 text-xs';
        if (text) text.textContent = 'Credentials';
        if (badge) {
          badge.className = 'px-2 py-0.5 rounded-full bg-emerald-500/25 border border-emerald-400/50 text-emerald-200 text-[10px] font-bold uppercase tracking-wider inline-flex items-center space-x-1';
          badge.innerHTML = '<i class="fa-solid fa-check text-[9px]"></i><span>Validated</span>';
        }
        if (pill) pill.title = `Chronicle Credentials Created & Validated for Use (${maskedEmail})`;
        if (modalTabBadgeSecops) {
          modalTabBadgeSecops.className = 'px-1.5 py-0.5 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold';
          modalTabBadgeSecops.innerHTML = '<i class="fa-solid fa-check mr-1"></i>Validated';
        }
        if (stepValidatedSecops) stepValidatedSecops.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-500/40 text-emerald-200';
        if (stepValidatedIconSecops) stepValidatedIconSecops.className = 'fa-solid fa-circle-check text-sm text-emerald-400';
        if (stepValidatedSubSecops) stepValidatedSubSecops.textContent = 'OAuth2 Verified & Ready for Use';

        if (saStatusLabel) {
          saStatusLabel.textContent = `Created & Validated (${maskedEmail})`;
          saStatusLabel.className = 'text-[11px] text-emerald-400 font-mono font-semibold';
        }
        if (identifiedStatus) {
          identifiedStatus.textContent = 'Validated for Use (AES-256 Encrypted)';
          identifiedStatus.className = 'font-mono text-emerald-400 font-semibold';
        }
        if (dropzone) {
          dropzone.className = 'border-2 border-dashed border-emerald-500/40 hover:border-emerald-400 rounded-lg p-5 text-center transition bg-emerald-950/10 cursor-pointer';
        }
        if (dropzoneIcon) {
          dropzoneIcon.className = 'fa-solid fa-file-shield text-2xl text-emerald-400 mb-1.5';
        }
        if (dropzoneTitle) {
          dropzoneTitle.innerHTML = `Service Account Key Validated (<code class="text-emerald-300">${escapeHtml(maskedEmail)}</code>) • <span class="text-emerald-400 underline">Click or drop file to replace</span>`;
        }
      } else {
        if (pill) pill.className = `${isSecopsTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25 cursor-pointer whitespace-nowrap flex-shrink-0 transition`;
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-pulse flex-shrink-0';
        if (icon) icon.className = 'fa-solid fa-shield-halved text-amber-400 text-xs';
        if (text) text.textContent = 'Credentials';
        if (badge) {
          badge.className = 'px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-400/40 text-amber-200 text-[10px] font-semibold';
          badge.textContent = 'Created • Verify';
        }
        if (pill) pill.title = `Chronicle Credentials Stored (${maskedEmail}) — Click to validate`;
        if (modalTabBadgeSecops) {
          modalTabBadgeSecops.className = 'px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[10px] font-semibold';
          modalTabBadgeSecops.textContent = 'Created';
        }
        if (stepValidatedSecops) stepValidatedSecops.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-amber-950/30 border border-amber-500/40 text-amber-200';
        if (stepValidatedIconSecops) stepValidatedIconSecops.className = 'fa-solid fa-clock text-sm text-amber-400';
        if (stepValidatedSubSecops) stepValidatedSubSecops.textContent = 'Click Test Chronicle Connection to validate';

        if (saStatusLabel) {
          saStatusLabel.textContent = `Key Created (${maskedEmail}) • Pending Validation`;
          saStatusLabel.className = 'text-[11px] text-amber-400 font-mono font-semibold';
        }
        if (identifiedStatus) {
          identifiedStatus.textContent = 'Created (Click Test Connection to Validate)';
          identifiedStatus.className = 'font-mono text-amber-400 font-semibold';
        }
        if (dropzone) {
          dropzone.className = 'border-2 border-dashed border-amber-500/40 hover:border-amber-400 rounded-lg p-5 text-center transition bg-amber-950/10 cursor-pointer';
        }
        if (dropzoneIcon) {
          dropzoneIcon.className = 'fa-solid fa-triangle-exclamation text-2xl text-amber-400 mb-1.5';
        }
        if (dropzoneTitle) {
          dropzoneTitle.innerHTML = `Key Loaded (<code class="text-amber-300">${escapeHtml(maskedEmail)}</code>) • <span class="text-amber-400 underline">Click or drop valid JSON key to replace</span>`;
        }
      }
    } else {
      if (pill) pill.className = `${isSecopsTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 cursor-pointer whitespace-nowrap flex-shrink-0 transition`;
      if (dot) dot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-pulse flex-shrink-0';
      if (icon) icon.className = 'fa-solid fa-key text-[11px]';
      if (text) text.textContent = 'Credentials';
      if (badge) {
        badge.className = 'px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-200 text-[10px] font-mono';
        badge.textContent = 'Not Set';
      }
      if (pill) pill.title = 'No Chronicle Credentials configured. Click to upload Service Account JSON.';
      if (modalTabBadgeSecops) {
        modalTabBadgeSecops.className = 'px-1.5 py-0.5 rounded-full bg-gray-800 text-gray-400 text-[10px] font-mono';
        modalTabBadgeSecops.textContent = 'Not Set';
      }
      if (stepCreatedSecops) stepCreatedSecops.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-gray-900/80 border border-gray-800 text-gray-400';
      if (stepCreatedIconSecops) stepCreatedIconSecops.className = 'fa-regular fa-circle text-sm text-gray-500';
      if (stepCreatedSubSecops) stepCreatedSubSecops.textContent = 'Awaiting Service Account JSON';
      if (stepValidatedSecops) stepValidatedSecops.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-gray-900/80 border border-gray-800 text-gray-400';
      if (stepValidatedIconSecops) stepValidatedIconSecops.className = 'fa-regular fa-circle text-sm text-gray-500';
      if (stepValidatedSubSecops) stepValidatedSubSecops.textContent = 'Pending OAuth2 verification';

      if (saStatusLabel) {
        saStatusLabel.textContent = 'Not configured (AES-256 encrypted storage ready)';
        saStatusLabel.className = 'text-[11px] text-gray-500 font-mono';
      }
      if (btnRemoveKey) btnRemoveKey.classList.add('hidden');
      if (identifiedCard) identifiedCard.classList.add('hidden');
      if (dropzone) {
        dropzone.className = 'border-2 border-dashed border-gray-700 hover:border-blue-500 rounded-lg p-5 text-center transition bg-[#141b2d] cursor-pointer';
      }
      if (dropzoneIcon) {
        dropzoneIcon.className = 'fa-solid fa-file-arrow-up text-2xl text-blue-400 mb-1.5';
      }
      if (dropzoneTitle) {
        dropzoneTitle.innerHTML = 'Click to upload or drag & drop <code class="text-blue-400">service_account.json</code> file';
      }
    }

    // Update GTI Credentials Pill & Modal Visual Indicators
    const gtiPill = document.getElementById('gti-auth-status-pill');
    const gtiDot = document.getElementById('gti-auth-status-dot');
    const gtiIcon = document.getElementById('gti-auth-status-icon');
    const gtiText = document.getElementById('gti-auth-status-text');
    const gtiBadge = document.getElementById('gti-auth-status-badge');
    const modalTabBadgeGti = document.getElementById('cfg-tab-badge-gti');
    const stepCreatedGti = document.getElementById('gti-step-created');
    const stepCreatedIconGti = document.getElementById('gti-step-created-icon');
    const stepCreatedSubGti = document.getElementById('gti-step-created-sub');
    const stepValidatedGti = document.getElementById('gti-step-validated');
    const stepValidatedIconGti = document.getElementById('gti-step-validated-icon');
    const stepValidatedSubGti = document.getElementById('gti-step-validated-sub');

    const gtiStatusLabel = document.getElementById('gti-status-label');
    const btnRemoveGtiKey = document.getElementById('btn-remove-gti-key');
    const gtiCard = document.getElementById('gti-identified-card');
    const gtiMaskedSpan = document.getElementById('gti-identified-masked');
    const gtiEndpointSpan = document.getElementById('gti-identified-endpoint');
    const gtiStatusSpan = document.getElementById('gti-identified-status');
    const isGtiTab = state.activePlatform === 'gti';

    if (data.has_gti_key) {
      const maskedGti = data.gti_api_key_masked || 'Encrypted GTI Key';
      if (btnRemoveGtiKey) btnRemoveGtiKey.classList.remove('hidden');
      if (gtiCard) gtiCard.classList.remove('hidden');
      if (gtiMaskedSpan) gtiMaskedSpan.textContent = maskedGti;
      if (gtiEndpointSpan) gtiEndpointSpan.textContent = `${(data.gti_endpoint || 'https://www.virustotal.com').replace(/\/$/, '')}/api/v3`;

      if (stepCreatedGti) stepCreatedGti.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-500/40 text-emerald-200';
      if (stepCreatedIconGti) stepCreatedIconGti.className = 'fa-solid fa-circle-check text-sm text-emerald-400';
      if (stepCreatedSubGti) stepCreatedSubGti.textContent = `AES-256 Encrypted (${maskedGti})`;

      if (data.gti_is_authenticated) {
        if (gtiPill) gtiPill.className = `${isGtiTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-emerald-500/15 border border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/25 cursor-pointer whitespace-nowrap flex-shrink-0 transition shadow-[0_0_12px_rgba(16,185,129,0.18)]`;
        if (gtiDot) gtiDot.className = 'w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399] flex-shrink-0';
        if (gtiIcon) gtiIcon.className = 'fa-solid fa-circle-check text-emerald-400 text-xs';
        if (gtiText) gtiText.textContent = 'Credentials';
        if (gtiBadge) {
          gtiBadge.className = 'px-2 py-0.5 rounded-full bg-emerald-500/25 border border-emerald-400/50 text-emerald-200 text-[10px] font-bold uppercase tracking-wider inline-flex items-center space-x-1';
          gtiBadge.innerHTML = '<i class="fa-solid fa-check text-[9px]"></i><span>Validated</span>';
        }
        if (gtiPill) gtiPill.title = `GTI Credentials Created & Validated for Use (${maskedGti})`;
        if (modalTabBadgeGti) {
          modalTabBadgeGti.className = 'px-1.5 py-0.5 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold';
          modalTabBadgeGti.innerHTML = '<i class="fa-solid fa-check mr-1"></i>Validated';
        }
        if (stepValidatedGti) stepValidatedGti.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-emerald-950/30 border border-emerald-500/40 text-emerald-200';
        if (stepValidatedIconGti) stepValidatedIconGti.className = 'fa-solid fa-circle-check text-sm text-emerald-400';
        if (stepValidatedSubGti) stepValidatedSubGti.textContent = 'Verified Live against GTI v3 & Ready for Use';

        if (gtiStatusLabel) {
          gtiStatusLabel.textContent = `Created & Validated (${maskedGti})`;
          gtiStatusLabel.className = 'text-[11px] text-emerald-400 font-mono font-semibold';
        }
        if (gtiStatusSpan) {
          gtiStatusSpan.textContent = 'Validated for Use (AES-256 Encrypted)';
          gtiStatusSpan.className = 'font-mono text-emerald-400 font-semibold';
        }
      } else {
        if (gtiPill) gtiPill.className = `${isGtiTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25 cursor-pointer whitespace-nowrap flex-shrink-0 transition`;
        if (gtiDot) gtiDot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-pulse flex-shrink-0';
        if (gtiIcon) gtiIcon.className = 'fa-solid fa-shield-halved text-amber-400 text-xs';
        if (gtiText) gtiText.textContent = 'Credentials';
        if (gtiBadge) {
          gtiBadge.className = 'px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-400/40 text-amber-200 text-[10px] font-semibold';
          gtiBadge.textContent = 'Created • Verify';
        }
        if (gtiPill) gtiPill.title = `GTI Key Created (${maskedGti}) — Click to validate`;
        if (modalTabBadgeGti) {
          modalTabBadgeGti.className = 'px-1.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[10px] font-semibold';
          modalTabBadgeGti.textContent = 'Created';
        }
        if (stepValidatedGti) stepValidatedGti.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-amber-950/30 border border-amber-500/40 text-amber-200';
        if (stepValidatedIconGti) stepValidatedIconGti.className = 'fa-solid fa-clock text-sm text-amber-400';
        if (stepValidatedSubGti) stepValidatedSubGti.textContent = 'Click Test GTI v3 Connection to validate';

        if (gtiStatusLabel) {
          gtiStatusLabel.textContent = `Key Created (${maskedGti}) • Pending Validation`;
          gtiStatusLabel.className = 'text-[11px] text-amber-400 font-mono font-semibold';
        }
        if (gtiStatusSpan) {
          gtiStatusSpan.textContent = 'Created (Click Test Connection to Validate)';
          gtiStatusSpan.className = 'font-mono text-amber-400 font-semibold';
        }
      }
    } else {
      if (gtiPill) gtiPill.className = `${isGtiTab ? '' : 'hidden '}inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 cursor-pointer whitespace-nowrap flex-shrink-0 transition`;
      if (gtiDot) gtiDot.className = 'w-2 h-2 rounded-full bg-cyan-400 animate-pulse flex-shrink-0';
      if (gtiIcon) gtiIcon.className = 'fa-solid fa-key text-[11px]';
      if (gtiText) gtiText.textContent = 'Credentials';
      if (gtiBadge) {
        gtiBadge.className = 'px-1.5 py-0.5 rounded-full bg-cyan-500/20 border border-cyan-500/30 text-cyan-200 text-[10px] font-mono';
        gtiBadge.textContent = 'Not Set';
      }
      if (gtiPill) gtiPill.title = 'No GTI Credentials configured. Click to enter or upload your GTI x-apikey.';
      if (modalTabBadgeGti) {
        modalTabBadgeGti.className = 'px-1.5 py-0.5 rounded-full bg-gray-800 text-gray-400 text-[10px] font-mono';
        modalTabBadgeGti.textContent = 'Not Set';
      }
      if (stepCreatedGti) stepCreatedGti.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-gray-900/80 border border-gray-800 text-gray-400';
      if (stepCreatedIconGti) stepCreatedIconGti.className = 'fa-regular fa-circle text-sm text-gray-500';
      if (stepCreatedSubGti) stepCreatedSubGti.textContent = 'Awaiting GTI x-apikey';
      if (stepValidatedGti) stepValidatedGti.className = 'flex items-center space-x-2.5 px-3 py-2 rounded-md bg-gray-900/80 border border-gray-800 text-gray-400';
      if (stepValidatedIconGti) stepValidatedIconGti.className = 'fa-regular fa-circle text-sm text-gray-500';
      if (stepValidatedSubGti) stepValidatedSubGti.textContent = 'Pending live GTI v3 verification';

      if (gtiStatusLabel) {
        gtiStatusLabel.textContent = 'Not configured (AES-256 encrypted storage ready)';
        gtiStatusLabel.className = 'text-[11px] text-gray-500 font-mono';
      }
      if (btnRemoveGtiKey) btnRemoveGtiKey.classList.add('hidden');
      if (gtiCard) gtiCard.classList.add('hidden');
    }

    updatePlatformAuthBanner();

    if (state.selectedEndpoint) {
      selectEndpoint(state.selectedEndpoint);
    }
  } catch (err) {
    console.error('Failed to load configuration:', err);
  }
}

function openConfigModal(initialTab = null) {
  document.getElementById('config-modal').classList.remove('hidden');
  document.getElementById('modal-test-result').classList.add('hidden');
  const targetTab = initialTab || state.activePlatform || 'secops';
  switchConfigModalTab(targetTab);
}

function switchConfigModalTab(tab) {
  const btnSecops = document.getElementById('cfg-tab-btn-secops');
  const btnGti = document.getElementById('cfg-tab-btn-gti');
  const panelSecops = document.getElementById('cfg-panel-secops');
  const panelGti = document.getElementById('cfg-panel-gti');
  const footerSecops = document.getElementById('cfg-footer-secops');
  const footerGti = document.getElementById('cfg-footer-gti');
  const testResult = document.getElementById('modal-test-result');
  if (testResult) testResult.classList.add('hidden');

  if (tab === 'gti') {
    if (btnGti) btnGti.className = 'px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 border-cyan-500 text-cyan-300 bg-[#111827] flex items-center space-x-1.5 transition';
    if (btnSecops) btnSecops.className = 'px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 border-transparent text-gray-400 hover:text-gray-200 flex items-center space-x-1.5 transition';
    if (panelGti) panelGti.classList.remove('hidden');
    if (panelSecops) panelSecops.classList.add('hidden');
    if (footerGti) footerGti.classList.remove('hidden');
    if (footerSecops) footerSecops.classList.add('hidden');
  } else {
    if (btnSecops) btnSecops.className = 'px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 border-blue-500 text-blue-300 bg-[#111827] flex items-center space-x-1.5 transition';
    if (btnGti) btnGti.className = 'px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 border-transparent text-gray-400 hover:text-gray-200 flex items-center space-x-1.5 transition';
    if (panelSecops) panelSecops.classList.remove('hidden');
    if (panelGti) panelGti.classList.add('hidden');
    if (footerSecops) footerSecops.classList.remove('hidden');
    if (footerGti) footerGti.classList.add('hidden');
  }
}

function closeConfigModal() {
  document.getElementById('config-modal').classList.add('hidden');
}

function handleGtiFileSelect(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    let raw = (e.target.result || '').trim();
    // If JSON file with api_key or x-apikey field, extract it
    if (raw.startsWith('{')) {
      try {
        const parsed = JSON.parse(raw);
        raw = (parsed.api_key || parsed['x-apikey'] || parsed.gti_api_key || parsed.key || '').trim();
      } catch (err) {}
    }
    if (raw) {
      const input = document.getElementById('cfg-gti-api-key');
      if (input) input.value = raw;
      await saveGtiConfiguration();
    } else {
      showToast('Could not find an API key in the uploaded file', 'error');
    }
  };
  reader.readAsText(file);
}

async function saveGtiConfiguration() {
  const keyInput = document.getElementById('cfg-gti-api-key');
  const endpointInput = document.getElementById('cfg-gti-endpoint');
  const apiKey = keyInput ? keyInput.value.trim() : '';
  const gtiEndpoint = endpointInput ? endpointInput.value.trim() : 'https://www.virustotal.com';

  if (!apiKey && (!state.config || !state.config.has_gti_key)) {
    showToast('Please enter or upload your Google Threat Intelligence (VirusTotal v3) x-apikey.', 'warning');
    return;
  }

  try {
    if (apiKey) {
      const res = await fetch('/api/gti/auth/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey, gti_endpoint: gtiEndpoint })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        if (keyInput) keyInput.value = '';
        showToast(data.message || 'GTI API key encrypted and saved!', data.is_authenticated ? 'success' : 'info');
        await loadConfig();
        const resultBox = document.getElementById('modal-test-result');
        if (resultBox) {
          resultBox.classList.remove('hidden');
          resultBox.className = data.is_authenticated
            ? 'p-3 rounded-lg border text-xs bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
            : 'p-3 rounded-lg border text-xs bg-amber-950/30 border-amber-500/40 text-amber-300';
          resultBox.innerHTML = `<div class="font-semibold">${escapeHtml(data.message)}</div>`;
        }
      } else {
        showToast(data.error || 'Failed to save GTI key', 'error');
      }
    } else {
      // Updating endpoint only
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gti_endpoint: gtiEndpoint })
      });
      if (res.ok) {
        showToast('GTI endpoint updated!', 'success');
        await loadConfig();
      }
    }
  } catch (err) {
    showToast('Error saving GTI configuration: ' + err.message, 'error');
  }
}

async function removeStoredGtiKey() {
  if (!confirm('Remove the stored encrypted Google Threat Intelligence API key?')) return;
  try {
    const res = await fetch('/api/gti/auth/remove', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast('Encrypted GTI API key removed', 'info');
      const keyInput = document.getElementById('cfg-gti-api-key');
      if (keyInput) keyInput.value = '';
      await loadConfig();
    } else {
      showToast(data.error || 'Failed to remove GTI key', 'error');
    }
  } catch (err) {
    showToast('Error removing GTI key: ' + err.message, 'error');
  }
}

async function testGtiConnectionFromModal() {
  const resultBox = document.getElementById('modal-test-result');
  resultBox.className = 'p-3 rounded-lg border text-xs bg-gray-900 border-gray-700 text-gray-300';
  resultBox.innerHTML = `<i class="fa-solid fa-spinner spin mr-2 text-cyan-400"></i>Testing connection to Google Threat Intelligence (/api/v3/ip_addresses/8.8.8.8)...`;
  resultBox.classList.remove('hidden');

  try {
    const res = await fetch('/api/gti/auth/test', { method: 'POST' });
    const data = await res.json();
    await loadConfig();
    if (data.success) {
      resultBox.className = 'p-3 rounded-lg border text-xs bg-emerald-950/30 border-emerald-500/40 text-emerald-300';
      resultBox.innerHTML = `
        <div class="font-bold flex items-center space-x-1.5 mb-1">
          <i class="fa-solid fa-circle-check text-emerald-400"></i>
          <span>GTI v3 Connection Verified (HTTP ${data.status_code} - ${data.elapsed_ms}ms)</span>
        </div>
        <div>${escapeHtml(data.message)}</div>
      `;
    } else {
      resultBox.className = 'p-3 rounded-lg border text-xs bg-red-950/30 border-red-500/40 text-red-300';
      resultBox.innerHTML = `
        <div class="font-bold flex items-center space-x-1.5 mb-1">
          <i class="fa-solid fa-circle-xmark text-red-400"></i>
          <span>GTI v3 Connection Failed (${data.status_code || 'Error'} - ${data.elapsed_ms || 0}ms)</span>
        </div>
        <div class="font-mono mt-1">${escapeHtml(data.error || 'Verify x-apikey permissions')}</div>
      `;
    }
  } catch (err) {
    resultBox.className = 'p-3 rounded-lg border text-xs bg-red-950/30 border-red-500/40 text-red-300';
    resultBox.innerHTML = `Connection request failed: ${escapeHtml(err.message)}`;
  }
}

function triggerSaFileSelect(event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const fileInput = document.getElementById('sa-file-input');
  if (fileInput) {
    fileInput.value = '';
    fileInput.click();
  }
}

function clearSaInput() {
  const fileInput = document.getElementById('sa-file-input');
  if (fileInput) {
    fileInput.value = '';
  }
}

async function removeStoredKey() {
  if (!confirm('Are you sure you want to remove the stored encrypted Service Account key? You will need to upload a key again to run requests.')) {
    return;
  }
  try {
    const res = await fetch('/api/auth/remove', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast('Encrypted key removed successfully', 'info');
      clearSaInput();
      await loadConfig();
    } else {
      showToast(data.error || 'Failed to remove key', 'error');
    }
  } catch (err) {
    showToast('Error removing key: ' + err.message, 'error');
  }
}

function updateEndpointFromLocation() {
  const loc = document.getElementById('cfg-location').value;
  document.getElementById('cfg-endpoint').value = `https://${loc}-chronicle.googleapis.com`;
}

async function uploadSaKeyContent(content, filename = '') {
  if (!content) return false;
  const cleanContent = content.replace(/^\uFEFF/, '').trim();
  if (!cleanContent) return false;

  let parsed = null;
  try {
    parsed = jsonLint(cleanContent);
    if (!parsed || typeof parsed !== 'object') {
      showToast('Invalid JSON file format: expected a JSON object', 'error');
      return false;
    }
    if (!parsed.client_email || !parsed.private_key) {
      showToast('Invalid Service Account JSON: missing "client_email" or "private_key" fields', 'error');
      return false;
    }
  } catch (err) {
    showToast('Invalid JSON syntax in uploaded file: ' + err.message, 'error');
    return false;
  }

  // Immediately identify and populate Project ID if present in the SA JSON
  const detectedProject = (parsed.project_id || '').trim();
  const projectInput = document.getElementById('cfg-project-id');
  if (detectedProject && projectInput && !projectInput.value.trim()) {
    projectInput.value = detectedProject;
  } else if (detectedProject && projectInput) {
    projectInput.value = detectedProject;
  }

  const currentProjectId = (projectInput ? projectInput.value.trim() : '') || detectedProject;
  const currentCustomerId = (document.getElementById('cfg-customer-id')?.value || '').trim();
  const currentLocation = document.getElementById('cfg-location')?.value || 'us';
  const currentEndpoint = (document.getElementById('cfg-endpoint')?.value || '').trim();

  const saStatusLabel = document.getElementById('sa-status-label');
  if (saStatusLabel) {
    saStatusLabel.textContent = 'Identifying, encrypting & verifying key...';
    saStatusLabel.className = 'text-[11px] text-cyan-400 font-mono';
  }

  const resultBox = document.getElementById('modal-test-result');
  if (resultBox) {
    resultBox.className = 'p-3 rounded-lg border text-xs bg-blue-950/30 border-blue-500/40 text-blue-300';
    resultBox.innerHTML = `<i class="fa-solid fa-spinner spin mr-2 text-blue-400"></i>Identifying Service Account key ${filename ? `(<code class="text-white">${escapeHtml(filename)}</code>)` : ''} and verifying OAuth2 token...`;
    resultBox.classList.remove('hidden');
  }

  showToast('Identifying & encrypting Service Account key...', 'info');

  try {
    const authRes = await fetch('/api/auth/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_account_json: cleanContent,
        project_id: currentProjectId,
        customer_id: currentCustomerId,
        location: currentLocation,
        endpoint: currentEndpoint
      })
    });
    const authData = await authRes.json();

    if (!authRes.ok) {
      showToast(authData.error || 'Failed to authenticate Service Account', 'error');
      if (saStatusLabel) {
        saStatusLabel.textContent = 'Identification failed';
        saStatusLabel.className = 'text-[11px] text-rose-400 font-mono';
      }
      if (resultBox) {
        resultBox.className = 'p-3 rounded-lg border text-xs bg-red-950/30 border-red-500/40 text-red-300';
        resultBox.innerHTML = `<strong>Upload Error:</strong> ${escapeHtml(authData.error || 'Failed to process Service Account JSON')}`;
      }
      return false;
    }

    const maskedEmail = authData.client_email_masked || authData.client_email || 'Service Account';

    if (authData.warning) {
      showToast(authData.warning, 'warning');
      if (resultBox) {
        resultBox.className = 'p-3 rounded-lg border text-xs bg-amber-950/30 border-amber-500/40 text-amber-300';
        resultBox.innerHTML = `
          <div class="font-bold flex items-center space-x-1.5 mb-1">
            <i class="fa-solid fa-triangle-exclamation text-amber-400"></i>
            <span>Service Account Key Identified (${escapeHtml(maskedEmail)}) — Verification Warning</span>
          </div>
          <div>${escapeHtml(authData.warning)}</div>
        `;
      }
    } else {
      showToast(`Identified & verified Service Account: ${maskedEmail}`, 'success');
      if (resultBox) {
        resultBox.className = 'p-3 rounded-lg border text-xs bg-emerald-950/30 border-emerald-500/40 text-emerald-300';
        resultBox.innerHTML = `
          <div class="font-bold flex items-center space-x-1.5 mb-1">
            <i class="fa-solid fa-circle-check text-emerald-400"></i>
            <span>Service Account Identified & Verified (${escapeHtml(maskedEmail)})</span>
          </div>
          <div>Project ID: <code class="text-emerald-200 font-mono">${escapeHtml(authData.project_id || currentProjectId)}</code> • Encrypted with AES-256 Fernet at rest.</div>
        `;
      }
    }

    await loadConfig();
    return true;
  } catch (err) {
    showToast('Error uploading key: ' + err.message, 'error');
    if (saStatusLabel) {
      saStatusLabel.textContent = 'Upload error';
      saStatusLabel.className = 'text-[11px] text-rose-400 font-mono';
    }
    return false;
  }
}

function handleSaFileSelect(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e) => {
    const content = e.target.result;
    await uploadSaKeyContent(content, file.name);
    event.target.value = '';
  };
  reader.readAsText(file);
}

function handleSaDragOver(event) {
  event.preventDefault();
  event.stopPropagation();
  const dropzone = document.getElementById('sa-dropzone');
  if (dropzone) dropzone.classList.add('border-blue-400', 'bg-[#1a233b]');
}

function handleSaDragLeave(event) {
  event.preventDefault();
  event.stopPropagation();
  const dropzone = document.getElementById('sa-dropzone');
  if (dropzone) dropzone.classList.remove('border-blue-400', 'bg-[#1a233b]');
}

function handleSaDrop(event) {
  event.preventDefault();
  event.stopPropagation();
  const dropzone = document.getElementById('sa-dropzone');
  if (dropzone) dropzone.classList.remove('border-blue-400', 'bg-[#1a233b]');

  const dt = event.dataTransfer;
  if (!dt || !dt.files || dt.files.length === 0) return;
  const file = dt.files[0];

  const reader = new FileReader();
  reader.onload = async (e) => {
    const content = e.target.result;
    await uploadSaKeyContent(content, file.name);
  };
  reader.readAsText(file);
}

async function saveConfiguration() {
  const projectId = document.getElementById('cfg-project-id').value.trim();
  const customerId = document.getElementById('cfg-customer-id').value.trim();
  const location = document.getElementById('cfg-location').value;
  const endpoint = document.getElementById('cfg-endpoint').value.trim();

  // Update parameters
  try {
    const cfgRes = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        customer_id: customerId,
        location: location,
        endpoint: endpoint
      })
    });
    if (cfgRes.ok) {
      showToast('Configuration saved successfully!', 'success');
      closeConfigModal();
      await loadConfig();
    } else {
      showToast('Failed to update config', 'error');
    }
  } catch (err) {
    showToast('Network error saving config: ' + err.message, 'error');
  }
}

async function testConnection() {
  const btn = document.getElementById('btn-test-ping');
  const originalHtml = btn.innerHTML;
  btn.innerHTML = `<i class="fa-solid fa-spinner spin text-amber-400 mr-1.5"></i><span>Pinging...</span>`;
  btn.disabled = true;

  try {
    const endpointUrl = state.activePlatform === 'gti' ? '/api/gti/auth/test' : '/api/auth/test';
    const res = await fetch(endpointUrl, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`Ping Successful! HTTP ${data.status_code} in ${data.elapsed_ms}ms`, 'success');
      await loadConfig();
    } else {
      showToast(`Ping Failed: ${data.error || 'Unknown error'} (${data.elapsed_ms || 0}ms)`, 'error');
    }
  } catch (err) {
    showToast('Ping error: ' + err.message, 'error');
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

async function testConnectionFromModal() {
  const resultBox = document.getElementById('modal-test-result');
  resultBox.className = 'p-3 rounded-lg border text-xs bg-gray-900 border-gray-700 text-gray-300';
  resultBox.innerHTML = `<i class="fa-solid fa-spinner spin mr-2 text-blue-400"></i>Testing connection to Chronicle v1alpha API...`;
  resultBox.classList.remove('hidden');

  try {
    const res = await fetch('/api/auth/test', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      resultBox.className = 'p-3 rounded-lg border text-xs bg-emerald-950/30 border-emerald-500/40 text-emerald-300';
      resultBox.innerHTML = `
        <div class="font-bold flex items-center space-x-1.5 mb-1">
          <i class="fa-solid fa-circle-check text-emerald-400"></i>
          <span>Connection Verified (200 OK - ${data.elapsed_ms}ms)</span>
        </div>
        <div>${escapeHtml(data.message)}</div>
      `;
      await loadConfig();
    } else {
      resultBox.className = 'p-3 rounded-lg border text-xs bg-red-950/30 border-red-500/40 text-red-300';
      resultBox.innerHTML = `
        <div class="font-bold flex items-center space-x-1.5 mb-1">
          <i class="fa-solid fa-circle-xmark text-red-400"></i>
          <span>Connection Failed (${data.status_code || 'Error'} - ${data.elapsed_ms}ms)</span>
        </div>
        <div class="font-mono mt-1">${escapeHtml(data.error || 'Check customer ID and permissions')}</div>
      `;
    }
  } catch (err) {
    resultBox.className = 'p-3 rounded-lg border text-xs bg-red-950/30 border-red-500/40 text-red-300';
    resultBox.innerHTML = `Connection request failed: ${escapeHtml(err.message)}`;
  }
}

// -----------------------------------------------------------------------------
// USER IDENTITY & AUTHENTICATION (Open Access - Non-blocking)
// -----------------------------------------------------------------------------

async function checkAuthUser() {
  try {
    const res = await fetch('/api/auth/user');
    const data = await res.json();
    const pill = document.getElementById('iap-user-pill');
    const emailSpan = document.getElementById('iap-user-email');

    if (res.ok && data.user) {
      state.user = data.user;
      if (pill && emailSpan) {
        if (data.user.email && data.user.email !== 'anonymous' && data.user.email !== 'iam-user') {
          emailSpan.textContent = data.user.email;
          pill.classList.remove('hidden');
          pill.title = `IAM User: ${data.user.email}`;
        } else {
          pill.classList.add('hidden');
        }
      }
    } else {
      state.user = { email: 'iam-user', name: 'IAM User' };
      if (pill) pill.classList.add('hidden');
    }
  } catch (err) {
    state.user = { email: 'iam-user', name: 'IAM User' };
  }
}

function openLoginModal() {}
function closeLoginModal() {}
async function submitLogin() {}
async function logoutUser() {}



// -----------------------------------------------------------------------------
// HTTP METHODS & REST GUIDE (Requirement 4)
// -----------------------------------------------------------------------------

function initMethodGuide() {
  handleMethodChange();
}

function handleMethodChange() {
  const methodSelect = document.getElementById('req-method');
  const badge = document.getElementById('method-guide-badge');
  const summary = document.getElementById('method-guide-summary');
  const bodyBadge = document.getElementById('req-body-badge');
  if (!methodSelect || !badge || !summary) return;

  const method = methodSelect.value.toUpperCase();
  badge.className = `method-badge ${getMethodClass(method)}`;
  badge.textContent = method;

  const summaries = {
    GET: 'Read / Fetch: Retrieves resources or lists without modifying state. No request body needed. Safe & idempotent.',
    POST: 'Create / Action: Creates a new resource or triggers custom AIP actions (e.g. :trigger, :search). Enter required payload in Required Inputs bar or Request Body tab.',
    PATCH: 'Partial Update: Modifies specific fields of an existing resource without full overwrite. Enter fields in Required Inputs bar or Request Body tab.',
    DELETE: 'Remove / Destroy: Permanently deletes a resource by ID. Irreversible destructive action. No request body.',
    PUT: 'Full Replacement: Overwrites an entire resource entity with the provided JSON payload. Enter payload in Request Body tab.'
  };

  summary.textContent = summaries[method] || 'Standard HTTP request method.';

  if (bodyBadge) {
    if (['POST', 'PATCH', 'PUT'].includes(method)) {
      bodyBadge.classList.remove('hidden');
    } else {
      bodyBadge.classList.add('hidden');
    }
  }

  if (typeof renderRequiredInputsBar === 'function') {
    renderRequiredInputsBar();
  }
}

function openMethodGuideModal() {
  const modal = document.getElementById('method-guide-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeMethodGuideModal() {
  const modal = document.getElementById('method-guide-modal');
  if (modal) modal.classList.add('hidden');
}

function loadGuideEndpoint(target) {
  closeMethodGuideModal();
  if (target === 'projects.locations.instances.feeds_list' || target === 'feeds_list') {
    selectPreset('feeds_list');
  } else if (target === 'projects.locations.instances_search' || target === 'search_udm') {
    selectPreset('search_udm');
  } else {
    const ep = (state.catalog.endpoints || []).find(e => e.id === target);
    if (ep) {
      selectEndpoint(ep);
    } else {
      selectPreset('feeds_list');
    }
  }
}



// -----------------------------------------------------------------------------
// ABOUT & AUTHOR DISCLAIMER MODAL (Requirement 6)
// -----------------------------------------------------------------------------

function openAboutModal() {
  const modal = document.getElementById('about-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeAboutModal() {
  const modal = document.getElementById('about-modal');
  if (modal) modal.classList.add('hidden');
}

// -----------------------------------------------------------------------------
// CATALOG & EXPLORER
// -----------------------------------------------------------------------------

async function loadCatalog(platform = null) {
  const targetPlatform = platform || state.activePlatform || 'secops';
  try {
    let data = null;
    if (targetPlatform === 'gti') {
      if (!state.gtiCatalog) {
        const res = await fetch('/api/catalog?platform=gti');
        state.gtiCatalog = await res.json();
      }
      data = state.gtiCatalog;
    } else {
      if (!state.secopsCatalog) {
        const res = await fetch('/api/catalog?platform=secops');
        state.secopsCatalog = await res.json();
      }
      data = state.secopsCatalog;
    }

    state.catalog = data;
    state.filteredEndpoints = data.endpoints || [];
    const totalCount = data.total || data.endpoints.length;
    document.getElementById('total-endpoint-count').textContent = totalCount.toLocaleString();
    const tabBadge = document.getElementById(targetPlatform === 'gti' ? 'gti-tab-count' : 'secops-tab-count');
    if (tabBadge) tabBadge.textContent = totalCount.toLocaleString();
    const presetCountEl = document.getElementById('preset-count');
    if (presetCountEl) presetCountEl.textContent = (data.presets || []).length;

    // Dynamically populate Category Filter dropdown for active platform
    const catSelect = document.getElementById('category-filter');
    if (catSelect) {
      const categories = [];
      (data.endpoints || []).forEach(ep => {
        if (ep.category && !categories.includes(ep.category)) {
          categories.push(ep.category);
        }
      });
      catSelect.innerHTML = `<option value="ALL">All Categories (${data.total || data.endpoints.length})</option>` +
        categories.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
    }

    renderPresets();
    filterEndpoints();
  } catch (err) {
    console.error('Failed to load catalog:', err);
    showToast('Failed to load API catalog', 'error');
  }
}

async function loadFavorites() {
  try {
    const res = await fetch('/api/favorites');
    const data = await res.json();
    state.favorites = new Set((data.favorites || []).map(f => f.endpoint_id));
    document.getElementById('fav-count').textContent = state.favorites.size;
    renderFavorites();
  } catch (err) {
    console.error('Failed to load favorites:', err);
  }
}

async function toggleFavorite(endpointId, event) {
  if (event) event.stopPropagation();
  try {
    const res = await fetch('/api/favorites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint_id: endpointId })
    });
    const data = await res.json();
    if (data.favorited) {
      state.favorites.add(endpointId);
      showToast('Added to Starred', 'info');
    } else {
      state.favorites.delete(endpointId);
      showToast('Removed from Starred', 'info');
    }
    document.getElementById('fav-count').textContent = state.favorites.size;
    renderFavorites();
    renderEndpoints();
  } catch (err) {
    console.error('Error toggling favorite:', err);
  }
}

function switchSidebarTab(tab) {
  state.activeSidebarTab = tab;
  const tabs = ['presets', 'all', 'favorites'];
  tabs.forEach(t => {
    const navBtn = document.getElementById(`tab-nav-${t}`);
    const panel = document.getElementById(`${t === 'all' ? 'endpoints' : t}-panel`);
    if (t === tab) {
      navBtn.className = 'flex-1 py-1 text-center border-b-2 border-blue-500 text-blue-400 font-medium transition';
      panel.classList.remove('hidden');
    } else {
      navBtn.className = 'flex-1 py-1 text-center border-b-2 border-transparent text-gray-400 hover:text-gray-200 transition';
      panel.classList.add('hidden');
    }
  });

  // If user switches tab, re-render appropriate list
  if (tab === 'presets') renderPresets();
  else if (tab === 'favorites') renderFavorites();
  else if (tab === 'all') {
    const tokens = getSearchTokens();
    renderEndpoints(tokens);
  }
}

function handleSearchKey(event) {
  if (event.key === 'Enter') {
    event.preventDefault();
    // 1-Click select top matched item on Enter
    if (state.filteredPresets && state.filteredPresets.length > 0) {
      selectPreset(state.filteredPresets[0].id);
      showToast(`Selected preset: ${state.filteredPresets[0].title}`, 'info');
    } else if (state.filteredEndpoints && state.filteredEndpoints.length > 0) {
      selectEndpoint(state.filteredEndpoints[0]);
      showToast(`Selected: ${state.filteredEndpoints[0].title}`, 'info');
    }
  } else if (event.key === 'Escape') {
    clearSearch();
  }
}

function setQuickSearch(term) {
  const input = document.getElementById('endpoint-search');
  input.value = term;
  filterEndpoints();
  input.focus();
}

function getSearchTokens() {
  const input = document.getElementById('endpoint-search');
  if (!input) return [];
  return input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

function highlightText(text, tokens) {
  if (!text) return '';
  const escaped = escapeHtml(String(text));
  if (!tokens || tokens.length === 0) return escaped;

  const safeTokens = tokens.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).filter(Boolean);
  if (safeTokens.length === 0) return escaped;

  const regex = new RegExp(`(${safeTokens.join('|')})`, 'gi');
  return escaped.replace(regex, '<mark class="bg-blue-500/30 text-blue-200 px-0.5 rounded font-semibold">$1</mark>');
}

function renderPresets() {
  const container = document.getElementById('presets-list');
  container.innerHTML = '';

  const tokens = getSearchTokens();

  state.catalog.presets.forEach(p => {
    const ep = state.catalog.endpoints.find(e => e.id === p.endpoint_id);
    const method = ep ? ep.httpMethod : 'GET';
    const methodClass = getMethodClass(method);

    const div = document.createElement('div');
    div.className = 'preset-pill p-2 rounded-lg bg-[#121827] border border-gray-800 flex items-start space-x-2.5 cursor-pointer hover:border-blue-500/40 transition';
    div.onclick = () => selectPreset(p.id);

    div.innerHTML = `
      <span class="method-badge ${methodClass} mt-0.5">${method}</span>
      <div class="flex-1 min-w-0">
        <div class="font-semibold text-xs text-gray-200 truncate">${highlightText(p.title, tokens)}</div>
        <div class="text-[11px] text-gray-400 truncate mt-0.5">${highlightText(p.description, tokens)}</div>
      </div>
      <i class="fa-solid fa-chevron-right text-gray-600 text-xs mt-1"></i>
    `;
    container.appendChild(div);
  });
}

function filterEndpoints() {
  const searchInput = document.getElementById('endpoint-search');
  const rawQuery = searchInput.value.trim();
  const category = document.getElementById('category-filter').value;
  const method = document.getElementById('method-filter').value;
  const clearBtn = document.getElementById('search-clear-btn');

  const tokens = rawQuery.toLowerCase().split(/\s+/).filter(Boolean);

  if (tokens.length > 0) {
    clearBtn.classList.remove('hidden');
    // Seamlessly switch to endpoints view while searching
    if (state.activeSidebarTab !== 'all') {
      switchSidebarTab('all');
    }
  } else {
    clearBtn.classList.add('hidden');
  }

  // Filter Presets matching query tokens
  state.filteredPresets = (state.catalog.presets || []).filter(preset => {
    if (tokens.length === 0) return true;
    const target = [
      preset.title || '',
      preset.description || '',
      preset.id || '',
      preset.endpoint_id || ''
    ].join(' ').toLowerCase();
    return tokens.every(token => target.includes(token));
  });

  // Filter Endpoints matching query tokens and dropdown filters
  state.filteredEndpoints = (state.catalog.endpoints || []).filter(ep => {
    if (category !== 'ALL' && ep.category !== category) return false;
    if (method !== 'ALL' && ep.httpMethod !== method) return false;
    if (tokens.length === 0) return true;

    const target = [
      ep.title || '',
      ep.resource || '',
      ep.method || '',
      ep.urlPath || '',
      ep.category || '',
      ep.httpMethod || '',
      (ep.tags || []).join(' ')
    ].join(' ').toLowerCase();

    return tokens.every(token => target.includes(token));
  });

  state.renderedEndpointCount = 60;

  // Update label
  const label = document.getElementById('endpoints-count-label');
  if (tokens.length > 0) {
    const presetMsg = state.filteredPresets.length > 0 ? ` & ${state.filteredPresets.length} preset(s)` : '';
    label.innerHTML = `
      <span>Found <strong class="text-blue-400 font-bold">${state.filteredEndpoints.length}</strong> endpoints${presetMsg}</span>
      <span class="text-[10px] text-gray-500">Press <kbd class="px-1 bg-gray-800 rounded font-mono text-gray-300">Enter</kbd> to select</span>
    `;
  } else {
    label.innerHTML = `<span>Showing ${state.filteredEndpoints.length} of ${state.catalog.total || state.catalog.endpoints.length} endpoints</span>`;
  }

  renderEndpoints(tokens);
}

function clearSearch() {
  document.getElementById('endpoint-search').value = '';
  document.getElementById('category-filter').value = 'ALL';
  document.getElementById('method-filter').value = 'ALL';
  filterEndpoints();
}

function renderEndpoints(tokens = null) {
  if (!tokens) tokens = getSearchTokens();
  const container = document.getElementById('endpoints-list');
  const presetsSection = document.getElementById('search-presets-section');
  const presetsList = document.getElementById('search-presets-list');
  container.innerHTML = '';
  presetsList.innerHTML = '';

  const isSearching = tokens && tokens.length > 0;

  // 1. Render Matching Presets (only when searching and matches exist)
  if (isSearching && state.filteredPresets && state.filteredPresets.length > 0) {
    presetsSection.classList.remove('hidden');
    state.filteredPresets.slice(0, 4).forEach(p => {
      const ep = state.catalog.endpoints.find(e => e.id === p.endpoint_id);
      const method = ep ? ep.httpMethod : 'POST';
      const methodClass = getMethodClass(method);

      const div = document.createElement('div');
      div.className = 'preset-pill p-2 rounded-lg bg-[#141e33] border border-blue-500/40 hover:border-blue-400 flex items-start space-x-2.5 cursor-pointer shadow-sm transition';
      div.onclick = () => selectPreset(p.id);

      div.innerHTML = `
        <span class="method-badge ${methodClass} mt-0.5">${method}</span>
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-xs text-blue-200 truncate">${highlightText(p.title, tokens)}</div>
          <div class="text-[11px] text-gray-400 truncate mt-0.5">${highlightText(p.description, tokens)}</div>
        </div>
        <span class="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono flex-shrink-0">Preset</span>
      `;
      presetsList.appendChild(div);
    });
  } else if (presetsSection) {
    presetsSection.classList.add('hidden');
  }

  // 2. Empty State if nothing matches
  if (state.filteredEndpoints.length === 0 && (!isSearching || (state.filteredPresets && state.filteredPresets.length === 0))) {
    const query = document.getElementById('endpoint-search').value.trim();
    container.innerHTML = `
      <div class="p-5 text-center text-gray-400 space-y-3 bg-gray-900/40 rounded-lg border border-gray-800/80 my-2">
        <div class="w-10 h-10 rounded-full bg-gray-800 flex items-center justify-center mx-auto text-gray-500">
          <i class="fa-solid fa-magnifying-glass text-sm"></i>
        </div>
        <div>
          <div class="text-xs font-semibold text-gray-200">No endpoints found</div>
          <p class="text-[11px] text-gray-500 mt-1">No Chronicle endpoints matched "${escapeHtml(query)}".</p>
        </div>
        <div class="pt-1">
          <div class="text-[10px] uppercase tracking-wider font-semibold text-gray-500 mb-1.5">Try popular searches:</div>
          <div class="flex flex-wrap gap-1.5 justify-center">
            <button onclick="setQuickSearch('feeds')" class="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] border border-gray-700 transition">feeds</button>
            <button onclick="setQuickSearch('search')" class="px-2 py-0.5 bg-blue-900/30 hover:bg-blue-800/40 text-blue-300 rounded text-[11px] border border-blue-700/50 transition">search</button>
            <button onclick="setQuickSearch('rules')" class="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] border border-gray-700 transition">rules</button>
            <button onclick="setQuickSearch('alerts')" class="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] border border-gray-700 transition">alerts</button>
            <button onclick="setQuickSearch('cases')" class="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] border border-gray-700 transition">cases</button>
            <button onclick="setQuickSearch('raw logs')" class="px-2 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] border border-gray-700 transition">raw logs</button>
          </div>
        </div>
        <button onclick="clearSearch()" class="text-xs text-blue-400 hover:underline pt-1 block mx-auto">
          Clear Search & Filters
        </button>
      </div>
    `;
    return;
  }

  // 3. Render Endpoints Slice
  const slice = state.filteredEndpoints.slice(0, state.renderedEndpointCount);
  slice.forEach(ep => {
    const isSelected = state.selectedEndpoint && state.selectedEndpoint.id === ep.id;
    const isFav = state.favorites.has(ep.id);
    const methodClass = getMethodClass(ep.httpMethod);

    const div = document.createElement('div');
    div.className = `endpoint-item p-2 rounded border border-transparent flex items-center justify-between space-x-2 ${isSelected ? 'active' : ''}`;
    div.onclick = () => selectEndpoint(ep);

    div.innerHTML = `
      <div class="flex items-center space-x-2 min-w-0 flex-1">
        <span class="method-badge ${methodClass}">${ep.httpMethod}</span>
        <div class="truncate min-w-0 flex-1">
          <div class="text-xs font-medium text-gray-200 truncate">${highlightText(ep.title, tokens)}</div>
          <div class="text-[10px] font-mono text-gray-500 truncate mt-0.5">${highlightText(ep.urlPath, tokens)}</div>
        </div>
      </div>
      <button class="text-xs ${isFav ? 'text-amber-400' : 'text-gray-600 hover:text-gray-400'} p-1 transition flex-shrink-0" 
              onclick="toggleFavorite('${ep.id}', event)" title="Star endpoint">
        <i class="${isFav ? 'fa-solid' : 'fa-regular'} fa-star"></i>
      </button>
    `;
    container.appendChild(div);
  });

  // Load More Button if results exceed slice
  if (state.renderedEndpointCount < state.filteredEndpoints.length) {
    const loadMoreBtn = document.createElement('button');
    loadMoreBtn.className = 'w-full py-2 text-center text-xs text-blue-400 hover:text-blue-300 font-medium bg-gray-900/50 hover:bg-gray-800/80 rounded border border-gray-800 mt-2 transition';
    loadMoreBtn.innerHTML = `Load More (${state.filteredEndpoints.length - state.renderedEndpointCount} remaining)`;
    loadMoreBtn.onclick = () => {
      state.renderedEndpointCount += 60;
      renderEndpoints(tokens);
    };
    container.appendChild(loadMoreBtn);
  }
}

function renderFavorites() {
  const container = document.getElementById('favorites-list');
  container.innerHTML = '';

  const favEndpoints = state.catalog.endpoints.filter(ep => state.favorites.has(ep.id));
  if (favEndpoints.length === 0) {
    container.innerHTML = `
      <div class="p-4 text-center text-gray-500 text-xs">
        <i class="fa-regular fa-star text-xl mb-2 text-gray-600"></i>
        <p>No starred endpoints yet.</p>
        <p class="text-[11px] mt-1">Click the star icon next to any endpoint to save it here for quick access.</p>
      </div>
    `;
    return;
  }

  favEndpoints.forEach(ep => {
    const isSelected = state.selectedEndpoint && state.selectedEndpoint.id === ep.id;
    const methodClass = getMethodClass(ep.httpMethod);

    const div = document.createElement('div');
    div.className = `endpoint-item p-2 rounded border border-transparent flex items-center justify-between space-x-2 ${isSelected ? 'active' : ''}`;
    div.onclick = () => selectEndpoint(ep);

    div.innerHTML = `
      <div class="flex items-center space-x-2 min-w-0 flex-1">
        <span class="method-badge ${methodClass}">${ep.httpMethod}</span>
        <div class="truncate min-w-0">
          <div class="text-xs font-medium text-gray-200 truncate">${escapeHtml(ep.title)}</div>
          <div class="text-[10px] font-mono text-gray-500 truncate mt-0.5">${escapeHtml(ep.urlPath)}</div>
        </div>
      </div>
      <button class="text-xs text-amber-400 p-1 hover:text-red-400 transition" 
              onclick="toggleFavorite('${ep.id}', event)" title="Remove from starred">
        <i class="fa-solid fa-star"></i>
      </button>
    `;
    container.appendChild(div);
  });
}

// -----------------------------------------------------------------------------
// ENDPOINT SELECTION & REQUEST SETUP
// -----------------------------------------------------------------------------

function selectPreset(presetId) {
  const preset = state.catalog.presets.find(p => p.id === presetId);
  if (!preset) return;

  const endpoint = state.catalog.endpoints.find(e => e.id === preset.endpoint_id);
  if (endpoint) {
    selectEndpoint(endpoint);
    if (preset.defaultPlaceholderValues && typeof preset.defaultPlaceholderValues === 'object') {
      Object.entries(preset.defaultPlaceholderValues).forEach(([tk, val]) => {
        updateUrlPlaceholder(tk, String(val), false);
      });
      renderRequiredInputsBar();
    }
    if (preset.queryParams && typeof preset.queryParams === 'object' && Object.keys(preset.queryParams).length > 0) {
      state.queryParams = Object.entries(preset.queryParams).map(([k, v]) => ({ key: k, value: String(v) }));
      renderQueryParamsTable();
    }
    if (preset.urlOverride) {
      document.getElementById('req-url').value = preset.urlOverride;
    }
  }
}

function quickFillGtiIndicator(type) {
  const indicators = {
    eicar: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    ip: '8.8.8.8',
    domain: 'virustotal.com',
    cve: 'vulnerability--cve-2024-21413',
    actor: 'APT41'
  };
  const baseUrl = state.baseUrlTemplate || document.getElementById('req-url')?.value || '';
  const phRegex = /\{([a-zA-Z0-9_.]+)\}/g;
  let match;
  let filled = false;
  while ((match = phRegex.exec(baseUrl)) !== null) {
    const varName = match[1];
    const token = `{${varName}}`;
    if (varName === 'ip') {
      updateUrlPlaceholder(token, indicators.ip, false);
      filled = true;
    } else if (varName === 'domain') {
      updateUrlPlaceholder(token, indicators.domain, false);
      filled = true;
    } else if (varName === 'vulnerability_id') {
      updateUrlPlaceholder(token, indicators.cve, false);
      filled = true;
    } else if (varName === 'threat_actor_id') {
      updateUrlPlaceholder(token, indicators.actor, false);
      filled = true;
    } else if (varName === 'id' || varName === 'collection_id') {
      const val = indicators[type] || indicators.eicar;
      updateUrlPlaceholder(token, val, false);
      filled = true;
    }
  }
  if (!filled) {
    if (type === 'actor') {
      state.queryParams = [{ key: 'filter', value: 'collection_type:threat-actor name:APT41' }, { key: 'limit', value: '10' }];
      renderQueryParamsTable();
      filled = true;
    } else if (type === 'eicar') {
      state.queryParams = [{ key: 'query', value: `entity:file ${indicators.eicar}` }, { key: 'limit', value: '10' }];
      renderQueryParamsTable();
      filled = true;
    }
  }
  renderRequiredInputsBar();
  showToast(`Filled GTI test indicator (${type.toUpperCase()})`, 'info');
}

function interpolateTenantConfig(url) {
  if (!url) return '';
  const proj = state.config.project_id || document.getElementById('cfg-project-id')?.value?.trim() || '';
  const loc = state.config.location || document.getElementById('cfg-location')?.value?.trim() || 'us';
  const inst = state.config.customer_id || document.getElementById('cfg-customer-id')?.value?.trim() || '';

  if (proj) {
    url = url.replace(/\{(project|projectId)\}/g, proj);
  }
  if (loc) {
    url = url.replace(/\{(location|locations|region)\}/g, loc);
  }
  if (inst) {
    url = url.replace(/\{(instance|instanceId|instances|tenantId)\}/g, inst);
  }
  return url;
}

function selectEndpoint(endpoint) {
  state.selectedEndpoint = endpoint;

  // Set Method and interpolate URL variables with active config
  document.getElementById('req-method').value = endpoint.httpMethod;

  const url = interpolateTenantConfig(endpoint.urlPath);
  state.baseUrlTemplate = url;
  state.urlPlaceholderValues = {};
  document.getElementById('req-url').value = url;

  // Set Documentation Link
  const docLink = document.getElementById('active-doc-link');
  const isGtiEp = (endpoint.urlPath || '').startsWith('/api/v3');
  docLink.href = endpoint.docUrl || (isGtiEp ? 'https://docs.virustotal.com/reference/overview' : 'https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha');
  document.getElementById('endpoint-doc-badge').classList.remove('hidden');

  // Set Documentation tab details
  document.getElementById('doc-title').textContent = endpoint.title;
  document.getElementById('doc-category-badge').textContent = endpoint.category;
  document.getElementById('doc-description').textContent = endpoint.description ? `${endpoint.description} (Resource: ${endpoint.resource} | Method: ${endpoint.method})` : `Resource: ${endpoint.resource} | Method: ${endpoint.method}`;

  // Preload Sample Body if available
  if (endpoint.sampleBody) {
    document.getElementById('req-body-input').value = JSON.stringify(endpoint.sampleBody, null, 2);
    if (['POST', 'PATCH', 'PUT'].includes(endpoint.httpMethod)) {
      switchReqTab('body');
    }
  } else if (['POST', 'PATCH', 'PUT'].includes(endpoint.httpMethod)) {
    document.getElementById('req-body-input').value = '{\n  \n}';
    switchReqTab('body');
  } else {
    document.getElementById('req-body-input').value = '';
    switchReqTab('params');
  }

  // Update HTTP Method badge, summary banner, and Required Inputs bar
  handleMethodChange();

  // Setup query params (e.g. pageSize for SecOps list operations or limit for GTI v3 list operations)
  state.queryParams = [];
  if (endpoint.queryParams && typeof endpoint.queryParams === 'object' && Object.keys(endpoint.queryParams).length > 0) {
    Object.entries(endpoint.queryParams).forEach(([k, v]) => {
      state.queryParams.push({ key: k, value: String(v) });
    });
  } else if (endpoint.method === 'list') {
    if (isGtiEp) {
      state.queryParams.push({ key: 'limit', value: '10' });
    } else {
      state.queryParams.push({ key: 'pageSize', value: '50' });
    }
  }
  renderQueryParamsTable();

  // Re-render list to highlight active item
  const tokens = getSearchTokens();
  renderEndpoints(tokens);
}

// -----------------------------------------------------------------------------
// DYNAMIC REQUIRED INPUTS BAR (URL Placeholders & JSON Body Fields)
// -----------------------------------------------------------------------------

function renderRequiredInputsBar(highlightField = '') {
  const bar = document.getElementById('required-inputs-bar');
  const grid = document.getElementById('required-inputs-grid');
  const hint = document.getElementById('required-inputs-hint');
  const jumpBtn = document.getElementById('btn-jump-to-body');
  if (!bar || !grid) return;

  const method = (document.getElementById('req-method')?.value || 'GET').toUpperCase();
  const baseUrl = state.baseUrlTemplate || document.getElementById('req-url')?.value || '';
  const isBodyMethod = ['POST', 'PATCH', 'PUT'].includes(method);

  // 1. Find any {placeholder} variables in the URL template
  const urlPlaceholders = [];
  const regex = /\{([a-zA-Z0-9_.]+)\}/g;
  let match;
  while ((match = regex.exec(baseUrl)) !== null) {
    const fullToken = match[0]; // e.g. {rule}
    const varName = match[1];   // e.g. rule
    if (!urlPlaceholders.some(p => p.token === fullToken)) {
      urlPlaceholders.push({ token: fullToken, name: varName });
    }
  }

  // 2. Parse JSON Body fields if POST/PATCH/PUT
  let bodyFields = [];
  if (isBodyMethod) {
    const rawBody = document.getElementById('req-body-input')?.value || '';
    try {
      const parsed = JSON.parse(rawBody);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        Object.entries(parsed).forEach(([k, v]) => {
          const isComplex = typeof v === 'object' && v !== null;
          const displayVal = isComplex ? JSON.stringify(v) : (v === null || v === undefined ? '' : String(v));
          bodyFields.push({ key: k, value: displayVal, isComplex });
        });
      }
    } catch (e) {
      // Raw body being edited manually
    }
  }

  if (urlPlaceholders.length === 0 && !isBodyMethod) {
    bar.classList.add('hidden');
    return;
  }

  bar.classList.remove('hidden');
  if (jumpBtn) {
    if (isBodyMethod) jumpBtn.classList.remove('hidden');
    else jumpBtn.classList.add('hidden');
  }

  if (highlightField && hint) {
    hint.innerHTML = `<span class="text-amber-300 font-semibold"><i class="fa-solid fa-bolt mr-1"></i>API requires <code class="bg-amber-950/80 px-1.5 py-0.5 rounded border border-amber-500/50 text-amber-200">${escapeHtml(highlightField)}</code> — Enter its value in the highlighted box below and click Send:</span>`;
  } else if (hint) {
    hint.textContent = isBodyMethod
      ? 'Enter required JSON payload fields & URL parameters below before clicking Send (updates JSON body & URL live):'
      : 'Enter required URL path parameters below to complete the request URL:';
  }

  grid.innerHTML = '';

  let allUrlPlaceholdersFilled = true;

  // Render URL Path Placeholder Cards
  urlPlaceholders.forEach(p => {
    const currentVal = (state.urlPlaceholderValues && state.urlPlaceholderValues[p.token]) || '';
    const isFilled = currentVal.trim() !== '';
    if (!isFilled) allUrlPlaceholdersFilled = false;

    const card = document.createElement('div');
    card.className = isFilled
      ? 'bg-emerald-950/15 border border-emerald-500/50 rounded-lg p-2 flex flex-col space-y-1 shadow-sm transition'
      : 'bg-[#141b2d] border border-purple-500/40 rounded-lg p-2 flex flex-col space-y-1 shadow-sm transition';

    card.innerHTML = `
      <div class="flex items-center justify-between text-[10px]">
        <span class="font-mono font-bold ${isFilled ? 'text-emerald-300' : 'text-purple-300'}"><i class="fa-solid fa-link mr-1"></i>URL Path: ${escapeHtml(p.token)}</span>
        <span class="px-1.5 py-0.2 rounded ${isFilled ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50' : 'bg-purple-950 text-purple-300 border border-purple-700/50'} font-semibold">
          ${isFilled ? '✓ Filled in URL' : 'Required in URL'}
        </span>
      </div>
      <input id="url-placeholder-input-${escapeHtml(p.name)}" type="text" value="${escapeHtml(currentVal)}" placeholder="Enter ${escapeHtml(p.name)} ID..."
             class="w-full bg-[#0a0e17] border ${isFilled ? 'border-emerald-500/50 text-emerald-200' : 'border-gray-700 text-white'} rounded px-2 py-1 text-xs font-mono focus:border-purple-400 focus:outline-none"
             oninput="updateUrlPlaceholder('${escapeHtml(p.token)}', this.value, false)">
    `;
    grid.appendChild(card);
  });

  // Add "Auto-Fill Live IDs" button card if URL placeholders exist
  if (urlPlaceholders.length > 0) {
    const autoCard = document.createElement('div');
    autoCard.id = 'btn-autofill-tenant';
    autoCard.className = allUrlPlaceholdersFilled
      ? 'border border-dashed border-emerald-500/50 hover:border-emerald-400 rounded-lg p-2 flex items-center justify-center cursor-pointer bg-emerald-950/20 hover:bg-emerald-950/35 transition text-xs text-emerald-300 font-semibold min-h-[54px] shadow-sm'
      : 'border border-dashed border-purple-500/50 hover:border-purple-400 rounded-lg p-2 flex items-center justify-center cursor-pointer bg-purple-950/20 hover:bg-purple-950/35 transition text-xs text-purple-300 font-semibold min-h-[54px] shadow-sm';
    autoCard.onclick = () => autoFillUrlPlaceholders(false);
    const isGtiMode = state.activePlatform === 'gti' || baseUrl.startsWith('/api/v3/');
    autoCard.innerHTML = allUrlPlaceholdersFilled
      ? `<i class="fa-solid fa-circle-check mr-1.5 text-emerald-400"></i>Live IDs Auto-Filled (Click to Refresh)`
      : `<i class="fa-solid fa-wand-magic-sparkles mr-1.5 text-purple-400"></i>${isGtiMode ? 'Auto-Fill GTI Indicators / IDs' : 'Auto-Fill Live IDs from Tenant'}`;
    grid.appendChild(autoCard);
  }

  // Render JSON Body Field Cards
  bodyFields.forEach(f => {
    const isHighlighted = highlightField && (f.key.toLowerCase() === highlightField.toLowerCase());
    const isPlaceholderVal = f.value.startsWith('ENTER_') || f.value === '';
    const borderClass = isHighlighted
      ? 'border-amber-400 ring-2 ring-amber-400/30 bg-amber-950/20'
      : (isPlaceholderVal ? 'border-blue-500/60 bg-[#141b2d]' : 'border-emerald-500/40 bg-[#141b2d]');

    const card = document.createElement('div');
    card.className = `${borderClass} border rounded-lg p-2 flex flex-col space-y-1 shadow-sm transition`;
    card.innerHTML = `
      <div class="flex items-center justify-between text-[10px]">
        <span class="font-mono font-bold ${isHighlighted ? 'text-amber-300' : 'text-blue-300'}">
          <i class="fa-solid fa-code mr-1"></i>Body Field: <span class="text-white">${escapeHtml(f.key)}</span>
        </span>
        <span class="px-1.5 py-0.2 rounded ${isHighlighted ? 'bg-amber-500 text-gray-950 font-bold' : 'bg-blue-950 text-blue-300 border border-blue-800/60'}">
          ${isHighlighted ? 'REQUIRED BY API' : 'JSON Payload'}
        </span>
      </div>
      <input id="quick-body-field-${escapeHtml(f.key)}" type="text"
             value="${escapeHtml(f.value.startsWith('ENTER_') ? '' : f.value)}"
             placeholder="${escapeHtml(f.value.startsWith('ENTER_') ? f.value : `Enter ${f.key} value...`)}"
             class="w-full bg-[#0a0e17] border ${isHighlighted ? 'border-amber-400' : 'border-gray-700'} rounded px-2 py-1 text-xs font-mono text-white focus:border-blue-400 focus:outline-none"
             oninput="updateJsonBodyField('${escapeHtml(f.key)}', this.value)">
    `;
    grid.appendChild(card);
  });

  // Add "+ Add JSON Field" button card for POST/PATCH/PUT
  if (isBodyMethod) {
    const addCard = document.createElement('div');
    addCard.className = 'border border-dashed border-gray-700 hover:border-blue-500 rounded-lg p-2 flex items-center justify-center cursor-pointer bg-[#111827]/60 hover:bg-[#141b2d] transition text-xs text-blue-400 font-medium min-h-[54px]';
    addCard.onclick = () => addBodyFieldPrompt();
    addCard.innerHTML = `<i class="fa-solid fa-plus-circle mr-1.5"></i>Add JSON Payload Field`;
    grid.appendChild(addCard);
  }

  if (highlightField) {
    setTimeout(() => {
      const targetInput = document.getElementById(`quick-body-field-${highlightField}`);
      if (targetInput) targetInput.focus();
    }, 50);
  }
}

const SAMPLE_FALLBACK_IDS = {
  watchlist: 'wl_sample_01',
  referenceList: 'Sample_Reference_List',
  dataAccessLabel: 'dal_sample_label',
  dataAccessScope: 'das_sample_scope',
  curatedRuleSet: 'crs_sample_01',
  curatedRuleSetCategory: 'cat_sample_01',
  retrohunt: 'rh_sample_01',
  findingsRefinement: 'fr_sample_01',
  parser: 'pr_sample_01',
  parserExtension: 'pe_sample_01',
  validationReport: 'vr_sample_01',
  feedPack: 'fp_sample_01',
  attachment: 'att_sample_01',
  chatMessage: 'msg_sample_01',
  customFieldValue: 'cfv_sample_01',
  contextProperty: 'cp_sample_01',
  ip: '8.8.8.8',
  domain: 'google.com',
  id: '44d88612fea8a8f36de82e1278abb02f',
  vulnerability_id: 'vulnerability--cve-2024-21413',
  collection_id: 'vulnerability--cve-2024-21413',
  threat_actor_id: 'APT29',
  relationship: 'resolutions'
};

async function autoFillUrlPlaceholders(silent = false) {
  const baseUrl = state.baseUrlTemplate || document.getElementById('req-url')?.value || '';
  const isGti = state.activePlatform === 'gti' || baseUrl.startsWith('/api/v3/');

  if (isGti) {
    const phRegex = /\{([a-zA-Z0-9_.]+)\}/g;
    let pm;
    const filledSummary = [];
    while ((pm = phRegex.exec(baseUrl)) !== null) {
      const varName = pm[1];
      const token = `{${varName}}`;
      if (state.urlPlaceholderValues && state.urlPlaceholderValues[token]) continue;
      const val = SAMPLE_FALLBACK_IDS[varName] || '8.8.8.8';
      updateUrlPlaceholder(token, val, false);
      filledSummary.push(`${token}=${val}`);
    }
    renderRequiredInputsBar();
    if (!silent && filledSummary.length > 0) {
      showToast(`Auto-filled GTI parameters: ${filledSummary.join(', ')}`, 'success');
    }
    return filledSummary.length > 0;
  }

  const autoBtn = document.getElementById('btn-autofill-tenant');
  if (autoBtn && !silent) {
    autoBtn.innerHTML = `<i class="fa-solid fa-spinner spin mr-1.5 text-purple-300"></i>Querying Tenant for Live IDs...`;
  }

  // Ensure config is loaded
  if (!state.config || !state.config.project_id || !state.config.customer_id) {
    try {
      const cfgRes = await fetch('/api/config');
      const cfgData = await cfgRes.json();
      state.config = cfgData;
    } catch (e) {}
  }

  const project = state.config.project_id || document.getElementById('cfg-project-id')?.value?.trim() || 'PROJECT';
  const location = state.config.location || document.getElementById('cfg-location')?.value?.trim() || 'us';
  const instance = state.config.customer_id || document.getElementById('cfg-customer-id')?.value?.trim() || 'INSTANCE';
  const basePrefix = `/v1alpha/projects/${project}/locations/${location}/instances/${instance}`;

  let filledAny = false;
  const filledSummary = [];
  const sampleSummary = [];

  if (!silent) {
    showToast('Querying your SecOps tenant for live resource IDs...', 'info');
  }

  try {
    // 1. First handle any project/location/instance placeholders if present
    const tenantTokens = [
      { tokens: ['{project}', '{projectId}'], val: project },
      { tokens: ['{location}', '{locations}', '{region}'], val: location },
      { tokens: ['{instance}', '{instanceId}', '{instances}', '{tenantId}'], val: instance }
    ];

    const currentTemplate = state.baseUrlTemplate || document.getElementById('req-url')?.value || '';
    tenantTokens.forEach(group => {
      group.tokens.forEach(tk => {
        if (currentTemplate.includes(tk) && group.val && !['PROJECT', 'INSTANCE'].includes(group.val)) {
          updateUrlPlaceholder(tk, group.val, false);
          filledSummary.push(`${tk}=${group.val}`);
          filledAny = true;
        }
      });
    });

    // 2. Check all remaining {placeholder} tokens in baseUrlTemplate
    const allPlaceholders = [];
    const phRegex = /\{([a-zA-Z0-9_.]+)\}/g;
    let pm;
    while ((pm = phRegex.exec(baseUrl)) !== null) {
      if (!allPlaceholders.includes(pm[1])) {
        allPlaceholders.push(pm[1]);
      }
    }

    // 3. Special handling if {case} or {caseAlert} is needed
    if (allPlaceholders.includes('case') || allPlaceholders.includes('caseAlert')) {
      const res = await fetch('/api/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: 'GET',
          url: `${basePrefix}/cases/-/caseAlerts`,
          params: { pageSize: '5' }
        })
      });
      const data = await res.json();
      const alerts = data?.response_body?.caseAlerts || [];
      if (alerts.length > 0 && alerts[0].name) {
        const m = alerts[0].name.match(/\/cases\/([^/]+)\/caseAlerts\/([^/]+)/);
        if (m) {
          if (allPlaceholders.includes('case')) {
            updateUrlPlaceholder('{case}', m[1], false);
            filledSummary.push(`{case}=${m[1]}`);
            filledAny = true;
          }
          if (allPlaceholders.includes('caseAlert')) {
            updateUrlPlaceholder('{caseAlert}', m[2], false);
            filledSummary.push(`{caseAlert}=${m[2]}`);
            filledAny = true;
          }
        }
      }
      // If {case} still needed and not filled by caseAlerts
      if (allPlaceholders.includes('case') && (!state.urlPlaceholderValues || !state.urlPlaceholderValues['{case}'])) {
        const cRes = await fetch('/api/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            method: 'GET',
            url: `${basePrefix}/cases`,
            params: { pageSize: '5' }
          })
        });
        const cData = await cRes.json();
        const casesList = cData?.response_body?.cases || [];
        if (casesList.length > 0 && casesList[0].name) {
          const cid = casesList[0].name.split('/').pop();
          if (cid) {
            updateUrlPlaceholder('{case}', cid, false);
            filledSummary.push(`{case}=${cid}`);
            filledAny = true;
          }
        }
      }
    }

    // 4. Generic left-to-right collection/{placeholder} resolution
    const segRegex = /\/([a-zA-Z0-9_]+)\/\{([a-zA-Z0-9_.]+)\}/g;
    let match;
    while ((match = segRegex.exec(baseUrl)) !== null) {
      const collection = match[1];
      const varName = match[2];
      const token = `{${varName}}`;

      // Skip if already filled
      if (state.urlPlaceholderValues && state.urlPlaceholderValues[token]) continue;

      if (['projects', 'locations', 'instances'].includes(collection)) continue;

      // Build current working URL up to this collection so parent IDs are included
      let workingUrl = baseUrl;
      Object.entries(state.urlPlaceholderValues || {}).forEach(([tk, v]) => {
        if (v) workingUrl = workingUrl.replace(new RegExp(tk.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), v);
      });

      const idx = workingUrl.indexOf(`/${collection}/${token}`);
      let listUrl = idx !== -1 ? workingUrl.substring(0, idx + collection.length + 1) : `${basePrefix}/${collection}`;

      // Handle dashboards -> nativeDashboards fallback
      const candidateUrls = [listUrl];
      if (collection === 'dashboards') {
        candidateUrls.push(`${basePrefix}/nativeDashboards`);
      }
      if (listUrl.includes('/cases/') && !listUrl.includes('/cases/-/')) {
        candidateUrls.push(listUrl.replace(/\/cases\/[^/]+\//, '/cases/-/'));
      }

      let resolvedId = null;
      for (const tryUrl of candidateUrls) {
        try {
          const res = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              method: 'GET',
              url: tryUrl,
              params: { pageSize: '5' }
            })
          });
          const data = await res.json();
          const bodyObj = data?.response_body;
          if (bodyObj && typeof bodyObj === 'object') {
            const listArr = Object.values(bodyObj).find(v => Array.isArray(v) && v.length > 0);
            if (listArr && listArr[0]) {
              const firstItem = listArr[0];
              if (firstItem.name) {
                const colMatch = firstItem.name.match(new RegExp(`/${collection}/([^/]+)`));
                resolvedId = colMatch ? colMatch[1] : firstItem.name.split('/').pop();
              } else if (firstItem.id || firstItem.uid) {
                resolvedId = String(firstItem.id || firstItem.uid);
              }
              if (resolvedId) break;
            }
          }
        } catch (err) {}
      }

      if (resolvedId) {
        updateUrlPlaceholder(token, resolvedId, false);
        filledSummary.push(`${token}=${resolvedId}`);
        filledAny = true;
      } else {
        // Fallback sample ID if tenant collection has 0 items
        const sampleId = SAMPLE_FALLBACK_IDS[varName] || `sample_${varName}_01`;
        updateUrlPlaceholder(token, sampleId, false);
        sampleSummary.push(`${token}=${sampleId}`);
        filledAny = true;
      }
    }

    renderRequiredInputsBar();

    if (filledAny) {
      if (!silent) {
        if (filledSummary.length > 0 && sampleSummary.length === 0) {
          showToast(`Auto-filled live tenant IDs: ${filledSummary.join(', ')}`, 'success');
        } else if (filledSummary.length > 0 && sampleSummary.length > 0) {
          showToast(`Auto-filled live IDs (${filledSummary.join(', ')}) + sample IDs for empty collections (${sampleSummary.join(', ')})`, 'info');
        } else {
          showToast(`Tenant has 0 items in collection; filled sample ID (${sampleSummary.join(', ')})`, 'info');
        }
      }
      return true;
    } else if (!silent) {
      showToast('All URL parameters are already populated.', 'info');
    }
  } catch (e) {
    renderRequiredInputsBar();
    if (!silent) {
      showToast('Auto-fill lookup error: ' + e.message, 'error');
    }
  }
  return false;
}

function updateUrlPlaceholder(token, val, shouldRender = true) {
  if (!state.urlPlaceholderValues) state.urlPlaceholderValues = {};
  state.urlPlaceholderValues[token] = val.trim();

  let newUrl = state.baseUrlTemplate || document.getElementById('req-url').value;
  Object.entries(state.urlPlaceholderValues).forEach(([tk, v]) => {
    if (v) {
      newUrl = newUrl.replace(new RegExp(tk.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), v);
    }
  });
  document.getElementById('req-url').value = newUrl;

  if (shouldRender && typeof renderRequiredInputsBar === 'function') {
    // Update badge styling without losing input focus
    const varName = token.replace(/[{}]/g, '');
    const activeElId = document.activeElement?.id;
    const cursorPos = document.activeElement?.selectionStart;
    renderRequiredInputsBar();
    if (activeElId) {
      const el = document.getElementById(activeElId);
      if (el) {
        el.focus();
        if (typeof cursorPos === 'number') el.setSelectionRange(cursorPos, cursorPos);
      }
    }
  }
}

function updateJsonBodyField(key, val) {
  const textarea = document.getElementById('req-body-input');
  if (!textarea) return;
  let obj = {};
  try {
    obj = JSON.parse(textarea.value || '{}');
  } catch (e) {
    obj = {};
  }

  // Try parsing numbers/booleans/JSON objects if appropriate, else string
  let parsedVal = val;
  if (val === 'true') parsedVal = true;
  else if (val === 'false') parsedVal = false;
  else if (val !== '' && !isNaN(Number(val)) && !val.startsWith('0') && val.length < 16) {
    parsedVal = Number(val);
  } else if ((val.startsWith('{') && val.endsWith('}')) || (val.startsWith('[') && val.endsWith(']'))) {
    try { parsedVal = JSON.parse(val); } catch (e) {}
  }

  obj[key] = parsedVal;
  textarea.value = JSON.stringify(obj, null, 2);
}

function handleRawBodyInput() {
  // Update quick fields when user edits raw JSON directly
  renderRequiredInputsBar();
}

function addBodyFieldPrompt() {
  const fieldName = prompt('Enter the JSON field name to add to Request Body (e.g. alertId, filter, pageSize):');
  if (!fieldName || !fieldName.trim()) return;
  const key = fieldName.trim();
  const textarea = document.getElementById('req-body-input');
  let obj = {};
  try {
    obj = JSON.parse(textarea.value || '{}');
  } catch (e) {
    obj = {};
  }
  if (!(key in obj)) {
    obj[key] = '';
  }
  textarea.value = JSON.stringify(obj, null, 2);
  switchReqTab('body');
  renderRequiredInputsBar(key);
}

function insertToken(token) {
  const input = document.getElementById('req-url');
  const start = input.selectionStart;
  const end = input.selectionEnd;
  const text = input.value;
  input.value = text.substring(0, start) + token + text.substring(end);
  input.focus();
  input.selectionStart = input.selectionEnd = start + token.length;
}

// -----------------------------------------------------------------------------
// REQUEST TABS & EDITORS
// -----------------------------------------------------------------------------

function switchReqTab(tab) {
  state.activeReqTab = tab;
  const tabs = ['params', 'body', 'headers', 'doc'];
  tabs.forEach(t => {
    const btn = document.getElementById(`req-tab-${t}`);
    const content = document.getElementById(`req-content-${t}`);
    if (t === tab) {
      btn.className = 'py-2 border-b-2 border-blue-500 text-blue-400 font-medium transition';
      content.classList.remove('hidden');
    } else {
      btn.className = 'py-2 border-b-2 border-transparent text-gray-400 hover:text-gray-200 font-medium transition';
      content.classList.add('hidden');
    }
  });

  const bodyActions = document.getElementById('body-tab-actions');
  if (tab === 'body') {
    bodyActions.classList.remove('hidden');
    bodyActions.classList.add('flex');
  } else {
    bodyActions.classList.add('hidden');
    bodyActions.classList.remove('flex');
  }
}

function renderQueryParamsTable() {
  const tbody = document.getElementById('params-table-body');
  tbody.innerHTML = '';
  document.getElementById('params-count').textContent = state.queryParams.length;

  state.queryParams.forEach((p, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-gray-800/40';
    tr.innerHTML = `
      <td class="py-1 pr-2">
        <input type="text" value="${escapeHtml(p.key)}" placeholder="e.g. pageSize"
               class="w-full bg-[#141b2d] border border-gray-700/80 rounded px-2 py-1 font-mono text-xs text-gray-200"
               onchange="updateQueryParam(${idx}, 'key', this.value)">
      </td>
      <td class="py-1 pr-2">
        <input type="text" value="${escapeHtml(p.value)}" placeholder="Value"
               class="w-full bg-[#141b2d] border border-gray-700/80 rounded px-2 py-1 font-mono text-xs text-gray-200"
               onchange="updateQueryParam(${idx}, 'value', this.value)">
      </td>
      <td class="py-1 text-center">
        <button onclick="removeQueryParam(${idx})" class="text-gray-500 hover:text-red-400 p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function addParamRow() {
  state.queryParams.push({ key: '', value: '' });
  renderQueryParamsTable();
}

function updateQueryParam(idx, field, val) {
  if (state.queryParams[idx]) {
    state.queryParams[idx][field] = val;
  }
}

function removeQueryParam(idx) {
  state.queryParams.splice(idx, 1);
  renderQueryParamsTable();
}

function renderHeadersTable() {
  const tbody = document.getElementById('headers-table-body');
  tbody.innerHTML = '';
  document.getElementById('headers-count').textContent = state.customHeaders.length;

  state.customHeaders.forEach((h, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-gray-800/40';
    tr.innerHTML = `
      <td class="py-1 pr-2">
        <input type="text" value="${escapeHtml(h.key)}" placeholder="Header-Name"
               class="w-full bg-[#141b2d] border border-gray-700/80 rounded px-2 py-1 font-mono text-xs text-gray-200"
               onchange="updateCustomHeader(${idx}, 'key', this.value)">
      </td>
      <td class="py-1 pr-2">
        <input type="text" value="${escapeHtml(h.value)}" placeholder="Header-Value"
               class="w-full bg-[#141b2d] border border-gray-700/80 rounded px-2 py-1 font-mono text-xs text-gray-200"
               onchange="updateCustomHeader(${idx}, 'value', this.value)">
      </td>
      <td class="py-1 text-center">
        <button onclick="removeCustomHeader(${idx})" class="text-gray-500 hover:text-red-400 p-1">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function addHeaderRow() {
  state.customHeaders.push({ key: '', value: '' });
  renderHeadersTable();
}

function updateCustomHeader(idx, field, val) {
  if (state.customHeaders[idx]) {
    state.customHeaders[idx][field] = val;
  }
}

function removeCustomHeader(idx) {
  state.customHeaders.splice(idx, 1);
  renderHeadersTable();
}

function formatRequestBody() {
  const textarea = document.getElementById('req-body-input');
  try {
    const parsed = JSON.parse(textarea.value);
    textarea.value = JSON.stringify(parsed, null, 2);
    showToast('JSON formatted', 'info');
  } catch (err) {
    showToast('Invalid JSON in request body', 'error');
  }
}

function loadSampleBody() {
  if (state.selectedEndpoint && state.selectedEndpoint.sampleBody) {
    document.getElementById('req-body-input').value = JSON.stringify(state.selectedEndpoint.sampleBody, null, 2);
    showToast('Loaded sample payload', 'info');
  } else {
    showToast('No default sample for this endpoint', 'info');
  }
}

function clearRequestBody() {
  document.getElementById('req-body-input').value = '';
}

// -----------------------------------------------------------------------------
// EXECUTE REQUEST
// -----------------------------------------------------------------------------

async function sendApiRequest() {
  const method = document.getElementById('req-method').value;
  let rawUrl = document.getElementById('req-url').value.trim();
  const rawBody = document.getElementById('req-body-input').value.trim();
  const isGti = state.activePlatform === 'gti' || rawUrl.startsWith('/api/v3/');

  // Requirement 3: Prompt user to upload credential if none is configured for active platform
  if (isGti) {
    if (!state.config || !state.config.has_gti_key) {
      showToast('Google Threat Intelligence (VirusTotal v3) API Key required. Please configure your encrypted x-apikey.', 'warning');
      openConfigModal('gti');
      return;
    }
  } else {
    if (!state.config || !state.config.has_service_account) {
      showToast('Chronicle Service Account key required. Please upload your encrypted key.', 'warning');
      openConfigModal('secops');
      return;
    }
  }

  if (!rawUrl) {
    showToast('Please enter an endpoint URL', 'error');
    return;
  }

  // If URL still contains unresolved {placeholder} variables, attempt live auto-fill first
  if (/\{[a-zA-Z0-9_]+\}/.test(rawUrl)) {
    setExecutionLoading(true);
    const filled = await autoFillUrlPlaceholders(true);
    setExecutionLoading(false);
    rawUrl = document.getElementById('req-url').value.trim();
    const remainingMatch = rawUrl.match(/\{([a-zA-Z0-9_]+)\}/);
    if (remainingMatch) {
      const missingVar = remainingMatch[1];
      showToast(`Please enter a value for required URL parameter "{${missingVar}}" in the Required Inputs bar above.`, 'warning');
      const targetInput = document.getElementById(`url-placeholder-input-${missingVar}`);
      if (targetInput) {
        targetInput.className = 'w-full bg-[#0a0e17] border-2 border-amber-400 rounded px-2 py-1 text-xs font-mono text-white focus:outline-none ring-2 ring-amber-400/30';
        targetInput.focus();
      }
      return;
    }
  }

  // Parse Body if present
  let bodyPayload = null;
  if (['POST', 'PATCH', 'PUT'].includes(method) && rawBody) {
    try {
      bodyPayload = JSON.parse(rawBody);
    } catch (err) {
      showToast('Request body is not valid JSON', 'error');
      switchReqTab('body');
      return;
    }
  }

  // Prepare Query Params
  const paramsObj = {};
  state.queryParams.forEach(p => {
    if (p.key.trim()) paramsObj[p.key.trim()] = p.value.trim();
  });

  // Prepare Headers
  const headersObj = {};
  state.customHeaders.forEach(h => {
    if (h.key.trim()) headersObj[h.key.trim()] = h.value.trim();
  });

  // UI Loading State
  setExecutionLoading(true);

  try {
    const res = await fetch('/api/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        platform: isGti ? 'gti' : 'secops',
        method: method,
        url: rawUrl,
        headers: headersObj,
        params: paramsObj,
        body: bodyPayload,
        endpoint_id: state.selectedEndpoint ? state.selectedEndpoint.id : ''
      })
    });

    const result = await res.json();
    state.lastResponse = result;
    renderResponse(result);
    if (result && result.status_code >= 200 && result.status_code < 300) {
      if ((isGti && (!state.config || !state.config.gti_is_authenticated)) ||
          (!isGti && (!state.config || !state.config.is_authenticated))) {
        await loadConfig();
      }
    }
    await loadHistory();

  } catch (err) {
    console.error('Request execution error:', err);
    renderResponse({
      status_code: 500,
      status_text: 'Client Execution Error',
      duration_ms: 0,
      response_headers: {},
      response_body: { error: err.message },
      is_json: true
    });
  } finally {
    setExecutionLoading(false);
  }
}

function setExecutionLoading(isLoading) {
  const btn = document.getElementById('btn-send');
  const icon = document.getElementById('btn-send-icon');
  const text = document.getElementById('btn-send-text');
  const emptyState = document.getElementById('res-empty-state');
  const loadingState = document.getElementById('res-loading-state');

  if (isLoading) {
    btn.disabled = true;
    icon.className = 'fa-solid fa-spinner spin';
    text.textContent = 'Running...';
    emptyState.classList.add('hidden');
    loadingState.classList.remove('hidden');
    hideAllResponseViews();
  } else {
    btn.disabled = false;
    icon.className = 'fa-solid fa-paper-plane';
    text.textContent = 'Send';
    loadingState.classList.add('hidden');
  }
}

function hideAllResponseViews() {
  document.getElementById('res-view-json').classList.add('hidden');
  document.getElementById('res-view-table').classList.add('hidden');
  document.getElementById('res-view-raw').classList.add('hidden');
  document.getElementById('res-view-headers').classList.add('hidden');
  document.getElementById('res-view-troubleshoot').classList.add('hidden');
}

// -----------------------------------------------------------------------------
// RESPONSE VIEWER & TROUBLESHOOTING
// -----------------------------------------------------------------------------

function renderResponse(res) {
  const statusPill = document.getElementById('res-status-pill');
  const statusBadge = document.getElementById('res-status-badge');
  const durationBadge = document.getElementById('res-duration-badge');
  const sizeBadge = document.getElementById('res-size-badge');

  statusPill.classList.remove('hidden');
  statusPill.classList.add('flex');

  // Status Badge Styling
  const code = res.status_code || 0;
  statusBadge.textContent = `${code} ${res.status_text || ''}`;
  if (code >= 200 && code < 300) {
    statusBadge.className = 'status-badge status-2xx';
  } else if (code >= 400 && code < 500) {
    statusBadge.className = 'status-badge status-4xx';
  } else {
    statusBadge.className = 'status-badge status-5xx';
  }

  // Duration and Size
  durationBadge.textContent = `${res.duration_ms}ms`;
  const bodyStr = typeof res.response_body === 'string' ? res.response_body : JSON.stringify(res.response_body);
  const bytes = new Blob([bodyStr]).size;
  sizeBadge.textContent = bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;

  // Populate JSON Viewer
  const jsonPre = document.getElementById('json-renderer');
  if (res.is_json) {
    jsonPre.innerHTML = syntaxHighlightJson(res.response_body);
  } else {
    jsonPre.textContent = bodyStr;
  }

  // Populate Raw Viewer
  document.getElementById('raw-renderer').textContent = bodyStr;

  // Populate Response Headers Table
  const headersTbody = document.getElementById('response-headers-body');
  headersTbody.innerHTML = '';
  Object.entries(res.response_headers || {}).forEach(([k, v]) => {
    const tr = document.createElement('tr');
    tr.className = 'border-b border-gray-800/40';
    tr.innerHTML = `
      <td class="py-1.5 font-bold text-gray-300 pr-2">${escapeHtml(k)}</td>
      <td class="py-1.5 font-mono text-gray-400 break-all">${escapeHtml(v)}</td>
    `;
    headersTbody.appendChild(tr);
  });

  // Check Table View capability
  const tableBtn = document.getElementById('res-tab-table');
  const tableContainer = document.getElementById('table-container');
  tableContainer.innerHTML = '';
  const arrayData = extractArrayFromResponse(res.response_body);
  if (arrayData && arrayData.length > 0) {
    tableBtn.classList.remove('hidden');
    renderTableResponse(arrayData);
  } else {
    tableBtn.classList.add('hidden');
  }

  // Troubleshoot view handling for non-200 responses
  const troubleBtn = document.getElementById('res-tab-troubleshoot');
  if (code >= 400) {
    troubleBtn.classList.remove('hidden');
    populateTroubleshooting(res);
    detectAndInjectMissingField(res);
  } else {
    troubleBtn.classList.add('hidden');
  }

  // Handle Long Running Operations (e.g. Chronicle Search)
  const lroBanner = document.getElementById('lro-banner');
  const lroName = document.getElementById('lro-name');
  const lroTitle = document.getElementById('lro-title');
  const lroIcon = document.getElementById('lro-icon');
  const btnFetchResults = document.getElementById('btn-fetch-results');
  const btnPollLro = document.getElementById('btn-poll-lro');

  const bodyObj = typeof res.response_body === 'object' && res.response_body !== null ? res.response_body : null;
  if (bodyObj && bodyObj.name && bodyObj.name.includes('/operations/s-lro-')) {
    state.activeLro = bodyObj.name;
    lroBanner.classList.remove('hidden');
    lroName.textContent = bodyObj.name;
    lroName.title = bodyObj.name;

    const isDone = bodyObj.done === true || (bodyObj.metadata && bodyObj.metadata.state === 'SUCCEEDED');
    if (isDone) {
      lroTitle.textContent = 'Chronicle Search Operation Completed (SUCCEEDED)';
      lroIcon.className = 'fa-solid fa-circle-check text-emerald-400';
      btnPollLro.classList.add('hidden');
      btnFetchResults.classList.remove('hidden');
      let sessionId = '';
      if (bodyObj.response && bodyObj.response.name) {
        sessionId = bodyObj.response.name.split('/').pop();
      } else {
        sessionId = bodyObj.name.split('/').pop();
      }
      state.activeSearchSession = sessionId;
    } else {
      const stateStr = (bodyObj.metadata && bodyObj.metadata.state) || 'RUNNING';
      const progress = (bodyObj.metadata && bodyObj.metadata.progress !== undefined) ? ` (${bodyObj.metadata.progress}%)` : '';
      lroTitle.textContent = `Chronicle Search Operation in Progress - ${stateStr}${progress}`;
      lroIcon.className = 'fa-solid fa-arrows-rotate spin text-blue-400';
      btnPollLro.classList.remove('hidden');
      btnFetchResults.classList.add('hidden');
    }
  } else if (lroBanner) {
    lroBanner.classList.add('hidden');
  }

  // Render GTI Threat Assessment Summary Card if present
  renderGtiSummaryCard(res.gti_summary);

  // Default view
  switchResTab('json');
}

function renderGtiSummaryCard(summary) {
  const card = document.getElementById('gti-summary-card');
  if (!card) return;
  if (!summary || (!summary.gti_verdict && summary.av_malicious === null && !summary.name && !summary.collection_type)) {
    card.classList.add('hidden');
    return;
  }

  card.classList.remove('hidden');
  const verdict = summary.gti_verdict || 'UNDETECTED';
  const score = summary.gti_threat_score !== null && summary.gti_threat_score !== undefined ? summary.gti_threat_score : null;
  const totalEngines = (summary.av_malicious || 0) + (summary.av_suspicious || 0) + (summary.av_harmless || 0) + (summary.av_undetected || 0);

  let badgesHtml = '';
  if (summary.tlp) {
    badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">TLP:${escapeHtml(summary.tlp)}</span>`;
  }
  if (summary.collection_type) {
    badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">${escapeHtml(summary.collection_type)}</span>`;
  }
  if (summary.popular_threat_name) {
    badgesHtml += `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30"><i class="fa-solid fa-biohazard mr-1"></i>${escapeHtml(summary.popular_threat_name)}</span>`;
  }

  let metricsHtml = '';
  if (score !== null) {
    const scoreColor = score >= 60 ? 'bg-rose-500' : score >= 30 ? 'bg-amber-500' : 'bg-emerald-500';
    metricsHtml += `
      <div class="bg-gray-900/90 border border-gray-800 rounded-lg p-2 flex-1 min-w-[140px]">
        <div class="flex items-center justify-between text-[11px] text-gray-400">
          <span>GTI Threat Score</span>
          <span class="font-mono font-bold text-white">${score} / 100</span>
        </div>
        <div class="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden mt-1">
          <div class="${scoreColor} h-full transition-all duration-500" style="width: ${Math.min(100, Math.max(4, score))}%"></div>
        </div>
      </div>
    `;
  }

  if (totalEngines > 0) {
    const malCount = summary.av_malicious || 0;
    const detColor = malCount > 0 ? 'text-rose-400' : 'text-emerald-400';
    metricsHtml += `
      <div class="bg-gray-900/90 border border-gray-800 rounded-lg p-2 flex-1 min-w-[140px]">
        <div class="text-[11px] text-gray-400">Security Vendor Detections</div>
        <div class="font-mono font-bold text-xs mt-0.5 ${detColor}">
          ${malCount} <span class="text-[11px] text-gray-500 font-normal">/ ${totalEngines} engines malicious</span>
        </div>
      </div>
    `;
  }

  card.innerHTML = `
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div class="flex items-center space-x-2.5 min-w-0">
        <span class="px-2.5 py-1 rounded-md text-xs font-mono font-extrabold uppercase verdict-${verdict}">
          ${escapeHtml(verdict)}
        </span>
        <div class="min-w-0">
          <div class="text-xs font-bold text-white truncate">${escapeHtml(summary.name || summary.entity_id || 'GTI Entity Report')}</div>
          <div class="text-[10px] font-mono text-gray-400 truncate">ID: ${escapeHtml(summary.entity_id || 'N/A')} (${escapeHtml(summary.entity_type || 'entity')})</div>
        </div>
      </div>
      <div class="flex items-center space-x-1.5">
        ${badgesHtml}
      </div>
    </div>
    ${metricsHtml ? `<div class="flex flex-wrap gap-2.5 pt-1">${metricsHtml}</div>` : ''}
  `;
}

async function pollCurrentOperation() {
  if (!state.activeLro) return;
  document.getElementById('req-method').value = 'GET';
  document.getElementById('req-url').value = `/v1alpha/${state.activeLro}`;
  switchReqTab('params');
  await sendApiRequest();
}

async function fetchCurrentSearchResults() {
  const customerId = state.config.customer_id || 'INSTANCE_ID';
  const project = state.config.project_id || 'PROJECT_ID';
  const location = state.config.location || 'us';
  const sessionId = state.activeSearchSession || (state.activeLro ? state.activeLro.split('/').pop() : '');

  if (!sessionId) {
    showToast('No active search session found', 'warning');
    return;
  }

  document.getElementById('req-method').value = 'GET';
  document.getElementById('req-url').value = `/v1alpha/projects/${project}/locations/${location}/instances/${customerId}/searchSessions/${sessionId}/searchedResults`;
  state.queryParams = [{ key: 'pageSize', value: '50' }];
  renderQueryParamsTable();
  switchReqTab('params');
  await sendApiRequest();
}

function switchResTab(tab) {
  state.activeResTab = tab;
  const tabs = ['json', 'table', 'raw', 'headers', 'troubleshoot'];
  tabs.forEach(t => {
    const btn = document.getElementById(`res-tab-${t}`);
    const view = document.getElementById(`res-view-${t}`);
    if (btn && view) {
      if (t === tab) {
        btn.className = t === 'troubleshoot' 
          ? 'px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-medium transition'
          : 'px-2.5 py-1 rounded bg-blue-600/20 text-blue-400 border border-blue-500/30 font-medium transition';
        view.classList.remove('hidden');
      } else {
        btn.className = t === 'troubleshoot'
          ? 'px-2.5 py-1 rounded text-amber-400 bg-amber-500/10 border border-amber-500/30 transition'
          : 'px-2.5 py-1 rounded text-gray-400 hover:text-gray-200 transition';
        view.classList.add('hidden');
      }
    }
  });
}

function extractArrayFromResponse(body) {
  if (!body || typeof body !== 'object') return null;
  if (Array.isArray(body)) return body;

  // Handle Chronicle Searched Results specifically
  if (Array.isArray(body.searchedResults)) {
    return body.searchedResults.map(r => {
      if (r.resultRow && r.resultRow.eventRecord && r.resultRow.eventRecord.event) {
        const ev = r.resultRow.eventRecord.event;
        const meta = ev.metadata || {};
        const principal = ev.principal || {};
        const target = ev.target || {};
        return {
          id: r.name ? r.name.split('/').pop() : '',
          timestamp: meta.eventTimestamp || '',
          eventType: meta.eventType || '',
          principalUser: principal.user ? principal.user.userid : '',
          principalIp: principal.ip || '',
          targetUser: target.user ? target.user.userid : '',
          targetHostname: target.hostname || ''
        };
      }
      return r;
    });
  }

  // Check common Chronicle response envelope keys
  for (const key of ['data', 'feeds', 'rules', 'alerts', 'cases', 'referenceLists', 'watchlists', 'dataTables', 'logTypes', 'operations', 'events']) {
    if (Array.isArray(body[key])) return body[key];
  }
  return null;
}

function renderTableResponse(items) {
  const container = document.getElementById('table-container');
  if (!items || items.length === 0) return;

  // Determine common keys across top 5 items
  const keys = Array.from(new Set(items.slice(0, 5).flatMap(obj => Object.keys(obj))));
  const displayKeys = keys.slice(0, 6); // Max 6 columns

  let html = `
    <table class="w-full text-left text-xs border-collapse font-sans">
      <thead>
        <tr class="text-gray-400 border-b border-gray-800 bg-[#0d1322] text-[11px] uppercase">
          ${displayKeys.map(k => `<th class="py-2 px-3">${escapeHtml(k)}</th>`).join('')}
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-800/60">
  `;

  items.forEach(item => {
    html += '<tr class="hover:bg-gray-800/30">';
    displayKeys.forEach(k => {
      let val = item[k];
      if (typeof val === 'object' && val !== null) {
        val = JSON.stringify(val);
      }
      html += `<td class="py-2 px-3 font-mono text-xs text-gray-300 max-w-[200px] truncate" title="${escapeHtml(String(val || ''))}">${escapeHtml(String(val !== undefined ? val : ''))}</td>`;
    });
    html += '</tr>';
  });

  html += '</tbody></table>';
  container.innerHTML = html;
}

function populateTroubleshooting(res) {
  const title = document.getElementById('troubleshoot-title');
  const desc = document.getElementById('troubleshoot-desc');
  const suggestions = document.getElementById('troubleshoot-suggestions');
  suggestions.innerHTML = '';

  const code = res.status_code;
  const raw = typeof res.response_body === 'string' ? res.response_body : JSON.stringify(res.response_body, null, 2);

  if (code === 403) {
    title.textContent = 'HTTP 403 Forbidden: Permission Denied';
    desc.textContent = 'The active Service Account lacks necessary IAM permissions in Chronicle or Google Cloud.';
    suggestions.innerHTML = `
      <li>Ensure the service account has roles such as <code class="text-blue-400">roles/chronicle.viewer</code> or <code class="text-blue-400">roles/chronicle.admin</code>.</li>
      <li>If accessing feeds or ingestion, verify permission <code class="text-blue-400">chronicle.feeds.list</code> or <code class="text-blue-400">chronicle.instances.get</code>.</li>
      <li>Verify that the Service Account is granted access in the target GCP Project <strong class="text-gray-200">${escapeHtml(state.config.project_id || '')}</strong>.</li>
    `;
  } else if (code === 404) {
    title.textContent = 'HTTP 404 Not Found: Resource or Endpoint Missing';
    desc.textContent = 'The requested URI does not exist or the customer instance ID / location is mismatched.';
    suggestions.innerHTML = `
      <li>Verify the Customer / Instance ID (currently set to <strong class="text-gray-200 font-mono">${escapeHtml(state.config.customer_id || 'unconfigured')}</strong>). Check Chronicle Console > SIEM Settings > Profile.</li>
      <li>Check the regional endpoint: ensure your location is correct (<code class="text-cyan-400">${escapeHtml(state.config.location || 'us')}</code>). Use <code class="text-blue-400">https://${escapeHtml(state.config.location || 'us')}-chronicle.googleapis.com</code>.</li>
      <li>For custom actions (like <code class="text-purple-400">:udmSearch</code> or <code class="text-purple-400">:importPushLogs</code>), ensure the syntax matches Google AIP standard.</li>
    `;
  } else if (code === 400) {
    title.textContent = 'HTTP 400 Bad Request: Invalid Payload or Parameters';
    desc.textContent = 'The Chronicle API rejected the request arguments or JSON structure.';
    suggestions.innerHTML = `
      <li>Inspect the JSON request body structure in the <strong>Request Body</strong> tab or the <strong>Required Inputs</strong> bar above.</li>
      <li>Verify ISO 8601 timestamp formats (e.g. <code class="text-blue-400">2026-09-03T00:00:00Z</code>).</li>
      <li>Check required fields specified in the endpoint documentation.</li>
    `;
  } else {
    title.textContent = `HTTP ${code}: Request Error`;
    desc.textContent = 'An unexpected response was returned by the service endpoint.';
    suggestions.innerHTML = `
      <li>Check raw response details in the Raw or Headers tab.</li>
      <li>Review the correlation ID in the response headers if provided (<code class="text-blue-400">X-GOOG-CHRONICLE-CORRELATION-ID</code>).</li>
    `;
  }
}

function detectAndInjectMissingField(res) {
  if (!res || res.status_code !== 400) return;
  const bodyObj = typeof res.response_body === 'object' && res.response_body !== null ? res.response_body : null;
  const errMsg = (bodyObj && bodyObj.error && bodyObj.error.message) ? bodyObj.error.message : (typeof res.response_body === 'string' ? res.response_body : '');
  if (!errMsg) return;

  // Match patterns like "alert ID is required", "field 'xyz' is required"
  let rawField = '';
  const m1 = errMsg.match(/([a-zA-Z0-9_]+(?:\s+[a-zA-Z0-9_]+)?)\s+is\s+required/i);
  if (m1 && m1[1]) {
    rawField = m1[1].trim();
  }

  if (!rawField) return;

  // Convert e.g. "alert ID" -> "alertId"
  const parts = rawField.split(/\s+/);
  const camelField = parts.map((word, idx) => {
    const clean = word.replace(/[^a-zA-Z0-9]/g, '');
    if (idx === 0) return clean.toLowerCase();
    return clean.charAt(0).toUpperCase() + clean.slice(1).toLowerCase();
  }).join('');

  if (!camelField) return;

  const method = (document.getElementById('req-method')?.value || 'GET').toUpperCase();
  if (['POST', 'PATCH', 'PUT'].includes(method)) {
    const textarea = document.getElementById('req-body-input');
    if (textarea) {
      let obj = {};
      try {
        obj = JSON.parse(textarea.value || '{}');
      } catch (e) {
        obj = {};
      }
      if (!(camelField in obj)) {
        obj[camelField] = '';
        textarea.value = JSON.stringify(obj, null, 2);
      }
      switchReqTab('body');
      renderRequiredInputsBar(camelField);
      showToast(`Required input "${camelField}" identified! Enter its value in the highlighted box above.`, 'warning');
    }
  }
}

function copyResponse() {
  if (!state.lastResponse) return;
  const str = typeof state.lastResponse.response_body === 'string'
    ? state.lastResponse.response_body
    : JSON.stringify(state.lastResponse.response_body, null, 2);
  navigator.clipboard.writeText(str);
  showToast('Response copied to clipboard', 'info');
}

function downloadResponse() {
  if (!state.lastResponse) return;
  const str = typeof state.lastResponse.response_body === 'string'
    ? state.lastResponse.response_body
    : JSON.stringify(state.lastResponse.response_body, null, 2);
  
  const blob = new Blob([str], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `chronicle-api-response-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function copyCurlCommand() {
  const method = document.getElementById('req-method').value;
  const rawUrl = document.getElementById('req-url').value;
  const body = document.getElementById('req-body-input').value.trim();

  let finalUrl = rawUrl;
  finalUrl = finalUrl.replace('{project}', state.config.project_id || 'PROJECT_ID');
  finalUrl = finalUrl.replace('{location}', state.config.location || 'us');
  finalUrl = finalUrl.replace('{instance}', state.config.customer_id || 'INSTANCE_ID');
  const isGtiCurl = state.activePlatform === 'gti' || finalUrl.startsWith('/api/v3');
  if (finalUrl.startsWith('/')) {
    if (isGtiCurl) {
      finalUrl = (state.config.gti_endpoint || 'https://www.virustotal.com').replace(/\/$/, '') + finalUrl;
    } else {
      finalUrl = (state.config.endpoint || 'https://us-chronicle.googleapis.com').replace(/\/$/, '') + finalUrl;
    }
  }

  let curl = isGtiCurl
    ? `curl -X ${method} "${finalUrl}" \\\n  -H "x-apikey: YOUR_GTI_API_KEY" \\\n  -H "Accept: application/json"`
    : `curl -X ${method} "${finalUrl}" \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" \\\n  -H "Content-Type: application/json"`;
  if (['POST', 'PATCH', 'PUT'].includes(method) && body) {
    curl += ` \\\n  -d '${body.replace(/'/g, "'\\''")}'`;
  }

  navigator.clipboard.writeText(curl);
  showToast('cURL command copied to clipboard', 'info');
}

// -----------------------------------------------------------------------------
// HISTORY DRAWER
// -----------------------------------------------------------------------------

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    state.history = data.history || [];
    document.getElementById('history-counter').textContent = state.history.length;
    renderHistoryTable();
  } catch (err) {
    console.error('Failed loading history:', err);
  }
}

function toggleHistoryDrawer() {
  const drawer = document.getElementById('history-drawer');
  drawer.classList.toggle('hidden');
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-table-body');
  tbody.innerHTML = '';

  if (state.history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="p-3 text-center text-gray-500">No requests in history yet.</td></tr>`;
    return;
  }

  state.history.forEach(item => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-gray-800/40 cursor-pointer transition';
    tr.onclick = () => restoreHistoryItem(item);

    const timeStr = new Date(item.timestamp).toLocaleTimeString();
    const methodClass = getMethodClass(item.method);
    const statusClass = item.status_code >= 200 && item.status_code < 300 ? 'text-emerald-400' : 'text-red-400';

    tr.innerHTML = `
      <td class="py-1.5 px-2 font-mono text-gray-400">${timeStr}</td>
      <td class="py-1.5 px-2"><span class="method-badge ${methodClass}">${item.method}</span></td>
      <td class="py-1.5 px-2 font-mono text-gray-300 max-w-[320px] truncate" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</td>
      <td class="py-1.5 px-2 font-mono font-semibold ${statusClass}">${item.status_code} ${escapeHtml(item.status_text || '')}</td>
      <td class="py-1.5 px-2 font-mono text-gray-400">${item.duration_ms}ms</td>
      <td class="py-1.5 px-2 text-center text-blue-400 hover:text-blue-300 font-medium">Replay</td>
    `;
    tbody.appendChild(tr);
  });
}

function restoreHistoryItem(item) {
  document.getElementById('req-method').value = item.method;
  document.getElementById('req-url').value = item.url;
  toggleHistoryDrawer();
  showToast('Restored request from history', 'info');
}

async function clearHistory() {
  try {
    await fetch('/api/history/clear', { method: 'POST' });
    await loadHistory();
    showToast('Execution history cleared', 'info');
  } catch (err) {
    showToast('Failed to clear history', 'error');
  }
}

// -----------------------------------------------------------------------------
// UTILITIES & HELPERS
// -----------------------------------------------------------------------------

function getMethodClass(method) {
  const m = (method || '').toUpperCase();
  if (m === 'GET') return 'method-get';
  if (m === 'POST') return 'method-post';
  if (m === 'PATCH') return 'method-patch';
  if (m === 'DELETE') return 'method-delete';
  if (m === 'PUT') return 'method-put';
  return 'method-get';
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function jsonLint(str) {
  return JSON.parse(str);
}

function syntaxHighlightJson(jsonObj) {
  if (typeof jsonObj !== 'string') {
    jsonObj = JSON.stringify(jsonObj, null, 2);
  }
  jsonObj = jsonObj.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return jsonObj.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'json-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-boolean';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.className = 'fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg shadow-xl text-xs font-medium flex items-center space-x-2 border transition-all duration-300';

  let icon = '<i class="fa-solid fa-circle-info text-blue-400"></i>';
  if (type === 'success') {
    toast.classList.add('bg-emerald-950', 'border-emerald-600', 'text-emerald-200');
    icon = '<i class="fa-solid fa-circle-check text-emerald-400"></i>';
  } else if (type === 'error') {
    toast.classList.add('bg-red-950', 'border-red-600', 'text-red-200');
    icon = '<i class="fa-solid fa-circle-exclamation text-red-400"></i>';
  } else if (type === 'warning') {
    toast.classList.add('bg-amber-950', 'border-amber-600', 'text-amber-200');
    icon = '<i class="fa-solid fa-triangle-exclamation text-amber-400"></i>';
  } else {
    toast.classList.add('bg-gray-900', 'border-gray-700', 'text-gray-200');
  }

  toast.innerHTML = `${icon}<span>${escapeHtml(message)}</span>`;
  toast.classList.remove('hidden');

  setTimeout(() => {
    toast.classList.add('hidden');
  }, 4000);
}
