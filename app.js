/* ═══════════════════════════════════════════════════════════
   CyberKhana SIEM Dashboard — Application Logic
   ═══════════════════════════════════════════════════════════ */

// ─── Hardcoded Log Data ──────────────────────────────────
// ~30 entries: 80% mundane traffic, 20% SSH brute-force narrative
// Attack story: 103.214.78.92 brute-forces SSH on 10.0.1.25

const ATTACKER_IP = '103.214.78.92';
const TARGET_IP   = '10.0.1.25';

const LOG_DATA = [
  // ── Normal traffic ─────────────────────────────────
  { timestamp: '2026-04-30 08:01:12', srcIp: '10.0.2.15',       dstIp: '8.8.8.8',          event: 'DNS Query — google.com',                  status: 'Success' },
  { timestamp: '2026-04-30 08:02:34', srcIp: '10.0.2.18',       dstIp: '172.217.14.206',   event: 'HTTPS GET — mail.google.com',              status: 'Success' },
  { timestamp: '2026-04-30 08:04:05', srcIp: '10.0.3.10',       dstIp: '10.0.1.5',         event: 'SMB File Access — \\\\filesvr\\reports',   status: 'Success' },
  { timestamp: '2026-04-30 08:05:47', srcIp: '10.0.2.22',       dstIp: '104.18.32.7',      event: 'HTTPS GET — cdn.jsdelivr.net',             status: 'Success' },
  { timestamp: '2026-04-30 08:07:11', srcIp: '10.0.1.5',        dstIp: '10.0.1.1',         event: 'NTP Sync — pool.ntp.org',                  status: 'Success' },

  // ── First SSH brute-force attempts ─────────────────
  { timestamp: '2026-04-30 08:08:22', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — root',                 status: 'Failed',  isThreat: true },
  { timestamp: '2026-04-30 08:08:24', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — admin',                status: 'Failed',  isThreat: true },

  // ── More normal traffic ────────────────────────────
  { timestamp: '2026-04-30 08:10:03', srcIp: '10.0.2.30',       dstIp: '151.101.1.140',    event: 'HTTPS GET — stackoverflow.com',            status: 'Success' },
  { timestamp: '2026-04-30 08:11:55', srcIp: '10.0.3.12',       dstIp: '10.0.1.2',         event: 'LDAP Bind — dc01.corp.local',              status: 'Success' },
  { timestamp: '2026-04-30 08:12:40', srcIp: '10.0.2.15',       dstIp: '8.8.4.4',          event: 'DNS Query — github.com',                   status: 'Success' },
  { timestamp: '2026-04-30 08:14:18', srcIp: '10.0.3.8',        dstIp: '10.0.1.5',         event: 'SMB File Access — \\\\filesvr\\shared',    status: 'Success' },
  { timestamp: '2026-04-30 08:15:02', srcIp: '10.0.2.25',       dstIp: '198.51.100.40',    event: 'HTTPS POST — api.analytics.corp',          status: 'Success' },

  // ── More brute-force attempts ──────────────────────
  { timestamp: '2026-04-30 08:15:33', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — ubuntu',               status: 'Failed',  isThreat: true },
  { timestamp: '2026-04-30 08:15:35', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — deploy',               status: 'Failed',  isThreat: true },

  // ── Normal traffic continues ───────────────────────
  { timestamp: '2026-04-30 08:17:44', srcIp: '10.0.4.2',        dstIp: '10.0.1.1',         event: 'DHCP Lease Renewal',                       status: 'Success' },
  { timestamp: '2026-04-30 08:18:30', srcIp: '10.0.2.18',       dstIp: '216.58.214.206',   event: 'HTTPS GET — drive.google.com',             status: 'Success' },
  { timestamp: '2026-04-30 08:19:55', srcIp: '10.0.3.14',       dstIp: '10.0.1.3',         event: 'RDP Session Start — jumpbox01',            status: 'Success' },
  { timestamp: '2026-04-30 08:21:07', srcIp: '10.0.2.22',       dstIp: '13.107.42.14',     event: 'HTTPS GET — outlook.office365.com',        status: 'Success' },
  { timestamp: '2026-04-30 08:22:33', srcIp: '10.0.2.30',       dstIp: '185.199.108.133',  event: 'HTTPS GET — github.com',                   status: 'Success' },
  { timestamp: '2026-04-30 08:24:10', srcIp: '10.0.1.5',        dstIp: '10.0.1.1',         event: 'Syslog Forward — fw01.corp.local',         status: 'Success' },
  { timestamp: '2026-04-30 08:25:48', srcIp: '10.0.3.10',       dstIp: '10.0.1.2',         event: 'Kerberos TGT Request',                     status: 'Success' },

  // ── Final brute-force wave + successful compromise ─
  { timestamp: '2026-04-30 08:26:02', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — sysadmin',             status: 'Failed',  isThreat: true },
  { timestamp: '2026-04-30 08:26:05', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login Attempt — devops',               status: 'Failed',  isThreat: true },
  { timestamp: '2026-04-30 08:26:09', srcIp: ATTACKER_IP,       dstIp: TARGET_IP,           event: 'SSH Login — devops (SUCCESSFUL)',          status: 'Success', isThreat: true, isCompromise: true },

  // ── Trailing normal traffic ────────────────────────
  { timestamp: '2026-04-30 08:28:15', srcIp: '10.0.2.15',       dstIp: '1.1.1.1',          event: 'DNS Query — slack.com',                    status: 'Success' },
  { timestamp: '2026-04-30 08:29:44', srcIp: '10.0.4.5',        dstIp: '10.0.1.1',         event: 'ICMP Ping — gateway health check',         status: 'Success' },
  { timestamp: '2026-04-30 08:30:22', srcIp: '10.0.2.25',       dstIp: '52.96.166.130',    event: 'HTTPS GET — teams.microsoft.com',          status: 'Success' },
  { timestamp: '2026-04-30 08:31:10', srcIp: '10.0.3.8',        dstIp: '10.0.1.5',         event: 'SMB Print Job — \\\\printsvr\\hp-4050',    status: 'Success' },
  { timestamp: '2026-04-30 08:32:58', srcIp: '10.0.2.18',       dstIp: '142.250.185.206',  event: 'HTTPS GET — calendar.google.com',          status: 'Success' },
  { timestamp: '2026-04-30 08:34:05', srcIp: '10.0.3.12',       dstIp: '10.0.1.2',         event: 'LDAP Search — user lookup',                status: 'Success' },
  { timestamp: '2026-04-30 08:35:30', srcIp: '10.0.4.2',        dstIp: '10.0.1.1',         event: 'ARP Request — gateway resolution',         status: 'Success' },
];


// ─── DOM References ──────────────────────────────────────
const searchInput  = document.getElementById('search-input');
const searchCount  = document.getElementById('search-count');
const logTbody     = document.getElementById('log-tbody');
const tableEmpty   = document.getElementById('table-empty');
const tableInfo    = document.getElementById('table-info');
const clockEl      = document.getElementById('header-clock');

// Stat value elements
const statTotalVal    = document.getElementById('stat-total-val');
const statCriticalVal = document.getElementById('stat-critical-val');
const statFailedVal   = document.getElementById('stat-failed-val');
const statSourcesVal  = document.getElementById('stat-sources-val');

// Navigation elements
const tabDashboard = document.getElementById('tab-dashboard');
const tabRules     = document.getElementById('tab-rules');
const viewDashboard = document.getElementById('view-dashboard');
const viewRules     = document.getElementById('view-rules');
const headerCenter  = document.getElementById('header-center');


// ─── Compute Stats ───────────────────────────────────────
function computeStats() {
  const total    = LOG_DATA.length;
  const critical = LOG_DATA.filter(l => l.isThreat).length;
  const failed   = LOG_DATA.filter(l => l.status === 'Failed').length;
  const sources  = new Set(LOG_DATA.map(l => l.srcIp)).size;

  statTotalVal.textContent    = total;
  statCriticalVal.textContent = critical;
  statFailedVal.textContent   = failed;
  statSourcesVal.textContent  = sources;
}


// ─── Render Table ────────────────────────────────────────
function getStatusClass(status) {
  switch (status.toLowerCase()) {
    case 'success': return 'status--success';
    case 'failed':  return 'status--failed';
    case 'blocked': return 'status--blocked';
    default:        return 'status--info';
  }
}

function getRowClass(log) {
  if (log.isCompromise) return 'row--success-attack';
  if (log.isThreat && log.status === 'Failed') return 'row--critical';
  return '';
}

function renderTable(filter = '') {
  const query = filter.toLowerCase().trim();

  const filtered = query
    ? LOG_DATA.filter(log => {
        const haystack = [
          log.timestamp,
          log.srcIp,
          log.dstIp,
          log.event,
          log.status
        ].join(' ').toLowerCase();
        return haystack.includes(query);
      })
    : LOG_DATA;

  // Update info
  if (query) {
    searchCount.textContent = `${filtered.length} / ${LOG_DATA.length}`;
    tableInfo.textContent   = `Showing ${filtered.length} of ${LOG_DATA.length} entries`;
  } else {
    searchCount.textContent = '';
    tableInfo.textContent   = `${LOG_DATA.length} entries`;
  }

  // Toggle empty state
  tableEmpty.style.display = filtered.length === 0 ? 'flex' : 'none';

  // Build rows
  logTbody.innerHTML = '';

  const fragment = document.createDocumentFragment();

  filtered.forEach(log => {
    const tr = document.createElement('tr');
    const rowClass = getRowClass(log);
    if (rowClass) tr.className = rowClass;

    tr.innerHTML = `
      <td>${escapeHtml(log.timestamp)}</td>
      <td>${escapeHtml(log.srcIp)}</td>
      <td>${escapeHtml(log.dstIp)}</td>
      <td>${escapeHtml(log.event)}</td>
      <td><span class="status-badge ${getStatusClass(log.status)}">${escapeHtml(log.status)}</span></td>
    `;

    fragment.appendChild(tr);
  });

  logTbody.appendChild(fragment);
}


// ─── View Switching ──────────────────────────────────────
function switchView(view) {
  if (view === 'dashboard') {
    viewDashboard.classList.remove('view-hidden');
    viewRules.classList.add('view-hidden');
    headerCenter.classList.remove('view-hidden');
    tabDashboard.classList.add('nav-tab--active');
    tabRules.classList.remove('nav-tab--active');
  } else {
    viewDashboard.classList.add('view-hidden');
    viewRules.classList.remove('view-hidden');
    headerCenter.classList.add('view-hidden');
    tabRules.classList.add('nav-tab--active');
    tabDashboard.classList.remove('nav-tab--active');
  }
}


// ─── Utilities ───────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function updateClock() {
  const now = new Date();
  const opts = {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false
  };
  clockEl.textContent = now.toLocaleDateString('en-US', opts);
}


// ─── Init ────────────────────────────────────────────────
function init() {
  computeStats();
  renderTable();
  updateClock();
  setInterval(updateClock, 1000);

  // Wire search with debounce
  let debounceTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      renderTable(searchInput.value);
    }, 120);
  });

  // Wire tab navigation
  tabDashboard.addEventListener('click', () => switchView('dashboard'));
  tabRules.addEventListener('click', () => switchView('rules'));
}

document.addEventListener('DOMContentLoaded', init);
