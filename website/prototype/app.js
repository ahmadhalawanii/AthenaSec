/* AthenaSec behavior-only JavaScript. HTML owns page content; CSS owns design. */
const DEMO_ACCOUNTS = [
  { email: 'analyst@athenasec.com', password: 'analyst123', role: 'Analyst', name: 'Analyst A', title: 'SOC Analyst', phone: '+971 50 100 2100' },
  { email: 'admin@athenasec.com', password: 'admin123', role: 'Administrator', name: 'System Administrator', title: 'Security Administrator', phone: '+971 50 900 1100' }
];
const MFA_CODE = '123456';
const SESSION_KEY = 'athenasecSession';
const ADMIN_PAGES = new Set(['configuration', 'detection-rules', 'response-policies', 'integrations', 'user-management', 'audit-logs', 'system-health', 'settings']);
const ANALYST_PAGES = new Set(['alerts', 'incidents', 'response-activity']);
const RETIRED_PAGES = new Set(['ai-analysis']);
const state = { currentUser: null, pendingUser: null, currentPage: 'dashboard', selectedAlert: 'ALT-001', selectedIncident: null };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function show(el) { el?.classList.remove('hidden'); }
function hide(el) { el?.classList.add('hidden'); }
function isAdmin() { return state.currentUser?.role === 'Administrator'; }
function canAccess(page) { if (RETIRED_PAGES.has(page)) return false; if (ADMIN_PAGES.has(page)) return isAdmin(); if (ANALYST_PAGES.has(page)) return state.currentUser?.role === 'Analyst'; return true; }
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }
function pillClass(value) { const t = String(value).toLowerCase(); if (t.includes('critical') || t.includes('danger') || t.includes('offline') || t.includes('failed')) return 'danger'; if (t.includes('high') || t.includes('warning')) return 'warn'; if (t.includes('connected') || t.includes('active') || t.includes('enabled') || t.includes('success') || t.includes('completed') || t.includes('closed')) return 'ok'; if (t.includes('medium') || t.includes('ai handled') || t.includes('open')) return 'blue'; return 'muted'; }
function pillHtml(value) { return `<span class="pill ${pillClass(value)}">${escapeHtml(value)}</span>`; }

function init() { restoreRememberedEmail(); bindForms(); bindInputs(); bindClicks(); applyAlertFilters(); restoreSession(); }
function restoreRememberedEmail() { const remembered = localStorage.getItem('athenasecRememberedEmail'); if (remembered) { $('#loginEmail').value = remembered; $('#rememberMe').checked = true; } }
function sessionSnapshot(page = state.currentPage) { return { currentUser: state.currentUser, currentPage: page, selectedAlert: state.selectedAlert }; }
function persistSession(page = state.currentPage) { if (state.currentUser) localStorage.setItem(SESSION_KEY, JSON.stringify(sessionSnapshot(page))); }
function clearSession() { localStorage.removeItem(SESSION_KEY); }
function restoreSession() {
  try {
    const saved = JSON.parse(localStorage.getItem(SESSION_KEY) || 'null');
    if (!saved?.currentUser?.email) return false;
    const account = DEMO_ACCOUNTS.find(user => user.email === saved.currentUser.email && user.role === saved.currentUser.role);
    if (!account) { clearSession(); return false; }
    state.currentUser = { ...account, ...saved.currentUser };
    state.selectedAlert = saved.selectedAlert || 'ALT-001';
    hide($('#authViews')); hide($('#loginView')); hide($('#mfaView')); show($('#appShell'));
    applyRoleAccess();
    navigate(canAccess(saved.currentPage) ? saved.currentPage : 'dashboard');
    showAiPanel(state.selectedAlert);
    return true;
  } catch {
    clearSession();
    return false;
  }
}

function bindForms() {
  $('#loginForm').addEventListener('submit', event => {
    event.preventDefault();
    const email = $('#loginEmail').value.trim().toLowerCase();
    const password = $('#loginPassword').value;
    const user = DEMO_ACCOUNTS.find(account => account.email === email && account.password === password);
    if (!user) return showInlineError('loginError', 'Invalid email or password. Use one of the AthenaSec demo accounts.');
    state.pendingUser = { ...user };
    $('#rememberMe').checked ? localStorage.setItem('athenasecRememberedEmail', email) : localStorage.removeItem('athenasecRememberedEmail');
    hide($('#loginView')); show($('#mfaView')); $('[data-mfa-digit]')?.focus();
  });
  $('#mfaForm').addEventListener('submit', event => {
    event.preventDefault();
    const code = $$('[data-mfa-digit]').map(input => input.value).join('');
    if (code !== MFA_CODE) return showInlineError('mfaError', 'Invalid MFA code. Enter the 6-digit demo code 123456.');
    state.currentUser = state.pendingUser; state.pendingUser = null;
    hide($('#authViews')); show($('#appShell')); applyRoleAccess(); navigate('dashboard'); persistSession('dashboard');
  });
}

function bindInputs() {
  $$('[data-mfa-digit]').forEach(input => input.addEventListener('input', () => { input.value = input.value.replace(/\D/g, '').slice(0, 1); if (input.value) input.nextElementSibling?.focus(); }));
  ['attackFilter', 'riskFilter', 'riskSort'].forEach(id => $('#' + id)?.addEventListener('change', applyAlertFilters));
  $('#dashboardSearch')?.addEventListener('input', filterDashboardAlerts); $('#dashboardSeverity')?.addEventListener('change', filterDashboardAlerts);
  $('#incidentSearch')?.addEventListener('input', filterIncidents); $('#incidentSeverity')?.addEventListener('change', filterIncidents); $('#incidentStatus')?.addEventListener('change', filterIncidents);
  $('#ruleSearch')?.addEventListener('input', filterRules); $('#ruleStatus')?.addEventListener('change', filterRules);
  $('#auditSearch')?.addEventListener('input', filterAuditLogs); $('#auditResult')?.addEventListener('change', filterAuditLogs);
  $('#globalSearch')?.addEventListener('input', updateGlobalSearch);
}

function bindClicks() {
  document.addEventListener('click', event => {
    const pageLink = event.target.closest('[data-page-link]');
    if (pageLink) return navigate(pageLink.dataset.pageLink);
    const button = event.target.closest('[data-action]');
    if (!button) return closeFloatingMenus(event);
    const action = button.dataset.action;
    if (action === 'logout') return confirmModal('Logout Confirmation', 'End this AthenaSec session and return to login?', logout);
    if (action === 'forgot-password') return modal('Forgot Password', 'For this demo, use analyst123 or admin123 for the demo accounts.');
    if (action === 'resend-code') return modal('MFA Code Sent', 'A new demo MFA code was sent. Continue using 123456 for this prototype.');
    if (action === 'view-alert') return showAlertDetail(button.dataset.alertId, true);
    if (action === 'close-alert-drawer') return closeAlertDrawer();
    if (action === 'close-alert') return closeAlert(button.dataset.alertId);
    if (action === 'view-logs') return modal('Alert Logs', `Relevant authentication and endpoint logs are preserved for ${button.dataset.alertId}.`);
    if (action === 'open-timeline') return modal('Open Timeline', 'The timeline view is available inside Alert Analysis and Incident Response.');
    if (action === 'view-case') return openCaseSummary(button.dataset.caseId);
    if (action === 'toggle-case-status') return toggleCaseStatus(button);
    if (action === 'view-execution') return openExecutionDetails(button.dataset.executionId);
    if (action === 'save-config') return saveConfig();
    if (action === 'cancel-config') return modal('Cancel Changes', 'Configuration changes were discarded.');
    if (action === 'add-rule') return addRule();
    if (action === 'edit-rule') return modal('Edit Rule', 'Rule editor opened for this demo row.');
    if (action === 'toggle-rule') return toggleRule(button);
    if (action === 'delete-rule') return deleteRule(button);
    if (action === 'save-policy') return modal('Policy Update', 'Response policy changes were saved.');
    if (action === 'sync-integration') return syncIntegration(button);
    if (action === 'add-user') return addUser();
    if (action === 'edit-user') return modal('Edit User', 'User editor opened for this demo row.');
    if (action === 'disable-user') return toggleUser(button);
    if (action === 'reset-user') return modal('Reset Password', 'Password reset workflow created.');
    if (action === 'refresh-health') return modal('System Health', 'System health metrics refreshed.');
    if (action === 'save-settings') return modal('Save Settings', 'Administrator console settings were saved.');
    if (action === 'cancel-settings') return modal('Cancel Settings', 'Settings changes were discarded.');
    if (action === 'save-profile') return saveProfile();
  });
  $('#notificationButton').addEventListener('click', () => toggleDropdown('notificationDropdown'));
  $('#userMenuButton').addEventListener('click', () => toggleDropdown('userDropdown'));
}

function applyRoleAccess() {
  const admin = isAdmin();
  $$('[data-admin-only]').forEach(el => el.classList.toggle('hidden', !admin));
  $$('[data-analyst-only]').forEach(el => el.classList.toggle('hidden', admin));
  $$('[data-role-view]').forEach(view => view.classList.toggle('hidden', view.dataset.roleView !== state.currentUser.role));
  $('#workspaceRole').textContent = `${state.currentUser.role} Workspace`;
  $('#sidebarTitle').textContent = admin ? 'Security Management' : 'Analyst';
  $('#userMenuButton').textContent = state.currentUser.name;
  $('#profileRole').textContent = state.currentUser.role;
  $('#profileName').value = state.currentUser.name;
  $('#profilePhone').value = state.currentUser.phone;
  $('#profileAccount').innerHTML = profileHtml();
}

function navigate(page) {
  if (!canAccess(page)) return modal('Access Restricted', 'This page is not available for the current role.');
  state.currentPage = page;
  $$('.page').forEach(section => section.classList.toggle('active', section.dataset.page === page));
  $$('[data-page-link]').forEach(link => link.classList.toggle('active', link.dataset.pageLink === page));
  hide($('#searchResults')); closeFloatingMenus();
  persistSession(page);
}

function showAlertDetail(alertId, shouldOpenDrawer) {
  state.selectedAlert = alertId;
  if (shouldOpenDrawer) {
    if (state.currentPage !== 'alerts') navigate('alerts');
    openAlertAnalysis(alertId);
  }
}
function alertAnalysisCopy(alertId) {
  const copy = {
    'ALT-001': {
      summary: 'AthenaSec detected a critical SSH brute force campaign against privileged accounts.',
      reasoning: 'The source generated a high-frequency failed login burst, matched prior scanner reputation, and crossed the critical authentication abuse threshold.',
      mitre: 'T1110 - Brute Force',
      explanation: 'The event indicates credential access activity. A case was created for analyst-owned follow-up while the AI supplied analysis and recommended containment evidence.'
    },
    'ALT-002': {
      summary: 'AthenaSec identified suspicious sudo escalation on endpoint-03.',
      reasoning: 'Privilege escalation telemetry matched an allowed autonomous response policy with high confidence and limited blast radius.',
      mitre: 'T1548 - Abuse Elevation Control Mechanism',
      explanation: 'The AI resolved the alert autonomously and recorded the reasoning for analyst review. No case lifecycle action was managed by AI.'
    },
    'ALT-003': {
      summary: 'AthenaSec correlated a password spray pattern across VPN authentication attempts.',
      reasoning: 'The activity was distributed across accounts and stayed below the critical threshold, so the alert remains open for analyst review.',
      mitre: 'T1110.003 - Password Spraying',
      explanation: 'This alert is related to Brute Force behavior and provides summary, risk, and evidence for analyst triage.'
    },
    'ALT-004': {
      summary: 'AthenaSec classified kernel exploit telemetry as malicious privilege escalation activity.',
      reasoning: 'The endpoint telemetry, exploit signature, and risk score matched the Critical Host Isolation policy.',
      mitre: 'T1068 - Exploitation for Privilege Escalation',
      explanation: 'The AI executed the autonomous response and records the full decision path in Incident Response history.'
    },
    'ALT-005': {
      summary: 'AthenaSec observed a low-volume SSH probe related to Brute Force reconnaissance.',
      reasoning: 'The activity had weak intensity, limited targeting, and no successful authentication, so it was closed after correlation.',
      mitre: 'T1110 - Brute Force',
      explanation: 'The alert remains visible as supporting history for future brute force correlation.'
    }
  };
  return copy[alertId] || copy['ALT-001'];
}
function openAlertAnalysis(alertId) {
  const row = document.querySelector(`[data-alert-id="${alertId}"]`);
  if (!row) return modal('Alert Analysis', 'Alert analysis is unavailable for this row.');
  const cells = $$('td', row);
  const analysis = alertAnalysisCopy(alertId);
  const detail = [
    ['Alert ID', cells[0]?.textContent],
    ['Severity', cells[1]?.textContent],
    ['Attack Type', cells[2]?.textContent],
    ['Source IP', cells[3]?.textContent],
    ['Destination IP', cells[4]?.textContent],
    ['Endpoint', cells[5]?.textContent],
    ['Risk Score', cells[6]?.textContent],
    ['Status', cells[7]?.textContent],
    ['Assigned Analyst', cells[8]?.textContent],
    ['Time', cells[9]?.textContent]
  ];
  $('#alertDrawerRoot').innerHTML = `<div class="drawer-backdrop" data-action="close-alert-drawer"><aside class="alert-drawer" role="dialog" aria-modal="true" aria-label="Alert analysis" onclick="event.stopPropagation()"><div class="drawer-head"><div><span class="sub">Alert Analysis</span><h2>${escapeHtml(alertId)}</h2></div><button class="icon-btn" data-action="close-alert-drawer" aria-label="Close alert analysis">x</button></div><div class="drawer-body"><div class="card"><h3>Alert Details</h3>${detail.map(([label, value]) => `<div class="kv"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div><div class="card"><h3>Attack Workflow</h3><div class="analysis-flow"><span>Detection</span><span>Correlation</span><span>Risk Scoring</span><span>AI Analysis</span></div></div><div class="card"><h3>AI-Generated Analysis</h3><p class="sub">${escapeHtml(analysis.summary)}</p></div><div class="card"><h3>AI Reasoning</h3><p class="sub">${escapeHtml(analysis.reasoning)}</p></div><div class="card"><h3>MITRE ATT&CK Mapping</h3><span class="pill blue">${escapeHtml(analysis.mitre)}</span><br><br><div class="kv"><span>Risk Score</span><strong>${escapeHtml(cells[6]?.textContent)} / 100</strong></div></div><div class="card"><h3>Technical Explanation</h3><p class="sub">${escapeHtml(analysis.explanation)}</p></div></div></aside></div>`;
  bindDrawerCloseButton();
}
function bindDrawerCloseButton() { $('#alertDrawerRoot .drawer-head button[data-action="close-alert-drawer"]')?.addEventListener('click', event => { event.stopPropagation(); closeAlertDrawer(); }); }
function closeAlertDrawer() { $('#alertDrawerRoot').innerHTML = ''; }
function showAiPanel(alertId) { state.selectedAlert = alertId; persistSession(); }

function applyAlertFilters() { const attack = $('#attackFilter').value, risk = $('#riskFilter').value, sort = $('#riskSort').value, tbody = $('#alertsTableBody'), rows = $$('tr', tbody); rows.forEach(row => row.classList.toggle('hidden', !((attack === 'all' || row.dataset.attack === attack) && (risk === 'all' || row.dataset.riskBand === risk)))); rows.sort((a, b) => sort === 'desc' ? Number(b.dataset.risk) - Number(a.dataset.risk) : Number(a.dataset.risk) - Number(b.dataset.risk)).forEach(row => tbody.appendChild(row)); $('#visibleAlertCount').textContent = rows.filter(row => !row.classList.contains('hidden')).length + ' visible alerts'; }
function filterDashboardAlerts() { const query = $('#dashboardSearch').value.toLowerCase(), severity = $('#dashboardSeverity').value; $$('[data-dashboard-alert]').forEach(row => row.classList.toggle('hidden', !(row.textContent.toLowerCase().includes(query) && (severity === 'all' || row.dataset.severity === severity)))); }
function filterIncidents() { const query = $('#incidentSearch').value.toLowerCase(), severity = $('#incidentSeverity').value, status = $('#incidentStatus').value; $$('#incidentRows tr').forEach(row => row.classList.toggle('hidden', !(row.textContent.toLowerCase().includes(query) && (severity === 'all' || row.dataset.severity === severity) && (status === 'all' || row.dataset.status === status)))); }
function filterRules() { const query = $('#ruleSearch').value.toLowerCase(), status = $('#ruleStatus').value; $$('#ruleRows tr').forEach(row => row.classList.toggle('hidden', !(row.textContent.toLowerCase().includes(query) && (status === 'all' || row.dataset.status === status)))); }
function filterAuditLogs() { const query = $('#auditSearch').value.toLowerCase(), result = $('#auditResult').value; $$('[data-page-target="audit-logs"]').forEach(row => row.classList.toggle('hidden', !(row.textContent.toLowerCase().includes(query) && (result === 'all' || row.textContent.includes(result))))); }

function updateGlobalSearch() {
  const query = $('#globalSearch').value.trim().toLowerCase();
  const box = $('#searchResults');
  if (!query) return hide(box);
  const records = searchableRecords().filter(record => record.text.toLowerCase().includes(query)).slice(0, 10);
  box.innerHTML = records.length ? records.map((record, i) => `<button class="search-result" data-search-result="${i}"><span>${record.pageName}</span><strong>${escapeHtml(record.title)}</strong><p>${escapeHtml(record.description)}</p></button>`).join('') : '<div class="empty">No matching results found.</div>';
  show(box);
  $$('[data-search-result]', box).forEach((button, i) => button.addEventListener('click', () => { const record = records[i]; record.alertId ? showAlertDetail(record.alertId, true) : navigate(record.pageId); highlightPage(record.pageId); }));
}
function searchableRecords() { const records = []; $$('[data-search-page]').forEach(page => { if (canAccess(page.dataset.page)) records.push({ pageId: page.dataset.page, pageName: page.dataset.pageName, title: page.dataset.pageName, description: page.textContent.trim().slice(0, 120), text: page.textContent }); }); $$('[data-search-record]').forEach(record => { const pageId = record.dataset.pageTarget; if (canAccess(pageId)) records.push({ pageId, pageName: pageName(pageId), title: firstCell(record), description: record.textContent.trim().slice(0, 140), text: record.textContent, alertId: record.dataset.alertId }); }); return records; }
function pageName(page) {
  const names = { incidents: 'Case Management', 'response-activity': 'Incident Response' };
  return names[page] || page.split('-').map(word => word[0].toUpperCase() + word.slice(1)).join(' ');
}
function firstCell(row) { return row.querySelector('td,h1,h2,strong')?.textContent.trim() || pageName(row.dataset.pageTarget); }
function highlightPage(page) { const section = document.querySelector(`[data-page="${page}"]`); section?.classList.add('is-highlighted'); setTimeout(() => section?.classList.remove('is-highlighted'), 1600); }

function caseSummaryData(caseId) {
  const data = {
    'CASE-006': {
      summary: 'Critical brute force case created from ALT-001 after repeated privileged SSH authentication failures.',
      aiSummary: 'AthenaSec summarized source reputation, failed login frequency, and affected account exposure for analyst review.',
      recommended: 'Validate account exposure, preserve authentication logs, and confirm whether additional accounts were targeted.',
      evidence: ['ALT-001 risk score 92', 'Source IP 192.168.1.45', 'Repeated SSH failures', 'Privileged account targeting']
    },
    'CASE-007': {
      summary: 'Privilege escalation case created from ALT-002 for analyst investigation and ownership.',
      aiSummary: 'AthenaSec identified suspicious sudo escalation telemetry and prepared context for the case record.',
      recommended: 'Review sudo command history, validate endpoint owner activity, and compare against approved maintenance windows.',
      evidence: ['ALT-002 risk score 84', 'endpoint-03 telemetry', 'sudo escalation sequence', 'Privilege policy match']
    },
    'CASE-008': {
      summary: 'Closed case for critical kernel exploit telemetry associated with ALT-004.',
      aiSummary: 'AthenaSec summarized exploit evidence and response context, while analysts retained case lifecycle ownership.',
      recommended: 'Retain evidence for audit and confirm endpoint recovery documentation is complete.',
      evidence: ['ALT-004 risk score 95', 'endpoint-09 exploit telemetry', 'Critical Host Isolation policy', 'Analyst C closure']
    }
  };
  return data[caseId] || data['CASE-006'];
}
function openCaseSummary(caseId) {
  const row = document.querySelector(`[data-case-id="${caseId}"]`);
  if (!row) return modal('Case Summary', 'Case summary is unavailable for this row.');
  const cells = $$('td', row);
  const data = caseSummaryData(caseId);
  $('#alertDrawerRoot').innerHTML = `<div class="drawer-backdrop" data-action="close-alert-drawer"><aside class="alert-drawer" role="dialog" aria-modal="true" aria-label="Case summary" onclick="event.stopPropagation()"><div class="drawer-head"><div><span class="sub">Case Summary</span><h2>${escapeHtml(caseId)}</h2></div><button class="icon-btn" data-action="close-alert-drawer" aria-label="Close case summary">x</button></div><div class="drawer-body"><div class="card"><h3>Case Details</h3><div class="kv"><span>Source Alert</span><strong>${escapeHtml(cells[1]?.textContent)}</strong></div><div class="kv"><span>Severity</span><strong>${escapeHtml(cells[2]?.textContent)}</strong></div><div class="kv"><span>Status</span><strong>${escapeHtml(cells[3]?.textContent)}</strong></div><div class="kv"><span>Assigned Analyst</span><strong>${escapeHtml(cells[4]?.textContent)}</strong></div></div><div class="card"><h3>Case Summary</h3><p class="sub">${escapeHtml(data.summary)}</p></div><div class="card"><h3>AI Summary</h3><p class="sub">${escapeHtml(data.aiSummary)}</p></div><div class="card"><h3>Recommended Response</h3><p class="sub">${escapeHtml(data.recommended)}</p></div><div class="card"><h3>Supporting Evidence</h3><div class="split-list">${data.evidence.map(item => `<span class="pill blue">${escapeHtml(item)}</span>`).join('')}</div></div><div class="notice">This panel is informational only. Case ownership, status changes, and lifecycle decisions remain analyst-driven.</div></div></aside></div>`;
  bindDrawerCloseButton();
}
function toggleCaseStatus(button) {
  const row = button.closest('tr[data-case-id]');
  if (!row) return;
  const caseId = row.dataset.caseId;
  const isOpen = row.dataset.status === 'Open';
  const nextStatus = isOpen ? 'Closed' : 'Open';
  const actionText = isOpen ? 'close' : 'reopen';
  confirmModal('Update Case Status', `Are you sure you want to ${actionText} this case?`, () => {
    row.dataset.status = nextStatus;
    row.querySelector('.incident-status').innerHTML = pillHtml(nextStatus);
    button.textContent = nextStatus === 'Open' ? 'Close Case' : 'Reopen Case';
    filterIncidents();
    modal('Case Status Updated', `${escapeHtml(caseId)} is now ${escapeHtml(nextStatus)}.`);
  });
}
function executionDetailsData(id) {
  const data = {
    'EXE-004': {
      happened: 'AthenaSec AI isolated endpoint-09 after kernel exploit telemetry matched a critical response policy.',
      classified: 'The telemetry showed privilege escalation behavior, local exploit indicators, and a risk score above the autonomous response threshold.',
      response: 'Endpoint isolation was selected to prevent lateral movement while preserving telemetry for investigation.',
      policy: 'Critical Host Isolation',
      evidence: ['Risk score 95', 'Kernel exploit attempt', 'Endpoint endpoint-09', 'Policy threshold met'],
      timeline: [['15:17', 'Exploit pattern detected'], ['15:18', 'Risk score calculated'], ['15:19', 'Endpoint isolated']]
    },
    'EXE-001': {
      happened: 'AthenaSec AI blocked source IP 192.168.1.45 after a critical brute force alert.',
      classified: 'The source matched suspicious reputation and generated a high-frequency authentication failure burst.',
      response: 'Blocking the IP reduced active credential attack pressure against privileged accounts.',
      policy: 'Critical Authentication Abuse',
      evidence: ['Risk score 92', 'SSH failure burst', 'Privileged account targeting', 'Scanner reputation match'],
      timeline: [['14:32', 'Failed SSH burst detected'], ['14:33', 'Policy matched'], ['14:33', 'Source IP blocked']]
    }
  };
  return data[id] || data['EXE-001'];
}
function openExecutionDetails(id) {
  const row = document.querySelector(`[data-execution-id="${id}"]`);
  if (!row) return modal('AI Execution Details', 'Execution details are unavailable for this row.');
  const data = executionDetailsData(id);
  $('#alertDrawerRoot').innerHTML = `<div class="drawer-backdrop" data-action="close-alert-drawer"><aside class="alert-drawer" role="dialog" aria-modal="true" aria-label="AI execution details" onclick="event.stopPropagation()"><div class="drawer-head"><div><span class="sub">AI Execution Details</span><h2>${escapeHtml(id)}</h2></div><button class="icon-btn" data-action="close-alert-drawer" aria-label="Close execution details">x</button></div><div class="drawer-body"><div class="card"><h3>What Happened</h3><p class="sub">${escapeHtml(data.happened)}</p></div><div class="card"><h3>Why It Was Malicious</h3><p class="sub">${escapeHtml(data.classified)}</p></div><div class="card"><h3>Why This Response Was Executed</h3><p class="sub">${escapeHtml(data.response)}</p></div><div class="card"><h3>Policy / Rule Triggered</h3><span class="pill blue">${escapeHtml(data.policy)}</span></div><div class="card"><h3>Supporting Evidence</h3><div class="split-list">${data.evidence.map(item => `<span class="pill blue">${escapeHtml(item)}</span>`).join('')}</div></div><div class="card"><h3>Timeline</h3><div class="timeline">${data.timeline.map(([time, event]) => `<div class="timeline-item"><strong>${escapeHtml(time)}</strong><span>${escapeHtml(event)}</span></div>`).join('')}</div></div></div></aside></div>`;
  bindDrawerCloseButton();
}
function closeAlert(id) { confirmModal('Close Alert', `Close ${id} and mark it as analyst-reviewed?`, () => { const row = document.querySelector(`[data-alert-id="${id}"]`); row.querySelector('.status-cell').innerHTML = pillHtml('Closed'); closeAlertDrawer(); modal('Alert Closed', `${id} has been closed.`); }); }
function saveConfig() { $('#configState').textContent = 'Saved'; $('#configState').className = 'pill ok'; modal('Save Changes', 'Configuration updates were saved.'); }
function addRule() { $('#ruleRows').insertAdjacentHTML('afterbegin', `<tr data-status="Enabled"><td>New Detection Rule</td><td>Authentication</td><td>5 events / 60s</td><td>Analyst review</td><td class="actions-cell"><button class="btn small" data-action="edit-rule">Edit/Modify</button> <button class="btn small" data-action="toggle-rule">Disable</button> <button class="btn small danger" data-action="delete-rule">Delete</button></td><td class="rule-status">${pillHtml('Enabled')}</td></tr>`); }
function toggleRule(button) { const row = button.closest('tr'); const next = row.dataset.status === 'Enabled' ? 'Disabled' : 'Enabled'; row.dataset.status = next; row.querySelector('.rule-status').innerHTML = pillHtml(next); button.textContent = next === 'Enabled' ? 'Disable' : 'Enable'; }
function deleteRule(button) { confirmModal('Rule Deletion', 'Delete this detection rule?', () => button.closest('tr').remove()); }
function syncIntegration(button) { const row = button.closest('tr'); row.children[2].innerHTML = pillHtml('Connected'); row.children[4].textContent = 'Just now'; }
function addUser() { $('#userRows').insertAdjacentHTML('beforeend', `<tr><td>New Analyst</td><td>Analyst</td><td class="user-status">${pillHtml('Active')}</td><td class="actions-cell"><button class="btn small" data-action="edit-user">Edit/Manage</button> <button class="btn small danger" data-action="disable-user">Disable User</button> <button class="btn small" data-action="reset-user">Reset Password</button></td><td>Never</td></tr>`); }
function toggleUser(button) { const cell = button.closest('tr').querySelector('.user-status'); const disabled = cell.textContent.includes('Disabled'); cell.innerHTML = pillHtml(disabled ? 'Active' : 'Disabled'); button.textContent = disabled ? 'Disable User' : 'Enable User'; }
function saveProfile() { state.currentUser.name = $('#profileName').value || state.currentUser.name; state.currentUser.phone = $('#profilePhone').value || state.currentUser.phone; applyRoleAccess(); persistSession(); modal('Profile Saved', 'Profile details were updated.'); }
function profileHtml() { return `<div class="kv"><span>Name</span><strong>${escapeHtml(state.currentUser.name)}</strong></div><div class="kv"><span>Email</span><strong>${escapeHtml(state.currentUser.email)}</strong></div><div class="kv"><span>Role</span><strong>${escapeHtml(state.currentUser.role)}</strong></div><div class="kv"><span>Title</span><strong>${escapeHtml(state.currentUser.title)}</strong></div><div class="kv"><span>Session</span><strong>${pillHtml('MFA Verified')}</strong></div>`; }
function toggleDropdown(id) { $$('.dropdown').forEach(dropdown => { if (dropdown.id !== id) hide(dropdown); }); document.getElementById(id).classList.toggle('hidden'); }
function closeFloatingMenus(event) { if (event && event.target.closest('.dropdown-wrap')) return; hide($('#notificationDropdown')); hide($('#userDropdown')); }
function showInlineError(id, msg) { const box = $('#' + id); box.textContent = msg; show(box); }
function modal(title, body) { $('#modal-root').innerHTML = `<div class="modal-backdrop" data-close-modal><div class="modal"><h2>${escapeHtml(title)}</h2><div class="modal-body">${body}</div><div class="modal-actions"><button class="btn primary" data-close-modal>OK</button></div></div></div>`; }
function confirmModal(title, body, onConfirm) { $('#modal-root').innerHTML = `<div class="modal-backdrop"><div class="modal"><h2>${escapeHtml(title)}</h2><div class="modal-body">${body}</div><div class="modal-actions"><button class="btn" data-close-modal>Cancel</button><button class="btn primary" id="confirmModalButton">Confirm</button></div></div></div>`; $('#confirmModalButton').onclick = () => { $('#modal-root').innerHTML = ''; onConfirm(); }; }
document.addEventListener('click', event => { if (event.target.matches('[data-close-modal]')) $('#modal-root').innerHTML = ''; });
function logout() { clearSession(); state.currentUser = null; hide($('#appShell')); show($('#authViews')); show($('#loginView')); hide($('#mfaView')); $('#modal-root').innerHTML = ''; }
init();
