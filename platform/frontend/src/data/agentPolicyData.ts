import type {
  ActionTier,
  ApproverRole,
  AssessmentInput,
  AssetClass,
  Outcome,
  Tier2ActionName,
} from '../types/policyTypes'

/*
  The Agent Action Catalogue and Approval Policy
  (design/agent-action-policy.pdf) as data. The numbers here are the
  policy's; the engine in policyEngine.ts applies them.
*/

// ----- Scoring -----

// risk = 100 x (0.35 S + 0.25 E + 0.25 R + 0.15 A), each input normalised to 0-1
export const RISK_WEIGHTS = { S: 0.35, E: 0.25, R: 0.25, A: 0.15 } as const

export const RULE_LEVEL_MAX = 15
export const SIGNALS_MAX = 5

// Asset criticality, normalised (decision: Critical 1.0, Business 0.6, Standard 0.3)
export const ASSET_WEIGHT: Record<AssetClass, number> = {
  Critical: 1,
  Business: 0.6,
  Standard: 0.3,
}

// Wazuh rule level bands
export const SEVERITY_BANDS = [
  { label: 'Low', min: 0, max: 6 },
  { label: 'Medium', min: 7, max: 9 },
  { label: 'High', min: 10, max: 12 },
  { label: 'Critical', min: 13, max: 15 },
] as const

// Confidence bands: Low < 0.50, Medium 0.50-0.79, High >= 0.80
export const CONFIDENCE_MEDIUM_FROM = 0.5
export const CONFIDENCE_HIGH_FROM = 0.8

/*
  "Now" in the demo: every deadline and expiry is compared with this,
  never with the real clock, so ALT-001's request (deadline 15:59:30)
  is still open however late the demo is run. One minute after the
  isolation finished (15:45:00). Only Demo mode moves it (from C4).
  A local "YYYY-MM-DDTHH:MM:SS" string, like every time in the seed.
*/
export const DEMO_NOW = '2026-08-03T15:46:00'

// Reputation at or above this is "malicious"
export const REPUTATION_MALICIOUS = 0.7

// ----- Decision ladder (page 6) -----

export const THRESHOLDS = {
  isolate: { risk: 85, confidence: 0.85 },
  block: { risk: 70, confidence: 0.8 },
  suspend: { risk: 75, confidence: 0.8 },
  // 60 and above becomes alert + ticket; 40-59 is investigate; below 40 is monitor
  ticketRisk: 60,
  investigateRisk: 40,
  // Below this confidence the agent investigates at any risk of 40 or more
  lowConfidence: 0.5,
} as const

export const OUTCOME_LABELS: Record<Outcome, string> = {
  monitor: 'Monitor',
  investigate_further: 'Investigate further',
  create_alert_and_ticket: 'Create alert and ticket',
  recommend_block_ip: 'Recommend IP block',
  recommend_host_isolation: 'Recommend host isolation',
}

// ----- The action catalogue's shared pieces -----

// Where a row's values come from: the page of the policy PDF that states them
export type CatalogueSource = 'PDF p.3' | 'PDF p.4' | 'PDF p.5'

/*
  A value the PDF does not give. It is shown with an "Assumption" tag and
  this note, and listed for the PDF revision (design/policy-pdf-gaps.md).
*/
export type Assumption = { field: 'reversible' | 'does'; note: string }

// ----- Tier 1: allowed, no approval -----

export type Tier1Action = {
  name: string
  does: string
  whenUsed: string
  limits: string
  // Only monitor has a duration
  maxMinutes?: number
  reversible: string
  source: 'PDF p.3'
  assumed?: Assumption[]
}

export const tier1Actions: Tier1Action[] = [
  {
    name: 'get_logs(source, time_range)',
    does: 'Pulls Wazuh and OpenSearch events',
    whenUsed: 'Any alert under analysis',
    limits: 'Read-only; 24 h window per call',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'analyse_alert(alert_id)',
    does: 'Correlates events, classifies the attack, computes risk and confidence',
    whenUsed: 'Every new alert',
    limits: 'Read-only',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'check_ip_reputation(ip)',
    does: 'Queries Cortex analyzers and MISP',
    whenUsed: 'Alert involves an external IP',
    limits: 'Read-only; analyzer rate limits apply',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'get_asset_context(host)',
    does: 'Returns owner, criticality class and exposure',
    whenUsed: 'Alert involves an internal host',
    limits: 'Read-only',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'monitor(entity, duration)',
    does: 'Adds an IP, user or host to a watchlist with tighter alerting',
    whenUsed: 'Risk below 40, or risk 40-59 with low confidence',
    limits: 'Max 24 h, then re-assessed',
    maxMinutes: 24 * 60,
    reversible: 'Expires after at most 24 h',
    source: 'PDF p.3',
  },
  {
    name: 'create_alert(alert)',
    does: 'Raises a correlated alert in the dashboard',
    whenUsed: 'Risk 40 or more',
    limits: 'No change to systems',
    reversible: 'No change to systems',
    source: 'PDF p.3',
  },
  {
    name: 'create_ticket(case)',
    does: 'Opens a case with evidence attached',
    whenUsed: 'Risk 60 or more, or any Tier 2 recommendation',
    limits: 'No change to systems',
    reversible: 'No change to systems',
    source: 'PDF p.3',
  },
  {
    name: 'recommend_response(rec)',
    does: 'Produces a structured recommendation for a human',
    whenUsed: 'Risk 70 or more and a matching policy',
    limits: 'Recommendation only, never executes',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'notify_analyst(channel, message)',
    does: 'Sends an alert or approval request',
    whenUsed: 'Any ticket or recommendation',
    limits: 'Internal channels only',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
  },
  {
    name: 'capture_telemetry(host)',
    does: 'Collects extra process and network data from a host',
    whenUsed: 'Evidence is thin and the host is reachable',
    limits: 'Read-only, changes nothing on the host',
    reversible: 'Nothing to reverse',
    source: 'PDF p.3',
    assumed: [{ field: 'does', note: 'The PDF does not list this action; the backend agent uses it to gather evidence, so the app shows it as Tier 1.' }],
  },
]

// ----- Tier 2: approval-required -----

export type Tier2Action = {
  name: Tier2ActionName
  signature: string
  // All of these must hold before the agent may recommend it
  conditions: string[]
  // Not set for an action that does not reverse on its own
  defaultMinutes?: number
  maxMinutes?: number
  // Duration wording from the policy
  durationNote: string
  approver: ApproverRole
  approvalWindowMinutes: number
  // The risk and confidence the agent needs before it may recommend this action
  floor: { risk: number; confidence: number }
  // The action as a phrase, so a refusal can name it ("Blocking an IP needs ...")
  phrase: string
  does: string
  reversible: string
  source: 'PDF p.4'
  assumed?: Assumption[]
}

const NO_DESCRIPTION: Assumption = {
  field: 'does',
  note: 'The PDF names this action but does not describe what it does; the wording is the app’s.',
}

const NOT_IN_PDF: Assumption = {
  field: 'does',
  note: 'The PDF does not list this action; the app adds it as an assumption (PDF gap 17).',
}

const NOT_REVERSIBLE: Assumption = {
  field: 'reversible',
  note: 'It does not reverse on its own, so it has no duration; a person undoes it.',
}

export const tier2Actions: Tier2Action[] = [
  {
    name: 'block_ip',
    signature: 'block_ip(ip, duration)',
    floor: THRESHOLDS.block,
    phrase: 'blocking an IP',
    does: 'Blocks an external IP at the firewall for a set time',
    reversible: 'Yes: auto-unblock on expiry',
    source: 'PDF p.4',
    assumed: [NO_DESCRIPTION],
    conditions: [
      'External IP, not on the allow-list',
      'Reputation 0.70 or more, OR 10 or more failed logins across 3 or more accounts in 5 min',
      'Risk 70 or more',
      'Confidence 0.80 or more',
      'A matching response policy',
    ],
    defaultMinutes: 30,
    maxMinutes: 24 * 60,
    durationNote: 'Default 30 min, max 24 h, auto-unblock on expiry',
    approver: 'soc_analyst',
    approvalWindowMinutes: 15,
  },
  {
    name: 'isolate_host',
    signature: 'isolate_host(host, path)',
    floor: THRESHOLDS.isolate,
    phrase: 'isolating an endpoint',
    does: 'Cuts a host off the network through the EDR',
    reversible: 'Yes: reconnects at expiry',
    source: 'PDF p.4',
    assumed: [
      NO_DESCRIPTION,
      {
        field: 'reversible',
        note: 'The PDF says “then re-review” for isolation, but also that every Tier 2 action expires automatically; the app reconnects the host at expiry.',
      },
    ],
    conditions: [
      'Exploit, malware or ransomware evidence on the host',
      'Risk 85 or more',
      'Confidence 0.85 or more',
      'Asset class Business or Standard only',
      'A matching response policy',
    ],
    defaultMinutes: 120,
    maxMinutes: 240,
    durationNote: 'Default 2 h, max 4 h, then re-review',
    approver: 'soc_lead',
    approvalWindowMinutes: 15,
  },
  {
    name: 'suspend_user_session',
    signature: 'suspend_user_session(user, duration)',
    floor: THRESHOLDS.suspend,
    phrase: 'locking an account',
    does: 'Ends a user’s sessions and holds the account for a set time',
    reversible: 'Yes: expires automatically',
    source: 'PDF p.4',
    assumed: [NO_DESCRIPTION],
    conditions: [
      'Non-privileged account only',
      'Credential misuse confirmed by 2 or more signals',
      'Risk 75 or more',
      'Confidence 0.80 or more',
    ],
    defaultMinutes: 30,
    maxMinutes: 60,
    durationNote: 'Default 30 min, max 60 min',
    approver: 'soc_analyst',
    approvalWindowMinutes: 15,
  },
  // The three below are not in the PDF (gap 17). They are the app's assumption: a SOC lead approves,
  // 15 min to decide, no duration because they do not reverse on their own. The agent never
  // recommends them (like suspend_user_session, gap 5); listing one only makes it available.
  {
    name: 'kill_process',
    signature: 'kill_process(host, process)',
    floor: THRESHOLDS.suspend,
    phrase: 'killing a process',
    does: 'Ends a running process on a host',
    reversible: 'No: a person restarts the process',
    source: 'PDF p.4',
    assumed: [NOT_IN_PDF, NOT_REVERSIBLE],
    conditions: ['Not a Critical host', 'Risk 75 or more', 'Confidence 0.80 or more'],
    durationNote: 'No duration: does not reverse on its own',
    approver: 'soc_lead',
    approvalWindowMinutes: 15,
  },
  {
    name: 'quarantine_file',
    signature: 'quarantine_file(host, path)',
    floor: THRESHOLDS.suspend,
    phrase: 'quarantining a file',
    does: 'Moves a file into quarantine on a host',
    reversible: 'No: a person restores the file',
    source: 'PDF p.4',
    assumed: [NOT_IN_PDF, NOT_REVERSIBLE],
    conditions: ['Risk 75 or more', 'Confidence 0.80 or more'],
    durationNote: 'No duration: does not reverse on its own',
    approver: 'soc_lead',
    approvalWindowMinutes: 15,
  },
  {
    name: 'reset_password',
    signature: 'reset_password(user)',
    floor: THRESHOLDS.suspend,
    phrase: 'resetting a password',
    does: 'Issues a temporary password for an account',
    reversible: 'No: a person decides what happens next',
    source: 'PDF p.4',
    assumed: [NOT_IN_PDF, NOT_REVERSIBLE],
    conditions: ['Non-privileged account only', 'Risk 75 or more', 'Confidence 0.80 or more'],
    durationNote: 'No duration: does not reverse on its own',
    approver: 'soc_lead',
    approvalWindowMinutes: 15,
  },
]

/*
  What a response policy may not go past, from the Tier 2 rows: the longest
  allowed time, the time to decide, the lowest approver and the lowest
  Minimum risk. A policy can only be stricter (shorter, a higher role, a higher risk).
*/
export type PolicyCap = {
  maxMinutes?: number
  windowMinutes: number
  approver: ApproverRole
  minRisk: number
}

export const POLICY_CAPS = Object.fromEntries(
  tier2Actions.map((action) => [
    action.name,
    {
      maxMinutes: action.maxMinutes,
      windowMinutes: action.approvalWindowMinutes,
      approver: action.approver,
      minRisk: action.floor.risk,
    },
  ]),
) as Record<Tier2ActionName, PolicyCap>

// How a role compares: a lead may approve anything an analyst may
export const ROLE_RANK: Record<ApproverRole, number> = { soc_analyst: 1, soc_lead: 2 }

export const APPROVER_LABELS: Record<ApproverRole, string> = {
  soc_analyst: 'SOC analyst',
  soc_lead: 'SOC lead',
}

// ----- Tier 3: prohibited -----

export type Tier3Action = {
  id: string
  action: string
  why: string
  // What a request for it looks like to the policy guard (never a registered tool)
  requestName: string
}

export const tier3Actions: Tier3Action[] = [
  {
    id: 'permanent-block',
    action: 'Permanent blocking, or any block longer than 24 h',
    why: 'Irreversible lockouts of legitimate users and partners',
    requestName: 'block_ip_permanent',
  },
  {
    id: 'delete-evidence',
    action: 'Deleting or modifying logs, alerts, cases or evidence',
    why: 'Destroys the audit trail and forensic value',
    requestName: 'delete_logs',
  },
  {
    id: 'disable-controls',
    action: 'Disabling or reconfiguring security controls (Wazuh agents, rules, firewall, EDR)',
    why: 'Blinds the SOC; a common attacker goal',
    requestName: 'disable_security_control',
  },
  {
    id: 'privileged-accounts',
    action: 'Creating, changing or disabling privileged accounts, credentials or group memberships',
    why: 'Highest-impact change; must stay with identity administrators',
    requestName: 'modify_privileged_account',
  },
  {
    id: 'isolate-critical',
    action: 'Isolating a Critical system without authorised approval',
    why: 'Can take the business offline; a person decides and acts',
    requestName: 'isolate_critical_host',
  },
  {
    id: 'change-own-policy',
    action: 'Changing its own policies, thresholds or allow-list',
    why: 'The agent cannot widen its own permissions',
    requestName: 'change_policy',
  },
]

// ----- The action catalogue: all 19 actions in one list -----

export type CatalogueRow = {
  // The function name for Tier 1 and 2; the guard's request name for Tier 3
  key: string
  tier: ActionTier
  // The signature (Tier 1 and 2) or the prohibited action in words (Tier 3)
  action: string
  does: string
  whenUsed: string
  limits: string
  defaultMinutes?: number
  maxMinutes?: number
  approver?: ApproverRole
  approvalWindowMinutes?: number
  riskFloor?: number
  confidenceFloor?: number
  reversible: string
  // Tier 3 only: why it is prohibited
  why?: string
  source: CatalogueSource
  assumed: Assumption[]
}

export const ACTION_CATALOGUE: CatalogueRow[] = [
  ...tier1Actions.map<CatalogueRow>((item) => ({
    key: item.name.split('(')[0],
    tier: 1,
    action: item.name,
    does: item.does,
    whenUsed: item.whenUsed,
    limits: item.limits,
    maxMinutes: item.maxMinutes,
    reversible: item.reversible,
    source: item.source,
    assumed: item.assumed ?? [],
  })),
  ...tier2Actions.map<CatalogueRow>((item) => ({
    key: item.name,
    tier: 2,
    action: item.signature,
    does: item.does,
    whenUsed: item.conditions.join(' · '),
    limits: item.durationNote,
    defaultMinutes: item.defaultMinutes,
    maxMinutes: item.maxMinutes,
    approver: item.approver,
    approvalWindowMinutes: item.approvalWindowMinutes,
    riskFloor: item.floor.risk,
    confidenceFloor: item.floor.confidence,
    reversible: item.reversible,
    source: item.source,
    assumed: item.assumed ?? [],
  })),
  ...tier3Actions.map<CatalogueRow>((item) => ({
    key: item.requestName,
    tier: 3,
    action: item.action,
    does: '',
    whenUsed: 'Never, under any input',
    limits: 'Never allowed',
    reversible: 'Not applicable: never runs',
    why: item.why,
    source: 'PDF p.5',
    assumed: [],
  })),
]

// "Runs automatically", "Needs a SOC analyst's approval", ...: the tier in words, never colour alone
export function tierWords(row: Pick<CatalogueRow, 'tier' | 'approver'>) {
  if (row.tier === 1) {
    return 'Runs automatically'
  }

  if (row.tier === 3) {
    return 'Never allowed'
  }

  return `Needs a ${row.approver ? APPROVER_LABELS[row.approver] : 'person'}’s approval`
}

// 30 -> "30 min", 120 -> "2 h", 1440 -> "24 h" (an hour reads as "60 min", as the PDF has it)
export function formatMinutes(minutes: number) {
  return minutes >= 120 && minutes % 60 === 0 ? `${minutes / 60} h` : `${minutes} min`
}

// ----- Allow-list (can never be recommended for blocking) -----

export const ALLOW_LIST = {
  // Internal ranges
  internal: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'],
  // Partner IPs and the organisation's cloud provider ranges (documentation ranges in this demo)
  partners: ['192.0.2.10/32'],
  cloud: ['192.0.2.128/25'],
  // The SIEM's own addresses
  siem: ['10.0.1.15/32'],
}

/*
  The PDF's protected targets as the policy's Required rows: the allow-list
  entries can never be blocked, and a Critical host is never isolated
  (the design's example names are mapped to the app's inventory).
*/
export const PROTECTED_BLOCK_SEEDS: Array<{ value: string; label: string }> = [
  ...ALLOW_LIST.internal.map((value) => ({ value, label: 'Internal range' })),
  ...ALLOW_LIST.partners.map((value) => ({ value, label: 'Partner address' })),
  ...ALLOW_LIST.cloud.map((value) => ({ value, label: 'Cloud provider range' })),
  ...ALLOW_LIST.siem.map((value) => ({ value, label: 'SIEM address' })),
]

export const PROTECTED_ISOLATE_SEEDS: Array<{ value: string; label: string }> = [
  { value: 'dc-01', label: 'Critical host: domain controller' },
  { value: 'db-prod-01', label: 'Critical host: production database' },
  { value: 'siem-01', label: 'Critical host: SIEM' },
]

// ----- Asset inventory -----

export type Asset = { name: string; assetClass: AssetClass; owner: string }

export const assetInventory: Asset[] = [
  { name: 'dc-01', assetClass: 'Critical', owner: 'Identity team' },
  { name: 'db-prod-01', assetClass: 'Critical', owner: 'Platform team' },
  { name: 'siem-01', assetClass: 'Critical', owner: 'Security Management' },
  { name: 'endpoint-01', assetClass: 'Business', owner: 'Security Operations' },
  { name: 'endpoint-03', assetClass: 'Business', owner: 'Security Operations' },
  { name: 'endpoint-09', assetClass: 'Business', owner: 'Threat Detection' },
  { name: 'endpoint-12', assetClass: 'Business', owner: 'Platform team' },
  { name: 'vpn-gateway-02', assetClass: 'Standard', owner: 'Network team' },
]

// ----- Per-alert inputs -----

/*
  Inputs for the alerts, taken from what the alerts, cases and response
  runs already say; nothing here is chosen to reach an outcome.
  Reputation applies only where the alert has an external source IP
  (check_ip_reputation is Tier 1 for external IPs only); an internal
  source gets 0. Items marked "assumed" are not in the older data and
  are listed in the commit summary for review.
*/
export const assessmentInputs: AssessmentInput[] = [
  {
    alertId: 'ALT-001',
    // Critical band (13-15); the alert is rated Critical
    ruleLevel: 13,
    signals: [
      '148 failed SSH logins in five minutes',
      'Multiple privileged usernames targeted',
      'Source matched earlier scanning activity',
    ],
    // The PDF's own example reputation for 203.0.113.45
    reputation: 0.92,
    reputationSource: 'AbuseIPDB via Cortex',
    sourceIp: '203.0.113.45',
    asset: 'endpoint-01',
    assetClass: 'Business',
    confidence: 0.88,
    // "Multiple privileged usernames": assumed 3 accounts
    failedLogins: { count: 148, accounts: 3, windowMin: 5 },
    hostExploitEvidence: false,
  },
  {
    alertId: 'ALT-002',
    // High band (10-12)
    ruleLevel: 11,
    signals: [
      'Unexpected sudo from a standard user session',
      'Elevation outside the maintenance window',
      'Command sequence matched known privilege-escalation behaviour',
    ],
    reputation: 0,
    reputationSource: 'None: internal source, no reputation lookup',
    sourceIp: '10.0.2.18',
    asset: 'endpoint-03',
    assetClass: 'Business',
    // Assumed: a behavioural match, no second source
    confidence: 0.75,
    hostExploitEvidence: false,
  },
  {
    alertId: 'ALT-003',
    // Medium band (7-9)
    ruleLevel: 8,
    signals: [
      'Login attempts spread across many VPN accounts',
      'All attempts from one source, 203.0.113.88',
      'Password-spray pattern correlated across VPN authentication attempts',
    ],
    // Assumed: moderate, below the 0.70 "malicious" line
    reputation: 0.65,
    reputationSource: 'AbuseIPDB via Cortex',
    sourceIp: '203.0.113.88',
    asset: 'vpn-gateway-02',
    assetClass: 'Standard',
    // Assumed
    confidence: 0.7,
    // "Many VPN accounts": assumed 12 failures across 6 accounts
    failedLogins: { count: 12, accounts: 6, windowMin: 5 },
    hostExploitEvidence: false,
  },
  {
    alertId: 'ALT-004',
    // Critical band (13-15)
    ruleLevel: 14,
    signals: [
      'Kernel exploit signature matched endpoint telemetry',
      'Privilege-escalation behaviour confirmed',
    ],
    reputation: 0,
    reputationSource: 'None: internal source, no reputation lookup',
    sourceIp: '10.0.7.51',
    asset: 'endpoint-09',
    assetClass: 'Business',
    // Assumed: a confirmed signature plus confirmed behaviour
    confidence: 0.9,
    hostExploitEvidence: true,
  },
  {
    alertId: 'ALT-005',
    // Low band (0-6)
    ruleLevel: 5,
    signals: ['One connection attempt to port 22, no follow-up'],
    // Assumed: "weak confidence indicators"
    reputation: 0.35,
    reputationSource: 'AbuseIPDB via Cortex',
    sourceIp: '198.51.100.77',
    asset: 'endpoint-01',
    assetClass: 'Business',
    confidence: 0.4,
    hostExploitEvidence: false,
  },
  {
    alertId: 'ALT-006',
    // Critical band (13-15); an exploited service beaconing out to a known-bad IP
    ruleLevel: 14,
    // Assumed: five independent signals, none of them a restatement of another
    signals: [
      'EDR flagged the web service injecting code into a system process',
      'Outbound beaconing every 60 seconds to 203.0.113.9',
      'Destination 203.0.113.9 is on a MISP command-and-control feed',
      'A new systemd service was created for persistence',
      'A shell was spawned by the application service account',
    ],
    // Assumed: a known-bad C2 address
    reputation: 0.95,
    reputationSource: 'MISP feed and AbuseIPDB via Cortex',
    sourceIp: '203.0.113.9',
    asset: 'endpoint-12',
    assetClass: 'Business',
    // Assumed
    confidence: 0.92,
    hostExploitEvidence: true,
  },
]

// The seed data's own copy of the inputs (the same list; kept so the seed approvals read as before)
export const seedAssessmentInputs: AssessmentInput[] = assessmentInputs
