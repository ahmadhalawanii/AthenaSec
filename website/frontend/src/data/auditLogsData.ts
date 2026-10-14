import type { AuditCategory, AuditLogRecord } from '../types/auditLogsTypes'

import { riskFor } from './alertAssessments'

export const auditLogs: AuditLogRecord[] = [
  {
    id: 'AUD-206',
    timestamp: '2026-08-03 15:44:07',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'Response Policy',
    action: 'Updated response policy',
    target: 'Response policy',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'The response policy now needs a SOC analyst to approve a block, and the minimum risk for a block was lowered to 70, the block_ip floor in the Agent Action Policy, so a confirmed critical brute-force alert can reach human approval for a block (version 2 → 3).',
    changes: [
      'block_ip: Automatic → Needs approval',
      'block_ip minimum risk: 90 → 70',
    ],
    metadata: {
      'Policy Version': '3',
      'Session ID': 'SES-ADMIN-4421',
    },
  },
  {
    id: 'AUD-205',
    timestamp: '2026-08-03 15:44:00',
    user: 'AthenaSec AI',
    role: 'System',
    category: 'Incident Response',
    action: 'Executed host isolation',
    target: 'endpoint-12',
    result: 'Success',
    sourceIp: '127.0.0.1',
    description:
      'AthenaSec AI isolated endpoint-12 for 120 minutes under response policy version 2, using the approval token issued to the System Administrator.',
    changes: [
      'Endpoint isolation command issued',
      'Isolation acknowledged by endpoint agent',
      'Approval token TKN-001 used (single use)',
      'Execution marked Completed',
    ],
    metadata: {
      'Execution ID': 'EXE-001',
      'Triggering Alert': 'ALT-006',
      Policy: 'Response policy v2: isolate_host',
      'Approved By': 'System Administrator (SOC lead)',
      'Approved At': '15:43:10',
      'Session ID': 'AI-WORKFLOW-771',
    },
    eventType: 'action_executed',
    record: {
      recommendation_id: 'REC-001',
      alert_id: 'ALT-006',
      policy_id: 'response-policy-v2',
      actor: 'agent',
      actor_role: 'agent',
      tier: 2,
      outcome: 'recommend_host_isolation',
      action: 'isolate_host',
      params: { host: 'endpoint-12', path: 'edr_network_isolation', duration_min: 120 },
      risk_score: 90,
      confidence: 0.92,
      decision: 'approved',
      execution_result: 'success',
      expires_at: '2026-08-03T17:44:00',
    },
  },
  {
    id: 'AUD-204',
    timestamp: '2026-08-03 15:42:18',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'System',
    action: 'Saved configuration',
    target: 'Workspace configuration',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'Workspace configuration was saved through the AthenaSec administration console.',
    changes: [
      'Correlation window (minutes): 10 → 5',
      'Hot storage (days): 14 → 30',
      'Critical alert notification: In-App Only → Email + In-App',
    ],
    metadata: {
      Organization: 'AthenaSec SOC',
      Workspace: 'Production',
      'Fields changed': '3',
      'Session ID': 'SES-ADMIN-4421',
    },
  },
  {
    id: 'AUD-203',
    timestamp: '2026-08-03 15:10:42',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'Response Policy',
    action: 'Updated response policy',
    target: 'Response policy',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'The response policy now needs an Administrator to approve an isolation before it runs. The Agent Action Policy does not allow isolation to run automatically (version 1 → 2).',
    changes: [
      'isolate_host: Automatic → Needs approval',
    ],
    metadata: {
      'Policy Version': '2',
      'Session ID': 'SES-ADMIN-4421',
    },
  },
  {
    id: 'AUD-202',
    timestamp: '2026-08-03 14:35:08',
    user: 'Analyst A',
    role: 'Analyst',
    category: 'Incident Response',
    action: 'Took ownership of alert',
    target: 'ALT-001 · Brute Force SSH',
    result: 'Success',
    sourceIp: '10.0.2.25',
    description:
      'Analyst A took ownership of alert ALT-001 and started the review.',
    changes: [
      'Assigned analyst set to Analyst A',
      'Alert status remained Open',
      'Related case CASE-006 opened',
    ],
    metadata: {
      'Alert ID': 'ALT-001',
      'Risk Score': String(riskFor('ALT-001')),
      Severity: 'Critical',
      'Session ID': 'SES-ANA-9821',
    },
  },
  {
    id: 'AUD-201',
    timestamp: '2026-08-03 14:21:08',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'User Management',
    action: 'Created user account',
    target: 'USR-003 · Analyst B',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'A new AthenaSec analyst account was created and MFA was enabled.',
    changes: [
      'User account created',
      'Role assigned as Analyst',
      'MFA requirement enabled',
      'Account status set to Active',
    ],
    metadata: {
      'User ID': 'USR-003',
      Email: 'analyst.b@athenasec.com',
      Department: 'Security Operations',
      'Session ID': 'SES-ADMIN-4388',
    },
  },
  {
    id: 'AUD-200',
    timestamp: '2026-08-03 13:55:31',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'System',
    action: 'Checked service',
    target: 'SVC-002 · OpenSearch',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'A simulated health check was run from the administration console.',
    changes: [
      'latency (ms): 44 → 38',
      'last check: 13:40 → 13:55',
      'Authentication accepted',
      'Index access verified',
    ],
    metadata: {
      'Service ID': 'SVC-002',
      Endpoint: 'https://opensearch.athenasec.local',
      Version: '2.19.1',
      'Session ID': 'SES-ADMIN-4360',
    },
  },
  {
    id: 'AUD-199',
    timestamp: '2026-08-03 12:10:04',
    user: 'Analyst B',
    role: 'Analyst',
    category: 'Authentication',
    action: 'Failed MFA verification',
    target: 'analyst.b@athenasec.com',
    result: 'Failed',
    sourceIp: '10.0.2.31',
    description:
      'An incorrect MFA verification code was submitted during authentication.',
    changes: [
      'Authentication attempt rejected',
      'Session not created',
      'Failure counter increased',
    ],
    metadata: {
      Email: 'analyst.b@athenasec.com',
      Method: 'MFA code',
      'Failure Count': '1',
      'Session ID': 'Not created',
    },
  },
  {
    id: 'AUD-198',
    timestamp: '2026-08-03 11:42:37',
    user: 'Unknown User',
    role: 'System',
    category: 'Authentication',
    action: 'Login denied',
    target: 'admin@athenasec.com',
    result: 'Denied',
    sourceIp: '203.0.113.70',
    description:
      'A login attempt was denied because the submitted password was incorrect.',
    changes: [
      'Authentication denied',
      'No session created',
      'Source IP recorded for monitoring',
    ],
    metadata: {
      Email: 'admin@athenasec.com',
      Method: 'Password',
      Reason: 'Invalid credentials',
      'Session ID': 'Not created',
    },
  },
  {
    id: 'AUD-197',
    timestamp: '2026-08-03 10:55:22',
    user: 'System Administrator',
    role: 'Administrator',
    category: 'System',
    action: 'Refreshed system health',
    target: '10 monitored services',
    result: 'Success',
    sourceIp: '10.0.1.10',
    description:
      'System health metrics and service latencies were refreshed.',
    changes: [
      'CPU Usage: 38 → 42',
      'Memory Usage: 64 → 67',
      'Service latencies updated',
    ],
    metadata: {
      Services: '10',
      Scope: 'Metrics and latencies',
      Source: 'Administration console',
      'Session ID': 'SES-ADMIN-4297',
    },
  },
  {
    id: 'AUD-196',
    timestamp: '2026-08-03 10:15:08',
    user: 'System',
    role: 'System',
    category: 'System',
    action: 'Completed audit synchronization',
    target: 'OpenSearch audit index',
    result: 'Success',
    sourceIp: '127.0.0.1',
    description:
      'AthenaSec completed the scheduled audit-log synchronization process.',
    changes: [
      '24 audit events indexed',
      'No rejected records',
      'Audit storage status confirmed healthy',
    ],
    metadata: {
      Index: 'athenasec-audit-2026.08',
      'Records Indexed': '24',
      Duration: '1.8 seconds',
      'Job ID': 'JOB-AUD-886',
    },
  },
]

/*
  Session audit events (changes made in this browser session). They use
  the seed log's day and the administration console address it records.
  Their time is the demo clock's, never the real clock's, so a session
  event can never be stamped earlier than the seed (the clock starts
  after the seed's last event and only moves forward).
*/
// Every category an event can have, in the order the filter chips show them
export const AUDIT_CATEGORIES: AuditCategory[] = [
  'Authentication',
  'Response Policy',
  'User Management',
  'Incident Response',
  'System',
]

export const AUDIT_DAY = '2026-08-03'
export const ADMIN_CONSOLE_IP = '10.0.1.10'

// "2026-08-03 15:46:00" from the demo clock's "2026-08-03T15:46:00"
export function auditTimestamp(demoTime: string) {
  return `${demoTime.slice(0, 10)} ${demoTime.slice(11, 19)}`
}

/*
  One counter for every session event, whichever provider records it
  (admin changes, the approval flow), so two events never share an id.
  It starts after the seed's last id (AUD-206, the response policy's version 3), only
  moves when an action runs, never while rendering, and starts again
  when the page reloads. Ids rise in the order events are recorded,
  which is the order of the audit hash chain.
*/
let lastAuditNumber = 206

export function takeAuditId() {
  lastAuditNumber += 1

  return `AUD-${String(lastAuditNumber).padStart(3, '0')}`
}

export const auditNumber = (log: AuditLogRecord) => Number(log.id.replace('AUD-', ''))

// Field name -> label used in "Recorded changes"
export type ChangeLabels<T> = Partial<Record<keyof T, string>>

function formatValue(value: unknown) {
  if (Array.isArray(value)) {
    return value.join(', ') || 'None'
  }

  if (typeof value === 'boolean') {
    return value ? 'On' : 'Off'
  }

  const text = String(value ?? '').trim()
  return text === '' ? 'None' : text
}

/*
  One line per changed field, "Field: old → new", in label order.
  An empty list means nothing changed.
*/
export function diffChanges<T extends object>(before: T, after: T, labels: ChangeLabels<T>) {
  return (Object.keys(labels) as Array<keyof T>).flatMap((key) => {
    const oldValue = formatValue(before[key])
    const newValue = formatValue(after[key])

    return oldValue === newValue ? [] : [`${labels[key]}: ${oldValue} → ${newValue}`]
  })
}

// A new record: "Field: None → value" for every labelled field
export function createdChanges<T extends object>(record: T, labels: ChangeLabels<T>) {
  return (Object.keys(labels) as Array<keyof T>).map(
    (key) => `${labels[key]}: None → ${formatValue(record[key])}`,
  )
}

// A removed record: "Field: value → Removed" for every labelled field
export function deletedChanges<T extends object>(record: T, labels: ChangeLabels<T>) {
  return (Object.keys(labels) as Array<keyof T>).map(
    (key) => `${labels[key]}: ${formatValue(record[key])} → Removed`,
  )
}
