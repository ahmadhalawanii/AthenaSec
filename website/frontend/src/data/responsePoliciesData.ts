import type { PolicyAction, PolicyFormState, ResponsePolicy } from '../types/responsePoliciesTypes'

export const initialPolicies: ResponsePolicy[] = [
  {
    id: 'POL-001',
    name: 'Critical Authentication Abuse',
    condition:
      'IF Severity = Critical AND Attack Type = Brute Force',
    actions: ['Block IP', 'Notify Administrator', 'Create Case'],
    approvalMode: 'Automatic',
    status: 'Enabled',
    riskThreshold: 90,
    description:
      'Automatically blocks the attacking source, notifies the administrator, and creates a case when critical brute-force activity is confirmed.',
    lastUpdated: 'Today, 15:42',
  },
  {
    id: 'POL-002',
    name: 'Privilege Escalation Session Control',
    condition:
      'IF Severity >= High AND Attack Type = Privilege Escalation',
    actions: [
      'Lock Account',
      'Capture Telemetry',
      'Notify Administrator',
    ],
    approvalMode: 'Analyst Approval',
    status: 'Enabled',
    riskThreshold: 80,
    description:
      'Restricts suspicious privileged activity after analyst review and preserves evidence for investigation.',
    lastUpdated: 'Today, 14:55',
  },
  {
    id: 'POL-003',
    name: 'Critical Host Isolation',
    condition:
      'IF Risk Score >= 90 AND Endpoint Exploit Evidence = True',
    actions: [
      'Isolate Endpoint',
      'Capture Telemetry',
      'Record Response',
    ],
    approvalMode: 'Automatic',
    status: 'Enabled',
    riskThreshold: 90,
    description:
      'Automatically isolates a compromised endpoint when critical exploit evidence and the required risk threshold are present.',
    lastUpdated: 'Today, 15:17',
  },
  {
    id: 'POL-004',
    name: 'VPN Password Spray Containment',
    condition:
      'IF Attack Type = Password Spray AND Risk Score >= 60',
    actions: ['Block IP', 'Notify Administrator', 'Create Case'],
    approvalMode: 'Analyst Approval',
    status: 'Enabled',
    riskThreshold: 60,
    description:
      'Allows an analyst to approve temporary containment for distributed VPN password-spray activity.',
    lastUpdated: 'Yesterday, 18:10',
  },
]

export const emptyPolicyForm: PolicyFormState = {
  name: '',
  condition: '',
  actions: '',
  approvalMode: 'Analyst Approval',
  status: 'Enabled',
  riskThreshold: '70',
  description: '',
}

export const allowedActions: PolicyAction[] = [
  'Block IP',
  'Isolate Endpoint',
  'Lock Account',
  'Create Case',
  'Notify Administrator',
  'Capture Telemetry',
  'Record Response',
]
