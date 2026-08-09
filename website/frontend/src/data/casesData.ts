import type { CaseRecord } from '../types/casesTypes'

export const initialCases: CaseRecord[] = [
  {
    id: 'CASE-006',
    sourceAlert: 'ALT-001',
    severity: 'Critical',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    attackType: 'Brute Force SSH',
    endpoint: 'endpoint-01',
    sourceIp: '192.168.1.45',
    riskScore: 92,
    createdAt: 'Today, 14:34',
    lastUpdated: 'Today, 14:46',
    summary:
      'A critical SSH brute-force campaign targeted privileged accounts on endpoint-01. The case remains open while the analyst validates affected accounts and containment evidence.',
    evidence: [
      '148 failed SSH authentication attempts in five minutes',
      'Multiple privileged usernames were targeted',
      'Source IP matched previous scanning activity',
      'No confirmed successful login was detected',
    ],
    recommendedActions: [
      'Block the source IP at the network boundary',
      'Review authentication logs for successful access',
      'Reset credentials for targeted privileged accounts',
      'Monitor endpoint-01 for follow-up activity',
    ],
    mitre: 'T1110 - Brute Force',
    timeline: [
      {
        time: '14:32',
        title: 'Alert created',
        description:
          'AthenaSec generated ALT-001 after detecting abnormal SSH authentication activity.',
      },
      {
        time: '14:33',
        title: 'AI analysis completed',
        description:
          'The activity was classified as a critical brute-force campaign.',
      },
      {
        time: '14:34',
        title: 'Case created',
        description:
          'CASE-006 was created and assigned to Analyst A.',
      },
      {
        time: '14:46',
        title: 'Analyst review started',
        description:
          'Authentication records and affected accounts are under review.',
      },
    ],
  },
  {
    id: 'CASE-007',
    sourceAlert: 'ALT-002',
    severity: 'High',
    status: 'Open',
    assignedAnalyst: 'Analyst B',
    attackType: 'Privilege Escalation',
    endpoint: 'endpoint-03',
    sourceIp: '10.0.2.18',
    riskScore: 84,
    createdAt: 'Today, 14:43',
    lastUpdated: 'Today, 14:55',
    summary:
      'Suspicious sudo activity was detected on endpoint-03. Automated response controls were applied, but the case remains open for analyst validation and scope assessment.',
    evidence: [
      'Unexpected sudo execution from a standard user session',
      'Elevation attempt occurred outside the normal maintenance window',
      'Command sequence matched known privilege-escalation behavior',
      'Autonomous containment policy was triggered',
    ],
    recommendedActions: [
      'Review the affected user account',
      'Inspect executed commands and process ancestry',
      'Validate endpoint integrity',
      'Confirm whether the activity was authorized',
    ],
    mitre: 'T1548 - Abuse Elevation Control Mechanism',
    timeline: [
      {
        time: '14:41',
        title: 'Alert created',
        description:
          'ALT-002 was generated after suspicious sudo activity was detected.',
      },
      {
        time: '14:42',
        title: 'Automated response applied',
        description:
          'The permitted response policy restricted the affected session.',
      },
      {
        time: '14:43',
        title: 'Case created',
        description:
          'CASE-007 was created and assigned to Analyst B.',
      },
      {
        time: '14:55',
        title: 'Evidence collected',
        description:
          'Command history and endpoint telemetry were added to the case.',
      },
    ],
  },
  {
    id: 'CASE-008',
    sourceAlert: 'ALT-004',
    severity: 'Critical',
    status: 'Closed',
    assignedAnalyst: 'Analyst C',
    attackType: 'Kernel Exploit Attempt',
    endpoint: 'endpoint-09',
    sourceIp: '10.0.7.51',
    riskScore: 95,
    createdAt: 'Today, 15:18',
    lastUpdated: 'Today, 15:42',
    summary:
      'A kernel exploit attempt was detected on endpoint-09. The endpoint was isolated automatically, evidence was preserved, and the case was closed after analyst validation.',
    evidence: [
      'Kernel exploit signature matched endpoint telemetry',
      'Privilege-escalation behavior was confirmed',
      'Endpoint isolation completed successfully',
      'No lateral movement was detected',
    ],
    recommendedActions: [
      'Apply the relevant operating-system security update',
      'Reimage the endpoint if integrity cannot be confirmed',
      'Rotate credentials used on the affected endpoint',
      'Continue monitoring adjacent systems',
    ],
    mitre: 'T1068 - Exploitation for Privilege Escalation',
    timeline: [
      {
        time: '15:17',
        title: 'Alert created',
        description:
          'ALT-004 was generated after kernel exploit telemetry was detected.',
      },
      {
        time: '15:18',
        title: 'Endpoint isolated',
        description:
          'The autonomous response policy isolated endpoint-09.',
      },
      {
        time: '15:18',
        title: 'Case created',
        description:
          'CASE-008 was created and assigned to Analyst C.',
      },
      {
        time: '15:42',
        title: 'Case closed',
        description:
          'The response was validated and no further malicious activity was found.',
      },
    ],
  },
]
