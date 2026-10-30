import type { CaseRecord } from '../types/casesTypes'

import { riskFor } from './alertAssessments'

// riskScore is the source alert's score from the policy formula (alertAssessments.ts)

export const initialCases: CaseRecord[] = [
  {
    id: 'CASE-006',
    sourceAlert: 'ALT-001',
    severity: 'Critical',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    attackType: 'Brute Force SSH',
    endpoint: 'endpoint-01',
    sourceIp: '203.0.113.45',
    riskScore: riskFor('ALT-001'),
    createdAt: 'Today, 14:34',
    lastUpdated: 'Today, 15:44',
    summary:
      'A critical SSH brute-force campaign targeted privileged accounts on endpoint-01. A block of the source is recommended and waits for a SOC analyst to approve it. The case remains open while the analyst validates affected accounts and containment evidence.',
    evidence: [
      '148 failed SSH authentication attempts in five minutes',
      'Multiple privileged usernames were targeted',
      'Source IP matched previous scanning activity',
      'No confirmed successful login was detected',
    ],
    recommendedActions: [
      // Waits on APR-002 (a SOC analyst's approval); not done until a run completes
      { label: 'Block the source IP at the network boundary', approvalId: 'APR-002' },
      { label: 'Review authentication logs for successful access' },
      { label: 'Reset credentials for targeted privileged accounts' },
      { label: 'Monitor endpoint-01 for follow-up activity' },
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
      {
        time: '15:44',
        title: 'Block recommended',
        description:
          'AthenaSec recommended blocking 203.0.113.45 for 30 minutes (risk 77). It waits for a SOC analyst to approve it.',
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
    riskScore: riskFor('ALT-002'),
    createdAt: 'Today, 14:43',
    lastUpdated: 'Today, 14:55',
    // The agent rated the alert "Investigate further" (risk 50), so nothing was run
    summary:
      'Suspicious sudo activity was detected on endpoint-03. The agent rated it risk 50, below what any containment needs, so nothing was changed and the case remains open for analyst validation and scope assessment.',
    evidence: [
      'Unexpected sudo execution from a standard user session',
      'Elevation attempt occurred outside the normal maintenance window',
      'Command sequence matched known privilege-escalation behavior',
      'Agent outcome: investigate further (risk 50, confidence 0.75)',
    ],
    recommendedActions: [
      { label: 'Review the affected user account' },
      { label: 'Inspect executed commands and process ancestry' },
      { label: 'Validate endpoint integrity' },
      { label: 'Confirm whether the activity was authorized' },
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
        title: 'Agent assessment',
        description:
          'Risk 50, confidence 0.75: investigate further. No containment was recommended.',
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
    riskScore: riskFor('ALT-004'),
    createdAt: 'Today, 15:18',
    lastUpdated: 'Today, 15:42',
    summary:
      'A kernel exploit attempt was detected on endpoint-09. The agent rated it risk 52, below the 85 isolation needs, so nothing was isolated. An analyst preserved the evidence and closed the case after validation.',
    evidence: [
      'Kernel exploit signature matched endpoint telemetry',
      'Privilege-escalation behavior was confirmed',
      'Evidence was preserved for forensics',
      'No lateral movement was detected',
    ],
    // Closed case: every action done
    recommendedActions: [
      { label: 'Apply the relevant operating-system security update', done: true },
      { label: 'Reimage the endpoint if integrity cannot be confirmed', done: true },
      { label: 'Rotate credentials used on the affected endpoint', done: true },
      { label: 'Continue monitoring adjacent systems', done: true },
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
        title: 'Agent assessment',
        description:
          'Risk 52, confidence 0.90: investigate further. No isolation was recommended.',
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
