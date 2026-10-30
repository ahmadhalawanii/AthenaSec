import type { AlertRecord } from '../types/alertsTypes'

import { riskBandFor, riskFor } from './alertAssessments'

// Risk and its band are not typed in: they come from the policy's formula (alertAssessments.ts)
const alertDetails: Array<Omit<AlertRecord, 'risk' | 'riskBand'>> = [
  {
    id: 'ALT-001',
    severity: 'Critical',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force SSH',
    sourceIp: '203.0.113.45',
    destinationIp: '10.0.4.21',
    endpoint: 'endpoint-01',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    time: '14:32',
    summary:
      'AthenaSec detected a critical SSH brute force campaign against privileged accounts.',
    reasoning:
      'The source generated a high-frequency failed login burst and matched prior scanner reputation. Risk 77 with confidence 0.88 reaches the minimum risk of 70 that the response policy sets for a block, so the agent recommended blocking the source for a SOC analyst to approve.',
    mitre: 'T1110 - Brute Force',
    explanation:
      'The activity indicates credential access behavior. Nothing is blocked yet: the block runs only after an analyst approves it. The alert remains open for analyst review and supporting evidence validation.',
  },
  {
    id: 'ALT-002',
    severity: 'High',
    attackGroup: 'Privilege Escalation',
    attackType: 'Privilege Escalation',
    sourceIp: '10.0.2.18',
    destinationIp: '10.0.4.33',
    endpoint: 'endpoint-03',
    status: 'Open',
    assignedAnalyst: 'Analyst B',
    time: '14:41',
    summary:
      'AthenaSec identified suspicious sudo escalation activity on endpoint-03.',
    reasoning:
      'Privilege escalation telemetry on a Business asset scored risk 50 with confidence 0.75, below the 70 needed to recommend any containment, so the agent chose to investigate further.',
    mitre: 'T1548 - Abuse Elevation Control Mechanism',
    explanation:
      'Nothing was changed on endpoint-03. The alert stays open for an analyst to validate the activity and decide whether any containment is needed.',
  },
  {
    id: 'ALT-003',
    severity: 'Medium',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force - Password Spray',
    sourceIp: '203.0.113.88',
    destinationIp: '10.0.4.41',
    endpoint: 'vpn-gateway-02',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    time: '15:02',
    summary:
      'AthenaSec correlated a password spray pattern across VPN authentication attempts.',
    reasoning:
      'The activity was distributed across multiple accounts. Risk 54 with confidence 0.70 is below the 70 needed to recommend a block, so the agent chose to investigate further.',
    mitre: 'T1110.003 - Password Spraying',
    explanation:
      'Nothing was blocked. The alert remains open for analyst investigation and validation.',
  },
  {
    id: 'ALT-004',
    severity: 'Critical',
    attackGroup: 'Privilege Escalation',
    attackType: 'Privilege Escalation - Kernel Exploit Attempt',
    sourceIp: '10.0.7.51',
    destinationIp: '10.0.7.51',
    endpoint: 'endpoint-09',
    status: 'Closed',
    assignedAnalyst: 'Analyst C',
    time: '15:17',
    summary:
      'AthenaSec classified kernel exploit telemetry as malicious privilege escalation activity.',
    reasoning:
      'The exploit signature and endpoint evidence were strong, but the source is internal so no reputation applies, which gave risk 52 against the 85 needed to recommend isolation. The agent chose to investigate further.',
    mitre: 'T1068 - Exploitation for Privilege Escalation',
    explanation:
      'Nothing was isolated. Analyst C investigated, preserved the evidence, found no lateral movement and closed the alert.',
  },
  {
    id: 'ALT-005',
    severity: 'Low',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force - SSH Probe',
    sourceIp: '198.51.100.77',
    destinationIp: '10.0.4.21',
    endpoint: 'endpoint-01',
    status: 'Closed',
    assignedAnalyst: 'Analyst A',
    time: '15:36',
    summary:
      'AthenaSec observed a low-volume SSH probe associated with brute-force reconnaissance.',
    reasoning:
      'The activity had limited intensity, no successful authentication, and weak confidence indicators.',
    mitre: 'T1110 - Brute Force',
    explanation:
      'The alert was closed after correlation and remains visible as supporting history.',
  },
  {
    id: 'ALT-006',
    severity: 'Critical',
    attackGroup: 'Command and Control',
    attackType: 'Malware - C2 Beaconing',
    sourceIp: '203.0.113.9',
    destinationIp: '10.0.7.64',
    endpoint: 'endpoint-12',
    status: 'Open',
    assignedAnalyst: 'Analyst B',
    time: '15:41',
    summary:
      'AthenaSec detected an exploited application service on endpoint-12 beaconing to a known command-and-control address.',
    reasoning:
      'EDR findings, a persistence mechanism and fixed-interval outbound traffic to a MISP-listed address agree, and the host is a Business asset, so isolation was recommended for a person to approve.',
    mitre: 'T1071 - Application Layer Protocol',
    explanation:
      'The System Administrator approved the isolation at 15:43 and endpoint-12 was isolated at 15:44 for 120 minutes. It reconnects automatically at 17:44.',
  },
]

export const initialAlerts: AlertRecord[] = alertDetails.map((alert) => {
  const risk = riskFor(alert.id)

  return { ...alert, risk, riskBand: riskBandFor(risk) }
})
