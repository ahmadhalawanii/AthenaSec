import type { AlertRecord } from '../types/alertsTypes'

export const initialAlerts: AlertRecord[] = [
  {
    id: 'ALT-001',
    severity: 'Critical',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force SSH',
    sourceIp: '192.168.1.45',
    destinationIp: '10.0.4.21',
    endpoint: 'endpoint-01',
    risk: 92,
    riskBand: 'critical',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    time: '14:32',
    summary:
      'AthenaSec detected a critical SSH brute force campaign against privileged accounts.',
    reasoning:
      'The source generated a high-frequency failed login burst, matched prior scanner reputation, and crossed the critical authentication abuse threshold.',
    mitre: 'T1110 - Brute Force',
    explanation:
      'The activity indicates credential access behavior. The alert remains open for analyst review and supporting evidence validation.',
  },
  {
    id: 'ALT-002',
    severity: 'High',
    attackGroup: 'Privilege Escalation',
    attackType: 'Privilege Escalation',
    sourceIp: '10.0.2.18',
    destinationIp: '10.0.4.33',
    endpoint: 'endpoint-03',
    risk: 84,
    riskBand: 'high',
    status: 'AI Handled',
    assignedAnalyst: 'Analyst B',
    time: '14:41',
    summary:
      'AthenaSec identified suspicious sudo escalation activity on endpoint-03.',
    reasoning:
      'Privilege escalation telemetry matched an allowed autonomous response policy with high confidence and limited blast radius.',
    mitre: 'T1548 - Abuse Elevation Control Mechanism',
    explanation:
      'The AI recorded the decision path and response result for analyst review.',
  },
  {
    id: 'ALT-003',
    severity: 'Medium',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force - Password Spray',
    sourceIp: '203.0.113.88',
    destinationIp: '10.0.4.41',
    endpoint: 'vpn-gateway-02',
    risk: 64,
    riskBand: 'medium',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    time: '15:02',
    summary:
      'AthenaSec correlated a password spray pattern across VPN authentication attempts.',
    reasoning:
      'The activity was distributed across multiple accounts and remained below the critical response threshold.',
    mitre: 'T1110.003 - Password Spraying',
    explanation:
      'The alert remains open for analyst investigation and validation.',
  },
  {
    id: 'ALT-004',
    severity: 'Critical',
    attackGroup: 'Privilege Escalation',
    attackType: 'Privilege Escalation - Kernel Exploit Attempt',
    sourceIp: '10.0.7.51',
    destinationIp: '10.0.7.51',
    endpoint: 'endpoint-09',
    risk: 95,
    riskBand: 'critical',
    status: 'AI Handled',
    assignedAnalyst: 'Analyst C',
    time: '15:17',
    summary:
      'AthenaSec classified kernel exploit telemetry as malicious privilege escalation activity.',
    reasoning:
      'The exploit signature, endpoint evidence, and risk score matched the Critical Host Isolation policy.',
    mitre: 'T1068 - Exploitation for Privilege Escalation',
    explanation:
      'The autonomous response isolated the endpoint and preserved telemetry for investigation.',
  },
  {
    id: 'ALT-005',
    severity: 'Low',
    attackGroup: 'Brute Force',
    attackType: 'Brute Force - SSH Probe',
    sourceIp: '198.51.100.77',
    destinationIp: '10.0.4.21',
    endpoint: 'endpoint-01',
    risk: 28,
    riskBand: 'low',
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
]
