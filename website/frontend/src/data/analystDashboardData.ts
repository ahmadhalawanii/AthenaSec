import type { DashboardAlert } from '../types/analystDashboardTypes'

export const dashboardAlerts: DashboardAlert[] = [
  {
    id: 'ALT-001',
    type: 'Brute Force SSH',
    endpoint: 'endpoint-01',
    severity: 'Critical',
    risk: 92,
    sourceIp: '192.168.1.45',
    destinationIp: '10.0.4.21',
    status: 'Open',
    assignedAnalyst: 'Analyst A',
    time: '14:32',
    summary:
      'AthenaSec detected a critical SSH brute force campaign against privileged accounts.',
    reasoning:
      'The source generated a high-frequency failed login burst, matched prior scanner reputation, and crossed the critical authentication abuse threshold.',
    mitre: 'T1110 - Brute Force',
    explanation:
      'The event indicates credential access activity. A case was created for analyst-owned follow-up while the AI supplied analysis and recommended containment evidence.',
  },
  {
    id: 'ALT-002',
    type: 'Privilege Escalation',
    endpoint: 'endpoint-03',
    severity: 'High',
    risk: 84,
    sourceIp: '10.0.2.18',
    destinationIp: '10.0.4.33',
    status: 'AI Handled',
    assignedAnalyst: 'Analyst B',
    time: '14:41',
    summary:
      'AthenaSec identified suspicious sudo escalation on endpoint-03.',
    reasoning:
      'Privilege escalation telemetry matched an allowed autonomous response policy with high confidence and limited blast radius.',
    mitre: 'T1548 - Abuse Elevation Control Mechanism',
    explanation:
      'The AI resolved the alert autonomously and recorded the reasoning for analyst review.',
  },
]
