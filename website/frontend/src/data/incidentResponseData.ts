import type { ExecutionRecord } from '../types/incidentResponseTypes'

export const executionRecords: ExecutionRecord[] = [
  {
    id: 'EXE-004',
    triggeringAlert: 'ALT-004',
    policy: 'Critical Host Isolation',
    action: 'Isolate Host',
    target: 'endpoint-09',
    initiator: 'AthenaSec AI',
    approvalType: 'Automatic',
    startTime: '15:17',
    endTime: '15:19',
    duration: '2 minutes',
    result: 'Completed',
    rollbackStatus: 'Not required',
    failureReason: 'None',
    happened:
      'AthenaSec AI isolated endpoint-09 after kernel exploit telemetry matched a critical response policy.',
    classified:
      'The telemetry showed privilege escalation behavior, local exploit indicators, and a risk score above the autonomous response threshold.',
    responseReason:
      'Endpoint isolation was selected to prevent lateral movement while preserving telemetry for investigation.',
    evidence: [
      'Risk score 95',
      'Kernel exploit attempt',
      'Endpoint endpoint-09',
      'Policy threshold met',
    ],
    timeline: [
      {
        time: '15:17',
        event: 'Exploit pattern detected',
      },
      {
        time: '15:18',
        event: 'Risk score calculated',
      },
      {
        time: '15:18',
        event: 'Critical Host Isolation policy matched',
      },
      {
        time: '15:19',
        event: 'Endpoint isolated successfully',
      },
    ],
  },
  {
    id: 'EXE-001',
    triggeringAlert: 'ALT-001',
    policy: 'Critical Authentication Abuse',
    action: 'Block IP',
    target: '192.168.1.45',
    initiator: 'AthenaSec AI',
    approvalType: 'Automatic',
    startTime: '14:32',
    endTime: '14:33',
    duration: '1 minute',
    result: 'Completed',
    rollbackStatus: 'Not required',
    failureReason: 'None',
    happened:
      'AthenaSec AI blocked source IP 192.168.1.45 after a critical brute force alert.',
    classified:
      'The source matched suspicious reputation and generated a high-frequency authentication failure burst.',
    responseReason:
      'Blocking the IP reduced active credential attack pressure against privileged accounts.',
    evidence: [
      'Risk score 92',
      'SSH failure burst',
      'Privileged account targeting',
      'Scanner reputation match',
    ],
    timeline: [
      {
        time: '14:32',
        event: 'Failed SSH burst detected',
      },
      {
        time: '14:33',
        event: 'Critical Authentication Abuse policy matched',
      },
      {
        time: '14:33',
        event: 'Source IP blocked successfully',
      },
    ],
  },
  {
    id: 'EXE-003',
    triggeringAlert: 'ALT-003',
    policy: 'VPN Password Spray Containment',
    action: 'Block IP',
    target: '203.0.113.88',
    initiator: 'Analyst A',
    approvalType: 'Analyst Approved',
    startTime: '15:08',
    endTime: '15:09',
    duration: '1 minute',
    result: 'Completed',
    rollbackStatus: 'Not required',
    failureReason: 'None',
    happened:
      'Analyst A approved a temporary IP block after AthenaSec correlated a VPN password-spray pattern.',
    classified:
      'The source attempted authentication across multiple accounts using a distributed password-spray pattern.',
    responseReason:
      'A temporary block was selected to stop further authentication attempts while the related accounts were reviewed.',
    evidence: [
      'Risk score 64',
      'Multiple accounts targeted',
      'VPN authentication failures',
      'Analyst approval recorded',
    ],
    timeline: [
      {
        time: '15:02',
        event: 'Password-spray alert created',
      },
      {
        time: '15:06',
        event: 'Analyst reviewed AI recommendation',
      },
      {
        time: '15:08',
        event: 'Response approved',
      },
      {
        time: '15:09',
        event: 'Source IP blocked',
      },
    ],
  },
  {
    id: 'EXE-002',
    triggeringAlert: 'ALT-002',
    policy: 'Privilege Escalation Session Control',
    action: 'Isolate Host',
    target: 'endpoint-03',
    initiator: 'AthenaSec AI',
    approvalType: 'Automatic',
    startTime: '14:41',
    endTime: '14:42',
    duration: '1 minute',
    result: 'Failed',
    rollbackStatus: 'Not applicable',
    failureReason:
      'The endpoint agent did not acknowledge the isolation command before the execution timeout.',
    happened:
      'AthenaSec attempted to isolate endpoint-03 after suspicious sudo escalation activity was detected.',
    classified:
      'The command sequence and user behavior matched privilege-escalation telemetry outside the normal maintenance window.',
    responseReason:
      'Host isolation was selected to limit further privileged activity while preserving endpoint evidence.',
    evidence: [
      'Risk score 84',
      'Unexpected sudo execution',
      'Maintenance-window mismatch',
      'Endpoint command timeout',
    ],
    timeline: [
      {
        time: '14:41',
        event: 'Privilege escalation detected',
      },
      {
        time: '14:41',
        event: 'Response policy matched',
      },
      {
        time: '14:42',
        event: 'Isolation command timed out',
      },
      {
        time: '14:42',
        event: 'Failure recorded for analyst review',
      },
    ],
  },
]
