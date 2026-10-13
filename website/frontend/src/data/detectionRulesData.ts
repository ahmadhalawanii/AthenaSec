import type { DetectionRule, RuleFormState } from '../types/detectionRulesTypes'

export const initialRules: DetectionRule[] = [
  {
    id: 'RULE-001',
    name: 'Brute Force SSH',
    category: 'Authentication',
    threshold: '10 failures / 5 min',
    policy: 'Critical Authentication Abuse',
    status: 'Enabled',
    severity: 'Critical',
    mitre: 'T1110 - Brute Force',
    description:
      'Detects repeated SSH authentication failures against privileged or administrative accounts.',
    dataSource: 'Wazuh authentication logs',
    lastUpdated: 'Today, 15:42',
  },
  {
    id: 'RULE-002',
    name: 'Privilege Escalation',
    category: 'Privilege Escalation',
    threshold: '1 suspicious sudo event',
    policy: 'Privilege Escalation Session Control',
    status: 'Enabled',
    severity: 'High',
    mitre: 'T1548 - Abuse Elevation Control Mechanism',
    description:
      'Detects suspicious sudo activity, unexpected privilege changes, and elevation outside approved maintenance windows.',
    dataSource: 'Wazuh endpoint telemetry',
    lastUpdated: 'Today, 14:55',
  },
  {
    id: 'RULE-003',
    name: 'VPN Password Spray',
    category: 'Authentication',
    threshold: '8 accounts / 10 min',
    policy: 'VPN Password Spray Containment',
    status: 'Enabled',
    severity: 'Medium',
    mitre: 'T1110.003 - Password Spraying',
    description:
      'Identifies distributed authentication attempts using a small number of passwords across multiple accounts.',
    dataSource: 'VPN gateway logs',
    lastUpdated: 'Yesterday, 18:10',
  },
  {
    id: 'RULE-004',
    name: 'Kernel Exploit Attempt',
    category: 'Endpoint',
    threshold: '1 exploit signature',
    policy: 'Critical Host Isolation',
    status: 'Enabled',
    severity: 'Critical',
    mitre: 'T1068 - Exploitation for Privilege Escalation',
    description:
      'Detects local kernel exploitation behavior and known privilege-escalation signatures on monitored Linux endpoints.',
    dataSource: 'Suricata and endpoint telemetry',
    lastUpdated: 'Today, 15:17',
  },
  {
    id: 'RULE-005',
    name: 'Suspicious Port Scan',
    category: 'Network',
    threshold: '25 ports / 60 sec',
    policy: 'Network Reconnaissance Review',
    status: 'Disabled',
    severity: 'Low',
    mitre: 'T1046 - Network Service Discovery',
    description:
      'Detects rapid connection attempts across multiple ports that may indicate reconnaissance activity.',
    dataSource: 'Suricata network alerts',
    lastUpdated: '3 days ago',
  },
]

export const emptyRuleForm: RuleFormState = {
  name: '',
  category: 'Authentication',
  threshold: '',
  policy: '',
  status: 'Enabled',
  severity: 'Medium',
  mitre: '',
  description: '',
  dataSource: '',
}
