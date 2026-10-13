import type { HealthEvent, HealthMetric, ServiceRecord } from '../types/systemHealthTypes'

export const initialMetrics: HealthMetric[] = [
  {
    id: 'cpu',
    name: 'CPU Usage',
    value: 42,
    description: 'Healthy load',
    level: 'Good',
  },
  {
    id: 'memory',
    name: 'Memory Usage',
    value: 67,
    description: 'Elevated',
    level: 'Watch',
  },
  {
    id: 'storage',
    name: 'Storage',
    value: 54,
    description: 'Moderate',
    level: 'Watch',
  },
  {
    id: 'network',
    name: 'Network',
    value: 31,
    description: 'Low traffic',
    level: 'Good',
  },
  {
    id: 'services',
    name: 'Running Services',
    value: 96,
    description: 'Nearly all up',
    level: 'Good',
  },
  {
    id: 'hosts',
    name: 'Connected Hosts',
    value: 82,
    description: 'Most online',
    level: 'Good',
  },
  {
    id: 'alerts',
    name: 'Alerts Processed',
    value: 74,
    description: 'Backlog forming',
    level: 'Watch',
  },
  {
    id: 'cases',
    name: 'Cases Created',
    value: 58,
    description: 'Below target',
    level: 'Critical',
  },
]

export const initialServices: ServiceRecord[] = [
  {
    id: 'SVC-001',
    name: 'Wazuh Manager',
    category: 'SIEM',
    status: 'Online',
    uptime: '99.98%',
    latency: 42,
    version: '4.12.0',
    endpoint: 'wazuh-manager:55000',
    lastCheck: '30 seconds ago',
    description:
      'Receives Linux endpoint telemetry, security events, authentication logs, and file-integrity alerts.',
  },
  {
    id: 'SVC-002',
    name: 'OpenSearch',
    category: 'Storage',
    status: 'Online',
    uptime: '99.95%',
    latency: 68,
    version: '2.19.1',
    endpoint: 'opensearch:9200',
    lastCheck: '35 seconds ago',
    description:
      'Stores and indexes AthenaSec alerts, cases, audit logs, response history, and system telemetry.',
  },
  {
    id: 'SVC-003',
    name: 'Suricata Sensor',
    category: 'Network IDS',
    status: 'Online',
    uptime: '99.91%',
    latency: 34,
    version: '7.0.10',
    endpoint: 'suricata-01',
    lastCheck: '41 seconds ago',
    description:
      'Monitors network traffic and creates intrusion-detection events from signatures and protocol analysis.',
  },
  {
    id: 'SVC-004',
    name: 'LangGraph Workflow',
    category: 'AI Workflow',
    status: 'Online',
    uptime: '99.72%',
    latency: 115,
    version: '0.6.2',
    endpoint: 'langgraph:8000',
    lastCheck: '45 seconds ago',
    description:
      'Coordinates detection, AI analysis, policy evaluation, response execution, and audit stages.',
  },
  {
    id: 'SVC-005',
    name: 'Ollama Runtime',
    category: 'AI Runtime',
    status: 'Degraded',
    uptime: '98.84%',
    latency: 486,
    version: '0.11.3',
    endpoint: 'ollama:11434',
    lastCheck: '52 seconds ago',
    description:
      'Hosts the local language model used for summaries, reasoning, technical explanations, and analyst context.',
  },
  {
    id: 'SVC-006',
    name: 'TheHive',
    category: 'Case Management',
    status: 'Online',
    uptime: '99.86%',
    latency: 96,
    version: '5.4.6',
    endpoint: 'thehive:9000',
    lastCheck: '1 minute ago',
    description:
      'Supports case creation and investigation tracking for validated security alerts.',
  },
  {
    id: 'SVC-007',
    name: 'Cortex',
    category: 'Analyzer',
    status: 'Online',
    uptime: '99.67%',
    latency: 122,
    version: '3.1.8',
    endpoint: 'cortex:9001',
    lastCheck: '1 minute ago',
    description:
      'Provides observable enrichment and analysis for IP addresses, domains, hashes, and endpoints.',
  },
]

export const healthEvents: HealthEvent[] = [
  {
    id: 'HLT-011',
    time: '15:42',
    severity: 'Warning',
    source: 'Ollama Runtime',
    message:
      'Model response latency exceeded the expected 400 ms threshold.',
  },
  {
    id: 'HLT-010',
    time: '15:18',
    severity: 'Info',
    source: 'OpenSearch',
    message:
      'Audit and response indexes completed synchronization successfully.',
  },
  {
    id: 'HLT-009',
    time: '14:56',
    severity: 'Warning',
    source: 'Alert Processor',
    message:
      'The alert-processing queue reached 74% of the configured capacity.',
  },
  {
    id: 'HLT-008',
    time: '14:31',
    severity: 'Info',
    source: 'Wazuh Manager',
    message:
      'All registered Linux agents completed their scheduled check-in.',
  },
  {
    id: 'HLT-007',
    time: '13:48',
    severity: 'Critical',
    source: 'Case Automation',
    message:
      'Case creation success rate dropped below the configured operational target.',
  },
]
