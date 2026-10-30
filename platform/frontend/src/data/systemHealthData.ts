import type { HealthEvent, HealthMetric, ServiceRecord } from '../types/systemHealthTypes'

import { formatUptime } from './servicePanel'

export const initialMetrics: HealthMetric[] = [
  {
    id: 'cpu',
    name: 'CPU Usage',
    // CPU, memory and running services are worked out from the VM usage and the inventory (see serviceInventory.ts)
    value: 38.4,
    description: 'Low usage',
    level: 'Good',
  },
  {
    id: 'memory',
    name: 'Memory Usage',
    value: 71.2,
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
    value: 80,
    description: 'Some degradation',
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

const DAY = 86400

/*
  The one service inventory, in two labelled groups with no service
  listed twice. The detection and AI pipeline is probed for response
  time; the security stack on the VM is checked for availability only
  (what the Service Panel reports, shown here from the same records).
*/
export const initialServices: ServiceRecord[] = [
  {
    id: 'SVC-002',
    name: 'OpenSearch',
    category: 'Storage',
    group: 'pipeline',
    status: 'Running',
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
    group: 'pipeline',
    status: 'Running',
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
    group: 'pipeline',
    status: 'Running',
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
    group: 'pipeline',
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
    id: 'SVC-001',
    name: 'Wazuh Manager',
    category: 'SIEM',
    group: 'vm',
    status: 'Running',
    uptime: formatUptime(2 * DAY + 4 * 3600 + 6 * 60),
    latency: null,
    check: { key: 'manager', detail: 'Service active', uptimeSeconds: 2 * DAY + 4 * 3600 + 6 * 60, statusLabel: '' },
    version: '4.12.0',
    endpoint: 'wazuh-manager:55000',
    lastCheck: 'Service Panel snapshot',
    description:
      'Receives Linux endpoint telemetry, security events, authentication logs, and file-integrity alerts.',
  },
  {
    id: 'SVC-008',
    name: 'Wazuh Indexer',
    category: 'SIEM storage',
    group: 'vm',
    status: 'Running',
    uptime: formatUptime(2 * DAY + 4 * 3600 + 8 * 60),
    latency: null,
    check: { key: 'indexer', detail: 'Service active', uptimeSeconds: 2 * DAY + 4 * 3600 + 8 * 60, statusLabel: '' },
    version: '4.12.0',
    endpoint: 'wazuh-indexer:9200',
    lastCheck: 'Service Panel snapshot',
    description:
      'Indexes the security events the Wazuh Manager collects, so the Wazuh Dashboard can search them.',
  },
  {
    id: 'SVC-009',
    name: 'Wazuh Dashboard',
    category: 'SIEM console',
    group: 'vm',
    status: 'Starting',
    uptime: '—',
    latency: null,
    check: { key: 'dashboard', detail: 'Service starting', uptimeSeconds: null, statusLabel: '' },
    version: '4.12.0',
    endpoint: 'wazuh-dashboard:443',
    lastCheck: 'Service Panel snapshot',
    description:
      'The Wazuh web console. Until it finishes starting, the Wazuh console may not load.',
  },
  {
    id: 'SVC-006',
    name: 'MISP',
    category: 'Threat intelligence',
    group: 'vm',
    status: 'Running',
    uptime: '—',
    latency: null,
    check: {
      key: 'misp',
      detail: 'MISP login page responded; web availability only',
      uptimeSeconds: null,
      statusLabel: 'Available',
    },
    version: '2.5',
    endpoint: 'misp:9445',
    lastCheck: 'Service Panel snapshot',
    description:
      'Shares threat-intelligence indicators with AthenaSec. Only web availability is checked, not every worker or queue.',
  },
  {
    id: 'SVC-007',
    name: 'Cortex',
    category: 'Analyzer',
    group: 'vm',
    status: 'Running',
    uptime: '—',
    latency: null,
    check: {
      key: 'cortex',
      detail: 'Cortex responded to /api/status. Availability only.',
      uptimeSeconds: null,
      statusLabel: '',
    },
    version: '3.1.8',
    endpoint: 'cortex:9444',
    lastCheck: 'Service Panel snapshot',
    description:
      'Provides observable enrichment and analysis for IP addresses, domains, hashes, and endpoints.',
  },
  {
    id: 'SVC-010',
    name: 'Docker Engine',
    category: 'Container runtime',
    group: 'vm',
    status: 'Running',
    uptime: formatUptime(2 * DAY + 4 * 3600 + 12 * 60),
    latency: null,
    check: {
      key: 'docker',
      detail: 'Service active. Hosts the MISP and Cortex containers.',
      uptimeSeconds: 2 * DAY + 4 * 3600 + 12 * 60,
      statusLabel: '',
    },
    version: '27.3',
    endpoint: 'docker (container service)',
    lastCheck: 'Service Panel snapshot',
    description:
      'Runs the MISP and Cortex containers on the VM.',
  },
]

// Expected response latency; services above it need attention (see HLT-011)
export const LATENCY_TARGET_MS = 400

// Figures shown under Processing Totals besides the live capacity bars
export const processingTotals = {
  eventsIndexedToday: '18,462',
  averageProcessingTime: '1.8 seconds',
  connectedHosts: '41 / 50',
}

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
