import type { IntegrationRecord } from '../types/integrationsTypes'

export const initialIntegrations: IntegrationRecord[] = [
  {
    id: 'INT-001',
    name: 'Wazuh',
    type: 'SIEM Agent',
    status: 'Connected',
    version: '4.12.0',
    endpoint: 'https://wazuh.athenasec.local',
    lastSync: '2 minutes ago',
    description:
      'Collects Linux endpoint security events, authentication logs, file integrity alerts, and system telemetry.',
    dataFlow:
      'Wazuh agents send endpoint events to the Wazuh manager, which forwards indexed security data to OpenSearch.',
  },
  {
    id: 'INT-002',
    name: 'OpenSearch',
    type: 'Search',
    status: 'Connected',
    version: '2.19.1',
    endpoint: 'https://opensearch.athenasec.local',
    lastSync: '1 minute ago',
    description:
      'Stores, indexes, searches, and retrieves AthenaSec alerts, cases, audit events, and response history.',
    dataFlow:
      'Security telemetry is indexed into OpenSearch and retrieved by the AthenaSec dashboard and AI workflow.',
  },
  {
    id: 'INT-003',
    name: 'TheHive',
    type: 'Case Management',
    status: 'Connected',
    version: '5.4.6',
    endpoint: 'https://thehive.athenasec.local',
    lastSync: '4 minutes ago',
    description:
      'Provides external case-management support for validated alerts and analyst-owned investigations.',
    dataFlow:
      'Validated alerts can create or update investigation cases while AthenaSec retains the response and audit history.',
  },
  {
    id: 'INT-004',
    name: 'Cortex',
    type: 'Analyzer',
    status: 'Connected',
    version: '3.1.8',
    endpoint: 'https://cortex.athenasec.local',
    lastSync: '5 minutes ago',
    description:
      'Runs analyzers and enrichment tasks against observables such as IP addresses, domains, hashes, and endpoints.',
    dataFlow:
      'AthenaSec sends selected observables to Cortex and records returned enrichment results with the related alert.',
  },
  {
    id: 'INT-005',
    name: 'Suricata',
    type: 'Network IDS',
    status: 'Connected',
    version: '7.0.10',
    endpoint: 'sensor://suricata-01',
    lastSync: '3 minutes ago',
    description:
      'Monitors network traffic and generates intrusion-detection events for suspicious connections and attack signatures.',
    dataFlow:
      'Suricata EVE events are collected and correlated with endpoint telemetry, detection rules, and MITRE ATT&CK mappings.',
  },
  {
    id: 'INT-006',
    name: 'Ollama',
    type: 'AI Runtime',
    status: 'Connected',
    version: '0.11.3',
    endpoint: 'http://ollama.athenasec.local:11434',
    lastSync: '1 minute ago',
    description:
      'Hosts the local language model used for summaries, analyst explanations, response reasoning, and investigation context.',
    dataFlow:
      'Sanitized alert context is sent to the local Ollama runtime and the generated analysis is returned to AthenaSec.',
  },
  {
    id: 'INT-007',
    name: 'LangGraph',
    type: 'AI Workflow',
    status: 'Connected',
    version: '0.6.2',
    endpoint: 'http://langgraph.athenasec.local',
    lastSync: '6 minutes ago',
    description:
      'Coordinates the agentic detection, classification, reasoning, policy-checking, and response workflow.',
    dataFlow:
      'LangGraph passes structured state between the detection, analysis, policy, action, and audit stages.',
  },
]
