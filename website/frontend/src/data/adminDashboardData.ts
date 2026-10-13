import type { ActivityRecord, IntegrationRecord } from '../types/adminDashboardTypes'

export const integrations: IntegrationRecord[] = [
  {
    name: 'Wazuh',
    status: 'Connected',
    lastCheck: '30 seconds ago',
  },
  {
    name: 'OpenSearch',
    status: 'Connected',
    lastCheck: '45 seconds ago',
  },
  {
    name: 'Ollama',
    status: 'Connected',
    lastCheck: '1 minute ago',
  },
  {
    name: 'Cortex',
    status: 'Connected',
    lastCheck: '1 minute ago',
  },
  {
    name: 'TheHive',
    status: 'Connected',
    lastCheck: '2 minutes ago',
  },
  {
    name: 'Slack Alerts',
    status: 'Connected',
    lastCheck: '2 minutes ago',
  },
]

export const recentActivity: ActivityRecord[] = [
  {
    id: 'AUD-205',
    time: '15:42',
    admin: 'System Administrator',
    action: 'Updated detection rule',
    target: 'Brute Force SSH',
    result: 'Saved',
  },
  {
    id: 'AUD-204',
    time: '15:10',
    admin: 'System Administrator',
    action: 'Validated response policy',
    target: 'Critical Host Isolation',
    result: 'Validated',
  },
  {
    id: 'AUD-203',
    time: '14:21',
    admin: 'System Administrator',
    action: 'Added user account',
    target: 'Analyst B',
    result: 'Created',
  },
  {
    id: 'AUD-202',
    time: '13:55',
    admin: 'System Administrator',
    action: 'Synchronized integration',
    target: 'OpenSearch',
    result: 'Completed',
  },
]
