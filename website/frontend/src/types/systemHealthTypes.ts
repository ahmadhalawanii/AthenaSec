import type { CheckKey } from './servicePanelTypes'

export type HealthLevel = 'Good' | 'Watch' | 'Critical'
/*
  The one set of service words, shared by the System Health page, the
  Service Panel, the top bar, the dashboard and the sidebar badge.
  Degraded is "working, but slower than the latency target"; Failed is
  the Service Panel's own "unhealthy" (a failed unit or a 5xx answer).
*/
export type ServiceStatus =
  | 'Running'
  | 'Starting'
  | 'Degraded'
  | 'Failed'
  | 'Stopped'
  | 'Unverified'

// The two labelled groups of the one service inventory
export type ServiceGroupKey = 'pipeline' | 'vm'

export type EventSeverity = 'Info' | 'Warning' | 'Critical'

export type HealthMetric = {
  id: string
  name: string
  value: number
  description: string
  level: HealthLevel
}

// What the Service Panel's Overview shows for a service on the VM
export type VmCheck = {
  key: CheckKey
  detail: string
  // Seconds since it became active, or null when unknown
  uptimeSeconds: number | null
  // Overrides the state's name on the Panel chip ("Available" for MISP)
  statusLabel: string
}

export type ServiceRecord = {
  id: string
  name: string
  category: string
  group: ServiceGroupKey
  status: ServiceStatus
  uptime: string
  // Response time in ms; null for the VM group, which is checked for availability only
  latency: number | null
  // Present on the VM group's services: the Service Panel's view of the same service
  check?: VmCheck
  version: string
  endpoint: string
  lastCheck: string
  description: string
}

export type HealthEvent = {
  id: string
  time: string
  severity: EventSeverity
  source: string
  message: string
}
