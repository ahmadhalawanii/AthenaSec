export type HealthLevel = 'Good' | 'Watch' | 'Critical'
export type ServiceStatus = 'Online' | 'Degraded' | 'Offline'
export type EventSeverity = 'Info' | 'Warning' | 'Critical'

export type HealthMetric = {
  id: string
  name: string
  value: number
  description: string
  level: HealthLevel
}

export type ServiceRecord = {
  id: string
  name: string
  category: string
  status: ServiceStatus
  uptime: string
  latency: number
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
