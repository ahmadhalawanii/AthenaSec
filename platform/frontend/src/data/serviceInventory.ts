import type { CheckResult, ServiceState } from '../types/servicePanelTypes'
import type {
  ServiceGroupKey,
  ServiceRecord,
  ServiceStatus,
} from '../types/systemHealthTypes'

import { LATENCY_TARGET_MS } from './systemHealthData'

/*
  Everything that counts, words or colours a service comes from here, so
  the System Health page, the Service Panel, the top bar, the dashboard,
  the login page and the sidebar badge cannot disagree. Pure: no React,
  no clock, no network.

  The words: Running, Starting, Degraded (working, but slower than the
  latency target), Failed (the Service Panel's own "unhealthy": a failed
  unit or a 5xx answer), Stopped and Unverified. Healthy means Running
  and, for a service with a response time, at or under the target.
*/

export const SERVICE_GROUPS: Array<{ key: ServiceGroupKey; name: string; note: string }> = [
  { key: 'pipeline', name: 'Detection and AI pipeline', note: 'Checked for response time' },
  { key: 'vm', name: 'Security stack on the VM', note: 'Checked for availability only' },
]

// Past this response time a probe counts the service as not responding
const STOPPED_LATENCY_MS = 600

// Worst first: what the top bar names and the order the lists use
const ATTENTION_ORDER: ServiceStatus[] = ['Failed', 'Stopped', 'Degraded', 'Starting', 'Unverified']

/*
  The word to show. A Running service slower than the target reads
  Degraded, whatever was stored. A service without a response time (the
  VM group) is never Degraded, so a failed one stays Failed.
*/
export function serviceStatus(service: ServiceRecord): ServiceStatus {
  return service.status === 'Running' && service.latency !== null && service.latency > LATENCY_TARGET_MS
    ? 'Degraded'
    : service.status
}

export const isHealthy = (service: ServiceRecord) => serviceStatus(service) === 'Running'

// Everything that is not healthy, worst first (ties keep inventory order)
export function attentionServices(services: ServiceRecord[]) {
  return services
    .filter((service) => !isHealthy(service))
    .sort(
      (first, second) =>
        ATTENTION_ORDER.indexOf(serviceStatus(first)) - ATTENTION_ORDER.indexOf(serviceStatus(second)),
    )
}

// The sidebar badge: how many services need attention
export const servicesNeedingAttention = (services: ServiceRecord[]) => attentionServices(services).length

export const servicesInGroup = (services: ServiceRecord[], group: ServiceGroupKey) =>
  services.filter((service) => service.group === group)

// "3 of 4 healthy" for one group
export function groupCount(services: ServiceRecord[], group: ServiceGroupKey) {
  const members = servicesInGroup(services, group)

  return { healthy: members.filter(isHealthy).length, total: members.length }
}

// (The colour of each word lives in utils/statusTone.ts, with every other status word.)

// ===== Probes (the pipeline group only) =====

export function statusForLatency(latency: number): ServiceStatus {
  if (latency > STOPPED_LATENCY_MS) {
    return 'Stopped'
  }

  return latency > LATENCY_TARGET_MS ? 'Degraded' : 'Running'
}

/*
  One simulated probe: the response time moves by `change` ms and the
  status follows it. Only the pipeline group has a response time to probe;
  a VM service comes back unchanged (it is a snapshot).
*/
export function probe(service: ServiceRecord, change: number): ServiceRecord {
  if (service.group !== 'pipeline' || service.latency === null) {
    return service
  }

  const latency = Math.max(10, service.latency + change)

  return { ...service, latency, status: statusForLatency(latency), lastCheck: 'Just now' }
}

// ===== Status line (top bar, dashboard, health summary) =====

export type SystemStatusLevel = 'ok' | 'warn' | 'danger'

export type SystemStatusSummary = {
  level: SystemStatusLevel
  title: string
  detail: string
  // Names of the services behind the status, worst first
  affected: string[]
  // The top bar text: "Ollama Runtime degraded", or "2 services need attention"
  text: string
  // The phone version: "1 degraded", "2 need attention"
  short: string
}

const lower = (status: ServiceStatus) => status.toLowerCase()

export function systemStatus(services: ServiceRecord[]): SystemStatusSummary {
  const affected = attentionServices(services)

  if (affected.length === 0) {
    return {
      level: 'ok',
      title: 'System Online',
      detail: 'All Systems Operational',
      affected: [],
      text: 'All Systems Operational',
      short: 'All running',
    }
  }

  // Stopped or failed is an outage; slow or still starting is a warning
  const outage = affected.some((service) => ['Stopped', 'Failed'].includes(serviceStatus(service)))
  const names = affected.map((service) => service.name)

  if (affected.length === 1) {
    const word = lower(serviceStatus(affected[0]))

    return {
      level: outage ? 'danger' : 'warn',
      title: outage ? 'Service Outage' : 'Attention Required',
      detail: `${names[0]} ${word}`,
      affected: names,
      text: `${names[0]} ${word}`,
      short: `1 ${word}`,
    }
  }

  return {
    level: outage ? 'danger' : 'warn',
    title: outage ? 'Service Outage' : 'Attention Required',
    detail: `${affected.length} services need attention`,
    affected: names,
    text: `${affected.length} services need attention`,
    short: `${affected.length} need attention`,
  }
}

const joinNames = (names: string[]) =>
  names.length <= 1 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`

// How one service reads in a sentence
function clause(service: ServiceRecord) {
  switch (serviceStatus(service)) {
    case 'Degraded':
      return `${service.name} is responding slowly`
    case 'Failed':
      return `${service.name} has failed`
    case 'Stopped':
      return `${service.name} is stopped`
    case 'Starting':
      return `${service.name} is still starting`
    default:
      return `${service.name} could not be verified`
  }
}

// "8 of 10 services healthy. Ollama Runtime is responding slowly and Wazuh Dashboard is still starting."
export function healthSummary(services: ServiceRecord[]) {
  const affected = attentionServices(services)
  const lead = `${services.length - affected.length} of ${services.length} services healthy.`

  return affected.length === 0
    ? `${lead} Everything is responding normally.`
    : `${lead} ${joinNames(affected.map(clause))}.`
}

// The dashboard's note under "Services healthy": "Ollama Runtime degraded", "A and B need attention"
export function healthNote(services: ServiceRecord[]) {
  const status = systemStatus(services)

  if (status.level === 'ok') {
    return 'All healthy'
  }

  return status.affected.length === 2 ? `${status.affected.join(' and ')} need attention` : status.detail
}

// ===== The Service Panel's view of the VM group =====

const PANEL_STATE: Record<ServiceStatus, ServiceState> = {
  Running: 'running',
  Starting: 'starting',
  Degraded: 'running',
  Failed: 'unhealthy',
  Stopped: 'stopped',
  Unverified: 'unknown',
}

// The six checks the Service Panel summarises, in the order of the inventory
export function vmChecks(services: ServiceRecord[]): CheckResult[] {
  return services.flatMap((service) =>
    service.group === 'vm' && service.check
      ? [
          {
            key: service.check.key,
            state: PANEL_STATE[serviceStatus(service)],
            detail: service.check.detail,
            uptime: service.check.uptimeSeconds,
            displayStatus: service.check.statusLabel,
          },
        ]
      : [],
  )
}

// The word for a Service Panel state (the Panel's "unhealthy" reads Failed)
export const STATE_WORDS: Record<ServiceState, string> = {
  running: 'Running',
  partial: 'Partially running',
  stopped: 'Stopped',
  starting: 'Starting',
  unhealthy: 'Failed',
  unknown: 'Unverified',
}

// Sentences and titles from the Panel's pure module, in the shared words
export const inDisplayWords = (text: string) =>
  text.replace(/\bUnhealthy\b/g, 'Failed').replace(/\bunhealthy\b/g, 'failed')
