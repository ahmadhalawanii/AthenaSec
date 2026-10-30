import type {
  CheckKey,
  CheckResult,
  ConsoleInfo,
  ConsoleKey,
  GroupInfo,
  GroupKey,
  GroupResult,
  ServiceCheck,
  ServiceState,
  StateTone,
} from '../types/servicePanelTypes'

/*
  The Service Panel's logic, ported from the desktop Service Panel v3
  (services.py, metrics.py, site_policy.py). Pure: no React, no clock, no
  network. The web page runs on demo data; the live probes stay in the
  desktop panel on the VM.
*/

// ===== Catalogue =====

export const SERVICE_STATES: ServiceState[] = [
  'running',
  'partial',
  'stopped',
  'starting',
  'unhealthy',
  'unknown',
]

// The six fixed checks, in the order the desktop panel runs them
export const SERVICE_CHECKS: ServiceCheck[] = [
  { key: 'manager', name: 'Wazuh Manager', metadata: 'Port 55000', unit: 'wazuh-manager' },
  { key: 'indexer', name: 'Wazuh Indexer', metadata: 'Port 9200', unit: 'wazuh-indexer' },
  { key: 'dashboard', name: 'Wazuh Dashboard', metadata: 'Port 443', unit: 'wazuh-dashboard' },
  { key: 'misp', name: 'MISP', metadata: 'Port 9445', port: 9445, path: '/users/heartbeat' },
  { key: 'cortex', name: 'Cortex', metadata: 'Port 9444', port: 9444, path: '/api/status' },
  { key: 'docker', name: 'Docker Engine', metadata: 'Container service', unit: 'docker' },
]

// The four groups on the Overview: Wazuh (three checks) then MISP, Cortex and Docker Engine
export const OVERVIEW_GROUPS: GroupInfo[] = [
  { key: 'wazuh', name: 'Wazuh', ports: 'Ports 55000 · 9200 · 443' },
  { key: 'misp', name: 'MISP', ports: 'Port 9445' },
  { key: 'cortex', name: 'Cortex', ports: 'Port 9444' },
  { key: 'docker', name: 'Docker Engine', ports: 'Container service' },
]

export const GROUP_COUNT = OVERVIEW_GROUPS.length

// The three checks that make up the Wazuh group, with the names shown for them
const WAZUH_PARTS: Array<{ key: CheckKey; name: string }> = [
  { key: 'manager', name: 'Manager' },
  { key: 'indexer', name: 'Indexer' },
  { key: 'dashboard', name: 'Dashboard' },
]

// The fixed console addresses: no editable URL, one place to change them
export const CONSOLES: Record<ConsoleKey, ConsoleInfo> = {
  wazuh: { name: 'Wazuh', origin: 'https://192.168.1.164' },
  cortex: { name: 'Cortex', origin: 'https://192.168.1.164:9444' },
  misp: { name: 'MISP', origin: 'https://192.168.1.164:9445' },
}

// ===== Summary (port of summarize()) =====

const missing = (key: CheckKey): CheckResult => ({
  key,
  state: 'unknown',
  detail: 'No result',
  uptime: null,
  displayStatus: '',
})

const capitalize = (text: string) => text.charAt(0).toUpperCase() + text.slice(1).toLowerCase()

/*
  Collapses the three Wazuh checks into one group without hiding a failed
  or unverified component, and passes MISP, Cortex and Docker through.
  Precedence, as in the desktop panel: 3/3 running; any unknown
  ("Unverified"); some running ("Partially running"); all stopped; any
  unhealthy; any starting; otherwise unknown. A missing check is unknown.
  Returns the four groups in overview order.
*/
export function summarizeWazuh(results: CheckResult[]): GroupResult[] {
  const byKey = new Map(results.map((item) => [item.key, item]))
  const components = WAZUH_PARTS.map((part) => byKey.get(part.key) ?? missing(part.key))
  const count = components.filter((item) => item.state === 'running').length
  const states = new Set(components.map((item) => item.state))

  let state: ServiceState
  let title: string
  let uptime: number | null = null

  if (count === 3) {
    state = 'running'
    title = 'Running — 3/3'

    if (components.every((item) => item.uptime !== null)) {
      uptime = Math.min(...components.map((item) => item.uptime as number))
    }
  } else if (states.has('unknown')) {
    state = 'unknown'
    title = `Unverified — ${count}/3 running`
  } else if (count > 0) {
    state = 'partial'
    title = `Partially running — ${count}/3`
  } else if (states.size === 1 && states.has('stopped')) {
    state = 'stopped'
    title = 'Stopped — 0/3'
  } else if (states.has('unhealthy')) {
    state = 'unhealthy'
    title = 'Unhealthy — 0/3 running'
  } else if (states.has('starting')) {
    state = 'starting'
    title = 'Starting — 0/3 running'
  } else {
    state = 'unknown'
    title = 'Unverified — 0/3 running'
  }

  const detail = components
    .map((item, index) => `${WAZUH_PARTS[index].name}: ${capitalize(item.state)}`)
    .join('\n')

  const wazuh: GroupResult = { key: 'wazuh', state, detail, uptime, displayStatus: title }

  const others: GroupResult[] = (['misp', 'cortex', 'docker'] as const).map((key) => {
    const item = byKey.get(key) ?? missing(key)

    return {
      key,
      state: item.state,
      detail: item.detail,
      uptime: item.uptime,
      displayStatus: item.displayStatus,
    }
  })

  return [wazuh, ...others]
}

// ===== Counts =====

export const runningCount = (groups: GroupResult[]) =>
  groups.filter((group) => group.state === 'running').length

// Four groups minus the running ones: partial, starting, stopped, unhealthy and unknown all count
export const issueCount = (groups: GroupResult[]) => GROUP_COUNT - runningCount(groups)

// ===== Uptime (port of format_uptime()) =====

const floorDiv = (value: number, divisor: number) => Math.floor(value / divisor)
const modulo = (value: number, divisor: number) => value - divisor * floorDiv(value, divisor)

// 59 s is "0m", 1 h is "1h 0m", 1 d is "1d 0h 0m"
export function formatUptime(seconds: number) {
  const totalMinutes = floorDiv(Math.trunc(seconds), 60)
  const days = floorDiv(totalMinutes, 1440)
  const afterDays = modulo(totalMinutes, 1440)
  const hours = floorDiv(afterDays, 60)
  const minutes = modulo(afterDays, 60)

  if (days) {
    return `${days}d ${hours}h ${minutes}m`
  }

  return hours ? `${hours}h ${minutes}m` : `${minutes}m`
}

// The line at the foot of a card
export function uptimeLine(key: GroupKey, uptime: number | null) {
  if (key === 'wazuh') {
    return `All active for: ${uptime === null ? '—' : formatUptime(uptime)}`
  }

  if (key === 'docker') {
    return `Uptime: ${uptime === null ? '—' : formatUptime(uptime)}`
  }

  return 'Endpoint check, no uptime'
}

// ===== Words =====

// How a state reads in a sentence: "Dashboard is still starting"
const STATE_PHRASES: Record<ServiceState, string> = {
  running: 'is active',
  partial: 'is partly running',
  starting: 'is still starting',
  stopped: 'is stopped',
  unhealthy: 'is unhealthy',
  unknown: 'could not be verified',
}

function joinNames(names: string[]) {
  if (names.length <= 1) {
    return names.join('')
  }

  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

// The Wazuh components that are not running, as "Wazuh Dashboard is still starting"
function wazuhProblems(results: CheckResult[]) {
  const byKey = new Map(results.map((item) => [item.key, item]))

  return WAZUH_PARTS.flatMap((part) => {
    const item = byKey.get(part.key) ?? missing(part.key)

    return item.state === 'running' ? [] : [{ name: part.name, state: item.state }]
  })
}

// The header sentence, worked out from the results
export function statusSentence(results: CheckResult[]) {
  const groups = summarizeWazuh(results)
  const running = runningCount(groups)
  const lead = 'The AthenaSec stack on the Ubuntu VM.'

  if (running === GROUP_COUNT) {
    return `${lead} All ${GROUP_COUNT} service groups running.`
  }

  const issues = groups.flatMap((group) => {
    if (group.state === 'running') {
      return []
    }

    if (group.key === 'wazuh') {
      return wazuhProblems(results).map(
        (problem) => `Wazuh ${problem.name} ${STATE_PHRASES[problem.state]}`,
      )
    }

    const name = OVERVIEW_GROUPS.find((info) => info.key === group.key)?.name ?? group.key

    return [`${name} ${STATE_PHRASES[group.state]}`]
  })

  return `${lead} ${running} of ${GROUP_COUNT} service groups running; ${issues.join('; ')}.`
}

// The Wazuh card's detail line, worked out from the same three checks as its sub-items
export function wazuhDetail(results: CheckResult[]) {
  const problems = wazuhProblems(results)

  if (problems.length === 0) {
    return 'Manager, Indexer and Dashboard are active.'
  }

  const byKey = new Map(results.map((item) => [item.key, item]))
  const active = WAZUH_PARTS.filter((part) => byKey.get(part.key)?.state === 'running').map(
    (part) => part.name,
  )

  const parts: string[] = []

  if (active.length > 0) {
    parts.push(`${joinNames(active)} ${active.length === 1 ? 'is' : 'are'} active.`)
  }

  const trouble = joinNames(problems.map((problem) => `${problem.name} ${STATE_PHRASES[problem.state]}`))
  const consoleDown = problems.some((problem) => problem.name === 'Dashboard')

  parts.push(`${trouble}${consoleDown ? ', so the Wazuh console may not load yet' : ''}.`)

  return parts.join(' ')
}

// ===== Colour =====

// Running is green, partial and starting amber, unhealthy red, stopped and unknown neutral
export function stateTone(state: ServiceState): StateTone {
  switch (state) {
    case 'running':
      return 'ok'
    case 'partial':
    case 'starting':
      return 'caution'
    case 'unhealthy':
      return 'danger'
    default:
      return 'neutral'
  }
}

// ===== Device usage (wording from metrics.py) =====

const GIB = 1024 ** 3

export const memoryPercent = (usedBytes: number, totalBytes: number) => (100 * usedBytes) / totalBytes

// "38.4" for "CPU 38.4%"
export const percentText = (value: number) => value.toFixed(1)

// "5.7 / 8.0 GiB"
export const memoryDetail = (usedBytes: number, totalBytes: number) =>
  `${(usedBytes / GIB).toFixed(1)} / ${(totalBytes / GIB).toFixed(1)} GiB`
