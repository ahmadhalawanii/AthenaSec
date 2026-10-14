/*
  Types for the Service Panel page, ported from the desktop Service Panel
  v3. Six checks feed four service groups; each has one of six states.
*/

export type ServiceState =
  | 'running'
  | 'partial'
  | 'stopped'
  | 'starting'
  | 'unhealthy'
  | 'unknown'

// The six checks: three Wazuh components, MISP, Cortex and Docker Engine
export type CheckKey = 'manager' | 'indexer' | 'dashboard' | 'misp' | 'cortex' | 'docker'

// The four groups shown on the Overview: the three Wazuh checks collapse into one
export type GroupKey = 'wazuh' | 'misp' | 'cortex' | 'docker'

// Groups that have a web console
export type ConsoleKey = 'wazuh' | 'cortex' | 'misp'

// What one check reports
export type CheckResult = {
  key: CheckKey
  state: ServiceState
  detail: string
  // Seconds since the service became active, or null when unknown
  uptime: number | null
  // Overrides the state's name on the status chip ("Available" for MISP)
  displayStatus: string
}

// What one group reports (Wazuh is the summary of its three checks)
export type GroupResult = {
  key: GroupKey
  state: ServiceState
  detail: string
  uptime: number | null
  displayStatus: string
}

// A fixed check: a systemd unit, or a local HTTPS endpoint
export type ServiceCheck = {
  key: CheckKey
  name: string
  metadata: string
  unit?: string
  port?: number
  path?: string
}

export type GroupInfo = {
  key: GroupKey
  name: string
  // Ports in mono under the name
  ports: string
}

export type ConsoleInfo = {
  name: string
  origin: string
}

// The machine running the panel (an Ubuntu VM guest in the demo)
export type DeviceUsage = {
  cpuPercent: number
  memoryUsedBytes: number
  memoryTotalBytes: number
}

// The Service Panel slice of the shared admin state
export type ServicePanelState = {
  results: CheckResult[]
  usage: DeviceUsage
}

// Tone names the page maps to existing colour tokens
export type StateTone = 'ok' | 'caution' | 'danger' | 'neutral'
