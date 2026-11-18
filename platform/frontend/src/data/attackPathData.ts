import type { AlertRecord } from '../types/alertsTypes'
import type {
  AttackPath,
  EndpointHealth,
  PathNode,
  PathStatus,
  PathZone,
} from '../types/attackPathTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'

import { alertResponseState, executionFor } from './statusSummary'
import type { ApprovalRecord } from '../types/approvalTypes'

export const PATH_ZONES: PathZone[] = ['Internet', 'Perimeter', 'Internal', 'Endpoints']

/*
  Map layout (positions on a 1000 x 360 grid). Labels are the IPs,
  devices and endpoints from the alert data; only the placement is
  fixed here. Statuses are derived below from the alerts and their
  response runs, so they follow every change made in the app.
*/
export const PATH_NODES: PathNode[] = [
  // Internet nodes are anchored by their left edge and endpoints by
  // their right edge (see .path-node in athenasec.css), so long
  // captions stay inside the map.
  // Spaced so no two nodes touch down to a ~600px-wide map (1260px screens).
  { id: 'src-203.0.113.45', label: '203.0.113.45', role: 'Source', zone: 'Internet', x: 20, y: 40 },
  { id: 'src-203.0.113.88', label: '203.0.113.88', role: 'Source', zone: 'Internet', x: 20, y: 130 },
  { id: 'src-198.51.100.77', label: '198.51.100.77', role: 'Source', zone: 'Internet', x: 20, y: 220 },
  { id: 'src-203.0.113.9', label: '203.0.113.9', role: 'Source', zone: 'Internet', x: 20, y: 310 },
  { id: 'firewall', label: 'Firewall', role: 'Perimeter', zone: 'Perimeter', x: 400, y: 100 },
  { id: 'vpn-gateway-02', label: 'vpn-gateway-02', role: 'VPN gateway', zone: 'Perimeter', x: 400, y: 200 },
  { id: 'src-10.0.2.18', label: '10.0.2.18', role: 'Internal host', zone: 'Internal', x: 610, y: 262 },
  { id: 'src-10.0.7.51', label: '10.0.7.51', role: 'Internal host', zone: 'Internal', x: 610, y: 325 },
  { id: 'endpoint-01', label: 'endpoint-01', role: 'Endpoint', zone: 'Endpoints', x: 980, y: 40 },
  { id: 'endpoint-03', label: 'endpoint-03', role: 'Endpoint', zone: 'Endpoints', x: 980, y: 130 },
  { id: 'endpoint-09', label: 'endpoint-09', role: 'Endpoint', zone: 'Endpoints', x: 980, y: 220 },
  { id: 'endpoint-12', label: 'endpoint-12', role: 'Endpoint', zone: 'Endpoints', x: 980, y: 310 },
]

export const ATTACK_PATHS: AttackPath[] = [
  { alertId: 'ALT-001', nodes: ['src-203.0.113.45', 'firewall', 'endpoint-01'], stoppedAt: 'firewall' },
  { alertId: 'ALT-002', nodes: ['src-10.0.2.18', 'endpoint-03'] },
  { alertId: 'ALT-003', nodes: ['src-203.0.113.88', 'vpn-gateway-02'], stoppedAt: 'vpn-gateway-02' },
  { alertId: 'ALT-004', nodes: ['src-10.0.7.51', 'endpoint-09'] },
  { alertId: 'ALT-005', nodes: ['src-198.51.100.77', 'firewall'], stoppedAt: 'firewall' },
  { alertId: 'ALT-006', nodes: ['src-203.0.113.9', 'firewall', 'endpoint-12'] },
]

/*
  Live mode: the sample layout above only fits the sample alerts, so the
  map is laid out from the live alerts themselves. Each brute-force or
  privilege-misuse alert becomes a path from its source (the attacking
  IP, or a local account when the alert has none) to the endpoint it
  hit; Internet sources pass through the Firewall. Other alerts
  (configuration checks and the like) are not attacks and stay off the
  map. The most urgent paths are shown: open ones first, highest risk.
*/
export const LIVE_MAP_LIMIT = 6

const NOT_RECORDED = 'Not recorded'
const MAP_TOP = 40
const MAP_BOTTOM = 310
const ZONE_X: Record<PathZone, number> = { Internet: 20, Perimeter: 400, Internal: 610, Endpoints: 980 }

function isPrivateAddress(ip: string) {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    ip === '::1' ||
    /^f[cd]/i.test(ip)
  )
}

export function buildLiveLayout(alerts: AlertRecord[]): { nodes: PathNode[]; paths: AttackPath[] } {
  const candidates = alerts
    .filter((alert) => alert.attackGroup !== 'Other' && alert.endpoint !== NOT_RECORDED)
    .sort(
      (first, second) =>
        Number(second.status === 'Open') - Number(first.status === 'Open') || second.risk - first.risk,
    )
    .slice(0, LIVE_MAP_LIMIT)

  const byId = new Map<string, Omit<PathNode, 'y'>>()
  const paths: AttackPath[] = []

  function add(id: string, label: string, role: string, zone: PathZone) {
    if (!byId.has(id)) {
      byId.set(id, { id, label, role, zone, x: ZONE_X[zone] })
    }

    return id
  }

  for (const alert of candidates) {
    const hasIp = alert.sourceIp !== NOT_RECORDED
    const internal = !hasIp || isPrivateAddress(alert.sourceIp)
    const source = hasIp
      ? add(`src-${alert.sourceIp}`, alert.sourceIp, internal ? 'Internal host' : 'Source', internal ? 'Internal' : 'Internet')
      : add(`local-${alert.endpoint}`, 'Local account', 'Internal host', 'Internal')
    const endpoint = add(`endpoint-${alert.endpoint}`, alert.endpoint, 'Endpoint', 'Endpoints')

    paths.push(
      internal
        ? { alertId: alert.id, nodes: [source, endpoint] }
        : {
            alertId: alert.id,
            nodes: [source, add('firewall', 'Firewall', 'Perimeter', 'Perimeter'), endpoint],
            stoppedAt: 'firewall',
          },
    )
  }

  /*
    Each path gets its own row, so sources in different columns never sit
    side by side and run into each other. A node shared by several paths
    (the Firewall, an endpoint hit more than once) sits in the middle of
    the rows of the paths that use it.
  */
  const rowY = (index: number) =>
    paths.length === 1
      ? (MAP_TOP + MAP_BOTTOM) / 2
      : MAP_TOP + (index * (MAP_BOTTOM - MAP_TOP)) / (paths.length - 1)

  const nodes: PathNode[] = [...byId.values()].map((node) => {
    const rows = paths
      .map((path, index) => (path.nodes.includes(node.id) ? rowY(index) : null))
      .filter((y): y is number => y !== null)
    const y = rows.reduce((sum, value) => sum + value, 0) / rows.length

    return { ...node, y: Math.round(y) }
  })

  return { nodes, paths }
}

const ZONE_ORDER: Record<PathZone, number> = {
  Internet: 0,
  Perimeter: 1,
  Internal: 2,
  Endpoints: 3,
}

function pathStatus(
  alert: AlertRecord,
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
): PathStatus {
  switch (alertResponseState(alert, executions, approvals)) {
    case 'Closed':
      return 'closed'
    case 'Contained':
      return 'contained'
    case 'Source blocked':
      return 'blocked'
    default:
      return 'active'
  }
}

export type MapEdge = {
  from: PathNode
  to: PathNode
  // Past the point where a block stopped the attack
  unreached: boolean
}

export type MapPath = {
  alert: AlertRecord
  status: PathStatus
  statusLabel: string
  route: string
  edges: MapEdge[]
  nodeIds: string[]
}

export type MapNode = PathNode & {
  // Second line: the attack (short form) for sources, health for endpoints
  caption: string
  // Third line on a path's source node: the path's status in words
  statusWord?: string
  alertIds: string[]
  health?: EndpointHealth
  // The most urgent status of the paths through this node
  status: PathStatus
}

export type AttackMap = {
  paths: MapPath[]
  nodes: MapNode[]
  summary: string
}

const STATUS_RANK: Record<PathStatus, number> = {
  active: 3,
  contained: 2,
  blocked: 1,
  closed: 0,
}

export function buildAttackMap(
  alerts: AlertRecord[],
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
): AttackMap {
  // The sample alerts keep their hand-made layout; live alerts get one built from them
  const isSample = ATTACK_PATHS.some((path) => alerts.some((alert) => alert.id === path.alertId))
  const layout = isSample ? { nodes: PATH_NODES, paths: ATTACK_PATHS } : buildLiveLayout(alerts)
  const nodeById = new Map(layout.nodes.map((node) => [node.id, node]))

  const paths: MapPath[] = layout.paths.flatMap((path) => {
    const alert = alerts.find((item) => item.id === path.alertId)

    if (!alert) {
      return []
    }

    const status = pathStatus(alert, executions, approvals)
    // Past the stop point only once something actually stopped the attack there
    // (an approved block ran) or the alert is closed; a recommendation stops nothing
    const stopIndex =
      path.stoppedAt && (status === 'blocked' || status === 'closed')
        ? path.nodes.indexOf(path.stoppedAt)
        : -1

    return [
      {
        alert,
        status,
        statusLabel: alertResponseState(alert, executions, approvals),
        route: `${alert.sourceIp === NOT_RECORDED ? 'Local account' : alert.sourceIp} to ${alert.endpoint}`,
        nodeIds: path.nodes,
        edges: path.nodes.slice(1).map((toId, index) => ({
          from: nodeById.get(path.nodes[index])!,
          to: nodeById.get(toId)!,
          unreached: stopIndex !== -1 && index >= stopIndex,
        })),
      },
    ]
  })

  const nodes: MapNode[] = layout.nodes.map((node) => {
    const through = paths.filter((path) => path.nodeIds.includes(node.id))
    const status = through.reduce<PathStatus>(
      (worst, path) => (STATUS_RANK[path.status] > STATUS_RANK[worst] ? path.status : worst),
      'closed',
    )

    let health: EndpointHealth | undefined
    let caption = node.role
    let statusWord: string | undefined

    if (node.zone === 'Endpoints') {
      const isolated = through.some((path) => {
        const run = executionFor(path.alert, executions)
        return (
          path.status === 'contained' &&
          run?.action === 'Isolate Host' &&
          (run.target === node.id || run.target === node.label)
        )
      })
      health = through.some((path) => path.status === 'active')
        ? 'At risk'
        : isolated
          ? 'Isolated'
          : 'Healthy'
      caption = health
    } else if (through[0] && through[0].nodeIds[0] === node.id) {
      // Each path starts at its own source node, which shows the attack
      // and the path's status in words. The short attack name is the
      // part after " - " ("Brute Force - Password Spray" -> "Password
      // Spray"); the full name is in the node's accessible name.
      const attack = through[0].alert.attackType
      const short = attack.includes(' - ') ? attack.split(' - ').slice(1).join(' - ') : attack
      // Live alerts are named after the Wazuh rule, which can be a whole sentence
      caption = short.length > 28 ? `${short.slice(0, 27).trimEnd()}…` : short
      statusWord = through[0].statusLabel
    }

    return {
      ...node,
      caption,
      statusWord,
      health,
      status,
      alertIds: through.map((path) => path.alert.id),
    }
  }).sort((first, second) => ZONE_ORDER[first.zone] - ZONE_ORDER[second.zone] || first.y - second.y)

  const summary =
    `${paths.length} attack paths. ` +
    paths
      .map((path) => `${path.alert.id} ${path.alert.attackType}, ${path.route}: ${path.statusLabel.toLowerCase()}.`)
      .join(' ')

  return { paths, nodes, summary }
}
