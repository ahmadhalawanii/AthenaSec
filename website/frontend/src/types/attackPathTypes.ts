// Columns of the attack path map, left to right
export type PathZone = 'Internet' | 'Perimeter' | 'Internal' | 'Endpoints'

export type PathNode = {
  id: string
  label: string
  // What the node is, e.g. "Perimeter", "VPN", "Internal host"
  role: string
  zone: PathZone
  // Position on the map's 1000 x 360 grid
  x: number
  y: number
}

export type AttackPath = {
  alertId: string
  // Node ids from source to target
  nodes: string[]
  // Where the attack was stopped, if a block stopped it partway
  stoppedAt?: string
}

// A path's status, derived from its alert's response state
export type PathStatus = 'active' | 'blocked' | 'contained' | 'closed'

export type EndpointHealth = 'At risk' | 'Isolated' | 'Healthy'
