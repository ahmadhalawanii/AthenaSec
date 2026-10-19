import type { AttackMap, MapNode } from '../data/attackPathData'
import { PATH_ZONES } from '../data/attackPathData'

type AttackPathMapProps = {
  map: AttackMap
  selectedId: string
  onSelect: (alertId: string) => void
  // id of the text that lists every path and its status
  describedBy: string
}

// Map grid (1000 x 360) to percentages for the HTML layer
const pctX = (x: number) => `${(1000 - x) / 10}%`
const pctY = (y: number) => `${y / 3.6}%`

function nodeLabel(node: MapNode, states: Map<string, string>) {
  const paths = node.alertIds
    .map((id) => `${id} ${states.get(id)?.toLowerCase() ?? ''}`)
    .join('; ')
  return `${node.label}, ${node.caption}, ${paths}`
}

/*
  The attack path map. Status never relies on colour: each line style
  has its own dash pattern, every path's source node shows the path's
  status in words, and endpoints show their health. Every node is a
  real button (in zone order, top to bottom) whose name says which
  paths run through it and their status, and the map points at a text
  summary of all paths.
*/
function AttackPathMap({ map, selectedId, onSelect, describedBy }: AttackPathMapProps) {
  const states = new Map(map.paths.map((path) => [path.alert.id, path.statusLabel]))

  function pick(node: MapNode) {
    // A shared node (the firewall) cycles through the paths it carries
    const current = node.alertIds.indexOf(selectedId)
    onSelect(node.alertIds[(current + 1) % node.alertIds.length] ?? selectedId)
  }

  return (
    <div className="path-map" role="group" aria-label="Attack path map" aria-describedby={describedBy}>
      <div className="path-zones" aria-hidden="true">
        {[...PATH_ZONES].reverse().map((zone) => (
          <span key={zone}>{zone}</span>
        ))}
      </div>

      <div className="path-canvas">
        <svg
          className="path-lines"
          viewBox="0 0 1000 360"
          preserveAspectRatio="none"
          aria-hidden="true"
          focusable="false"
        >
          {map.paths.map((path) =>
            path.edges.map((edge) => (
              <line
                key={`${path.alert.id}-${edge.from.id}-${edge.to.id}`}
                className={[
                  'path-edge',
                  path.status,
                  edge.unreached ? 'unreached' : '',
                  path.alert.id === selectedId ? 'selected' : 'dimmed',
                ].join(' ')}
                x1={1000 - edge.from.x}
                y1={edge.from.y}
                x2={1000 - edge.to.x}
                y2={edge.to.y}
              />
            )),
          )}
        </svg>

        {[...map.nodes]
          .sort((a, b) =>
            PATH_ZONES.indexOf(b.zone) - PATH_ZONES.indexOf(a.zone) || a.y - b.y,
          )
          .map((node) => {
          const selected = node.alertIds.includes(selectedId)
          return (
            <button
              key={node.id}
              type="button"
              className={[
                'path-node',
                node.status,
                node.health === 'Isolated' ? 'isolated' : '',
                selected ? 'selected' : '',
              ].join(' ')}
              style={{ left: pctX(node.x), top: pctY(node.y) }}
              aria-pressed={selected}
              aria-label={nodeLabel(node, states)}
              onClick={() => pick(node)}
              data-node-id={node.id}
              data-zone={node.zone}
            >
              <span className="path-node-dot" aria-hidden="true" />
              <span className="path-node-text">
                <span className="path-node-label">{node.label}</span>
                <span className="path-node-caption">{node.caption}</span>
                {node.statusWord && (
                  <span className="path-node-status">{node.statusWord}</span>
                )}
              </span>
            </button>
          )
        })}
      </div>

      <ul className="path-legend" aria-label="Legend">
        <li>
          <svg width="22" height="6" aria-hidden="true">
            <line className="path-edge active" x1="0" y1="3" x2="22" y2="3" />
          </svg>
          Active, not blocked or contained yet
        </li>
        <li>
          <svg width="22" height="6" aria-hidden="true">
            <line className="path-edge blocked" x1="0" y1="3" x2="22" y2="3" />
          </svg>
          Blocked or contained
        </li>
        <li>
          <svg width="22" height="6" aria-hidden="true">
            <line className="path-edge closed" x1="0" y1="3" x2="22" y2="3" />
          </svg>
          Closed
        </li>
        <li>
          <span className="legend-isolated" aria-hidden="true" />
          Isolated host
        </li>
      </ul>
    </div>
  )
}

export default AttackPathMap
