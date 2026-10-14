import { statusTone } from '../utils/statusTone'

type GaugeProps = {
  value: number
  // Names the gauge for screen readers ("CPU Usage 42%")
  label: string
  // The state word decides the colour (Good, Watch, Critical)
  state: string
  size?: number
}

// Same ring as RiskRing (a 40-unit box scaled to `size`), but it shows a percentage.
const RADIUS = 16
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function Gauge({ value, label, state, size = 58 }: GaugeProps) {
  const clamped = Math.min(100, Math.max(0, value))
  const filled = (clamped / 100) * CIRCUMFERENCE

  return (
    <svg
      className={`risk-ring gauge ${statusTone(state)}`}
      width={size}
      height={size}
      viewBox="0 0 40 40"
      role="img"
      aria-label={`${label} ${clamped}%`}
    >
      <circle className="risk-ring-track" cx="20" cy="20" r={RADIUS} />
      <circle
        className="risk-ring-arc"
        cx="20"
        cy="20"
        r={RADIUS}
        strokeDasharray={`${filled.toFixed(1)} ${CIRCUMFERENCE.toFixed(1)}`}
        transform="rotate(-90 20 20)"
      />
      <text
        className={`risk-ring-score${String(clamped).length > 3 ? ' decimal' : ''}`}
        x="20"
        y="23.5"
        textAnchor="middle"
      >
        {clamped}%
      </text>
    </svg>
  )
}

export default Gauge
