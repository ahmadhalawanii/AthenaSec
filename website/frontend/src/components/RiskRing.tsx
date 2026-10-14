import { statusTone } from '../utils/statusTone'

type RiskRingProps = {
  score: number
  size?: number
}

// Drawn on a 40-unit box and scaled to `size`.
const RADIUS = 16
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function RiskRing({ score, size = 40 }: RiskRingProps) {
  const clamped = Math.min(100, Math.max(0, score))
  const filled = (clamped / 100) * CIRCUMFERENCE

  return (
    <svg
      className={`risk-ring ${statusTone(clamped)}`}
      width={size}
      height={size}
      viewBox="0 0 40 40"
      role="img"
      aria-label={`Risk ${clamped} of 100`}
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
      <text className="risk-ring-score" x="20" y="24.5" textAnchor="middle">
        {clamped}
      </text>
    </svg>
  )
}

export default RiskRing
