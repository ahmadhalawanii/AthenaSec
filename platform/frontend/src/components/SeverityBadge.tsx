import { statusTone } from '../utils/statusTone'

type SeverityBadgeProps = {
  severity: string
}

function SeverityBadge({ severity }: SeverityBadgeProps) {
  return <span className={`pill ${statusTone(severity)}`}>{severity}</span>
}

export default SeverityBadge
