import type { StatusDotProps } from '../types/uiTypes'

function StatusDot({ tone, label }: StatusDotProps) {
  return (
    <span className={`status-dot ${tone}`}>
      <span className="status-dot-mark" aria-hidden="true" />
      {label}
    </span>
  )
}

export default StatusDot
