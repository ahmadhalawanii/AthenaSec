import type { TimelineStep, TimelineStepState } from '../types/uiTypes'

type TimelineProps = {
  steps: TimelineStep[]
  label?: string
}

// Colour alone doesn't say a step failed or is still running.
const STATE_TEXT: Record<TimelineStepState, string | null> = {
  done: null,
  fail: 'Failed:',
  active: 'In progress:',
}

function Timeline({ steps, label }: TimelineProps) {
  return (
    <ol className="step-timeline" aria-label={label}>
      {steps.map((step, index) => (
        <li
          key={`${step.time}-${index}`}
          className={`step-timeline-item ${step.state}`}
        >
          <span className="step-timeline-rail" aria-hidden="true">
            <span className="step-timeline-dot" />
            <span className="step-timeline-line" />
          </span>
          <span className="step-timeline-time">{step.time}</span>
          <span className="step-timeline-label">
            {STATE_TEXT[step.state] && (
              <span className="visually-hidden">{STATE_TEXT[step.state]} </span>
            )}
            {step.label}
          </span>
        </li>
      ))}
    </ol>
  )
}

export default Timeline
