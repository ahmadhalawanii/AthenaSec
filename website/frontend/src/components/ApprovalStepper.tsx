// "Executing", not "Running": Running is a service's healthy state (green) elsewhere in the app
export type ApprovalStage = 'Approved' | 'Executing' | 'Done' | 'Failed' | 'Not run'

const STEPS = ['Approved', 'Executing', 'Done'] as const

type ApprovalStepperProps = {
  stage: ApprovalStage
}

/*
  The executor's three steps for an approved request. Each step is
  named in words with its state ("done", "now", "failed", "not yet"),
  so nothing depends on colour or on the pulse, which only plays when
  the person has not asked for reduced motion. A run that failed ends
  on its last step, shown as "Failed".
*/
function ApprovalStepper({ stage }: ApprovalStepperProps) {
  const index = stage === 'Failed' ? STEPS.length - 1 : STEPS.indexOf(stage as (typeof STEPS)[number])

  return (
    <ol className="approval-steps" aria-label="Execution steps" data-stage={stage}>
      {STEPS.map((name, position) => {
        const last = position === STEPS.length - 1
        const state =
          index === -1 || position > index
            ? 'todo'
            : stage === 'Failed' && last
              ? 'failed'
              : position < index || stage === 'Done'
                ? 'done'
                : 'current'

        return (
          <li
            key={name}
            className={`approval-step ${state}`}
            data-step={name}
            data-state={state}
            aria-current={state === 'current' ? 'step' : undefined}
          >
            <span className="approval-dot" aria-hidden="true" />
            <span className="approval-step-name">{stage === 'Failed' && last ? 'Failed' : name}</span>
            <span className="visually-hidden">
              : {state === 'done' ? 'done' : state === 'current' ? 'now' : state === 'failed' ? 'failed' : 'not yet'}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

export default ApprovalStepper
