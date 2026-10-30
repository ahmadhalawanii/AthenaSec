import { useState } from 'react'

import { useResponseState } from '../hooks/useResponseState'
import type { ExecutionRecord } from '../types/incidentResponseTypes'

type RequestAgainProps = {
  run: ExecutionRecord
  // The alert the run belongs to is still open
  alertOpen: boolean
}

/*
  Asks for a failed or lapsed action again. An analyst asks; the new
  request has a new id and needs a new decision and a new token, and
  the person who asked cannot decide it. Nothing is shown for a run
  that neither failed nor lapsed, or to anyone but an analyst.
*/
function RequestAgain({ run, alertOpen }: RequestAgainProps) {
  const { actor, requestAgain, requestAgainRefusal } = useResponseState()
  const [message, setMessage] = useState('')

  if (actor?.role !== 'soc_analyst' || (run.result !== 'Failed' && !run.reversedAt)) {
    return null
  }

  const refusal = requestAgainRefusal(run, alertOpen)

  return (
    <div className="approval-again" data-field="requestAgain">
      <button
        className="btn primary"
        type="button"
        disabled={Boolean(refusal)}
        onClick={() => {
          const outcome = requestAgain(run.id, alertOpen)

          setMessage(
            outcome.ok
              ? 'Asked again. The new request is waiting in Approvals; you cannot decide on it yourself.'
              : outcome.reason,
          )
        }}
      >
        Request again
      </button>

      {refusal && (
        <p className="approval-hint" data-field="requestAgainReason">
          {refusal}
        </p>
      )}

      {message && (
        <p className="approval-hint" role="status" data-field="requestAgainMessage">
          {message}
        </p>
      )}
    </div>
  )
}

export default RequestAgain
