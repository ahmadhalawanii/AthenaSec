import { useState } from 'react'

import { ADVANCE_STEPS } from '../data/approvalFlow'
import { useResponseState } from '../hooks/useResponseState'
import type { ConfirmModalContent } from '../types/confirmModalTypes'

import ConfirmModal from './ConfirmModal'

const RESET_CONFIRMATION: ConfirmModalContent = {
  title: 'Reset the demo?',
  message: 'Everything changed in this session goes back to the starting data: requests, runs, tokens and audit events.',
  confirmLabel: 'Reset demo',
  cancelLabel: 'Cancel',
  tone: 'danger',
}

/*
  Demo mode controls for the approval flow. They simulate what the live
  system does on its own (time passing, an executor failing) so a
  presenter can show a timeout, a lapse, a failure and a new request.
  Each use is written to the audit log as a Demo event, and none of
  them reads the real clock: demo time moves only in these fixed steps.
*/
function DemoModePanel() {
  const { now, failNext, advance, armFailure, resetDemo } = useResponseState()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [message, setMessage] = useState('')

  function run(outcome: { ok: true } | { ok: false; reason: string }) {
    setMessage(outcome.ok ? '' : outcome.reason)
  }

  return (
    <section className="demo-panel approval-demo" aria-labelledby="approvalDemoTitle" data-demo-panel>
      <div className="demo-head">
        <h2 className="demo-badge" id="approvalDemoTitle">
          Demo mode
        </h2>
        <span>
          These controls simulate what the live system does on its own. Each use is written to the audit log as
          a Demo event, and none of them reads the real clock.
        </span>
      </div>

      <div className="approval-demo-grid">
        <div className="approval-demo-group">
          <p className="approval-demo-label">
            Demo time <span className="mono" data-field="demoNow">{now.slice(11)}</span>
          </p>
          <div className="approval-demo-buttons">
            {ADVANCE_STEPS.map((minutes) => (
              <button key={minutes} className="btn small" type="button" onClick={() => run(advance(minutes))}>
                Advance {minutes === 60 ? '1 h' : `${minutes} min`}
              </button>
            ))}
          </div>
          <p className="approval-hint">A request past its deadline times out; a block or isolation past its time lapses.</p>
        </div>

        <div className="approval-demo-group">
          <p className="approval-demo-label">Executor</p>
          <div className="approval-demo-buttons">
            <button className="btn small" type="button" disabled={failNext} onClick={() => run(armFailure())}>
              {failNext ? 'Failure armed' : 'Make the next execution fail'}
            </button>
          </div>
          <p className="approval-hint" data-field="armState">
            {failNext
              ? 'The next approved action will fail after using up its token.'
              : 'The next approved action will succeed.'}
          </p>
        </div>

        <div className="approval-demo-group">
          <p className="approval-demo-label">Start again</p>
          <div className="approval-demo-buttons">
            <button className="btn small" type="button" onClick={() => setConfirmOpen(true)}>
              Reset demo
            </button>
          </div>
          <p className="approval-hint">Back to the starting data.</p>
        </div>
      </div>

      <p className="approval-message" role="status" data-field="demoMessage">
        {message}
      </p>

      <ConfirmModal
        open={confirmOpen}
        {...RESET_CONFIRMATION}
        onCancel={() => setConfirmOpen(false)}
        onConfirm={() => {
          setConfirmOpen(false)
          resetDemo()
        }}
      />
    </section>
  )
}

export default DemoModePanel
