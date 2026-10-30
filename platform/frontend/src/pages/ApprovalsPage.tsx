import { useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import ApprovalDetails from '../components/ApprovalDetails'
import ApprovalStepper, { type ApprovalStage } from '../components/ApprovalStepper'
import DemoModePanel from '../components/DemoModePanel'
import RequestAgain from '../components/RequestAgain'
import ResponsiveDetail from '../components/ResponsiveDetail'
import RiskAssessment from '../components/RiskAssessment'
import RiskRing from '../components/RiskRing'
import Segmented from '../components/Segmented'
import { APPROVER_LABELS, ROLE_RANK } from '../data/agentPolicyData'
import { alertEvidence } from '../data/alertDetailsData'
import { approvalActionTitle } from '../data/approvalFlow'
import { clockOf, windowState } from '../data/policyEngine'
import { useAssessments } from '../hooks/useAssessments'
import { useResponseState } from '../hooks/useResponseState'
import { useSearchSelection } from '../hooks/useSearchSelection'
import { useSocState } from '../hooks/useSocState'
import type { ApprovalRecord } from '../types/approvalTypes'
import type { DecisionRequest } from '../types/responseStateTypes'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

type QueueView = 'waiting' | 'decided'

const linkState = (id: string): SearchNavigationState => ({ highlight: id })

const minutesOf = (approval: ApprovalRecord) => Number(approval.recommendation.action.params.duration_min)

type DecisionFormProps = {
  approval: ApprovalRecord
  refusal: string | null
  onDecide: (request: DecisionRequest) => Promise<{ ok: true } | { ok: false; reason: string }>
  onDecided: (approval: ApprovalRecord) => void
}

// Approve, shorten the duration, or reject: each needs a reason
function DecisionForm({ approval, refusal, onDecide, onDecided }: DecisionFormProps) {
  const recommended = minutesOf(approval)
  const [kind, setKind] = useState<DecisionRequest['kind']>('approve')
  const [reason, setReason] = useState('')
  const [minutes, setMinutes] = useState(String(Math.max(1, recommended - 1)))
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)

    const outcome = await onDecide({
      approvalId: approval.id,
      kind,
      reason,
      minutes: kind === 'modify' ? Number(minutes) : undefined,
    })

    setBusy(false)

    if (outcome.ok) {
      setMessage('')
      onDecided(approval)
      return
    }

    setMessage(outcome.reason)
  }

  const label =
    kind === 'approve' ? 'Approve request' : kind === 'modify' ? 'Approve with a shorter duration' : 'Reject request'

  return (
    <form className="approval-form" data-field="decisionForm" onSubmit={submit} noValidate>
      <fieldset disabled={Boolean(refusal) || busy}>
        <legend className="workspace-subhead first">Your decision</legend>

        <div className="approval-choices" role="radiogroup" aria-label="Decision">
          {(
            [
              ['approve', 'Approve'],
              ['modify', 'Shorten the duration'],
              ['reject', 'Reject'],
            ] as const
          ).map(([value, text]) => (
            <label key={value} className="approval-choice">
              <input
                type="radio"
                name={`decision-${approval.id}`}
                value={value}
                checked={kind === value}
                onChange={() => {
                  setKind(value)
                  setMessage('')
                }}
              />
              <span>{text}</span>
            </label>
          ))}
        </div>

        {kind === 'modify' && (
          <div className="approval-field">
            <label className="form-label" htmlFor={`minutes-${approval.id}`}>
              Duration in minutes
            </label>
            <input
              className="field-input"
              id={`minutes-${approval.id}`}
              name="minutes"
              autoComplete="off"
              type="number"
              inputMode="numeric"
              min={1}
              max={Math.max(1, recommended - 1)}
              step={1}
              value={minutes}
              onChange={(event) => setMinutes(event.target.value)}
              aria-describedby={`minutes-hint-${approval.id}`}
            />
            <p className="approval-hint" id={`minutes-hint-${approval.id}`}>
              The agent recommended {recommended} min. A duration can only be shortened, never extended, and
              the action and its target stay as recommended.
            </p>
          </div>
        )}

        <div className="approval-field">
          <label className="form-label" htmlFor={`reason-${approval.id}`}>
            Reason (required)
          </label>
          <textarea
            className="textarea-input"
            id={`reason-${approval.id}`}
            name="reason"
            autoComplete="off"
            rows={3}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={kind === 'reject' ? 'Why this should not run…' : 'Why this should run…'}
          />
        </div>

        <button className={kind === 'reject' ? 'btn' : 'btn primary'} type="submit">
          {label}
        </button>
      </fieldset>

      {refusal && (
        <p className="notice approval-refusal" data-field="refusal">
          {refusal}
        </p>
      )}

      <p className="approval-message" role="status" data-field="decisionMessage">
        {message}
      </p>
    </form>
  )
}

function ApprovalsPage() {
  const { approvals, tokens, facts, runs, running, refusals, now, actor, refusalFor, decide, announcement } =
    useResponseState()
  const { alerts } = useSocState()
  // Risk breakdown per alert, from the policy formula
  const assessments = useAssessments()

  const [view, setView] = useState<QueueView>('waiting')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Phones: the detail opens as a drawer only when a request is chosen
  const [detailOpen, setDetailOpen] = useState(false)

  const isLead = actor?.role === 'soc_lead'
  const rank = actor ? ROLE_RANK[actor.role] : 0
  // This person's role is high enough and they did not ask for it themselves
  const canDecide = (approval: ApprovalRecord) =>
    rank >= ROLE_RANK[approval.requiredRole] && approval.recommendation.requestedBy !== actor?.id

  const waiting = approvals.filter((approval) => approval.decision === 'Pending')
  const decided = useMemo(
    () =>
      approvals
        .filter((approval) => approval.decision !== 'Pending')
        .sort((a, b) => (b.decidedAt ?? b.recommendation.createdAt).localeCompare(a.decidedAt ?? a.recommendation.createdAt)),
    [approvals],
  )
  const waitingForYou = waiting.filter(canDecide).length
  const waitingForOthers = waiting.length - waitingForYou

  const views = [
    { value: 'waiting' as const, label: 'Waiting', count: waiting.length },
    { value: 'decided' as const, label: 'Decided', count: decided.length },
  ]

  const visible = view === 'waiting' ? waiting : decided
  const selected = visible.find((approval) => approval.id === selectedId) ?? visible[0] ?? null

  // The step an approved request is at: approved, running, done (or not run, if the guard refused it)
  function stageOf(approval: ApprovalRecord): ApprovalStage {
    if (refusals[approval.id]) {
      return 'Not run'
    }

    if (running.includes(approval.id)) {
      return 'Executing'
    }

    const run = runs.find((item) => item.approvalId === approval.id)

    if (!run) {
      return 'Approved'
    }

    return run.result === 'Failed' ? 'Failed' : 'Done'
  }

  // The word on a row: waiting, then the executor's step ("Reversed" once a block or isolation lapsed),
  // or how it was decided
  function stateWord(approval: ApprovalRecord) {
    if (approval.decision === 'Pending') {
      return 'Waiting'
    }

    if (approval.decision !== 'Approved') {
      return approval.decision
    }

    return runs.find((run) => run.approvalId === approval.id)?.reversedAt ? 'Reversed' : stageOf(approval)
  }

  const alertFor = (approval: ApprovalRecord) => alerts.find((alert) => alert.id === approval.recommendation.alertId)

  useSearchSelection(
    approvals.map((approval) => approval.id),
    setSelectedId,
    (id) => setView(approvals.find((approval) => approval.id === id)?.decision === 'Pending' ? 'waiting' : 'decided'),
  )

  function choose(id: string) {
    setSelectedId(id)
    setDetailOpen(true)
  }

  // After a decision the request moves to Decided; keep it selected so the steps are in view
  function afterDecision(approval: ApprovalRecord) {
    setView('decided')
    setSelectedId(approval.id)
  }

  const executorBusy =
    running.length > 0 ||
    approvals.some((approval) => approval.decision === 'Approved' && !approval.executionId && !refusals[approval.id])
  const selectedRun = selected ? runs.find((run) => run.approvalId === selected.id) : undefined
  const selectedAlert = selected ? alertFor(selected) : undefined

  return (
    <section
      className="page active"
      data-page="approvals"
      data-page-name="Approvals"
      data-search-page
      // "busy" while an approved request has not finished running (a run in progress, or approved and not started)
      data-executor={executorBusy ? 'busy' : 'idle'}
    >
      <div className="headline">
        <div>
          <h1>Approvals</h1>
          <p className="sub" id="approvalsSummary">
            {waiting.length === 0
              ? 'No request is waiting for a decision.'
              : `${waitingForYou} ${waitingForYou === 1 ? 'request is' : 'requests are'} waiting for you${
                  waitingForOthers > 0 ? `, ${waitingForOthers} for someone else` : ''
                }.`}{' '}
            Nothing runs until a person approves it.
          </p>
        </div>

        <Segmented label="Show requests" options={views} value={view} onChange={setView} />
      </div>

      <p className="visually-hidden" role="status" id="approvalsAnnouncement">
        {announcement}
      </p>

      <div className="split-layout">
        <section className="card queue" aria-label="Approval requests">
          {visible.length === 0 ? (
            <div className="empty">
              <p>{view === 'waiting' ? 'No request is waiting.' : 'No request has been decided yet.'}</p>
            </div>
          ) : (
            <ul className="queue-list">
              {visible.map((approval) => {
                const { recommendation } = approval
                const alert = alertFor(approval)
                const word = stateWord(approval)

                return (
                  <li key={approval.id} className="approval-row">
                    <button
                      type="button"
                      className="queue-item"
                      aria-pressed={approval.id === selected?.id}
                      onClick={() => choose(approval.id)}
                      data-record-id={approval.id}
                    >
                      <RiskRing score={recommendation.riskScore} />
                      <span className="queue-text">
                        <span className="queue-title">
                          <span className="queue-name">
                            {approvalActionTitle(approval)} for {minutesOf(approval)} min
                          </span>
                        </span>
                        <span className="queue-route mono">
                          <span className="nowrap">{recommendation.alertId}</span>
                          {alert ? ` · ${alert.attackType}` : ''}
                        </span>
                        <span className="queue-meta">
                          Response policy version {approval.policy.version} ·
                          needs a {APPROVER_LABELS[approval.requiredRole]}
                        </span>
                        <span className="queue-outcome" data-field="outcome">
                          Risk {recommendation.riskScore}, confidence {recommendation.confidence.toFixed(2)} ·{' '}
                          {approval.decision === 'Pending'
                            ? windowState(recommendation.approvalDeadline, now).label
                            : `decided ${clockOf(approval.decidedAt ?? recommendation.createdAt)}`}
                        </span>
                      </span>
                      <span className={`queue-state path-status ${statusTone(word)}`}>{word}</span>
                    </button>

                    {!isLead && (
                      <Link
                        className="text-link approval-alert-link"
                        to="/app/alerts"
                        state={linkState(recommendation.alertId)}
                      >
                        Open {recommendation.alertId}
                      </Link>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        {selected && (
          <ResponsiveDetail
            open={detailOpen}
            onClose={() => setDetailOpen(false)}
            labelledBy="approvalTitle"
            closeLabel="Close request details"
            className="workspace"
          >
            <div className="workspace-head" data-workspace-id={selected.id}>
              <div className="dash-path-meta">
                <span className="mono">{selected.id}</span>
                <span className={`path-status ${statusTone(stateWord(selected))}`}>{stateWord(selected)}</span>
              </div>
              <h2 className="workspace-title" id="approvalTitle">
                {approvalActionTitle(selected)} for {minutesOf(selected)} min
              </h2>
              <p className="dash-path-route mono">
                {selected.recommendation.alertId}
                {selectedAlert ? ` · ${selectedAlert.attackType} · ${selectedAlert.endpoint}` : ''}
              </p>

              {!isLead && (
                <div className="workspace-actions">
                  <Link className="btn ghost" to="/app/alerts" state={linkState(selected.recommendation.alertId)}>
                    Open {selected.recommendation.alertId}
                  </Link>
                  {selectedRun && (
                    <Link className="btn ghost" to="/app/incident" state={linkState(selectedRun.id)}>
                      View {selectedRun.id}
                    </Link>
                  )}
                </div>
              )}
            </div>

            {selected.decision === 'Approved' && (
              <section aria-label="Execution">
                <h3 className="workspace-subhead">Execution</h3>
                <ApprovalStepper stage={stageOf(selected)} />
                {refusals[selected.id] && (
                  <p className="notice approval-refusal" data-field="executionRefusal">
                    The action did not run: {refusals[selected.id]}
                  </p>
                )}
              </section>
            )}

            <h3 className="workspace-subhead">Request</h3>
            <ApprovalDetails
              approval={selected}
              token={tokens.find((token) => token.id === selected.tokenId)}
              facts={facts.find((item) => item.approvalId === selected.id)}
              failed={selectedRun?.result === 'Failed'}
            />

            {selected.decision === 'Pending' && (
              <DecisionForm
                key={selected.id}
                approval={selected}
                refusal={refusalFor(selected)}
                onDecide={decide}
                onDecided={afterDecision}
              />
            )}

            {selectedRun && (selectedRun.result === 'Failed' || selectedRun.reversedAt) && (
              <RequestAgain run={selectedRun} alertOpen={selectedAlert?.status === 'Open'} />
            )}

            {/* Why, for a person who has no Alerts page: the key evidence, then the risk breakdown */}
            <section aria-label="Why it was recommended" data-field="why">
              <h3 className="workspace-subhead">Key evidence</h3>
              <ul className="evidence-list" data-field="keyEvidence">
                {(alertEvidence[selected.recommendation.alertId] ?? []).map((item) => (
                  <li key={item.text}>
                    <span className={`evidence-tag ${item.source.toLowerCase()}`}>{item.source}</span>
                    <span>{item.text}</span>
                  </li>
                ))}
              </ul>

              {assessments[selected.recommendation.alertId] && (
                <RiskAssessment assessment={assessments[selected.recommendation.alertId]} />
              )}
            </section>
          </ResponsiveDetail>
        )}
      </div>

      <DemoModePanel />
    </section>
  )
}

export default ApprovalsPage
