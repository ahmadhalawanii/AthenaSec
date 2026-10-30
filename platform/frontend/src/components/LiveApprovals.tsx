import { useCallback, useEffect, useState } from 'react'

import { friendlyTime } from '../api/adapters'
import type { ApiApproval, ApiApprovalAction } from '../api/apiTypes'
import { ApiError, api, apiList } from '../api/client'
import { useLiveData } from '../api/liveDataContext'
import { statusTone } from '../utils/statusTone'

import ResponsiveDetail from './ResponsiveDetail'
import Segmented from './Segmented'

/*
  Approvals in live mode: the backend's pending and decided requests
  (GET /api/v1/approvals), what each one asks for (GET .../action), and the
  decision (POST .../decision). Nothing runs until a person approves it.
*/

type QueueView = 'waiting' | 'decided'

const ACTION_NAMES: Record<string, string> = {
  block_ip: 'Block IP',
  lock_account: 'Lock account',
  capture_telemetry: 'Capture telemetry',
}

const STATUS_WORDS: Record<ApiApproval['status'], string> = {
  PENDING: 'Waiting',
  APPROVED: 'Approved',
  REJECTED: 'Rejected',
  EXPIRED: 'Timed out',
  CANCELLED: 'Cancelled',
}

function title(detail: ApiApprovalAction | undefined) {
  const action = detail?.proposed_action

  if (!action) {
    return 'Action details unavailable'
  }

  const name = ACTION_NAMES[action.action_type] ?? action.action_type
  const minutes = action.parameters.duration_minutes

  return `${name} ${action.target}${typeof minutes === 'number' ? ` for ${minutes} min` : ''}`
}

function timeLeft(expiresAt: string | null) {
  if (!expiresAt) {
    return 'no deadline'
  }

  const minutes = Math.round((new Date(expiresAt).getTime() - Date.now()) / 60000)

  return minutes > 0 ? `${minutes} min left to decide` : 'decision window closed'
}

function LiveApprovals() {
  const { refresh: refreshEverything } = useLiveData()
  const [approvals, setApprovals] = useState<ApiApproval[] | null>(null)
  const [details, setDetails] = useState<Record<string, ApiApprovalAction>>({})
  const [loadError, setLoadError] = useState('')
  const [view, setView] = useState<QueueView>('waiting')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  // Bumped after a decision to load the list again straight away
  const [reloadKey, setReloadKey] = useState(0)
  const reload = useCallback(() => setReloadKey((value) => value + 1), [])

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const items = await apiList<ApiApproval>('/approvals')
        const pairs = await Promise.all(
          items.slice(0, 50).map((item) =>
            api<ApiApprovalAction>(`/approvals/${encodeURIComponent(item.approval_id)}/action`)
              .then((detail) => [item.approval_id, detail] as const)
              .catch(() => null),
          ),
        )

        if (cancelled) {
          return
        }

        setApprovals(items)
        setDetails(Object.fromEntries(pairs.filter((pair) => pair !== null)))
        setLoadError('')
      } catch (error) {
        if (cancelled) {
          return
        }

        setApprovals([])
        setLoadError(error instanceof Error ? error.message : 'Could not load approval requests.')
      }
    }

    load()
    const timer = window.setInterval(load, 30000)

    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [reloadKey])

  const waiting = (approvals ?? []).filter((item) => item.status === 'PENDING')
  const decided = (approvals ?? []).filter((item) => item.status !== 'PENDING')
  const visible = view === 'waiting' ? waiting : decided
  const selected = visible.find((item) => item.approval_id === selectedId) ?? visible[0]
  const selectedDetail = selected ? details[selected.approval_id] : undefined

  function choose(id: string) {
    setSelectedId(id)
    setDetailOpen(true)
    setReason('')
    setMessage('')
  }

  async function decide(decision: 'APPROVED' | 'REJECTED') {
    if (!selected || busy) {
      return
    }

    if (!reason.trim()) {
      setMessage('Give a reason for your decision.')
      return
    }

    setBusy(true)

    try {
      await api<ApiApproval>(`/approvals/${encodeURIComponent(selected.approval_id)}/decision`, {
        method: 'POST',
        body: { decision, reason: reason.trim() },
      })
      setMessage(decision === 'APPROVED' ? 'Approved. The agent can now run the action.' : 'Rejected. Nothing will run.')
      setReason('')
      setView('decided')
      setSelectedId(selected.approval_id)
      reload()
      refreshEverything()
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setMessage('Someone already decided this request, or the action changed. The list has been refreshed.')
        reload()
      } else if (error instanceof ApiError && error.status === 403) {
        setMessage('Your account is not allowed to decide approval requests.')
      } else {
        setMessage(error instanceof Error ? error.message : 'The decision was not saved.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="page active" data-page="approvals" data-page-name="Approvals" data-search-page>
      <div className="headline">
        <div>
          <h1>Approvals</h1>
          <p className="sub" id="approvalsSummary">
            {approvals === null
              ? 'Loading requests…'
              : waiting.length === 0
                ? 'No request is waiting for a decision.'
                : `${waiting.length} ${waiting.length === 1 ? 'request is' : 'requests are'} waiting for a decision.`}{' '}
            Nothing runs until a person approves it.
          </p>
        </div>

        <Segmented
          label="Show requests"
          options={[
            { value: 'waiting', label: 'Needs decision', count: waiting.length },
            { value: 'decided', label: 'Decided', count: decided.length },
          ]}
          value={view}
          onChange={(next) => {
            setView(next)
            setSelectedId(null)
          }}
        />
      </div>

      {loadError && <p className="notice">{loadError}</p>}

      <div className="split-layout">
        <section className="card queue" aria-label="Approval requests">
          {visible.length === 0 ? (
            <div className="empty">
              <p>{view === 'waiting' ? 'No request is waiting.' : 'No request has been decided yet.'}</p>
            </div>
          ) : (
            <ul className="queue-list">
              {visible.map((approval) => {
                const word = STATUS_WORDS[approval.status]

                return (
                  <li key={approval.approval_id} className="approval-row">
                    <button
                      type="button"
                      className="queue-item"
                      aria-pressed={approval.approval_id === selected?.approval_id}
                      onClick={() => choose(approval.approval_id)}
                      data-record-id={approval.approval_id}
                    >
                      <span className="queue-text">
                        <span className="queue-title">
                          <span className="queue-name">{title(details[approval.approval_id])}</span>
                        </span>
                        <span className="queue-route mono">{approval.incident_id}</span>
                        <span className="queue-meta">
                          Requested {friendlyTime(approval.requested_at)} by {approval.requested_by}
                        </span>
                        <span className="queue-outcome">
                          {approval.status === 'PENDING'
                            ? timeLeft(approval.expires_at)
                            : `${word} ${friendlyTime(approval.decided_at)}${approval.decided_by ? ` by ${approval.decided_by}` : ''}`}
                        </span>
                      </span>
                      <span className={`queue-state path-status ${statusTone(word)}`}>{word}</span>
                    </button>
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
            <div className="workspace-head" data-workspace-id={selected.approval_id}>
              <div className="dash-path-meta">
                <span className="mono">{selected.approval_id}</span>
                <span className={`path-status ${statusTone(STATUS_WORDS[selected.status])}`}>
                  {STATUS_WORDS[selected.status]}
                </span>
              </div>
              <h2 className="workspace-title" id="approvalTitle">
                {title(selectedDetail)}
              </h2>
              <p className="dash-path-route mono">{selected.incident_id}</p>
            </div>

            <h3 className="workspace-subhead">Why the agent asked</h3>
            <ul className="evidence-list">
              {selectedDetail?.proposed_action && (
                <li>
                  <span className="evidence-tag response">Agent</span>
                  <span>{selectedDetail.proposed_action.reason}</span>
                </li>
              )}
              {selectedDetail?.policy_decision && (
                <li>
                  <span className="evidence-tag policy">Policy</span>
                  <span>{selectedDetail.policy_decision.reason}</span>
                </li>
              )}
              {selectedDetail?.proposed_action && (
                <li>
                  <span className="evidence-tag response">Undo</span>
                  <span>
                    {selectedDetail.proposed_action.reversible
                      ? 'Reversible: the action can be rolled back.'
                      : 'Not reversible.'}
                  </span>
                </li>
              )}
            </ul>

            {selected.status === 'PENDING' ? (
              <form
                className="approval-form"
                onSubmit={(event) => {
                  event.preventDefault()
                  decide('APPROVED')
                }}
                noValidate
              >
                <fieldset>
                  <legend className="workspace-subhead first">Your decision</legend>
                  <div className="approval-field">
                    <label className="form-label" htmlFor={`reason-${selected.approval_id}`}>
                      Reason (required)
                    </label>
                    <textarea
                      className="textarea-input"
                      id={`reason-${selected.approval_id}`}
                      name="reason"
                      autoComplete="off"
                      rows={3}
                      value={reason}
                      onChange={(event) => setReason(event.target.value)}
                      placeholder="Why this should or should not run…"
                    />
                  </div>
                  <div className="workspace-actions">
                    <button className="btn primary" type="submit" disabled={busy}>
                      Approve
                    </button>
                    <button className="btn" type="button" disabled={busy} onClick={() => decide('REJECTED')}>
                      Reject
                    </button>
                  </div>
                </fieldset>
                <p className="approval-message" role="status">
                  {message}
                </p>
              </form>
            ) : (
              <>
                <h3 className="workspace-subhead">Decision</h3>
                <p>
                  {STATUS_WORDS[selected.status]} {friendlyTime(selected.decided_at)}
                  {selected.decided_by ? ` by ${selected.decided_by}` : ''}.
                  {selected.decision_reason ? ` Reason: ${selected.decision_reason}` : ''}
                </p>
                {message && (
                  <p className="approval-message" role="status">
                    {message}
                  </p>
                )}
              </>
            )}
          </ResponsiveDetail>
        )}
      </div>
    </section>
  )
}

export default LiveApprovals
