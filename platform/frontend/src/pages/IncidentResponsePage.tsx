import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import ApprovalDetails from '../components/ApprovalDetails'
import RequestAgain from '../components/RequestAgain'
import ResponsiveDetail from '../components/ResponsiveDetail'
import TableScroll from '../components/TableScroll'
import Timeline from '../components/Timeline'
import { APPROVER_LABELS } from '../data/agentPolicyData'
import {
  approvalForRun,
  executionStages,
  executionTimeline,
  responseSummary,
} from '../data/statusSummary'
import { useSearchSelection } from '../hooks/useSearchSelection'
import { useSocState } from '../hooks/useSocState'
import type { ExecutionRecord } from '../types/incidentResponseTypes'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

const STAGE_NAMES = ['Detected', 'Scored', 'Policy matched', 'Approved', 'Executed']

const LEGEND = [
  { state: 'done', label: 'Done' },
  { state: 'analyst', label: 'Analyst: approved by an analyst' },
  { state: 'lead', label: 'SOC lead: approved by a SOC lead' },
  { state: 'failed', label: 'Failed' },
]

// "Isolate endpoint-12", "Block IP 203.0.113.45"
function runTitle(run: ExecutionRecord) {
  return run.action === 'Isolate Host' ? `Isolate ${run.target}` : `${run.action} ${run.target}`
}

function IncidentResponsePage() {
  // Shared state: what ran, and the approvals behind it
  const { executions, approvals, executionFacts, tokens, alerts } = useSocState()
  const [searchQuery, setSearchQuery] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Phones: the panel opens as a drawer only when a run is chosen
  const [detailOpen, setDetailOpen] = useState(false)

  const summary = responseSummary(executions, approvals)

  const visibleRuns = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return executions.filter((run) => {
      const decidedBy = approvalForRun(run, approvals)?.decidedBy
      const matchesSearch =
        normalizedQuery === '' ||
        [
          run.id,
          run.triggeringAlert,
          run.policy,
          run.action,
          run.target,
          decidedBy?.name ?? '',
          run.result,
        ].some((value) => value.toLowerCase().includes(normalizedQuery))

      const matchesAction = actionFilter === 'all' || run.action === actionFilter
      const matchesResult = resultFilter === 'all' || run.result === resultFilter

      return matchesSearch && matchesAction && matchesResult
    })
  }, [executions, approvals, searchQuery, actionFilter, resultFilter])

  // The chosen run, or else the first failed one, or else the first
  const selected =
    visibleRuns.find((run) => run.id === selectedId) ??
    visibleRuns.find((run) => run.result === 'Failed') ??
    visibleRuns[0] ??
    null

  const selectedApproval = selected ? approvalForRun(selected, approvals) : undefined

  function resetFilters() {
    setSearchQuery('')
    setActionFilter('all')
    setResultFilter('all')
  }

  function choose(runId: string) {
    setSelectedId(runId)
    setDetailOpen(true)
  }

  // Search and links from other pages: clear the filters, then select it
  useSearchSelection(
    executions.map((run) => run.id),
    setSelectedId,
    resetFilters,
  )

  const alertLink: SearchNavigationState | undefined = selected
    ? { highlight: selected.triggeringAlert }
    : undefined

  return (
    <section
      className="page active"
      data-page="incident"
      data-page-name="Incident Response"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Incident Response</h1>
          <p className="sub">
            Every action AthenaSec took, why it took it, and whether it worked.
            Records are read-only.
          </p>
        </div>
      </div>

      <section className="response-summary" aria-label="Response summary">
        <div data-figure="succeeded">
          <strong>
            {summary.succeeded} of {summary.total}
          </strong>
          <span>responses succeeded</span>
        </div>
        <div data-figure="fastest">
          <strong>{summary.fastest ? `${summary.fastest.minutes} min` : 'None'}</strong>
          <span>
            fastest containment
            {summary.fastest && (
              <>
                , <span className="mono">{summary.fastest.runId}</span>
              </>
            )}
          </span>
        </div>
        <div data-figure="approval">
          <strong>{summary.approvedByAnalyst + summary.approvedByLead}</strong>
          <span>
            approved by a person ({summary.approvedByLead} SOC lead, {summary.approvedByAnalyst} analyst),{' '}
            {summary.awaiting} awaiting approval
          </span>
        </div>
        <div data-figure="failed" className={summary.failed > 0 ? 'attention' : undefined}>
          <strong>{summary.failed}</strong>
          <span>{summary.failed > 0 ? 'failed and needs a person' : 'failed runs'}</span>
        </div>
      </section>

      <div className="toolbar">
        <input
          className="field-input"
          type="search"
          name="runSearch"
          autoComplete="off"
          aria-label="Search executions, alerts, policies, or targets"
          placeholder="Search runs, alerts, targets…"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />

        <select
          className="select-input"
          name="actionFilter"
          autoComplete="off"
          aria-label="Filter by action"
          value={actionFilter}
          onChange={(event) => setActionFilter(event.target.value)}
        >
          <option value="all">All Actions</option>
          <option value="Block IP">Block IP</option>
          <option value="Isolate Host">Isolate Host</option>
          <option value="Lock Account">Lock Account</option>
          <option value="Capture Telemetry">Capture Telemetry</option>
        </select>

        <select
          className="select-input"
          name="resultFilter"
          autoComplete="off"
          aria-label="Filter by result"
          value={resultFilter}
          onChange={(event) => setResultFilter(event.target.value)}
        >
          <option value="all">All Results</option>
          <option value="Completed">Completed</option>
          <option value="Failed">Failed</option>
        </select>

        <button className="btn" type="button" onClick={resetFilters}>
          Reset Filters
        </button>

        <span className="pill blue" role="status">
          {visibleRuns.length} visible
        </span>
      </div>

      <section className="card pipeline" aria-labelledby="pipelineTitle">
        <div className="pipeline-head">
          <h2 id="pipelineTitle">Response pipeline</h2>
          <p className="pipeline-hint">Each row is one run. Select one to see the reasoning.</p>
          <ul className="stage-legend" aria-label="Stage key">
            {LEGEND.map((item) => (
              <li key={item.state}>
                <span className={`stage-dot ${item.state}`} aria-hidden="true" />
                {item.label}
              </li>
            ))}
          </ul>
        </div>

        {visibleRuns.length === 0 ? (
          <div className="empty">
            <p>No response runs match the current search and filters.</p>
            <button className="btn primary" type="button" onClick={resetFilters}>
              Clear Filters
            </button>
          </div>
        ) : (
          <TableScroll label="Response pipeline">
            <div className="pipeline-grid">
              <div className="pipeline-columns" aria-hidden="true">
                <span>Run</span>
                {STAGE_NAMES.map((name) => (
                  <span key={name}>{name}</span>
                ))}
                <span className="pipeline-result-col">Result</span>
              </div>

              <ul className="pipeline-list">
                {visibleRuns.map((run) => (
                  <li key={run.id}>
                    <button
                      type="button"
                      className={`run-row${run.result === 'Failed' ? ' failed' : ''}`}
                      aria-pressed={run.id === selected?.id}
                      onClick={() => choose(run.id)}
                      data-record-id={run.id}
                    >
                      {/* The {' '} spaces keep the button's accessible name readable;
                          the grid doesn't render them */}
                      <span className="run-name">
                        <span className="run-title">{runTitle(run)}</span>{' '}
                        <span className="run-meta mono">
                          {run.id} for {run.triggeringAlert}
                        </span>
                      </span>{' '}

                      {executionStages(run, approvalForRun(run, approvals)).map((stage, index) => (
                        <span
                          key={stage.name}
                          className={`run-stage ${stage.state}`}
                          data-stage={stage.name}
                          data-state={stage.state}
                        >
                          <span className="visually-hidden">{stage.name}: </span>
                          <span className="stage-track" aria-hidden="true">
                            <span className={`stage-dot ${stage.state}`} />
                            {index < STAGE_NAMES.length - 1 && <span className="stage-line" />}
                          </span>
                          <span className="stage-label">{stage.label}</span>{' '}
                        </span>
                      ))}

                      <span className={`run-result path-status ${statusTone(run.result)}`}>
                        <span className="visually-hidden">Result: </span>
                        {run.result}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </TableScroll>
        )}
      </section>

      {selected && (
        <ResponsiveDetail
          open={detailOpen}
          onClose={() => setDetailOpen(false)}
          labelledBy="runPanelTitle"
          closeLabel="Close response details"
          className="run-panel"
        >
          <div className="workspace-head" data-workspace-id={selected.id}>
            <div className="dash-path-meta">
              <span className="mono">{selected.id}</span>
              <span className={`path-status ${statusTone(selected.result)}`}>
                {selected.result}
              </span>
            </div>
            <h2 className="workspace-title" id="runPanelTitle">
              {runTitle(selected)}
            </h2>
            <div className="workspace-actions">
              <Link className="btn ghost" to="/app/alerts" state={alertLink}>
                View {selected.triggeringAlert}
              </Link>
            </div>
          </div>

          <dl className="facts run-facts">
            <div>
              <dt>Triggering alert</dt>
              <dd className="mono" data-field="triggeringAlert">{selected.triggeringAlert}</dd>
            </div>
            <div>
              <dt>Action</dt>
              <dd data-field="action">{selected.action}</dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd className="mono" data-field="target">{selected.target}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd data-field="policy">{selected.policy}</dd>
            </div>
            <div>
              <dt>Approved by</dt>
              <dd data-field="approvedBy">
                {selectedApproval?.decidedBy
                  ? `${selectedApproval.decidedBy.name} (${APPROVER_LABELS[selectedApproval.decidedBy.role]})`
                  : selected.approvedByName
                    ? `${selected.approvedByName}${selected.approvedRole ? ` (${APPROVER_LABELS[selected.approvedRole]})` : ''}`
                    : 'Not on record'}
              </dd>
            </div>
            <div>
              <dt>Result</dt>
              <dd data-field="result">
                <span className={`pill ${statusTone(selected.result)}`}>{selected.result}</span>
              </dd>
            </div>
            <div>
              <dt>Start time</dt>
              <dd className="mono" data-field="startTime">{selected.startTime}</dd>
            </div>
            <div>
              <dt>End time</dt>
              <dd className="mono" data-field="endTime">{selected.endTime}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd data-field="duration">{selected.duration}</dd>
            </div>
            <div>
              <dt>Rollback status</dt>
              <dd data-field="rollbackStatus">{selected.rollbackStatus}</dd>
            </div>
            <div>
              <dt>Failure reason</dt>
              <dd data-field="failureReason">{selected.failureReason}</dd>
            </div>
          </dl>

          <RequestAgain
            run={selected}
            alertOpen={alerts.find((alert) => alert.id === selected.triggeringAlert)?.status === 'Open'}
          />

          {selectedApproval && (
            <section aria-label="Approval record">
              <h3 className="workspace-subhead">Approval record</h3>
              <ApprovalDetails
                approval={selectedApproval}
                token={tokens.find((token) => token.id === selectedApproval.tokenId)}
                facts={executionFacts.find((facts) => facts.approvalId === selectedApproval.id)}
                failed={selected.result === 'Failed'}
              />
            </section>
          )}

          <div className="run-columns">
            <section aria-label="Reasoning">
              <h3 className="workspace-subhead">What happened</h3>
              <p className="workspace-text" data-field="happened">{selected.happened}</p>
              <h3 className="workspace-subhead">Why it was malicious</h3>
              <p className="workspace-text" data-field="classified">{selected.classified}</p>
              <h3 className="workspace-subhead">Why AthenaSec acted</h3>
              <p className="workspace-text" data-field="responseReason">{selected.responseReason}</p>
            </section>

            <section aria-label="Evidence and timeline">
              <h3 className="workspace-subhead">Supporting evidence</h3>
              <ul className="evidence-list run-evidence" data-field="evidence">
                {selected.evidence.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
              <h3 className="workspace-subhead">Timeline</h3>
              <Timeline steps={executionTimeline(selected)} label={`${selected.id} timeline`} />
            </section>
          </div>
        </ResponsiveDetail>
      )}
    </section>
  )
}

export default IncidentResponsePage
