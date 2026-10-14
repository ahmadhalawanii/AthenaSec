import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import ResponsiveDetail from '../components/ResponsiveDetail'
import SeverityBadge from '../components/SeverityBadge'
import Timeline from '../components/Timeline'
import { OUTCOME_LABELS } from '../data/agentPolicyData'
import { caseTimeline } from '../data/statusSummary'
import { useAssessments } from '../hooks/useAssessments'
import { useSearchSelection } from '../hooks/useSearchSelection'
import { useSocState } from '../hooks/useSocState'
import type { CaseRecord } from '../types/casesTypes'
import type { SearchNavigationState } from '../types/searchTypes'
import type { CaseActionState } from '../types/socTypes'
import { statusTone } from '../utils/statusTone'

const linkState = (id: string): SearchNavigationState => ({ highlight: id })

// Board columns, in reading order
const COLUMNS = [
  { status: 'Open' as const, label: 'Investigating' },
  { status: 'Closed' as const, label: 'Closed' },
]

const doneCount = (actions: CaseActionState[]) =>
  actions.filter((action) => action.done).length

function CasesPage() {
  // Shared with the sidebar badge, search, dashboard and Alerts page
  const { cases, caseActions, caseEvents, toggleCaseStatus, toggleCaseAction } = useSocState()
  const assessments = useAssessments()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Phones: the detail opens as a drawer only when a case is chosen
  const [detailOpen, setDetailOpen] = useState(false)

  const visibleCases = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return cases.filter((caseItem) => {
      const matchesSearch =
        normalizedQuery === '' ||
        [
          caseItem.id,
          caseItem.sourceAlert,
          caseItem.assignedAnalyst,
          caseItem.attackType,
          caseItem.endpoint,
          caseItem.sourceIp,
        ].some((value) => value.toLowerCase().includes(normalizedQuery))

      const matchesSeverity =
        severityFilter === 'all' || caseItem.severity === severityFilter

      const matchesStatus =
        statusFilter === 'all' || caseItem.status === statusFilter

      return matchesSearch && matchesSeverity && matchesStatus
    })
  }, [cases, searchQuery, severityFilter, statusFilter])

  // Reading order: the Investigating column, then Closed
  const columns = COLUMNS.map((column) => ({
    ...column,
    cases: visibleCases.filter((caseItem) => caseItem.status === column.status),
  }))
  const ordered = columns.flatMap((column) => column.cases)

  const selected = ordered.find((caseItem) => caseItem.id === selectedId) ?? ordered[0] ?? null

  const openTotal = cases.filter((caseItem) => caseItem.status === 'Open').length
  const closedTotal = cases.length - openTotal

  function resetFilters() {
    setSearchQuery('')
    setSeverityFilter('all')
    setStatusFilter('all')
  }

  function choose(caseId: string) {
    setSelectedId(caseId)
    setDetailOpen(true)
  }

  // Search and links from Alerts: clear the filters, then select the case
  useSearchSelection(cases.map((caseItem) => caseItem.id), setSelectedId, resetFilters)

  const selectedActions = selected ? caseActions[selected.id] ?? [] : []

  return (
    <section className="page active" data-page="cases" data-page-name="Case Management" data-search-page>
      <div className="headline">
        <div>
          <h1>Case Management</h1>
          <p className="sub">
            Investigations opened from validated alerts. {openTotal} in progress, {closedTotal} closed.
          </p>
        </div>
      </div>

      <div className="toolbar">
        <input
          className="field-input"
          id="casesearch"
          name="caseSearch"
          autoComplete="off"
          type="search"
          aria-label="Search cases"
          placeholder="Search cases…"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />

        <select
          className="select-input"
          id="caseseverity"
          name="severityFilter"
          autoComplete="off"
          aria-label="Filter by severity"
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
        </select>

        <select
          className="select-input"
          id="casestatus"
          name="statusFilter"
          autoComplete="off"
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
        >
          <option value="all">All Statuses</option>
          <option value="Open">Open</option>
          <option value="Closed">Closed</option>
        </select>

        <button className="btn" type="button" onClick={resetFilters}>
          Reset Filters
        </button>

        <span className="pill blue" id="visibleCaseCount" role="status">
          {visibleCases.length} visible
        </span>
      </div>

      <div className="split-layout">
        <div className="board" aria-label="Case board">
          {columns.map((column) => (
            <section
              key={column.status}
              className="board-column"
              aria-labelledby={`column-${column.status}`}
              data-column={column.label}
            >
              <h2 className="board-column-title" id={`column-${column.status}`}>
                {column.label} <span className="board-count">{column.cases.length}</span>
              </h2>

              {column.cases.length === 0 ? (
                <p className="board-empty">No matching cases</p>
              ) : (
                <ul className="board-list">
                  {column.cases.map((caseItem) => (
                    <li key={caseItem.id}>
                      <CaseCard
                        caseItem={caseItem}
                        actions={caseActions[caseItem.id] ?? []}
                        selected={caseItem.id === selected?.id}
                        onChoose={() => choose(caseItem.id)}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </div>

        {selected && (
          <ResponsiveDetail
            open={detailOpen}
            onClose={() => setDetailOpen(false)}
            labelledBy="caseDetailTitle"
            closeLabel="Close case details"
            className="case-detail"
          >
            <div className="workspace-head" data-case-id={selected.id}>
              <p className="case-origin">
                <span className="mono">{selected.id}</span> from{' '}
                <Link className="mono text-inline-link" to="/app/alerts" state={linkState(selected.sourceAlert)}>
                  {selected.sourceAlert}
                </Link>
              </p>
              <h2 className="workspace-title" id="caseDetailTitle">
                {selected.attackType}
              </h2>
              <p className="workspace-text">{selected.summary}</p>
              <div className="workspace-actions">
                <button
                  className={selected.status === 'Open' ? 'btn primary' : 'btn'}
                  type="button"
                  onClick={() => toggleCaseStatus(selected.id)}
                >
                  {selected.status === 'Open' ? 'Close case' : 'Reopen case'}
                </button>
              </div>
            </div>

            <dl className="facts case-facts">
              <div>
                <dt>Status</dt>
                <dd data-field="status">
                  <span className={`pill ${statusTone(selected.status)}`}>{selected.status}</span>
                </dd>
              </div>
              <div>
                <dt>Assigned analyst</dt>
                <dd data-field="assignedAnalyst">{selected.assignedAnalyst}</dd>
              </div>
              <div>
                <dt>Source alert</dt>
                <dd className="mono" data-field="sourceAlert">{selected.sourceAlert}</dd>
              </div>
              <div>
                <dt>Severity</dt>
                <dd data-field="severity">
                  <SeverityBadge severity={selected.severity} />
                </dd>
              </div>
              <div>
                <dt>Endpoint</dt>
                <dd className="mono" data-field="endpoint">{selected.endpoint}</dd>
              </div>
              <div>
                <dt>Source IP</dt>
                <dd className="mono" data-field="sourceIp">{selected.sourceIp}</dd>
              </div>
              <div>
                <dt>Risk score</dt>
                <dd data-field="riskScore">{selected.riskScore} / 100</dd>
              </div>
              <div>
                <dt>Agent outcome</dt>
                <dd data-field="outcome">
                  {assessments[selected.sourceAlert]
                    ? OUTCOME_LABELS[assessments[selected.sourceAlert].outcome]
                    : 'Not assessed'}
                </dd>
              </div>
              <div>
                <dt>MITRE ATT&amp;CK</dt>
                <dd data-field="mitre">{selected.mitre}</dd>
              </div>
              <div>
                <dt>Created</dt>
                <dd data-field="createdAt">{selected.createdAt}</dd>
              </div>
              <div>
                <dt>Last updated</dt>
                <dd data-field="lastUpdated">{selected.lastUpdated}</dd>
              </div>
            </dl>

            <div className="case-columns">
              <section aria-labelledby="caseEvidenceTitle">
                <h3 className="workspace-subhead" id="caseEvidenceTitle">Collected evidence</h3>
                <ul className="evidence-list case-evidence">
                  {selected.evidence.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </section>

              <section aria-labelledby="caseActionsTitle">
                <h3 className="workspace-subhead" id="caseActionsTitle">
                  Recommended actions{' '}
                  <span className="case-progress-text" role="status">
                    {doneCount(selectedActions)} of {selectedActions.length} done
                  </span>
                </h3>
                <ul className="case-actions">
                  {selectedActions.map((action, index) => (
                    <li key={action.label} className={action.done ? 'done' : undefined}>
                      <label className="case-action">
                        <input
                          type="checkbox"
                          name="caseAction"
                          checked={action.done}
                          // Run-linked actions follow their response run
                          disabled={Boolean(action.runId || action.approvalId)}
                          onChange={() => toggleCaseAction(selected.id, index)}
                          data-action-index={index}
                        />
                        <span className="case-action-text">
                          <span>{action.label}</span>
                          {(action.runId || action.approvalId) && (
                            <span className="case-action-run">
                              {action.done
                                ? `Done by ${action.runId}`
                                : action.runId
                                  ? `${action.runId} ${action.runResult?.toLowerCase() ?? 'pending'}; it needs a new approval`
                                  : `Waiting for approval (${action.approvalId})`}
                            </span>
                          )}
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </section>
            </div>

            <h3 className="workspace-subhead">Case timeline</h3>
            <Timeline steps={caseTimeline(selected, caseEvents)} label={`${selected.id} timeline`} />
          </ResponsiveDetail>
        )}
      </div>
    </section>
  )
}

type CaseCardProps = {
  caseItem: CaseRecord
  actions: CaseActionState[]
  selected: boolean
  onChoose: () => void
}

function CaseCard({ caseItem, actions, selected, onChoose }: CaseCardProps) {
  const done = doneCount(actions)
  const percent = actions.length ? Math.round((done / actions.length) * 100) : 0

  return (
    <button
      type="button"
      className="case-card"
      aria-pressed={selected}
      onClick={onChoose}
      data-record-id={caseItem.id}
    >
      <span className="case-card-top">
        <span className="mono">{caseItem.id}</span>
        <SeverityBadge severity={caseItem.severity} />
      </span>
      <span className="case-card-title">
        {caseItem.attackType} on <span className="nowrap">{caseItem.endpoint}</span>
      </span>
      <span className="case-bar" aria-hidden="true">
        <span
          className={done === actions.length ? 'case-bar-fill complete' : 'case-bar-fill'}
          style={{ width: `${percent}%` }}
        />
      </span>
      <span className="case-card-meta">
        <span className="nowrap">{caseItem.assignedAnalyst}</span>
        <span className="nowrap case-card-progress">
          {done} of {actions.length} actions
        </span>
      </span>
      <span className="case-card-meta">
        <span>
          From <span className="mono">{caseItem.sourceAlert}</span>
        </span>
      </span>
    </button>
  )
}

export default CasesPage
