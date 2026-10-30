import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import ApprovalDetails from '../components/ApprovalDetails'
import RequestAgain from '../components/RequestAgain'
import ResponsiveDetail from '../components/ResponsiveDetail'
import RiskAssessment from '../components/RiskAssessment'
import RiskRing from '../components/RiskRing'
import Segmented from '../components/Segmented'
import SeverityBadge from '../components/SeverityBadge'
import Tabs from '../components/Tabs'
import Timeline from '../components/Timeline'
import { OUTCOME_LABELS } from '../data/agentPolicyData'
import { alertEvidence, alertNextSteps } from '../data/alertDetailsData'
import {
  alertResponseState,
  alertTimeline,
  executionFor,
  needsDecision,
} from '../data/statusSummary'
import { useAssessments } from '../hooks/useAssessments'
import { useSearchSelection } from '../hooks/useSearchSelection'
import { useSocState } from '../hooks/useSocState'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

type AlertView = 'decision' | 'all' | 'resolved'
type WorkspaceTab = 'overview' | 'evidence' | 'response'

const TABS = [
  { value: 'overview' as const, label: 'Overview' },
  { value: 'evidence' as const, label: 'Evidence' },
  { value: 'response' as const, label: 'Response' },
]

const linkState = (id: string): SearchNavigationState => ({ highlight: id })

function AlertsPage() {
  // Shared with the dashboard, top bar, sidebar and search (SocStateProvider)
  const {
    alerts,
    executions,
    cases,
    actions,
    currentUser,
    approvals,
    executionFacts,
    tokens,
    toggleAlertStatus,
    assignToMe,
  } = useSocState()

  // Risk, confidence and outcome per alert, from the policy formula
  const assessments = useAssessments()

  const [view, setView] = useState<AlertView>('decision')
  const [searchQuery, setSearchQuery] = useState('')
  const [attackFilter, setAttackFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [riskSort, setRiskSort] = useState<'asc' | 'desc'>('desc')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Phones: the workspace opens as a drawer only when an item is chosen
  const [detailOpen, setDetailOpen] = useState(false)
  const [tab, setTab] = useState<WorkspaceTab>('overview')

  const counts = {
    decision: alerts.filter((alert) => needsDecision(alert, executions)).length,
    all: alerts.length,
    resolved: alerts.filter((alert) => !needsDecision(alert, executions)).length,
  }

  const views = [
    { value: 'decision' as const, label: 'Needs decision', count: counts.decision },
    { value: 'all' as const, label: 'All today', count: counts.all },
    { value: 'resolved' as const, label: 'Resolved', count: counts.resolved },
  ]

  const visibleAlerts = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return [...alerts]
      .filter((alert) => {
        const inView =
          view === 'all' ||
          (view === 'decision') === needsDecision(alert, executions)

        const matchesSearch =
          normalizedQuery === '' ||
          [
            alert.id,
            alert.attackType,
            alert.sourceIp,
            alert.destinationIp,
            alert.endpoint,
            alert.assignedAnalyst,
          ].some((value) => value.toLowerCase().includes(normalizedQuery))

        const matchesAttack =
          attackFilter === 'all' || alert.attackGroup === attackFilter

        const matchesRisk = riskFilter === 'all' || alert.riskBand === riskFilter

        return inView && matchesSearch && matchesAttack && matchesRisk
      })
      .sort((first, second) =>
        riskSort === 'asc' ? first.risk - second.risk : second.risk - first.risk,
      )
  }, [alerts, executions, view, searchQuery, attackFilter, riskFilter, riskSort])

  // The chosen alert, or the first one in the list
  const selected =
    visibleAlerts.find((alert) => alert.id === selectedId) ?? visibleAlerts[0] ?? null

  function resetFilters() {
    setSearchQuery('')
    setAttackFilter('all')
    setRiskFilter('all')
    setRiskSort('desc')
  }

  function choose(alertId: string) {
    setSelectedId(alertId)
    setTab('overview')
    setDetailOpen(true)
  }

  // Search and links from other pages: show everything, then select it
  useSearchSelection(
    alerts.map((alert) => alert.id),
    (alertId) => {
      setSelectedId(alertId)
      setTab('overview')
    },
    () => {
      setView('all')
      resetFilters()
    },
  )

  const run = selected ? executionFor(selected, executions) : undefined
  const state = selected ? alertResponseState(selected, executions, approvals) : null
  const caseItem = selected
    ? cases.find((entry) => entry.sourceAlert === selected.id)
    : undefined
  // The latest request for this alert, decided or not (a failed or lapsed run can be asked for again)
  const alertApproval = selected
    ? [...approvals].reverse().find((approval) => approval.recommendation.alertId === selected.id)
    : undefined

  return (
    <section className="page active" data-page="alerts" data-page-name="Alerts" data-search-page>
      <div className="headline">
        <div>
          <h1>Alerts</h1>
          <p className="sub">
            {counts.decision === 0
              ? 'No alerts need a decision.'
              : `${counts.decision} ${counts.decision === 1 ? 'alert needs' : 'alerts need'} a decision.`}{' '}
            {riskSort === 'desc' ? 'Highest risk first.' : 'Lowest risk first.'}
          </p>
        </div>

        <Segmented label="Show alerts" options={views} value={view} onChange={setView} />
      </div>

      <div className="toolbar">
        <input
          className="field-input"
          id="alertSearch"
          name="alertSearch"
          autoComplete="off"
          type="search"
          aria-label="Search alerts"
          placeholder="Search alerts…"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />

        <select
          className="select-input"
          id="attackFilter"
          name="attackFilter"
          autoComplete="off"
          aria-label="Filter by attack type"
          value={attackFilter}
          onChange={(event) => setAttackFilter(event.target.value)}
        >
          <option value="all">All Attacks</option>
          <option value="Brute Force">Brute Force</option>
          <option value="Privilege Escalation">Privilege Escalation</option>
          <option value="Command and Control">Command and Control</option>
          <option value="Other">Other</option>
        </select>

        <select
          className="select-input"
          id="riskFilter"
          name="riskFilter"
          autoComplete="off"
          aria-label="Filter by risk score"
          value={riskFilter}
          onChange={(event) => setRiskFilter(event.target.value)}
        >
          <option value="all">All Risk Scores</option>
          <option value="low">Low (0-39)</option>
          <option value="medium">Medium (40-69)</option>
          <option value="high">High (70-89)</option>
          <option value="critical">Critical (90-100)</option>
        </select>

        <select
          className="select-input"
          id="riskSort"
          name="riskSort"
          autoComplete="off"
          aria-label="Sort alerts"
          value={riskSort}
          onChange={(event) => setRiskSort(event.target.value as 'asc' | 'desc')}
        >
          <option value="desc">Highest Risk First</option>
          <option value="asc">Lowest Risk First</option>
        </select>

        <button className="btn" type="button" onClick={resetFilters}>
          Reset Filters
        </button>

        <span className="pill blue" id="visibleAlertCount" role="status">
          {visibleAlerts.length} visible
        </span>
      </div>

      <div className="split-layout">
        <section className="card queue" aria-label="Alert queue">
          {visibleAlerts.length === 0 ? (
            <div className="empty">
              <p>No alerts match the selected view and filters.</p>
            </div>
          ) : (
            <ul className="queue-list">
              {visibleAlerts.map((alert) => {
                const itemState = alertResponseState(alert, executions, approvals)
                return (
                  <li key={alert.id}>
                    <button
                      type="button"
                      className="queue-item"
                      aria-pressed={alert.id === selected?.id}
                      onClick={() => choose(alert.id)}
                      data-record-id={alert.id}
                    >
                      <RiskRing score={alert.risk} />
                      <span className="queue-text">
                        <span className="queue-title">
                          <span className="queue-name">{alert.attackType}</span>
                          <SeverityBadge severity={alert.severity} />
                        </span>
                        {/* Each address wraps as a whole, never mid-name */}
                        <span className="queue-route mono">
                          <span className="nowrap">{alert.sourceIp}</span> →{' '}
                          <span className="nowrap">{alert.destinationIp}</span>{' '}
                          <span className="nowrap">({alert.endpoint})</span>
                        </span>
                        <span className="queue-meta">
                          <span className="mono">{alert.id}</span> at{' '}
                          <span className="mono">{alert.time}</span>,{' '}
                          <span className="nowrap">{alert.assignedAnalyst}</span>
                        </span>
                        {assessments[alert.id] && (
                          <span className="queue-outcome" data-field="outcome">
                            {OUTCOME_LABELS[assessments[alert.id].outcome]}
                            <span className="queue-confidence">
                              {' '}
                              · confidence {assessments[alert.id].confidence.toFixed(2)}
                            </span>
                          </span>
                        )}
                      </span>
                      <span className={`queue-state path-status ${statusTone(itemState)}`}>
                        {itemState}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        {selected && state && (
          <ResponsiveDetail
            open={detailOpen}
            onClose={() => setDetailOpen(false)}
            labelledBy="alertWorkspaceTitle"
            closeLabel="Close alert details"
            className="workspace"
          >
            <div className="workspace-head" data-workspace-id={selected.id}>
              <div className="dash-path-meta">
                <SeverityBadge severity={selected.severity} />
                <span className="mono">{selected.id}</span>
                <span className={`path-status ${statusTone(state)}`}>{state}</span>
              </div>
              <h2 className="workspace-title" id="alertWorkspaceTitle">
                {selected.attackType}
              </h2>
              <p className="dash-path-route mono">
                {selected.sourceIp} to {selected.endpoint}
              </p>

              <div className="workspace-actions">
                <button className="btn" type="button" onClick={() => {
                  // Stay on this alert even if closing moves it down the list
                  setSelectedId(selected.id)
                  toggleAlertStatus(selected.id)
                }}>
                  {selected.status === 'Closed' ? 'Reopen alert' : 'Close alert'}
                </button>
                {selected.assignedAnalyst === currentUser ? (
                  <span className="assigned-note">Assigned to you</span>
                ) : (
                  <button className="btn ghost" type="button" onClick={() => {
                    setSelectedId(selected.id)
                    assignToMe(selected.id)
                  }}>
                    Assign to me
                  </button>
                )}
                {caseItem && (
                  <Link className="btn ghost" to="/app/cases" state={linkState(caseItem.id)}>
                    Open {caseItem.id}
                  </Link>
                )}
                {run && (
                  <Link className="btn ghost" to="/app/incident" state={linkState(run.id)}>
                    View {run.id}
                  </Link>
                )}
              </div>
            </div>

            <Tabs label="Alert details" tabs={TABS} value={tab} onChange={setTab}>
              {tab === 'overview' && (
                <>
                  <dl className="facts">
                    <div>
                      <dt>Source IP</dt>
                      <dd className="mono" data-field="sourceIp">{selected.sourceIp}</dd>
                    </div>
                    <div>
                      <dt>Destination IP</dt>
                      <dd className="mono" data-field="destinationIp">{selected.destinationIp}</dd>
                    </div>
                    <div>
                      <dt>Endpoint</dt>
                      <dd className="mono" data-field="endpoint">{selected.endpoint}</dd>
                    </div>
                    <div>
                      <dt>Risk score</dt>
                      <dd data-field="risk">{selected.risk} / 100</dd>
                    </div>
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
                      <dt>Time</dt>
                      <dd className="mono" data-field="time">{selected.time}</dd>
                    </div>
                    <div>
                      <dt>MITRE ATT&amp;CK</dt>
                      <dd data-field="mitre">{selected.mitre}</dd>
                    </div>
                    <div>
                      <dt>Response</dt>
                      <dd data-field="response">
                        {run ? `${run.id}, ${run.result.toLowerCase()}` : 'None'}
                      </dd>
                    </div>
                  </dl>

                  {assessments[selected.id] && (
                    <RiskAssessment assessment={assessments[selected.id]} />
                  )}

                  <h3 className="workspace-subhead">AI assessment</h3>
                  <p className="workspace-text">{selected.summary}</p>
                  <p className="workspace-text">{selected.reasoning}</p>
                  <p className="workspace-text">{selected.explanation}</p>

                  <h3 className="workspace-subhead">Timeline</h3>
                  <Timeline
                    steps={alertTimeline(selected, executions, cases, actions, approvals)}
                    label={`${selected.id} timeline`}
                  />
                </>
              )}

              {tab === 'evidence' && (
                <ul className="evidence-list">
                  {(alertEvidence[selected.id] ?? []).map((item) => (
                    <li key={item.text}>
                      <span className={`evidence-tag ${item.source.toLowerCase()}`}>{item.source}</span>
                      <span>{item.text}</span>
                    </li>
                  ))}
                </ul>
              )}

              {tab === 'response' && (
                <>
                  <h3 className="workspace-subhead first">Recommended next steps</h3>
                  <ol className="next-steps">
                    {(alertNextSteps[selected.id] ?? []).map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                  {alertApproval && (
                    <section aria-label="Approval">
                      <h3 className="workspace-subhead">Approval</h3>
                      <ApprovalDetails
                        approval={alertApproval}
                        token={tokens.find((token) => token.id === alertApproval.tokenId)}
                        facts={executionFacts.find((facts) => facts.approvalId === alertApproval.id)}
                        failed={run?.approvalId === alertApproval.id && run.result === 'Failed'}
                      />
                    </section>
                  )}
                  {run && <RequestAgain run={run} alertOpen={selected.status === 'Open'} />}
                  <p className="policy-note">
                    {run
                      ? `Response ran under ${run.policy}: ${run.action} on ${run.target}, ${run.result.toLowerCase()}.`
                      : alertApproval
                        ? 'Nothing has run for this alert: the recommendation needs a person to approve it first.'
                        : 'No response policy ran for this alert.'}
                  </p>
                </>
              )}
            </Tabs>
          </ResponsiveDetail>
        )}
      </div>
    </section>
  )
}

export default AlertsPage
