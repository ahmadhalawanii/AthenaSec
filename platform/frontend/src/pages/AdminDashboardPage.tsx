import { Link } from 'react-router-dom'

import {
  adminPosture,
  needsAdministrator,
  recentAdminChanges,
} from '../data/statusSummary'
import { useAdminState } from '../hooks/useAdminState'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

function AdminDashboardPage() {
  // Shared admin state: every figure follows changes made on the other admin pages
  const adminState = useAdminState()
  const { auditLogs } = adminState
  const posture = adminPosture(adminState)
  const tasks = needsAdministrator(adminState)
  const changes = recentAdminChanges(auditLogs)

  const policy = adminState.responsePolicy
  const { criticalRiskThreshold, correlationWindowMinutes } = adminState.configuration

  const recordLink = (recordId: string): SearchNavigationState => ({ highlight: recordId })

  return (
    <section
      className="page active"
      data-page="dashboard"
      data-page-name="Security Management"
    >
      <div className="headline">
        <div>
          <h1>Security Management</h1>
          <p className="sub">
            How well AthenaSec is set up to detect and respond, and what changed today.
          </p>
        </div>
      </div>

      <ul className="card posture admin-posture" aria-label="Platform posture">
        {posture.map((item) => (
          <li key={item.page} className={item.tone ? `posture-${item.tone}` : undefined}>
            <Link to={`/app/${item.page}${item.view ? `?view=${item.view}` : ''}`} className="posture-link" data-posture={item.page}>
              <strong>
                {item.value}
                {item.total && <span className="posture-total">{item.total}</span>}
              </strong>
              <span className="posture-label">{item.label}</span>
              <span className="posture-note">{item.note}</span>
            </Link>
          </li>
        ))}
      </ul>

      <section className="card key governance-card" aria-labelledby="governanceTitle">
        <div className="governance-head">
          <div>
            <h2 id="governanceTitle">Platform governance and controls</h2>
            <p className="sub">
              Review the safeguards and configuration that govern automated response, access and accountability.
            </p>
          </div>
        </div>

        <div className="governance-grid">
          <Link to="/app/response-policies" className="governance-item" data-governance="policy">
            <span className="governance-label">Response authorization</span>
            <strong className="governance-value">Policy</strong>
            <span className="governance-detail">
              Protected targets: {policy.neverBlock.length} block safeguards · {policy.neverIsolate.length} isolation safeguards
            </span>
            <span className="governance-link">Manage response policies <span aria-hidden="true">→</span></span>
          </Link>

          <Link to="/app/user-management" className="governance-item" data-governance="access">
            <span className="governance-label">Identity and access</span>
            <strong className="governance-value">
              Role management
            </strong>
            <span className="governance-detail">
              Review roles and administrative access boundaries
            </span>
            <span className="governance-link">Review user access <span aria-hidden="true">→</span></span>
          </Link>

          <Link to="/app/configuration" className="governance-item" data-governance="detection">
            <span className="governance-label">Detection configuration</span>
            <strong className="governance-value">Risk threshold {criticalRiskThreshold}</strong>
            <span className="governance-detail">
              Correlation window: {correlationWindowMinutes} minutes
            </span>
            <span className="governance-link">Open configuration <span aria-hidden="true">→</span></span>
          </Link>

          <Link to="/app/audit-logs" className="governance-item" data-governance="audit">
            <span className="governance-label">Audit oversight</span>
            <strong className="governance-value">Audit integrity</strong>
            <span className="governance-detail">
              Review event history and investigate integrity warnings
            </span>
            <span className="governance-link">Inspect audit trail <span aria-hidden="true">→</span></span>
          </Link>
        </div>
      </section>

      <div className="dash-lower">
        <section className="card dash-queue admin-changes" aria-labelledby="changesTitle">
          <div className="dash-card-head">
            <h2 id="changesTitle">Recent administrative changes</h2>
            <Link className="text-link" to="/app/audit-logs">Open audit log</Link>
          </div>

          <ol className="change-list">
            {changes.map((change) => (
              <li key={change.id} data-change-id={change.id}>
                <span className="mono change-time">{change.time}</span>
                <span className="change-text">
                  <span className="change-action">{change.action}</span>{' '}
                  <span className="change-target">{change.target}</span>
                </span>
                <span className="mono change-id">{change.id}</span>
                <span className={`pill ${statusTone(change.result)}`}>{change.result}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="card key dash-log admin-tasks" aria-labelledby="tasksTitle">
          <h2 id="tasksTitle">Needs an administrator</h2>

          {tasks.length === 0 ? (
            <p className="dash-empty">Nothing needs an administrator right now.</p>
          ) : (
            <ul className="task-list">
              {tasks.map((task) => (
                <li key={task.id} className={`task-${task.tone}`} data-task-id={task.id}>
                  <span className="task-dot" aria-hidden="true" />
                  <span>
                    {task.text}{' '}
                    <Link className="task-link" aria-label={`${task.linkLabel}: ${task.text}`} to={`/app/${task.page}${task.view ? `?view=${task.view}` : ''}`} state={recordLink(task.recordId)}>
                      {task.linkLabel}
                    </Link>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </section>
  )
}

export default AdminDashboardPage
