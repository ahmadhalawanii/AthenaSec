import { useState } from 'react'
import { Link } from 'react-router-dom'

import TableScroll from '../components/TableScroll'
import {
  adminPosture,
  attackActivity,
  needsAdministrator,
  recentAdminChanges,
} from '../data/statusSummary'
import { useAdminState } from '../hooks/useAdminState'
import { useAssessments } from '../hooks/useAssessments'
import { PHONE_QUERY, useMediaQuery } from '../hooks/useMediaQuery'
import { useSocState } from '../hooks/useSocState'
import type { ActivityColumn, ActivityState } from '../types/mitreTypes'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

// Words for each activity state, so the grid never relies on colour alone
const ACTIVITY_LABELS: Record<ActivityState, string> = {
  failed: 'Containment failed',
  waiting: 'Waiting for approval',
  open: 'Open',
  handled: 'Handled',
  quiet: 'Not seen',
}

const ACTIVITY_LEGEND: ActivityState[] = ['failed', 'waiting', 'open', 'handled', 'quiet']

const DEFAULT_TECHNIQUE = 'T1110'

// "Reconnaissance" is wider than a column at a laptop width, so it may break after "Recon" with a hyphen
const tacticLabel = (name: string) => name.replace('Reconnaissance', 'Recon­naissance')

function AdminDashboardPage() {
  // Shared admin state: every figure follows changes made on the other admin pages
  const adminState = useAdminState()
  const { auditLogs } = adminState
  // The alerts, what was done about them and what the agent decided: the same live state the analyst sees
  const { alerts, executions, approvals } = useSocState()
  const assessments = useAssessments()
  const isPhone = useMediaQuery(PHONE_QUERY)

  const posture = adminPosture(adminState)
  const activity = attackActivity(alerts, executions, approvals, assessments)
  const tasks = needsAdministrator(adminState)
  const changes = recentAdminChanges(auditLogs)

  const cells = activity.flatMap((column) => column.cells)
  const [pickedId, setPickedId] = useState(DEFAULT_TECHNIQUE)
  const picked = cells.find((cell) => cell.id === pickedId) ?? cells[0]
  const pendingApproval = picked.alerts.find((alert) => alert.approvalId)

  const seenTechniques = cells.filter((cell) => cell.state !== 'quiet').length
  const seenTactics = activity.filter((column) => column.seenCount > 0).length
  const waitingTechniques = cells.filter((cell) => cell.state === 'waiting' || cell.state === 'failed').length

  const recordLink = (recordId: string): SearchNavigationState => ({ highlight: recordId })

  // One tactic: its name and count, then a button per technique
  function renderColumn(column: ActivityColumn, className: string) {
    const headingId = `tactic-${column.tactic.replace(/\s+/g, '-')}`

    return (
      <div key={column.tactic} className={className} role="group" aria-labelledby={headingId}>
        <p className={`mitre-tactic${column.seenCount > 0 ? ' covered' : ''}`} id={headingId}>
          {tacticLabel(column.tactic)}{' '}
          <span className="mitre-tactic-count">
            {column.seenCount > 0 ? `${column.seenCount} seen` : 'None seen'}
          </span>
        </p>

        {column.cells.map((cell) => (
          <button
            key={cell.id}
            type="button"
            className={`mitre-cell ${cell.state}`}
            aria-pressed={cell.id === picked.id}
            aria-label={`${cell.id} ${cell.name}: ${ACTIVITY_LABELS[cell.state]}${
              cell.alerts.length > 0 ? `, ${cell.alerts.length} ${cell.alerts.length === 1 ? 'alert' : 'alerts'}` : ''
            }`}
            data-technique={cell.id}
            onClick={() => setPickedId(cell.id)}
          >
            <span className="mitre-cell-id mono">{cell.id}</span>
            <span className="mitre-cell-name">{cell.name}</span>
            <span className="mitre-cell-state">
              {ACTIVITY_LABELS[cell.state]}
              {cell.alerts.length > 0 ? ` · ${cell.alerts.length}` : ''}
            </span>
          </button>
        ))}
      </div>
    )
  }

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

      <section className="card key mitre-card" aria-labelledby="mitreTitle">
        <div className="mitre-head">
          <div>
            <h2 id="mitreTitle">ATT&amp;CK activity and the agent&apos;s response</h2>
            <p className="sub">
              {seenTechniques} {seenTechniques === 1 ? 'technique' : 'techniques'} seen in today&apos;s alerts across{' '}
              {seenTactics} {seenTactics === 1 ? 'tactic' : 'tactics'};{' '}
              {waitingTechniques === 0
                ? 'none is waiting for a person.'
                : `${waitingTechniques} ${waitingTechniques === 1 ? 'is' : 'are'} waiting for a person or failed.`}
            </p>
          </div>
          <ul className="mitre-legend" aria-label="Legend">
            {ACTIVITY_LEGEND.map((state) => (
              <li key={state}>
                <span className={`mitre-swatch ${state}`} aria-hidden="true" />
                {ACTIVITY_LABELS[state]}
              </li>
            ))}
          </ul>
        </div>

        {isPhone ? (
          // Phones: only the tactics with tracked techniques, stacked; the rest named below
          <div className="mitre-list">
            {activity
              .filter((column) => column.cells.length > 0)
              .map((column) => renderColumn(column, 'mitre-list-group'))}
            <p className="mitre-untracked">
              No techniques tracked yet:{' '}
              {activity
                .filter((column) => column.cells.length === 0)
                .map((column) => column.tactic)
                .join(', ')}
              .
            </p>
          </div>
        ) : (
          <TableScroll label="MITRE ATT&CK activity">
            <div className="mitre-grid">
              {activity.map((column) => renderColumn(column, 'mitre-column'))}
            </div>
          </TableScroll>
        )}

        <div className="mitre-pick" aria-live="polite" data-picked={picked.id}>
          <span className="mitre-pick-id mono">{picked.id}</span>
          <span className="mitre-pick-name">{picked.name}</span>
          <span className={`pill ${statusTone(ACTIVITY_LABELS[picked.state])}`} data-field="pickState">
            {ACTIVITY_LABELS[picked.state]}
          </span>
          {picked.alerts.length === 0 ? (
            <span className="mitre-pick-detail">No alert has used this technique today.</span>
          ) : (
            <ul className="mitre-pick-alerts" data-field="pickAlerts">
              {picked.alerts.map((alert) => (
                <li key={alert.id} data-alert-id={alert.id}>
                  <span className="mono">{alert.id}</span> {alert.title}, risk {alert.risk}. The agent&apos;s outcome:{' '}
                  {alert.outcome}. {alert.response}.
                </li>
              ))}
            </ul>
          )}
          {pendingApproval?.approvalId && (
            <Link className="text-link" to="/app/approvals" state={recordLink(pendingApproval.approvalId)}>
              Open request {pendingApproval.approvalId}
            </Link>
          )}
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
