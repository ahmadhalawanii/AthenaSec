import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import type {
  AlertRecord,
  AlertStatus,
} from '../types/alertsTypes'

import { initialAlerts } from '../data/alertsData'

function severityClass(severity: AlertRecord['severity']) {
  if (severity === 'Critical') {
    return 'danger'
  }

  if (severity === 'High') {
    return 'warn'
  }

  if (severity === 'Medium') {
    return 'blue'
  }

  return 'muted'
}

function statusClass(status: AlertStatus) {
  if (status === 'Closed') {
    return 'ok'
  }

  return 'blue'
}

function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertRecord[]>(initialAlerts)
  const [attackFilter, setAttackFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [riskSort, setRiskSort] = useState<'asc' | 'desc'>('desc')
  const [selectedAlert, setSelectedAlert] =
    useState<AlertRecord | null>(null)

  const visibleAlerts = useMemo(() => {
    return [...alerts]
      .filter((alert) => {
        const matchesAttack =
          attackFilter === 'all' ||
          alert.attackGroup === attackFilter

        const matchesRisk =
          riskFilter === 'all' ||
          alert.riskBand === riskFilter

        return matchesAttack && matchesRisk
      })
      .sort((firstAlert, secondAlert) => {
        if (riskSort === 'asc') {
          return firstAlert.risk - secondAlert.risk
        }

        return secondAlert.risk - firstAlert.risk
      })
  }, [alerts, attackFilter, riskFilter, riskSort])

  function toggleAlertStatus(alertId: string) {
    setAlerts((currentAlerts) =>
      currentAlerts.map((alert) => {
        if (alert.id !== alertId) {
          return alert
        }

        return {
          ...alert,
          status: alert.status === 'Closed' ? 'Open' : 'Closed',
        }
      }),
    )

    setSelectedAlert((currentAlert) => {
      if (!currentAlert || currentAlert.id !== alertId) {
        return currentAlert
      }

      return {
        ...currentAlert,
        status:
          currentAlert.status === 'Closed' ? 'Open' : 'Closed',
      }
    })
  }

  return (
    <section
      className="page active"
      data-page="alerts"
      data-page-name="Alerts"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Alerts</h1>

          <p className="sub">
            Brute Force and Privilege Escalation alerts with AI-generated
            analysis and case context.
          </p>
        </div>

        <span className="pill blue" id="visibleAlertCount">
          {visibleAlerts.length} visible{' '}
          {visibleAlerts.length === 1 ? 'alert' : 'alerts'}
        </span>
      </div>

      <div className="card">
        <h2>Advanced Filters</h2>

        <div className="toolbar">
          <select
            className="select-input"
            id="attackFilter"
            value={attackFilter}
            onChange={(event) => setAttackFilter(event.target.value)}
          >
            <option value="all">All Attacks</option>
            <option value="Brute Force">Brute Force</option>
            <option value="Privilege Escalation">
              Privilege Escalation
            </option>
          </select>

          <select
            className="select-input"
            id="riskFilter"
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
            value={riskSort}
            onChange={(event) =>
              setRiskSort(event.target.value as 'asc' | 'desc')
            }
          >
            <option value="desc">Highest Risk First</option>
            <option value="asc">Lowest Risk First</option>
          </select>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Endpoint</th>
                <th>Risk Score</th>
                <th>Status</th>
                <th>Assigned Analyst</th>
                <th>Time</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody id="alertsTableBody">
              {visibleAlerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="data-row"
                  data-search-record
                  data-page-target="alerts"
                  data-alert-id={alert.id}
                  data-attack={alert.attackGroup}
                  data-risk={alert.risk}
                  data-risk-band={alert.riskBand}
                >
                  <td>{alert.id}</td>

                  <td>
                    <span
                      className={`pill ${severityClass(
                        alert.severity,
                      )}`}
                    >
                      {alert.severity}
                    </span>
                  </td>

                  <td>{alert.attackType}</td>
                  <td>{alert.sourceIp}</td>
                  <td>{alert.destinationIp}</td>
                  <td>{alert.endpoint}</td>
                  <td>{alert.risk}</td>

                  <td className="status-cell">
                    <span
                      className={`pill ${statusClass(alert.status)}`}
                    >
                      {alert.status}
                    </span>
                  </td>

                  <td>{alert.assignedAnalyst}</td>
                  <td>{alert.time}</td>

                  <td>
                    <button
                      className="btn small primary"
                      type="button"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}

              {visibleAlerts.length === 0 && (
                <tr>
                  <td colSpan={11}>
                    <div className="empty">
                      No alerts match the selected filters.
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedAlert &&
        createPortal(
          <div
            className="drawer-backdrop"
            role="presentation"
            onClick={() => setSelectedAlert(null)}
          >
            <aside
              className="alert-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Alert analysis"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="drawer-head">
                <div>
                  <span className="sub">Alert Analysis</span>
                  <h2>{selectedAlert.id}</h2>
                </div>

                <button
                  className="icon-btn"
                  type="button"
                  aria-label="Close alert analysis"
                  onClick={() => setSelectedAlert(null)}
                >
                  ×
                </button>
              </div>

              <div className="drawer-body">
                <div className="card">
                  <h3>Alert Details</h3>

                  <div className="kv">
                    <span>Alert ID</span>
                    <strong>{selectedAlert.id}</strong>
                  </div>

                  <div className="kv">
                    <span>Severity</span>
                    <strong>{selectedAlert.severity}</strong>
                  </div>

                  <div className="kv">
                    <span>Attack Type</span>
                    <strong>{selectedAlert.attackType}</strong>
                  </div>

                  <div className="kv">
                    <span>Source IP</span>
                    <strong>{selectedAlert.sourceIp}</strong>
                  </div>

                  <div className="kv">
                    <span>Destination IP</span>
                    <strong>{selectedAlert.destinationIp}</strong>
                  </div>

                  <div className="kv">
                    <span>Endpoint</span>
                    <strong>{selectedAlert.endpoint}</strong>
                  </div>

                  <div className="kv">
                    <span>Risk Score</span>
                    <strong>{selectedAlert.risk} / 100</strong>
                  </div>

                  <div className="kv">
                    <span>Status</span>
                    <strong>{selectedAlert.status}</strong>
                  </div>

                  <div className="kv">
                    <span>Assigned Analyst</span>
                    <strong>{selectedAlert.assignedAnalyst}</strong>
                  </div>

                  <div className="kv">
                    <span>Time</span>
                    <strong>{selectedAlert.time}</strong>
                  </div>
                </div>

                <div className="card">
                  <h3>Attack Workflow</h3>

                  <div className="analysis-flow">
                    <span>Detection</span>
                    <span>Correlation</span>
                    <span>Risk Scoring</span>
                    <span>AI Analysis</span>
                  </div>
                </div>

                <div className="card">
                  <h3>AI-Generated Analysis</h3>
                  <p className="sub">{selectedAlert.summary}</p>
                </div>

                <div className="card">
                  <h3>AI Reasoning</h3>
                  <p className="sub">{selectedAlert.reasoning}</p>
                </div>

                <div className="card">
                  <h3>MITRE ATT&amp;CK Mapping</h3>

                  <span className="pill blue">
                    {selectedAlert.mitre}
                  </span>
                </div>

                <div className="card">
                  <h3>Technical Explanation</h3>
                  <p className="sub">{selectedAlert.explanation}</p>
                </div>

                <div className="card">
                  <h3>Analyst Action</h3>

                  <p className="sub">
                    {selectedAlert.status === 'Closed'
                      ? 'Reopen this alert and return it to the analyst review queue.'
                      : 'Mark this alert as reviewed and closed for the current frontend session.'}
                  </p>

                  <button
                    className={
                      selectedAlert.status === 'Closed'
                        ? 'btn primary'
                        : 'btn danger'
                    }
                    type="button"
                    onClick={() =>
                      toggleAlertStatus(selectedAlert.id)
                    }
                    style={{ marginTop: '14px' }}
                  >
                    {selectedAlert.status === 'Closed'
                      ? 'Reopen Alert'
                      : 'Close Alert'}
                  </button>
                </div>
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default AlertsPage
