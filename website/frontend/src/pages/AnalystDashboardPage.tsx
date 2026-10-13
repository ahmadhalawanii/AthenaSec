import { useMemo, useState } from 'react'
import type {
  AlertSeverity,
  DashboardAlert,
} from '../types/analystDashboardTypes'

import { dashboardAlerts } from '../data/analystDashboardData'

function severityClass(severity: AlertSeverity) {
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

function AnalystDashboardPage() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [selectedAlert, setSelectedAlert] =
    useState<DashboardAlert | null>(null)

  const filteredAlerts = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase()

    return dashboardAlerts.filter((alert) => {
      const matchesSearch =
        normalizedSearch === '' ||
        alert.id.toLowerCase().includes(normalizedSearch) ||
        alert.type.toLowerCase().includes(normalizedSearch) ||
        alert.endpoint.toLowerCase().includes(normalizedSearch) ||
        alert.severity.toLowerCase().includes(normalizedSearch)

      const matchesSeverity =
        severity === 'all' || alert.severity === severity

      return matchesSearch && matchesSeverity
    })
  }, [search, severity])

  return (
    <div className="role-view" data-role-view="Analyst">
      <div className="headline">
        <div>
          <h1>Security Dashboard</h1>

          <p className="sub">
            Monitor detections, cases, and autonomous response history.
          </p>
        </div>

        <span className="pill ok">System Online</span>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>5</strong>
          <span>Total Alerts</span>
          <small>+18% today</small>
        </div>

        <div className="stat">
          <strong>2</strong>
          <span>Critical Alerts</span>
          <small>AI handled</small>
        </div>

        <div className="stat">
          <strong>2</strong>
          <span>Open Cases</span>
          <small>Analyst-owned</small>
        </div>

        <div className="stat">
          <strong>2</strong>
          <span>AI Actions</span>
          <small>AI handled</small>
        </div>
      </div>

      <div className="card" style={{ marginTop: '18px' }}>
        <div className="headline">
          <div>
            <h2>Recent Alerts</h2>

            <p className="sub">
              Search and filter recent alerts without leaving this view.
            </p>
          </div>

          <div className="toolbar" style={{ marginBottom: 0 }}>
            <input
              className="field-input"
              id="dashboardSearch"
              placeholder="Search recent alerts"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />

            <select
              className="select-input"
              id="dashboardSeverity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Type</th>
                <th>Endpoint</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody id="dashboardAlertRows">
              {filteredAlerts.map((alert) => (
                <tr
                  key={alert.id}
                  data-dashboard-alert
                  data-severity={alert.severity}
                >
                  <td>{alert.id}</td>
                  <td>{alert.type}</td>
                  <td>{alert.endpoint}</td>

                  <td>
                    <span
                      className={`pill ${severityClass(
                        alert.severity,
                      )}`}
                    >
                      {alert.severity}
                    </span>
                  </td>

                  <td>{alert.risk}</td>

                  <td>
                    <button
                      className="btn small"
                      type="button"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}

              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={6}>
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

      <div className="grid two" style={{ marginTop: '18px' }}>
        <div className="card">
          <h2>Alert Severity - Last 24 Hours</h2>

          <div className="chart">
            <button
              className="bar"
              type="button"
              style={{ height: '38%' }}
              onClick={() => setSeverity('Low')}
            >
              <span>Low</span>
            </button>

            <button
              className="bar"
              type="button"
              style={{ height: '58%' }}
              onClick={() => setSeverity('Medium')}
            >
              <span>Medium</span>
            </button>

            <button
              className="bar"
              type="button"
              style={{ height: '74%' }}
              onClick={() => setSeverity('High')}
            >
              <span>High</span>
            </button>

            <button
              className="bar"
              type="button"
              style={{ height: '88%' }}
              onClick={() => setSeverity('Critical')}
            >
              <span>Critical</span>
            </button>

            <button
              className="bar"
              type="button"
              style={{ height: '66%' }}
              onClick={() => setSeverity('all')}
            >
              <span>All</span>
            </button>
          </div>
        </div>

        <div className="card">
          <h2>Endpoint Status</h2>

          <div className="table-scroll">
            <table>
              <tbody>
                <tr>
                  <td>Active</td>
                  <td>
                    <span className="pill ok">2</span>
                  </td>
                </tr>

                <tr>
                  <td>Warning</td>
                  <td>
                    <span className="pill warn">1</span>
                  </td>
                </tr>

                <tr>
                  <td>Isolated</td>
                  <td>
                    <span className="pill danger">1</span>
                  </td>
                </tr>

                <tr>
                  <td>Offline</td>
                  <td>
                    <span className="pill danger">1</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {selectedAlert && (
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
                  <strong>{selectedAlert.type}</strong>
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
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}

export default AnalystDashboardPage
