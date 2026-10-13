import type { CSSProperties } from 'react'
import type {
  AdminDashboardPageProps,
  IntegrationStatus,
} from '../types/adminDashboardTypes'

import { integrations, recentActivity } from '../data/adminDashboardData'


function integrationStatusClass(status: IntegrationStatus) {
  if (status === 'Connected') {
    return 'ok'
  }

  if (status === 'Warning') {
    return 'warn'
  }

  return 'danger'
}

function AdminDashboardPage({
  onNavigate,
}: AdminDashboardPageProps) {
  const connectedIntegrations = integrations.filter(
    (integration) => integration.status === 'Connected',
  ).length

  const allServicesHealthy =
    connectedIntegrations === integrations.length

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
            Administrative dashboard for configuration, integrations,
            detection rules, response policies, users, and audit logs.
          </p>
        </div>

        <span
          className={`pill ${
            allServicesHealthy ? 'ok' : 'warn'
          }`}
        >
          {allServicesHealthy
            ? 'All Services Healthy'
            : 'Service Attention Required'}
        </span>
      </div>

      <div className="grid stats">
        <button
          className="stat"
          type="button"
          onClick={() => onNavigate('integrations')}
          aria-label="Open integrations"
        >
          <strong>{connectedIntegrations}</strong>
          <span>Integrations</span>
          <small>Connected now</small>
        </button>

        <button
          className="stat"
          type="button"
          onClick={() => onNavigate('detection-rules')}
          aria-label="Open detection rules"
        >
          <strong>5</strong>
          <span>Detection Rules</span>
          <small>3 updated today</small>
        </button>

        <button
          className="stat"
          type="button"
          onClick={() => onNavigate('response-policies')}
          aria-label="Open response policies"
        >
          <strong>4</strong>
          <span>Response Policies</span>
          <small>2 AI-managed</small>
        </button>

        <button
          className="stat"
          type="button"
          onClick={() => onNavigate('audit-logs')}
          aria-label="Open audit logs"
        >
          <strong>100%</strong>
          <span>Audit Stored</span>
          <small>OpenSearch synced</small>
        </button>
      </div>

      <div className="grid three" style={{ marginTop: '18px' }}>
        <button
          className="card"
          type="button"
          onClick={() => onNavigate('configuration')}
          style={{ textAlign: 'left' }}
        >
          <h2>Configuration</h2>

          <p className="sub">
            Edit general, detection, logging, retention, and
            notification controls.
          </p>

          <span
            className="pill blue"
            style={{ marginTop: '14px' }}
          >
            Open Configuration
          </span>
        </button>

        <button
          className="card"
          type="button"
          onClick={() => onNavigate('detection-rules')}
          style={{ textAlign: 'left' }}
        >
          <h2>Detection Rules</h2>

          <p className="sub">
            Add, edit, enable, disable, and delete SOC detection
            logic.
          </p>

          <span
            className="pill blue"
            style={{ marginTop: '14px' }}
          >
            Manage Rules
          </span>
        </button>

        <button
          className="card"
          type="button"
          onClick={() => onNavigate('system-health')}
          style={{ textAlign: 'left' }}
        >
          <h2>System Health</h2>

          <p className="sub">
            Review CPU, memory, storage, service health, and
            processing totals.
          </p>

          <span
            className="pill blue"
            style={{ marginTop: '14px' }}
          >
            View Health
          </span>
        </button>
      </div>

      <div className="grid two" style={{ marginTop: '18px' }}>
        <div className="card">
          <div className="headline">
            <div>
              <h2>System Health Snapshot</h2>

              <p className="sub">
                Current static system-resource summary.
              </p>
            </div>

            <span className="pill ok">Operational</span>
          </div>

          <div
            className="grid"
            style={{
              gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
              gap: '14px',
            }}
          >
            <div className="health-stat">
              <div
                className="donut good"
                style={
                  {
                    '--donut-pct': 42,
                  } as CSSProperties
                }
              >
                <div className="donut-label">42%</div>
              </div>

              <div className="health-info">
                <strong
                  style={{
                    color: '#fff',
                    fontSize: '14px',
                  }}
                >
                  CPU
                </strong>

                <span className="health-tag good">Good</span>
              </div>
            </div>

            <div className="health-stat">
              <div
                className="donut warn"
                style={
                  {
                    '--donut-pct': 67,
                  } as CSSProperties
                }
              >
                <div className="donut-label">67%</div>
              </div>

              <div className="health-info">
                <strong
                  style={{
                    color: '#fff',
                    fontSize: '14px',
                  }}
                >
                  Memory
                </strong>

                <span className="health-tag warn">Watch</span>
              </div>
            </div>

            <div className="health-stat">
              <div
                className="donut good"
                style={
                  {
                    '--donut-pct': 96,
                  } as CSSProperties
                }
              >
                <div className="donut-label">96%</div>
              </div>

              <div className="health-info">
                <strong
                  style={{
                    color: '#fff',
                    fontSize: '14px',
                  }}
                >
                  Services
                </strong>

                <span className="health-tag good">Good</span>
              </div>
            </div>

            <div className="health-stat">
              <div
                className="donut bad"
                style={
                  {
                    '--donut-pct': 58,
                  } as CSSProperties
                }
              >
                <div className="donut-label">58%</div>
              </div>

              <div className="health-info">
                <strong
                  style={{
                    color: '#fff',
                    fontSize: '14px',
                  }}
                >
                  Case Automation
                </strong>

                <span className="health-tag bad">
                  Attention
                </span>
              </div>
            </div>
          </div>

          <button
            className="btn ghost small"
            type="button"
            onClick={() => onNavigate('system-health')}
            style={{
              justifyContent: 'center',
              marginTop: '16px',
              width: '100%',
            }}
          >
            View Full System Health
          </button>
        </div>

        <div className="card">
          <div className="headline">
            <div>
              <h2>Integration Status</h2>

              <p className="sub">
                {connectedIntegrations} of {integrations.length}{' '}
                integrations connected.
              </p>
            </div>

            <span className="pill ok">
              {connectedIntegrations} online
            </span>
          </div>

          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Integration</th>
                  <th>Last Check</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {integrations.map((integration) => (
                  <tr key={integration.name}>
                    <td>{integration.name}</td>
                    <td>{integration.lastCheck}</td>

                    <td>
                      <span
                        className={`pill ${integrationStatusClass(
                          integration.status,
                        )}`}
                      >
                        {integration.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <button
            className="btn ghost small"
            type="button"
            onClick={() => onNavigate('integrations')}
            style={{
              justifyContent: 'center',
              marginTop: '14px',
              width: '100%',
            }}
          >
            Manage Integrations
          </button>
        </div>
      </div>

      <div className="card" style={{ marginTop: '18px' }}>
        <div className="headline">
          <div>
            <h2>Recent Administrative Activity</h2>

            <p className="sub">
              Recent configuration, policy, integration, and user
              management events.
            </p>
          </div>

          <button
            className="btn ghost small"
            type="button"
            onClick={() => onNavigate('audit-logs')}
          >
            View Audit Logs
          </button>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Time</th>
                <th>Admin</th>
                <th>Action</th>
                <th>Target</th>
                <th>Result</th>
              </tr>
            </thead>

            <tbody>
              {recentActivity.map((activity) => (
                <tr key={activity.id}>
                  <td>{activity.id}</td>
                  <td>{activity.time}</td>
                  <td>{activity.admin}</td>
                  <td>{activity.action}</td>
                  <td>{activity.target}</td>

                  <td>
                    <span className="pill ok">
                      {activity.result}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

export default AdminDashboardPage
