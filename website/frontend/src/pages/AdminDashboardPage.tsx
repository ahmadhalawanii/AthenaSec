
import type {
  AdminDashboardPageProps
} from '../types/adminDashboardTypes'

import { integrations, recentActivity } from '../data/adminDashboardData'



function AdminDashboardPage({
  onNavigate,
}: AdminDashboardPageProps) {
  const connectedIntegrations = integrations.filter(
    (integration) => integration.status === 'Connected',
  ).length


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

      </div>

      <div className="grid stats">
        <button
          className="stat"
          type="button"
          onClick={() => onNavigate('integrations')}
          aria-label="Open integrations"
        >
          <strong>{connectedIntegrations}</strong>
          <span>Integrations </span>
          <small>Connected & Synced</small>
        </button>

        <button
          className="stat"
          type="button"
          aria-label="Open integrations"
        >
          <span>Integrations </span>
          <small>Failed Syncing</small>
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
