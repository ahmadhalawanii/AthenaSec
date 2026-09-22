import { NavLink } from 'react-router-dom'

type SidebarProps = {
  role: 'Analyst' | 'Administrator'
  onLogout: () => void
}

function Sidebar({
  role,
  onLogout,
}: SidebarProps) {
  const isAdmin = role === 'Administrator'

  function linkClass({
    isActive,
  }: {
    isActive: boolean
  }) {
    return isActive
      ? 'side-item active'
      : 'side-item'
  }

  return (
    <aside className="sidebar">
      <div className="side-title">
        {isAdmin ? 'Security Management' : 'Analyst'}
      </div>

      <NavLink
        to="/app/dashboard"
        className={linkClass}
      >
        <span>Dashboard</span>
      </NavLink>

      {!isAdmin && (
        <>
          <NavLink
            to="/app/alerts"
            className={linkClass}
          >
            <span>Alerts</span>
            <span className="count">4</span>
          </NavLink>

          <NavLink
            to="/app/cases"
            className={linkClass}
          >
            <span>Case Management</span>
            <span className="count">3</span>
          </NavLink>

          <NavLink
            to="/app/incident"
            className={linkClass}
          >
            <span>Incident Response</span>
          </NavLink>
        </>
      )}

      {isAdmin && (
        <>
          <NavLink
            to="/app/configuration"
            className={linkClass}
          >
            <span>Configuration</span>
          </NavLink>

          <NavLink
            to="/app/detection-rules"
            className={linkClass}
          >
            <span>Detection Rules</span>
          </NavLink>

          <NavLink
            to="/app/response-policies"
            className={linkClass}
          >
            <span>Response Policies</span>
          </NavLink>

          <NavLink
            to="/app/integrations"
            className={linkClass}
          >
            <span>Integrations</span>
          </NavLink>

          <NavLink
            to="/app/user-management"
            className={linkClass}
          >
            <span>User Management</span>
          </NavLink>

          <NavLink
            to="/app/audit-logs"
            className={linkClass}
          >
            <span>Audit Logs</span>
          </NavLink>

          <NavLink
            to="/app/system-health"
            className={linkClass}
          >
            <span>System Health</span>
          </NavLink>

          <NavLink
            to="/app/settings"
            className={linkClass}
          >
            <span>Settings</span>
          </NavLink>
        </>
      )}

      <NavLink
        to="/app/profile"
        className={linkClass}
      >
        <span>Profile</span>
      </NavLink>

      <button
        className="side-item"
        onClick={onLogout}
      >
        <span>Logout</span>
      </button>
    </aside>
  )
}

export default Sidebar