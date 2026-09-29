import { useState } from 'react'
import { NavLink } from 'react-router-dom'

type SidebarProps = {
  role: 'Analyst' | 'Administrator'
  onLogout: () => void
}

function Sidebar({
  role,
}: SidebarProps) {
  const isAdmin = role === 'Administrator'
  const [sidebarOpen, setSidebarOpen] = useState(false)

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
    <>
      {/* Hamburger menu */}
      <button
        className="sidebar-toggle"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        aria-label="Open navigation menu"
      >
        <span></span>
        <span></span>
        <span></span>
      </button>

      {/* Sidebar */}
      <aside
        className={
          sidebarOpen
            ? 'sidebar sidebar-open'
            : 'sidebar'
        }
      >
        <div className="side-title">
          {isAdmin ? 'Security Management' : 'Analyst'}
        </div>

        <NavLink
          to="/app/dashboard"
          className={linkClass}
          onClick={() => setSidebarOpen(false)}
        >
          <span>Dashboard</span>
        </NavLink>

        {!isAdmin && (
          <>
            <NavLink
              to="/app/alerts"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>Alerts</span>
              <span className="count">4</span>
            </NavLink>

            <NavLink
              to="/app/cases"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>Case Management</span>
              <span className="count">3</span>
            </NavLink>

            <NavLink
              to="/app/incident"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
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
              onClick={() => setSidebarOpen(false)}
            >
              <span>Configuration</span>
            </NavLink>

            <NavLink
              to="/app/detection-rules"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>Detection Rules</span>
            </NavLink>

            <NavLink
              to="/app/response-policies"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>Response Policies</span>
            </NavLink>

            <NavLink
              to="/app/user-management"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>User Management</span>
            </NavLink>

            <NavLink
              to="/app/audit-logs"
              className={linkClass}
              onClick={() => setSidebarOpen(false)}
            >
              <span>Audit Logs</span>
            </NavLink>
          </>
        )}
      </aside>

      {/* Background overlay */}
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </>
  )
}

export default Sidebar