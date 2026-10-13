type SidebarProps = {
  role: 'Analyst' | 'Administrator'
  currentPage: string
  onNavigate: (page: string) => void
  onLogout: () => void
}

function Sidebar({
  role,
  currentPage,
  onNavigate,
  onLogout,
}: SidebarProps) {
  const isAdmin = role === 'Administrator'

  function pageClass(page: string) {
    return currentPage === page
      ? 'side-item active'
      : 'side-item'
  }

  return (
    <aside className="sidebar">
      <div className="side-title">
        {isAdmin ? 'Security Management' : 'Analyst'}
      </div>

      <button
        className={pageClass('dashboard')}
        onClick={() => onNavigate('dashboard')}
      >
        <span>Dashboard</span>
      </button>

      {!isAdmin && (
        <>
          <button
            className={pageClass('alerts')}
            onClick={() => onNavigate('alerts')}
          >
            <span>Alerts</span>
            <span className="count">4</span>
          </button>

          <button
            className={pageClass('incidents')}
            onClick={() => onNavigate('incidents')}
          >
            <span>Case Management</span>
            <span className="count">3</span>
          </button>

          <button
            className={pageClass('response-activity')}
            onClick={() => onNavigate('response-activity')}
          >
            <span>Incident Response</span>
          </button>
        </>
      )}

      {isAdmin && (
        <>
          <button
            className={pageClass('configuration')}
            onClick={() => onNavigate('configuration')}
          >
            <span>Configuration</span>
          </button>

          <button
            className={pageClass('detection-rules')}
            onClick={() => onNavigate('detection-rules')}
          >
            <span>Detection Rules</span>
          </button>

          <button
            className={pageClass('response-policies')}
            onClick={() => onNavigate('response-policies')}
          >
            <span>Response Policies</span>
          </button>

          <button
            className={pageClass('integrations')}
            onClick={() => onNavigate('integrations')}
          >
            <span>Integrations</span>
          </button>

          <button
            className={pageClass('user-management')}
            onClick={() => onNavigate('user-management')}
          >
            <span>User Management</span>
          </button>

          <button
            className={pageClass('audit-logs')}
            onClick={() => onNavigate('audit-logs')}
          >
            <span>Audit Logs</span>
          </button>

          <button
            className={pageClass('system-health')}
            onClick={() => onNavigate('system-health')}
          >
            <span>System Health</span>
          </button>

          <button
            className={pageClass('settings')}
            onClick={() => onNavigate('settings')}
          >
            <span>Settings</span>
          </button>
        </>
      )}

      <button
        className={pageClass('profile')}
        onClick={() => onNavigate('profile')}
      >
        <span>Profile</span>
      </button>

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