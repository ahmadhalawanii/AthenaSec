import { useState } from 'react'

type TopBarProps = {
  userName: string
  role: 'Analyst' | 'Administrator'
  onNavigate: (page: string) => void
  onLogout: () => void
}

function TopBar({
  userName,
  role,
  onNavigate,
  onLogout,
}: TopBarProps) {
  const [notificationOpen, setNotificationOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  function openNotifications() {
    setNotificationOpen(!notificationOpen)
    setUserMenuOpen(false)
  }

  function openUserMenu() {
    setUserMenuOpen(!userMenuOpen)
    setNotificationOpen(false)
  }

  function navigate(page: string) {
    setNotificationOpen(false)
    setUserMenuOpen(false)
    onNavigate(page)
  }

  return (
    <div className="topbar">
      <button
        className="logo"
        onClick={() => navigate('dashboard')}
      >
        AthenaSec
      </button>

      <div
        className="system-status-widget"
        aria-label="System status"
      >
        <span
          className="status-indicator"
          aria-hidden="true"
        />

        <span className="status-copy">
          <strong>System Online</strong>
          <small>All Systems Operational</small>
        </span>
      </div>

      <div className="search-wrap">
        <input
          className="search-input"
          id="globalSearch"
          placeholder="Search alerts, cases, responses, policies..."
        />
      </div>

      <div className="top-actions">
        <div className="dropdown-wrap">
          <button
            className="icon-btn"
            onClick={openNotifications}
          >
            <span className="bell-shape" />
            <span className="badge-dot" />
          </button>

          {notificationOpen && (
            <div className="dropdown">
              <button
                className="drop-item"
                onClick={() => navigate('alerts')}
              >
                <strong>New Alert</strong>
                <p>
                  ALT-004 Kernel Exploit Attempt scored Critical.
                </p>
              </button>

              <button
                className="drop-item"
                onClick={() => navigate('incidents')}
              >
                <strong>Case Created</strong>
                <p>
                  CASE-008 was created from endpoint-09 telemetry.
                </p>
              </button>

              {role === 'Administrator' && (
                <>
                  <button
                    className="drop-item"
                    onClick={() => navigate('response-policies')}
                  >
                    <strong>Policy Updated</strong>
                    <p>
                      Critical Host Isolation policy was validated.
                    </p>
                  </button>

                  <button
                    className="drop-item"
                    onClick={() => navigate('system-health')}
                  >
                    <strong>System Warning</strong>
                    <p>
                      Telemetry sync latency is above the expected threshold.
                    </p>
                  </button>
                </>
              )}
            </div>
          )}
        </div>

        <div className="dropdown-wrap">
          <button
            className="user-chip"
            onClick={openUserMenu}
          >
            {userName}
          </button>

          {userMenuOpen && (
            <div className="dropdown">
              <button
                className="drop-item"
                onClick={() => navigate('profile')}
              >
                <strong>Profile</strong>
                <p>View role, contact, and session details.</p>
              </button>

              {role === 'Administrator' && (
                <button
                  className="drop-item"
                  onClick={() => navigate('settings')}
                >
                  <strong>Settings</strong>
                  <p>
                    Manage console theme, MFA, and session timeout.
                  </p>
                </button>
              )}

              <button
                className="drop-item"
                onClick={onLogout}
              >
                <strong>Logout</strong>
                <p>End the current AthenaSec session.</p>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default TopBar