import type { ReactNode } from 'react'

import Sidebar from './Sidebar'
import TopBar from './TopBar'

type AppLayoutProps = {
  children: ReactNode
  role: 'Analyst' | 'Administrator'
  userName: string
  onLogout: () => void
}

function AppLayout({
  children,
  role,
  userName,
  onLogout,
}: AppLayoutProps) {
  return (
    <section className="section">
      <div className="label">
        <span>AthenaSec High Fidelity</span>

        <span className="prototype-note">
          {role} Workspace
        </span>
      </div>

      <div className="screen">
        <TopBar
          userName={userName}
          role={role}
          onLogout={onLogout}
        />

        <div className="body">
          <Sidebar
            role={role}
            onLogout={onLogout}
          />

          <main className="main">
            {children}
          </main>
        </div>
      </div>
    </section>
  )
}

export default AppLayout