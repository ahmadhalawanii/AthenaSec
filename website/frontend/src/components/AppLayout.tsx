import type { ReactNode } from 'react'
import Sidebar from './Sidebar'
import TopBar from './TopBar'

type AppLayoutProps = {
  children: ReactNode
  role: 'Analyst' | 'Administrator'
  userName: string
  currentPage: string
  onNavigate: (page: string) => void
  onLogout: () => void
}

function AppLayout({
  children,
  role,
  userName,
  currentPage,
  onNavigate,
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
          onNavigate={onNavigate}
          onLogout={onLogout}
        />

        <div className="body">
          <Sidebar
            role={role}
            currentPage={currentPage}
            onNavigate={onNavigate}
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