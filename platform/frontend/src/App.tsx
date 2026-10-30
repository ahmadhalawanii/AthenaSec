import { useEffect, useState } from 'react'
import {
  Navigate,
  Route,
  Routes,
  useNavigate,
} from 'react-router-dom'

import AppLayout from './components/AppLayout'
import LogoutConfirm from './components/LogoutConfirm'
import ResponsePolicyProvider from './components/ResponsePolicyProvider'
import ResponseStateProvider from './components/ResponseStateProvider'

import LoginPage from './pages/LoginPage'
import MfaPage from './pages/MfaPage'
import NewPasswordPage from './pages/NewPasswordPage'

import AnalystDashboardPage from './pages/AnalystDashboardPage'
import AdminDashboardPage from './pages/AdminDashboardPage'
import AlertsPage from './pages/AlertsPage'
import CasesPage from './pages/CasesPage'
import IncidentResponsePage from './pages/IncidentResponsePage'
import ApprovalsPage from './pages/ApprovalsPage'
import ConfigurationPage from './pages/ConfigurationPage'
import ResponsePoliciesPage from './pages/ResponsePoliciesPage'
import UserManagementPage from './pages/UserManagementPage'
import AuditLogsPage from './pages/AuditLogsPage'
import ServicePanelPage from './pages/ServicePanelPage'
import SettingsPage from './pages/SettingsPage'
import ProfilePage from './pages/ProfilePage'

import { usePageTitle } from './hooks/usePageTitle'
import { ApiError, api, setCsrfToken } from './api/client'
import type { ApiSession } from './api/apiTypes'
import type { DataMode } from './api/liveDataContext'
import LiveApprovals from './components/LiveApprovals'
import LiveDataProvider from './components/LiveDataProvider'

import { AUTH_STORAGE_KEY } from './data/appData'
import { DEMO_ACCOUNTS } from './data/loginData'

import type {
  AuthenticatedUser,
  DemoAccount,
  Role,
} from './types/appTypes'

function readStoredUser(): AuthenticatedUser | null {
  try {
    const storedUser = localStorage.getItem(AUTH_STORAGE_KEY)

    if (!storedUser) {
      return null
    }

    const parsedUser = JSON.parse(
      storedUser,
    ) as Partial<AuthenticatedUser>

    if (
      typeof parsedUser.email !== 'string' ||
      typeof parsedUser.name !== 'string' ||
      (
        parsedUser.role !== 'Analyst' &&
        parsedUser.role !== 'Administrator'
      )
    ) {
      localStorage.removeItem(AUTH_STORAGE_KEY)
      return null
    }

    return {
      email: parsedUser.email,
      name: parsedUser.name,
      role: parsedUser.role,
    }
  } catch {
    localStorage.removeItem(AUTH_STORAGE_KEY)
    return null
  }
}

type PendingSignIn = {
  email: string
  // Live mode: the backend's one-time challenge for the second factor
  challenge?: string
  // Demo mode: the sample account being signed in
  demoAccount?: DemoAccount
  // "Keep me signed in" was ticked
  remember: boolean
}

// VITE_DATA_MODE=demo forces sample data even when a backend is running
const FORCED_DEMO = import.meta.env.VITE_DATA_MODE === 'demo'

function App() {
  const routerNavigate = useNavigate()
  usePageTitle()

  // null while the app checks whether the backend is there
  const [mode, setMode] = useState<DataMode | null>(FORCED_DEMO ? 'demo' : null)

  const [currentUser, setCurrentUser] =
    useState<AuthenticatedUser | null>(() =>
      FORCED_DEMO ? readStoredUser() : null,
    )

  const [pendingUser, setPendingUser] =
    useState<PendingSignIn | null>(null)

  // Live mode: signed in with a temporary password, so a new one comes before the console
  const [mustChangePassword, setMustChangePassword] = useState(false)

  // Demo sign-ins are remembered in the browser only when "Keep me signed in" was ticked
  const [rememberDemo, setRememberDemo] = useState(() => readStoredUser() !== null)

  const [logoutConfirmationOpen, setLogoutConfirmationOpen] =
    useState(false)

  const role: Role =
    currentUser?.role ?? 'Analyst'

  /*
    Ask the backend who is signed in. A session cookie means live mode and
    a signed-in user; "not signed in" means live mode at the login page; no
    answer at all means the backend is not running, so the app falls back
    to demo mode with its sample data.
  */
  useEffect(() => {
    if (FORCED_DEMO) {
      return
    }

    let cancelled = false

    api<ApiSession>('/auth/me')
      .then((session) => {
        if (cancelled) {
          return
        }

        setCsrfToken(session.csrf_token)
        setCurrentUser(session.user)
        setMustChangePassword(Boolean(session.must_change_password))
        setMode('live')
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return
        }

        if (error instanceof ApiError && error.unreachable) {
          setCurrentUser(readStoredUser())
          setMode('demo')
          return
        }

        setMode('live')
      })

    return () => {
      cancelled = true
    }
  }, [])

  // Only demo sign-ins are remembered in the browser; live mode uses the session cookie
  useEffect(() => {
    // Still checking for the backend: leave a saved demo sign-in alone
    if (mode === null) {
      return
    }

    if (mode !== 'demo' || !currentUser || !rememberDemo) {
      localStorage.removeItem(AUTH_STORAGE_KEY)
      return
    }

    localStorage.setItem(
      AUTH_STORAGE_KEY,
      JSON.stringify(currentUser),
    )
  }, [currentUser, mode, rememberDemo])

  async function handleLogin(
    email: string,
    password: string,
    remember: boolean,
  ): Promise<string | null> {
    const normalizedEmail =
      email.trim().toLowerCase()

    if (mode === 'demo') {
      const account = DEMO_ACCOUNTS.find(
        (user) =>
          user.email === normalizedEmail &&
          user.password === password,
      )

      if (!account) {
        return 'Invalid email or password'
      }

      setPendingUser({ email: account.email, demoAccount: account, remember })
      routerNavigate('/mfa')
      return null
    }

    try {
      const { challenge } = await api<{ challenge: string }>('/auth/login', {
        method: 'POST',
        body: { email: normalizedEmail, password },
      })

      setPendingUser({ email: normalizedEmail, challenge, remember })
      routerNavigate('/mfa')
      return null
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        return 'Invalid email or password'
      }

      if (error instanceof ApiError && error.status === 503) {
        return 'Sign-in is not set up on the server yet. Ask an administrator.'
      }

      return error instanceof Error ? error.message : 'Sign-in failed.'
    }
  }

  function finishSignIn(user: AuthenticatedUser) {
    setCurrentUser(user)
    setPendingUser(null)

    routerNavigate('/app/dashboard', {
      replace: true,
    })
  }

  async function handleMfaVerify(code: string): Promise<string | null> {
    if (!pendingUser) {
      routerNavigate('/login', {
        replace: true,
      })
      return null
    }

    if (pendingUser.demoAccount) {
      const account = pendingUser.demoAccount

      setRememberDemo(pendingUser.remember)
      finishSignIn({ email: account.email, role: account.role, name: account.name })
      return null
    }

    try {
      const session = await api<ApiSession>('/auth/mfa', {
        method: 'POST',
        body: { challenge: pendingUser.challenge, code },
      })

      setCsrfToken(session.csrf_token)
      setMustChangePassword(Boolean(session.must_change_password))
      finishSignIn(session.user)
      return null
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        return 'Invalid or expired code. Sign in again if this keeps happening.'
      }

      return error instanceof Error ? error.message : 'Verification failed.'
    }
  }

  function logout() {
    setLogoutConfirmationOpen(false)

    if (mode === 'live') {
      // Ends the session on the server too; leave the console either way
      api('/auth/logout', { method: 'POST' }).catch(() => {})
      setCsrfToken(null)
    }

    setCurrentUser(null)
    setPendingUser(null)
    setMustChangePassword(false)

    localStorage.removeItem(AUTH_STORAGE_KEY)

    routerNavigate('/login', {
      replace: true,
    })
  }

  function requestLogout() {
    setLogoutConfirmationOpen(true)
  }

  function renderWorkspace() {
    if (!currentUser) {
      return (
        <Navigate
          to="/login"
          replace
        />
      )
    }

    if (mustChangePassword) {
      return (
        <NewPasswordPage
          name={currentUser.name}
          onDone={() => setMustChangePassword(false)}
          onLogout={logout}
        />
      )
    }

    return (
      <>
        <AppLayout
          role={currentUser.role}
          userName={currentUser.name}
          userEmail={currentUser.email}
          onLogout={requestLogout}
        >
          <Routes>
            <Route
              index
              element={
                <Navigate
                  to="dashboard"
                  replace
                />
              }
            />

            <Route
              path="dashboard"
              element={
                role === 'Administrator' ? (
                  <AdminDashboardPage />
                ) : (
                  <AnalystDashboardPage />
                )
              }
            />

            <Route
              path="alerts"
              element={
                role === 'Analyst' ? (
                  <AlertsPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="cases"
              element={
                role === 'Analyst' ? (
                  <CasesPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="incident"
              element={
                role === 'Analyst' ? (
                  <IncidentResponsePage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            {/* Both roles open the queue; what each can decide is the page's own rule */}
            <Route
              path="approvals"
              element={mode === 'live' ? <LiveApprovals /> : <ApprovalsPage />}
            />

            <Route
              path="configuration"
              element={
                role === 'Administrator' ? (
                  <ConfigurationPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="response-policies"
              element={
                role === 'Administrator' ? (
                  <ResponsePoliciesPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="user-management"
              element={
                role === 'Administrator' ? (
                  <UserManagementPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="audit-logs"
              element={
                role === 'Administrator' ? (
                  <AuditLogsPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="system-health"
              element={
                role === 'Administrator' ? (
                  // System Health is the Service Panel's "System health" tab now; old links land there
                  <Navigate
                    to="/app/service-panel?view=health"
                    replace
                  />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="service-panel"
              element={
                role === 'Administrator' ? (
                  <ServicePanelPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="settings"
              element={
                role === 'Administrator' ? (
                  <SettingsPage />
                ) : (
                  <Navigate
                    to="/app/dashboard"
                    replace
                  />
                )
              }
            />

            <Route
              path="profile"
              element={
                <ProfilePage
                  userName={currentUser.name}
                  userEmail={currentUser.email}
                  role={currentUser.role}
                />
              }
            />

            <Route
              path="*"
              element={
                <Navigate
                  to="/app/dashboard"
                  replace
                />
              }
            />
          </Routes>
        </AppLayout>

        <LogoutConfirm
          open={logoutConfirmationOpen}
          onCancel={() =>
            setLogoutConfirmationOpen(false)
          }
          onConfirm={logout}
        />
      </>
    )
  }

  if (mode === null) {
    return (
      <p className="app-connecting" role="status">
        Connecting to AthenaSec…
      </p>
    )
  }

  return (
    <LiveDataProvider mode={mode} role={currentUser?.role ?? null}>
    {/* The approval flow sits above the routes, so a request survives signing out and in as someone else */}
    <ResponsePolicyProvider userKey={currentUser?.email ?? null}>
    <ResponseStateProvider user={currentUser}>
    <Routes>
      <Route
        path="/"
        element={
          <Navigate
            to={
              currentUser
                ? '/app/dashboard'
                : '/login'
            }
            replace
          />
        }
      />

      <Route
        path="/login"
        element={
          currentUser ? (
            <Navigate
              to="/app/dashboard"
              replace
            />
          ) : (
            <LoginPage
              onSignIn={handleLogin}
              demoMode={mode === 'demo'}
            />
          )
        }
      />

      <Route
        path="/mfa"
        element={
          pendingUser ? (
            <MfaPage
              onVerify={handleMfaVerify}
              accountEmail={pendingUser.email}
              accountRole={pendingUser.demoAccount?.role ?? null}
              demoMode={mode === 'demo'}
            />
          ) : (
            <Navigate
              to="/login"
              replace
            />
          )
        }
      />

      <Route
        path="/app/*"
        element={renderWorkspace()}
      />

      <Route
        path="*"
        element={
          <Navigate
            to={
              currentUser
                ? '/app/dashboard'
                : '/login'
            }
            replace
          />
        }
      />
    </Routes>
    </ResponseStateProvider>
    </ResponsePolicyProvider>
    </LiveDataProvider>
  )
}

export default App