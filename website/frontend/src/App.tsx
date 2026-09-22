import { useEffect, useState } from 'react'
import {
  Navigate,
  Route,
  Routes,
  useNavigate,
} from 'react-router-dom'

import AppLayout from './components/AppLayout'
import ConfirmModal from './components/ConfirmModal'

import LoginPage from './pages/LoginPage'
import MfaPage from './pages/MfaPage'

import AnalystDashboardPage from './pages/AnalystDashboardPage'
import AdminDashboardPage from './pages/AdminDashboardPage'
import AlertsPage from './pages/AlertsPage'
import CasesPage from './pages/CasesPage'
import IncidentResponsePage from './pages/IncidentResponsePage'
import ConfigurationPage from './pages/ConfigurationPage'
import DetectionRulesPage from './pages/DetectionRulesPage'
import ResponsePoliciesPage from './pages/ResponsePoliciesPage'
import IntegrationsPage from './pages/IntegrationsPage'
import UserManagementPage from './pages/UserManagementPage'
import AuditLogsPage from './pages/AuditLogsPage'
import SystemHealthPage from './pages/SystemHealthPage'
import SettingsPage from './pages/SettingsPage'
import ProfilePage from './pages/ProfilePage'

import {
  adminPages,
  analystPages,
  AUTH_STORAGE_KEY,
} from './data/appData'
import { LOGOUT_CONFIRMATION } from './data/confirmModalData'
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

function App() {
  const routerNavigate = useNavigate()

  const [currentUser, setCurrentUser] =
    useState<AuthenticatedUser | null>(() =>
      readStoredUser(),
    )

  const [pendingUser, setPendingUser] =
    useState<DemoAccount | null>(null)

  const [logoutConfirmationOpen, setLogoutConfirmationOpen] =
    useState(false)

  const role: Role =
    currentUser?.role ?? 'Analyst'

  const allowedPages =
    role === 'Administrator'
      ? adminPages
      : analystPages

  useEffect(() => {
    if (!currentUser) {
      localStorage.removeItem(AUTH_STORAGE_KEY)
      return
    }

    localStorage.setItem(
      AUTH_STORAGE_KEY,
      JSON.stringify(currentUser),
    )
  }, [currentUser])

  function handleLogin(
    email: string,
    password: string,
  ) {
    const normalizedEmail =
      email.trim().toLowerCase()

    const account = DEMO_ACCOUNTS.find(
      (user) =>
        user.email === normalizedEmail &&
        user.password === password,
    )

    if (!account) {
      return false
    }

    setPendingUser(account)
    routerNavigate('/mfa')

    return true
  }

  function handleMfaVerify() {
    if (!pendingUser) {
      routerNavigate('/login', {
        replace: true,
      })
      return
    }

    const authenticatedUser: AuthenticatedUser = {
      email: pendingUser.email,
      role: pendingUser.role,
      name: pendingUser.name,
    }

    setCurrentUser(authenticatedUser)
    setPendingUser(null)

    localStorage.setItem(
      AUTH_STORAGE_KEY,
      JSON.stringify(authenticatedUser),
    )

    routerNavigate('/app/dashboard', {
      replace: true,
    })
  }

  function navigate(page: string) {
    const nextPage =
      allowedPages.includes(page)
        ? page
        : 'dashboard'

    routerNavigate(`/app/${nextPage}`)
  }

  function logout() {
    setLogoutConfirmationOpen(false)
    setCurrentUser(null)
    setPendingUser(null)

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

    return (
      <>
        <AppLayout
          role={currentUser.role}
          userName={currentUser.name}
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
                  <AdminDashboardPage
                    onNavigate={navigate}
                  />
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
              path="detection-rules"
              element={
                role === 'Administrator' ? (
                  <DetectionRulesPage />
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
              path="integrations"
              element={
                role === 'Administrator' ? (
                  <IntegrationsPage />
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
                  <SystemHealthPage />
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

        <ConfirmModal
          open={logoutConfirmationOpen}
          {...LOGOUT_CONFIRMATION}
          onCancel={() =>
            setLogoutConfirmationOpen(false)
          }
          onConfirm={logout}
        />
      </>
    )
  }

  return (
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
  )
}

export default App