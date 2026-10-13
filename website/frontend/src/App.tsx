import { useEffect, useState } from 'react'

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
  PAGE_STORAGE_KEY,
} from './data/appData'
import { LOGOUT_CONFIRMATION } from './data/confirmModalData'
import { DEMO_ACCOUNTS } from './data/loginData'
import type {
  AppView,
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

function readStoredPage(
  user: AuthenticatedUser | null,
): string {
  if (!user) {
    return 'dashboard'
  }

  const storedPage =
    localStorage.getItem(PAGE_STORAGE_KEY) ?? 'dashboard'

  const allowedPages =
    user.role === 'Administrator'
      ? adminPages
      : analystPages

  return allowedPages.includes(storedPage)
    ? storedPage
    : 'dashboard'
}

function App() {
  const [currentUser, setCurrentUser] =
    useState<AuthenticatedUser | null>(() =>
      readStoredUser(),
    )

  const [appView, setAppView] =
    useState<AppView>(() =>
      readStoredUser() ? 'app' : 'login',
    )

  const [currentPage, setCurrentPage] =
    useState<string>(() => {
      const storedUser = readStoredUser()
      return readStoredPage(storedUser)
    })

  const [pendingUser, setPendingUser] =
    useState<DemoAccount | null>(null)

  const [logoutConfirmationOpen, setLogoutConfirmationOpen] =
    useState(false)

  const role: Role =
    currentUser?.role ?? 'Analyst'

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

  useEffect(() => {
    if (appView !== 'app' || !currentUser) {
      return
    }

    localStorage.setItem(
      PAGE_STORAGE_KEY,
      currentPage,
    )
  }, [appView, currentPage, currentUser])

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
    setAppView('mfa')

    return true
  }

  function handleMfaVerify() {
    if (!pendingUser) {
      setAppView('login')
      return
    }

    const authenticatedUser: AuthenticatedUser = {
      email: pendingUser.email,
      role: pendingUser.role,
      name: pendingUser.name,
    }

    setCurrentUser(authenticatedUser)
    setPendingUser(null)
    setCurrentPage('dashboard')
    setAppView('app')

    localStorage.setItem(
      AUTH_STORAGE_KEY,
      JSON.stringify(authenticatedUser),
    )

    localStorage.setItem(
      PAGE_STORAGE_KEY,
      'dashboard',
    )
  }

  function navigate(page: string) {
    const allowedPages =
      role === 'Administrator'
        ? adminPages
        : analystPages

    const nextPage = allowedPages.includes(page)
      ? page
      : 'dashboard'

    setCurrentPage(nextPage)

    localStorage.setItem(
      PAGE_STORAGE_KEY,
      nextPage,
    )
  }

  function logout() {
    setLogoutConfirmationOpen(false)
    setCurrentUser(null)
    setPendingUser(null)
    setCurrentPage('dashboard')
    setAppView('login')

    localStorage.removeItem(AUTH_STORAGE_KEY)
    localStorage.removeItem(PAGE_STORAGE_KEY)
  }

  function requestLogout() {
    setLogoutConfirmationOpen(true)
  }

  function renderCurrentPage() {
    switch (currentPage) {
      case 'dashboard':
        return role === 'Administrator' ? (
          <AdminDashboardPage
            onNavigate={navigate}
          />
        ) : (
          <AnalystDashboardPage />
        )

      case 'alerts':
        return <AlertsPage />

      case 'incidents':
        return <CasesPage />

      case 'response-activity':
        return <IncidentResponsePage />

      case 'configuration':
        return <ConfigurationPage />

      case 'detection-rules':
        return <DetectionRulesPage />

      case 'response-policies':
        return <ResponsePoliciesPage />

      case 'integrations':
        return <IntegrationsPage />

      case 'user-management':
        return <UserManagementPage />

      case 'audit-logs':
        return <AuditLogsPage />

      case 'system-health':
        return <SystemHealthPage />

      case 'settings':
        return <SettingsPage />

      case 'profile':
        return (
          <ProfilePage
            userName={currentUser?.name}
            userEmail={currentUser?.email}
            role={currentUser?.role}
          />
        )

      default:
        return role === 'Administrator' ? (
          <AdminDashboardPage
            onNavigate={navigate}
          />
        ) : (
          <AnalystDashboardPage />
        )
    }
  }

  if (appView === 'login') {
    return (
      <LoginPage
        onSignIn={handleLogin}
      />
    )
  }

  if (appView === 'mfa') {
    return (
      <MfaPage
        onVerify={handleMfaVerify}
      />
    )
  }

  if (!currentUser) {
    return (
      <LoginPage
        onSignIn={handleLogin}
      />
    )
  }

  return (
    <>
      <AppLayout
        role={currentUser.role}
        userName={currentUser.name}
        currentPage={currentPage}
        onNavigate={navigate}
        onLogout={requestLogout}
      >
        {renderCurrentPage()}
      </AppLayout>

      <ConfirmModal
        open={logoutConfirmationOpen}
        {...LOGOUT_CONFIRMATION}
        onCancel={() => setLogoutConfirmationOpen(false)}
        onConfirm={logout}
      />
    </>
  )
}

export default App
