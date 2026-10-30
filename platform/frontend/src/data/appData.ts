import type { Role } from '../types/appTypes'

// Set only when "Keep me signed in" is ticked (demo mode)
export const AUTH_STORAGE_KEY = 'athenasec-remembered-user'

// How each role is named to people (account pill, Demo mode, MFA)
export const ROLE_LABELS: Record<Role, string> = {
  Analyst: 'Security analyst',
  Administrator: 'Administrator',
}
export const PAGE_STORAGE_KEY = 'athenasec-current-page'

export const analystPages = [
  'dashboard',
  'alerts',
  'cases',
  'incident',
  'approvals',
  'profile',
]

export const adminPages = [
  'dashboard',
  'configuration',
  'response-policies',
  'approvals',
  'user-management',
  'audit-logs',
  'service-panel',
  'settings',
  'profile',
]
