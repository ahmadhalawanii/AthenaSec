import type { SettingsValues } from '../types/settingsTypes'

export const initialSettings: SettingsValues = {
  theme: 'Dark Enterprise',
  language: 'English',
  notificationsEnabled: true,
  criticalAlertNotifications: true,
  caseNotifications: true,
  systemHealthNotifications: true,
  emailNotifications: true,
  sessionTimeout: '30 minutes',
  mfaEnabled: true,
  requireMfaForSensitiveActions: true,
  autoLogoutWarning: true,
}
