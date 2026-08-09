export type ThemePreference =
  | 'Dark Enterprise'
  | 'High Contrast'

export type LanguagePreference = 'English' | 'Arabic'

export type SessionTimeout =
  | '30 minutes'
  | '60 minutes'
  | '4 hours'

export type SettingsState = 'Saved' | 'Draft' | 'Error'

export type SettingsValues = {
  theme: ThemePreference
  language: LanguagePreference
  notificationsEnabled: boolean
  criticalAlertNotifications: boolean
  caseNotifications: boolean
  systemHealthNotifications: boolean
  emailNotifications: boolean
  sessionTimeout: SessionTimeout
  mfaEnabled: boolean
  requireMfaForSensitiveActions: boolean
  autoLogoutWarning: boolean
}
