import type {
  LanguagePreference,
  SessionTimeout,
  SettingsValues,
  SettingsToggle,
  ThemePreference,
} from '../types/settingsTypes'

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

// Theme swatches: sidebar, main area and accent colours of each theme
export const themeOptions: Array<{
  value: ThemePreference
  sidebar: string
  main: string
}> = [
  { value: 'Dark Enterprise', sidebar: '#3a0c14', main: '#1c0b0d' },
  { value: 'High Contrast', sidebar: '#000000', main: '#ffffff' },
]

export const languageOptions: LanguagePreference[] = ['English', 'Arabic']

export const timeoutOptions: SessionTimeout[] = ['30 minutes', '60 minutes', '4 hours']

// Switches under "Session security"
export const sessionToggles: SettingsToggle[] = [
  {
    key: 'autoLogoutWarning',
    label: 'Show warning before automatic logout',
    note: 'A warning appears shortly before the session timeout signs you out.',
  },
  {
    key: 'mfaEnabled',
    label: 'Enable MFA',
    note: 'Turning MFA off also turns off the requirement for sensitive actions.',
  },
  {
    key: 'requireMfaForSensitiveActions',
    label: 'Require MFA for sensitive administrator actions',
    note: 'Needs MFA to be enabled.',
  },
]

// Switches under "Notify me about"; the first is the master switch
export const notificationToggles: SettingsToggle[] = [
  {
    key: 'notificationsEnabled',
    label: 'Enable notifications',
    note: 'Controls whether AthenaSec displays security and operational notifications.',
  },
  {
    key: 'criticalAlertNotifications',
    label: 'Critical alert notifications',
    note: 'When a critical alert is raised.',
  },
  {
    key: 'caseNotifications',
    label: 'Case creation and assignment notifications',
    note: 'When a case is created or assigned.',
  },
  {
    key: 'systemHealthNotifications',
    label: 'System health warnings',
    note: 'When a service is slow or offline.',
  },
  {
    key: 'emailNotifications',
    label: 'Email notifications',
    note: 'Also send notifications by email.',
  },
]
