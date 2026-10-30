/*
  The backend's configuration, personal settings and profile (snake_case, numbers)
  and the pages' shapes (camelCase, form strings).
*/
import type { ConfigurationValues } from '../types/configurationTypes'
import type { ProfileValues } from '../types/profileTypes'
import type { SettingsValues } from '../types/settingsTypes'

export type ApiConfiguration = {
  organization: string
  workspace: string
  correlation_window_minutes: number
  critical_risk_threshold: number
  logging_destination: string
  logging_mode: string
  hot_storage_days: number
  audit_retention_days: number
  critical_alert_notification: string
  version: number
}

export function toConfiguration(doc: ApiConfiguration): ConfigurationValues {
  return {
    organization: doc.organization,
    workspace: doc.workspace,
    correlationWindowMinutes: String(doc.correlation_window_minutes),
    criticalRiskThreshold: String(doc.critical_risk_threshold),
    loggingDestination: doc.logging_destination,
    loggingMode: doc.logging_mode,
    hotStorageDays: String(doc.hot_storage_days),
    auditRetentionDays: String(doc.audit_retention_days),
    criticalAlertNotification: doc.critical_alert_notification,
  }
}

export function fromConfiguration(values: ConfigurationValues, baseVersion: number) {
  return {
    organization: values.organization.trim(),
    workspace: values.workspace,
    correlation_window_minutes: Number(values.correlationWindowMinutes),
    critical_risk_threshold: Number(values.criticalRiskThreshold),
    logging_destination: values.loggingDestination,
    logging_mode: values.loggingMode,
    hot_storage_days: Number(values.hotStorageDays),
    audit_retention_days: Number(values.auditRetentionDays),
    critical_alert_notification: values.criticalAlertNotification,
    base_version: baseVersion,
  }
}

export type ApiSettings = {
  theme: SettingsValues['theme']
  language: SettingsValues['language']
  notifications_enabled: boolean
  critical_alert_notifications: boolean
  case_notifications: boolean
  system_health_notifications: boolean
  email_notifications: boolean
  session_timeout: SettingsValues['sessionTimeout']
  mfa_enabled: boolean
  require_mfa_for_sensitive_actions: boolean
  auto_logout_warning: boolean
}

export function toSettings(doc: ApiSettings): SettingsValues {
  return {
    theme: doc.theme,
    language: doc.language,
    notificationsEnabled: doc.notifications_enabled,
    criticalAlertNotifications: doc.critical_alert_notifications,
    caseNotifications: doc.case_notifications,
    systemHealthNotifications: doc.system_health_notifications,
    emailNotifications: doc.email_notifications,
    sessionTimeout: doc.session_timeout,
    mfaEnabled: doc.mfa_enabled,
    requireMfaForSensitiveActions: doc.require_mfa_for_sensitive_actions,
    autoLogoutWarning: doc.auto_logout_warning,
  }
}

export function fromSettings(values: SettingsValues): ApiSettings {
  return {
    theme: values.theme,
    language: values.language,
    notifications_enabled: values.notificationsEnabled,
    critical_alert_notifications: values.criticalAlertNotifications,
    case_notifications: values.caseNotifications,
    system_health_notifications: values.systemHealthNotifications,
    email_notifications: values.emailNotifications,
    session_timeout: values.sessionTimeout,
    // Two-factor is required for every account in live mode
    mfa_enabled: true,
    require_mfa_for_sensitive_actions: values.requireMfaForSensitiveActions,
    auto_logout_warning: values.autoLogoutWarning,
  }
}

export type ApiProfile = {
  user_id: string
  role: string
  display_name: string
  email: string
  department: string
  phone: string
  timezone: string
}

export function toProfile(doc: ApiProfile): ProfileValues {
  return {
    displayName: doc.display_name,
    email: doc.email,
    department: doc.department,
    phone: doc.phone,
    timezone: doc.timezone,
  }
}

export function fromProfile(values: ProfileValues) {
  return {
    display_name: values.displayName.trim(),
    email: values.email.trim(),
    department: values.department.trim(),
    phone: values.phone.trim(),
    timezone: values.timezone,
  }
}
