export type ConfigurationState = 'Saved' | 'Draft' | 'Error'

export type ConfigurationValues = {
  organization: string
  workspace: string
  correlationWindowMinutes: string
  criticalRiskThreshold: string
  loggingDestination: string
  loggingMode: string
  hotStorageDays: string
  auditRetentionDays: string
  criticalAlertNotification: string
}
