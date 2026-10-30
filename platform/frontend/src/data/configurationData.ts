import type { ConfigurationValues } from '../types/configurationTypes'

export const initialConfiguration: ConfigurationValues = {
  organization: 'AthenaSec SOC',
  workspace: 'Production',
  // Matches the backend's default (alerts within 15 minutes can join one incident)
  correlationWindowMinutes: '15',
  criticalRiskThreshold: '90',
  loggingDestination: 'OpenSearch',
  loggingMode: 'Realtime',
  hotStorageDays: '30',
  auditRetentionDays: '365',
  criticalAlertNotification: 'Email + In-App',
}

// Allowed ranges, shown beside each field and used to validate it
export const configurationLimits = {
  correlationWindowMinutes: { min: 1, max: 1440 },
  criticalRiskThreshold: { min: 0, max: 100 },
  retentionDays: { min: 1, max: 3650 },
}

export const environmentOptions = ['Production', 'Staging', 'Development', 'Testing']
export const destinationOptions = ['OpenSearch', 'Local File', 'Syslog']
export const modeOptions = ['Realtime', 'Batch', 'Manual']

// One choice for critical alerts (the data has no per-channel settings)
export const notificationOptions = ['Email + In-App', 'Email Only', 'In-App Only', 'Disabled']
