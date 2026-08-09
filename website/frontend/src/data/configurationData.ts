import type { ConfigurationValues } from '../types/configurationTypes'

export const initialConfiguration: ConfigurationValues = {
  organization: 'AthenaSec SOC',
  workspace: 'Production',
  correlationWindowMinutes: '5',
  criticalRiskThreshold: '90',
  loggingDestination: 'OpenSearch',
  loggingMode: 'Realtime',
  hotStorageDays: '30',
  auditRetentionDays: '365',
  criticalAlertNotification: 'Email + In-App',
}
