import type { AuditStorage } from '../types/adminDashboardTypes'

/*
  Audit storage health for the dashboard's posture strip. The last audit
  synchronization (AUD-196) indexed every event with no rejected records.
  The retention period comes from the saved configuration.
*/
export const auditStorage: AuditStorage = {
  storedPercent: 100,
  store: 'OpenSearch',
}

// How many recent administrative changes the dashboard lists
export const RECENT_CHANGES_SHOWN = 4
