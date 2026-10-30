import { createContext, useContext } from 'react'

import type { AlertRecord } from '../types/alertsTypes'
import type { AuditIntegrity, AuditLogRecord } from '../types/auditLogsTypes'
import type { CaseRecord } from '../types/casesTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'
import type { ServiceRecord } from '../types/systemHealthTypes'
import type { UserRecord } from '../types/userManagementTypes'

/*
  live: signed in against the backend; pages show its data.
  demo: the backend is not reachable (or VITE_DATA_MODE=demo); pages use
        the sample data in src/data/, as the prototype always did.
*/
export type DataMode = 'live' | 'demo'

// One list loaded from the backend. null = not loaded (demo mode, or still loading)
export type LiveList<T> = { items: T[] | null; error: string | null }

export type LiveData = {
  mode: DataMode
  loading: boolean
  alerts: LiveList<AlertRecord>
  cases: LiveList<CaseRecord>
  users: LiveList<UserRecord>
  services: LiveList<ServiceRecord>
  audit: LiveList<AuditLogRecord>
  // Executed containment actions (GET /responses)
  responses: LiveList<ExecutionRecord>
  auditIntegrity: AuditIntegrity | null
  // Fetch everything again (after an approval decision, for example)
  refresh: () => void
  // A change the backend refused or could not save, shown above every page until dismissed
  notice: string | null
  setNotice: (message: string | null) => void
}

const empty = { items: null, error: null }

export const LiveDataContext = createContext<LiveData>({
  mode: 'demo',
  loading: false,
  alerts: empty,
  cases: empty,
  users: empty,
  services: empty,
  audit: empty,
  responses: empty,
  auditIntegrity: null,
  refresh: () => {},
  notice: null,
  setNotice: () => {},
})

export function useLiveData() {
  return useContext(LiveDataContext)
}
