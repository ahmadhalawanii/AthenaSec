import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import { toAlertRecord, toAuditRecord, toCaseRecord, toExecutionRecord, toServiceRecord, toUserRecord } from '../api/adapters'
import type { ApiAlert, ApiAuditEvent, ApiCase, ApiChainVerification, ApiResponseRun, ApiSystemHealth, ApiUser } from '../api/apiTypes'
import { api, apiList } from '../api/client'
import { LiveDataContext, type DataMode, type LiveData, type LiveList } from '../api/liveDataContext'
import type { Role } from '../types/appTypes'

type LiveDataProviderProps = {
  mode: DataMode
  role: Role | null
  children: ReactNode
}

const IDLE = { items: null, error: null }
const REFRESH_MS = 30000

// Loads one list; a failure only blanks that list and records why
async function load<T>(request: () => Promise<T[]>): Promise<LiveList<T>> {
  try {
    return { items: await request(), error: null }
  } catch (error) {
    return { items: [], error: error instanceof Error ? error.message : 'Could not load.' }
  }
}

function LiveDataProvider({ mode, role, children }: LiveDataProviderProps) {
  const [notice, setNotice] = useState<string | null>(null)
  const [state, setState] = useState<Omit<LiveData, 'mode' | 'refresh' | 'notice' | 'setNotice'>>({
    loading: false,
    alerts: IDLE,
    cases: IDLE,
    users: IDLE,
    services: IDLE,
    audit: IDLE,
    responses: IDLE,
    auditIntegrity: null,
  })
  const [tick, setTick] = useState(0)
  const refresh = useCallback(() => setTick((value) => value + 1), [])

  const active = mode === 'live' && role !== null

  useEffect(() => {
    if (!active) {
      return
    }

    let cancelled = false
    const isAdmin = role === 'Administrator'

    async function run() {
      setState((current) => ({ ...current, loading: true }))

      const [alerts, cases, services, responses, users, audit, integrity] = await Promise.all([
        load(() => apiList<ApiAlert>('/alerts').then((items) => items.map(toAlertRecord))),
        load(() => apiList<ApiCase>('/cases').then((items) => items.map(toCaseRecord))),
        load(() => api<ApiSystemHealth>('/system/health').then((health) => health.services.map(toServiceRecord))),
        load(() => apiList<ApiResponseRun>('/responses').then((items) => items.map(toExecutionRecord))),
        // Users and the audit log are administrator routes
        isAdmin ? load(() => apiList<ApiUser>('/users').then((items) => items.map(toUserRecord))) : Promise.resolve(IDLE),
        isAdmin ? load(() => apiList<ApiAuditEvent>('/audit').then((items) => items.map(toAuditRecord))) : Promise.resolve(IDLE),
        isAdmin ? api<ApiChainVerification>('/audit/verify').catch(() => null) : Promise.resolve(null),
      ])

      if (cancelled) {
        return
      }

      setState({
        loading: false,
        alerts,
        cases,
        services,
        responses,
        users,
        audit,
        auditIntegrity: integrity
          ? {
              status: integrity.valid ? 'intact' : 'broken',
              count: integrity.checked,
              brokenId: integrity.first_broken_seq !== null ? String(integrity.first_broken_seq) : undefined,
            }
          : null,
      })
    }

    run()
    const timer = window.setInterval(run, REFRESH_MS)

    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [active, role, tick])

  const value = useMemo<LiveData>(
    () => (active
      ? { ...state, mode, refresh, notice, setNotice }
      : { ...state, mode, refresh, notice: null, setNotice, alerts: IDLE, cases: IDLE, users: IDLE, services: IDLE, audit: IDLE, responses: IDLE, auditIntegrity: null }),
    [active, state, mode, refresh, notice],
  )

  return <LiveDataContext.Provider value={value}>{children}</LiveDataContext.Provider>
}

export default LiveDataProvider
