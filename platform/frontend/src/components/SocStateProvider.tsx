import { useMemo, useState, type ReactNode } from 'react'

import { api } from '../api/client'
import { useLiveData } from '../api/liveDataContext'
import { initialAlerts } from '../data/alertsData'
import { initialCases } from '../data/casesData'
import { caseActionStates } from '../data/statusSummary'
import { SocContext } from '../hooks/socContext'
import { useResponseState } from '../hooks/useResponseState'
import type { AlertRecord, AlertStatus } from '../types/alertsTypes'
import type { CaseRecord, CaseStatus } from '../types/casesTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'
import type { AnalystAction, CaseEvent, SocState } from '../types/socTypes'

const NO_ALERTS: AlertRecord[] = []
const NO_CASES: CaseRecord[] = []
const NO_RUNS: ExecutionRecord[] = []

type SocStateProviderProps = {
  currentUser: string
  children: ReactNode
}

/*
  Analyst actions. Only the changes are stored; the seed data stays
  untouched and the current view is derived from both.

  Demo mode: held in memory like the rest of the prototype (they reset on reload).
  Live mode: each change shows at once, is sent to the backend, and the lists are
  fetched again. The local changes are dropped whenever a new copy of the alerts or
  cases arrives, so the backend's state wins. A refused change is put back and the
  reason shown (LiveNotice).
*/
function SocStateProvider({ currentUser, children }: SocStateProviderProps) {
  const [statusChanges, setStatusChanges] = useState<Record<string, AlertStatus>>({})
  const [assignments, setAssignments] = useState<Record<string, string>>({})
  // What ran, the approvals behind it and their tokens come from the approval flow (above the routes)
  const { runs: flowRuns, approvals, facts: executionFacts, tokens } = useResponseState()
  const [actions, setActions] = useState<AnalystAction[]>([])
  const [caseStatusChanges, setCaseStatusChanges] = useState<Record<string, CaseStatus>>({})
  // Case id -> action index -> ticked (manual actions only)
  const [caseTicks, setCaseTicks] = useState<Record<string, Record<number, boolean>>>({})
  const [caseEvents, setCaseEvents] = useState<CaseEvent[]>([])

  // Live mode starts from the backend's alerts and cases; demo mode from the sample data
  const live = useLiveData()
  const isLive = live.mode === 'live'
  const seedAlerts = isLive ? live.alerts.items ?? NO_ALERTS : initialAlerts
  const seedCases = isLive ? live.cases.items ?? NO_CASES : initialCases
  const { refresh: refreshLive, setNotice } = live
  // Live mode: what the backend actually ran; demo mode: the approval flow's runs
  const executions = isLive ? live.responses.items ?? NO_RUNS : flowRuns

  // A new copy from the backend replaces this tab's pending changes
  const [seenAlerts, setSeenAlerts] = useState(seedAlerts)
  const [seenCases, setSeenCases] = useState(seedCases)

  if (isLive && seenAlerts !== seedAlerts) {
    setSeenAlerts(seedAlerts)
    setStatusChanges({})
    setAssignments({})
  }

  if (isLive && seenCases !== seedCases) {
    setSeenCases(seedCases)
    setCaseStatusChanges({})
    setCaseTicks({})
  }

  const alerts = useMemo(
    () =>
      seedAlerts.map((alert) => ({
        ...alert,
        status: statusChanges[alert.id] ?? alert.status,
        assignedAnalyst: assignments[alert.id] ?? alert.assignedAnalyst,
      })),
    [seedAlerts, statusChanges, assignments],
  )

  const cases = useMemo(
    () =>
      seedCases.map((caseItem) =>
        caseStatusChanges[caseItem.id]
          ? { ...caseItem, status: caseStatusChanges[caseItem.id], lastUpdated: 'Just now' }
          : caseItem,
      ),
    [seedCases, caseStatusChanges],
  )

  const caseActions = useMemo(
    () =>
      Object.fromEntries(
        cases.map((caseItem) => [
          caseItem.id,
          caseActionStates(caseItem, executions, caseTicks[caseItem.id]),
        ]),
      ),
    [cases, executions, caseTicks],
  )

  const value = useMemo<SocState>(() => {
    function record(alertId: string, label: string) {
      setActions((current) => [...current, { alertId, label }])
    }

    // Live mode: send the change; on failure run undo and say why
    function send(path: string, body: unknown, undo: () => void, method: 'POST' | 'PUT' = 'POST') {
      if (!isLive) {
        return
      }

      api(path, { method, body })
        .then(() => refreshLive())
        .catch((error: unknown) => {
          undo()
          setNotice(`Not saved: ${error instanceof Error ? error.message : 'the backend refused the change.'}`)
        })
    }

    return {
      alerts,
      executions,
      cases,
      caseActions,
      actions,
      caseEvents,
      currentUser,
      approvals,
      executionFacts,
      tokens,

      // Closed <-> Open, as on the Alerts page before
      toggleAlertStatus(alertId) {
        const alert = alerts.find((item) => item.id === alertId)

        if (!alert) {
          return
        }

        const next: AlertStatus = alert.status === 'Closed' ? 'Open' : 'Closed'
        setStatusChanges((current) => ({ ...current, [alertId]: next }))
        record(alertId, `${next === 'Closed' ? 'Closed' : 'Reopened'} by ${currentUser}`)
        send(`/alerts/${encodeURIComponent(alertId)}/status`, { status: next.toLowerCase() }, () =>
          setStatusChanges((current) => ({ ...current, [alertId]: alert.status })),
        )
      },

      assignToMe(alertId) {
        const alert = alerts.find((item) => item.id === alertId)

        if (!alert || alert.assignedAnalyst === currentUser) {
          return
        }

        setAssignments((current) => ({ ...current, [alertId]: currentUser }))
        record(alertId, `Assigned to ${currentUser}`)
        send(`/alerts/${encodeURIComponent(alertId)}/assign`, undefined, () =>
          setAssignments((current) => ({ ...current, [alertId]: alert.assignedAnalyst })),
        )
      },

      // Open <-> Closed, as on the Cases page before ("Last updated" becomes "Just now")
      toggleCaseStatus(caseId) {
        const caseItem = cases.find((item) => item.id === caseId)

        if (!caseItem) {
          return
        }

        const next: CaseStatus = caseItem.status === 'Closed' ? 'Open' : 'Closed'
        setCaseStatusChanges((current) => ({ ...current, [caseId]: next }))

        // Live mode: the backend adds the timeline entry itself
        if (!isLive) {
          setCaseEvents((current) => [
            ...current,
            { caseId, label: `${next === 'Closed' ? 'Closed' : 'Reopened'} by ${currentUser}` },
          ])
        }

        send(`/cases/${encodeURIComponent(caseId)}/status`, { status: next.toLowerCase() }, () =>
          setCaseStatusChanges((current) => ({ ...current, [caseId]: caseItem.status })),
        )
      },

      toggleCaseAction(caseId, index) {
        const action = caseActions[caseId]?.[index]

        // Actions a response run carries out can't be ticked by hand
        if (!action || action.runId || action.approvalId) {
          return
        }

        setCaseTicks((current) => ({
          ...current,
          [caseId]: { ...current[caseId], [index]: !action.done },
        }))

        const position = cases.find((item) => item.id === caseId)?.recommendedActions[index]?.position ?? index
        send(
          `/cases/${encodeURIComponent(caseId)}/actions/${position}`,
          { done: !action.done },
          () => setCaseTicks((current) => ({ ...current, [caseId]: { ...current[caseId], [index]: action.done } })),
          'PUT',
        )
      },
    }
  }, [alerts, executions, approvals, executionFacts, tokens, cases, caseActions, actions, caseEvents, currentUser, isLive, refreshLive, setNotice])

  return <SocContext.Provider value={value}>{children}</SocContext.Provider>
}

export default SocStateProvider
