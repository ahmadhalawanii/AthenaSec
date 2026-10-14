import { useMemo, useState, type ReactNode } from 'react'

import { initialAlerts } from '../data/alertsData'
import { initialCases } from '../data/casesData'
import { caseActionStates } from '../data/statusSummary'
import { SocContext } from '../hooks/socContext'
import { useResponseState } from '../hooks/useResponseState'
import type { AlertStatus } from '../types/alertsTypes'
import type { CaseStatus } from '../types/casesTypes'
import type { AnalystAction, CaseEvent, SocState } from '../types/socTypes'

type SocStateProviderProps = {
  currentUser: string
  children: ReactNode
}

/*
  Simulated analyst actions, held in memory like the rest of the
  prototype (they reset on reload). Only the changes are stored; the
  seed data stays untouched and the current view is derived from both.
*/
function SocStateProvider({ currentUser, children }: SocStateProviderProps) {
  const [statusChanges, setStatusChanges] = useState<Record<string, AlertStatus>>({})
  const [assignments, setAssignments] = useState<Record<string, string>>({})
  // What ran, the approvals behind it and their tokens come from the approval flow (above the routes)
  const { runs: executions, approvals, facts: executionFacts, tokens } = useResponseState()
  const [actions, setActions] = useState<AnalystAction[]>([])
  const [caseStatusChanges, setCaseStatusChanges] = useState<Record<string, CaseStatus>>({})
  // Case id -> action index -> ticked (manual actions only)
  const [caseTicks, setCaseTicks] = useState<Record<string, Record<number, boolean>>>({})
  const [caseEvents, setCaseEvents] = useState<CaseEvent[]>([])

  const alerts = useMemo(
    () =>
      initialAlerts.map((alert) => ({
        ...alert,
        status: statusChanges[alert.id] ?? alert.status,
        assignedAnalyst: assignments[alert.id] ?? alert.assignedAnalyst,
      })),
    [statusChanges, assignments],
  )

  const cases = useMemo(
    () =>
      initialCases.map((caseItem) =>
        caseStatusChanges[caseItem.id]
          ? { ...caseItem, status: caseStatusChanges[caseItem.id], lastUpdated: 'Just now' }
          : caseItem,
      ),
    [caseStatusChanges],
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
      },

      assignToMe(alertId) {
        const alert = alerts.find((item) => item.id === alertId)

        if (!alert || alert.assignedAnalyst === currentUser) {
          return
        }

        setAssignments((current) => ({ ...current, [alertId]: currentUser }))
        record(alertId, `Assigned to ${currentUser}`)
      },

      // Open <-> Closed, as on the Cases page before ("Last updated" becomes "Just now")
      toggleCaseStatus(caseId) {
        const caseItem = cases.find((item) => item.id === caseId)

        if (!caseItem) {
          return
        }

        const next: CaseStatus = caseItem.status === 'Closed' ? 'Open' : 'Closed'
        setCaseStatusChanges((current) => ({ ...current, [caseId]: next }))
        setCaseEvents((current) => [
          ...current,
          { caseId, label: `${next === 'Closed' ? 'Closed' : 'Reopened'} by ${currentUser}` },
        ])
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
      },
    }
  }, [alerts, executions, approvals, executionFacts, tokens, cases, caseActions, actions, caseEvents, currentUser])

  return <SocContext.Provider value={value}>{children}</SocContext.Provider>
}

export default SocStateProvider
