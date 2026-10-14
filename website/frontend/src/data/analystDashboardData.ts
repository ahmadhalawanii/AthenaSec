import type { AlertRecord } from '../types/alertsTypes'
import type {
  DecisionItem,
  PostureItem,
  ResponseLogItem,
} from '../types/analystDashboardTypes'
import type { ApprovalRecord } from '../types/approvalTypes'
import type { CaseRecord } from '../types/casesTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'

import { APPROVER_LABELS } from './agentPolicyData'
import { clockOf } from './policyEngine'
import {
  alertResponseState,
  approvalActionTitle,
  approvalForRun,
  executionFor,
  needsDecision,
  pendingApprovalFor,
} from './statusSummary'

/*
  Dashboard figures. Each builder takes the current alerts, response
  runs and cases (seed data plus anything changed this session), so
  the dashboard agrees with the Alerts, Cases and Incident Response
  pages after every action.
*/

function joinNames(names: string[]) {
  return names.length === 0 ? 'None' : names.join(', ')
}

export function buildPosture(
  alerts: AlertRecord[],
  executions: ExecutionRecord[],
  cases: CaseRecord[],
  approvals: ApprovalRecord[],
): PostureItem[] {
  // Still attacking: needs a person, and nothing has blocked or contained it
  const active = alerts.filter((alert) =>
    ['Open', 'Awaiting approval', 'Containment failed'].includes(
      alertResponseState(alert, executions, approvals),
    ),
  )
  const open = alerts.filter((alert) => alert.status === 'Open')
  const criticalOpen = alerts.filter(
    (alert) => alert.severity === 'Critical' && needsDecision(alert, executions),
  )
  // Only what is still in force: a block or isolation that lapsed no longer counts
  const blocked = executions.filter(
    (run) => run.action === 'Block IP' && run.result === 'Completed' && !run.reversedAt,
  )
  const isolated = executions.filter(
    (run) => run.action === 'Isolate Host' && run.result === 'Completed' && !run.reversedAt,
  )
  const openCases = cases.filter((caseItem) => caseItem.status === 'Open')

  return [
    {
      value: active.length,
      label: active.length === 1 ? 'Active attack path' : 'Active attack paths',
      note: joinNames(active.map((alert) => alert.id)),
      tone: active.length > 0 ? 'warn' : undefined,
    },
    {
      value: open.length,
      label: 'Open alerts',
      note: `of ${alerts.length} today`,
    },
    {
      value: criticalOpen.length,
      label: 'Critical, needs decision',
      note: joinNames(criticalOpen.map((alert) => alert.id)),
      tone: criticalOpen.length > 0 ? 'danger' : undefined,
    },
    {
      value: blocked.length,
      label: blocked.length === 1 ? 'Source blocked' : 'Sources blocked',
      note: joinNames(blocked.map((run) => run.target)),
    },
    {
      value: isolated.length,
      label: isolated.length === 1 ? 'Host isolated' : 'Hosts isolated',
      note: joinNames(isolated.map((run) => run.target)),
      tone: isolated.length > 0 ? 'info' : undefined,
    },
    {
      value: openCases.length,
      label: 'Open cases',
      note: joinNames([...new Set(openCases.map((caseItem) => caseItem.assignedAnalyst))]),
    },
  ]
}

// Failed containment first, then by risk
export function buildDecisionQueue(
  alerts: AlertRecord[],
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
): DecisionItem[] {
  return alerts
    .filter((alert) => needsDecision(alert, executions))
    .map((alert) => {
      const state = alertResponseState(alert, executions, approvals)
      const run = executionFor(alert, executions)
      const pending = pendingApprovalFor(alert.id, approvals)

      let detail = `Open, assigned to ${alert.assignedAnalyst}`

      if (state === 'Containment failed' && run) {
        detail = `${run.action} on ${run.target} failed at ${run.endTime}, needs a new approval`
      } else if (state === 'Source blocked' && run) {
        detail = `${run.target} blocked at ${run.endTime}, confirm and close`
      } else if (state === 'Contained' && run) {
        detail = `${run.target} isolated at ${run.endTime}, confirm and close`
      } else if (pending) {
        detail = `${approvalActionTitle(pending)} waits for a ${APPROVER_LABELS[pending.requiredRole]}, by ${clockOf(pending.recommendation.approvalDeadline)}`
      } else if (run?.reversedAt) {
        detail = `${run.target} ${run.action === 'Block IP' ? 'block lapsed' : 'isolation lapsed'} at ${clockOf(run.reversedAt)}, ask again if it is still needed`
      }

      return { alert, state, detail }
    })
    .sort((first, second) => {
      const firstFailed = first.state === 'Containment failed' ? 1 : 0
      const secondFailed = second.state === 'Containment failed' ? 1 : 0
      return secondFailed - firstFailed || second.alert.risk - first.alert.risk
    })
}

/*
  The attack path to show first: among the active ones (Open, Awaiting
  approval or Containment failed, so nothing blocks or contains them)
  prefer one that waits for a person's approval, then the highest risk.
  With none active it falls back to the first decision, then the first path.
*/
export function mostUrgentPath(
  paths: Array<{ alert: AlertRecord; status: string; statusLabel: string }>,
  queue: DecisionItem[],
) {
  const awaiting = (path: { statusLabel: string }) => Number(path.statusLabel === 'Awaiting approval')
  const active = paths
    .filter((path) => path.status === 'active')
    .sort((first, second) => awaiting(second) - awaiting(first) || second.alert.risk - first.alert.risk)

  return active[0]?.alert.id ?? queue[0]?.alert.id ?? paths[0]?.alert.id ?? ''
}

// Newest first
export function buildResponseLog(
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
): ResponseLogItem[] {
  return [...executions]
    .sort((first, second) => second.endTime.localeCompare(first.endTime))
    .map((run) => {
      const approver = approvalForRun(run, approvals)?.decidedBy

      return {
        id: run.id,
        time: run.endTime,
        action: `${run.action} ${run.target}`,
        by: `${approver ? `Approved by ${approver.name}` : 'No approval on record'}, ${run.policy}`,
        result: run.result === 'Completed' ? 'Done' : 'Failed',
      }
    })
}

// The most recent alert time, shown instead of a live clock
export function latestEventTime(alerts: AlertRecord[]) {
  return alerts.reduce((latest, alert) => (alert.time > latest ? alert.time : latest), '00:00')
}
