import type {
  AlertRecord,
  AlertResponseState,
} from '../types/alertsTypes'
import type { ApprovalRecord } from '../types/approvalTypes'
import type { CaseRecord } from '../types/casesTypes'
import type {
  ExecutionRecord,
  ExecutionStage,
  ResponseSummary,
} from '../types/incidentResponseTypes'
import type {
  AnalystAction,
  CaseActionState,
  CaseEvent,
} from '../types/socTypes'
import type { AdminTask, PostureItem } from '../types/adminDashboardTypes'
import type { AdminState } from '../types/adminStateTypes'
import type { AuditLogRecord } from '../types/auditLogsTypes'
import type { ActivityAlert, ActivityColumn, ActivityState } from '../types/mitreTypes'
import type { Assessment } from '../types/policyTypes'
import type { TimelineStep } from '../types/uiTypes'
import type { UserRecord } from '../types/userManagementTypes'

import { auditStorage, RECENT_CHANGES_SHOWN } from './adminDashboardData'
import { ACTION_CATALOGUE, APPROVER_LABELS, OUTCOME_LABELS } from './agentPolicyData'
import { initialAlerts } from './alertsData'
import { approvalActionTitle } from './approvalFlow'
import { mitreId, mitreTactics } from './mitreData'
import { clockOf } from './policyEngine'
import {
  attentionServices,
  healthNote,
  isHealthy,
  serviceStatus,
  systemStatus,
} from './serviceInventory'
import { LATENCY_TARGET_MS } from './systemHealthData'

// The service counts and words come from the one inventory (serviceInventory.ts)
export type { SystemStatusLevel, SystemStatusSummary } from './serviceInventory'
export { healthSummary, servicesNeedingAttention, systemStatus as getSystemStatus } from './serviceInventory'

export const openAlertCount = initialAlerts.filter(
  (alert) => alert.status === 'Open',
).length

/*
  A case's recommended actions with their current state. Actions linked
  to a response run, or to an approval a run will carry out, are done
  exactly when that run completed; the rest use the analyst's ticks
  from this session, or their starting state.
*/
export function caseActionStates(
  caseItem: CaseRecord,
  executions: ExecutionRecord[],
  ticks: Record<number, boolean> = {},
): CaseActionState[] {
  return caseItem.recommendedActions.map((action, index) => {
    // Waiting on an approval until a run exists for it, then it follows that run
    if (action.approvalId) {
      const run = executions.find((item) => item.approvalId === action.approvalId)

      return run
        ? { label: action.label, done: run.result === 'Completed', runId: run.id, runResult: run.result }
        : { label: action.label, done: false, approvalId: action.approvalId }
    }

    if (action.runId) {
      const run = executions.find((item) => item.id === action.runId)
      return {
        label: action.label,
        done: run?.result === 'Completed',
        runId: action.runId,
        runResult: run?.result,
      }
    }

    return { label: action.label, done: ticks[index] ?? action.done ?? false }
  })
}

// A case's own timeline plus this session's Close/Reopen events
export function caseTimeline(caseItem: CaseRecord, events: CaseEvent[]): TimelineStep[] {
  return [
    ...caseItem.timeline.map((item) => ({
      time: item.time,
      label: item.title,
      state: item.failed ? ('fail' as const) : ('done' as const),
    })),
    ...events
      .filter((event) => event.caseId === caseItem.id)
      .map((event) => ({ time: 'Now', label: event.label, state: 'done' as const })),
  ]
}

/*
  Threat level for the top bar meter. Each open alert adds its
  severity weight; the total picks a band. The band's segment count
  fills the five-segment meter.
*/
export type ThreatLevelLabel = 'Low' | 'Guarded' | 'Elevated' | 'High' | 'Severe'

export type ThreatLevel = {
  label: ThreatLevelLabel
  segments: number
  score: number
}

export const THREAT_WEIGHTS: Record<AlertRecord['severity'], number> = {
  Critical: 3,
  High: 2,
  Medium: 1,
  Low: 0,
}

// Lowest score that reaches each band, in ascending order.
export const THREAT_BANDS: Array<{ min: number; label: ThreatLevelLabel }> = [
  { min: 0, label: 'Low' },
  { min: 1, label: 'Guarded' },
  { min: 3, label: 'Elevated' },
  { min: 6, label: 'High' },
  { min: 9, label: 'Severe' },
]

// The latest response run for an alert, if one ran (an alert can have several: a failed one, then a retry)
export function executionFor(
  alert: AlertRecord,
  executions: ExecutionRecord[],
) {
  return [...executions].reverse().find((run) => run.triggeringAlert === alert.id)
}

/*
  Where an alert stands once its response is counted: closed beats
  everything; a failed run means containment failed; a completed
  isolation means contained; a completed block on an alert that is
  still open means the source is blocked but someone has to confirm
  and close it; a recommendation nobody has decided yet is "Awaiting
  approval" (nothing has run).
*/
export function alertResponseState(
  alert: AlertRecord,
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[] = [],
): AlertResponseState {
  if (alert.status === 'Closed') {
    return 'Closed'
  }

  const latest = executionFor(alert, executions)
  // A block or isolation that lapsed no longer holds anything back
  const run = latest && !latest.reversedAt ? latest : undefined

  if (run?.result === 'Completed' && run.action === 'Isolate Host') {
    return 'Contained'
  }

  if (run?.result === 'Completed' && run.action === 'Block IP') {
    return 'Source blocked'
  }

  // A new request for a failed or lapsed run outranks the failure
  if (pendingApprovalFor(alert.id, approvals)) {
    return 'Awaiting approval'
  }

  return run?.result === 'Failed' ? 'Containment failed' : 'Open'
}

// The request for this alert that nobody has decided yet, if any
export function pendingApprovalFor(alertId: string, approvals: ApprovalRecord[]) {
  return approvals.find(
    (approval) => approval.recommendation.alertId === alertId && approval.decision === 'Pending',
  )
}

// "Block 203.0.113.45" or "Isolate endpoint-12" (defined with the approval flow)
export { approvalActionTitle }

// Open alerts and failed containments wait on an analyst
export function needsDecision(
  alert: AlertRecord,
  executions: ExecutionRecord[],
) {
  return (
    alert.status === 'Open' ||
    alertResponseState(alert, executions) === 'Containment failed'
  )
}

/*
  Active alerts (open, or containment failed) add their severity
  weight; the total picks a band.
*/
export function getThreatLevel(
  alerts: AlertRecord[],
  executions: ExecutionRecord[],
): ThreatLevel {
  const score = alerts
    .filter((alert) => needsDecision(alert, executions))
    .reduce((total, alert) => total + THREAT_WEIGHTS[alert.severity], 0)

  let bandIndex = 0
  THREAT_BANDS.forEach((band, index) => {
    if (score >= band.min) {
      bandIndex = index
    }
  })

  return {
    label: THREAT_BANDS[bandIndex].label,
    segments: bandIndex + 1,
    score,
  }
}

// The approval record a run was carried out under
export function approvalForRun(run: ExecutionRecord, approvals: ApprovalRecord[]) {
  return approvals.find((approval) => approval.id === run.approvalId)
}

/*
  A response run's pipeline. The first three stages always happened
  (a run only exists once a policy matched); the approval stage names
  who approved (from the approval record: a SOC lead or an analyst),
  and the last stage comes from the result.
*/
export function executionStages(run: ExecutionRecord, approval: ApprovalRecord | undefined): ExecutionStage[] {
  const executed: ExecutionStage =
    run.result === 'Failed'
      ? { name: 'Executed', state: 'failed', label: 'Failed' }
      : { name: 'Executed', state: 'done', label: run.reversedAt ? 'Reversed' : 'Done' }

  return [
    { name: 'Detected', state: 'done', label: 'Done' },
    { name: 'Scored', state: 'done', label: 'Done' },
    { name: 'Policy matched', state: 'done', label: 'Done' },
    approval?.decidedBy?.role === 'soc_lead'
      ? { name: 'Approved', state: 'lead', label: 'SOC lead' }
      : { name: 'Approved', state: 'analyst', label: 'Analyst' },
    executed,
  ]
}

// "14:32" to minutes since midnight
function clockMinutes(time: string) {
  const [hours, minutes] = time.split(':').map(Number)
  return hours * 60 + minutes
}

/*
  Figures above the pipeline, from the current runs. Fastest
  containment is the shortest completed run; on a tie the one that
  started first wins.
*/
export function responseSummary(
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
): ResponseSummary {
  const completed = executions.filter((run) => run.result === 'Completed')

  const fastestRun = [...completed].sort(
    (first, second) =>
      clockMinutes(first.endTime) - clockMinutes(first.startTime) -
        (clockMinutes(second.endTime) - clockMinutes(second.startTime)) ||
      clockMinutes(first.startTime) - clockMinutes(second.startTime),
  )[0]

  return {
    succeeded: completed.length,
    total: executions.length,
    fastest: fastestRun && {
      minutes: clockMinutes(fastestRun.endTime) - clockMinutes(fastestRun.startTime),
      runId: fastestRun.id,
    },
    approvedByAnalyst: executions.filter(
      (run) => approvalForRun(run, approvals)?.decidedBy?.role === 'soc_analyst',
    ).length,
    approvedByLead: executions.filter(
      (run) => approvalForRun(run, approvals)?.decidedBy?.role === 'soc_lead',
    ).length,
    awaiting: approvals.filter((approval) => approval.decision === 'Pending').length,
    failed: executions.length - completed.length,
  }
}

// A run's own timeline; the step at the end time of a failed run is marked failed
export function executionTimeline(run: ExecutionRecord): TimelineStep[] {
  const failedAt =
    run.result === 'Failed'
      ? run.timeline.findIndex((item) => item.time === run.endTime)
      : -1

  const steps: TimelineStep[] = run.timeline.map((item, index) => ({
    time: item.time,
    label: item.event,
    state: index === failedAt ? 'fail' : 'done',
  }))

  if (run.reversedAt) {
    steps.push({
      time: clockOf(run.reversedAt),
      label: run.action === 'Block IP' ? `${run.target} block lifted automatically` : `${run.target} reconnected automatically`,
      state: 'done',
    })
  }

  return steps
}

/*
  An alert's timeline, built from data rather than typed per alert:
  the response run's own timeline (or the detection time if no run),
  the case opening, anything an analyst did this session, and a final
  "now" step while it still needs a decision.
*/
export function alertTimeline(
  alert: AlertRecord,
  executions: ExecutionRecord[],
  cases: CaseRecord[],
  actions: AnalystAction[],
  approvals: ApprovalRecord[] = [],
): TimelineStep[] {
  const run = executionFor(alert, executions)
  const pending = pendingApprovalFor(alert.id, approvals)

  const steps: TimelineStep[] = run
    ? executionTimeline(run)
    : [{ time: alert.time, label: `${alert.attackType} detected`, state: 'done' }]

  const caseItem = cases.find((entry) => entry.sourceAlert === alert.id)

  if (caseItem) {
    steps.push({
      time: caseItem.createdAt.replace(/^Today,\s*/, ''),
      label: `${caseItem.id} opened for ${caseItem.assignedAnalyst}`,
      state: 'done',
    })
  }

  if (pending) {
    steps.push({
      time: clockOf(pending.recommendation.createdAt),
      label: `Agent recommended: ${approvalActionTitle(pending).toLowerCase()} for ${pending.recommendation.action.params.duration_min} min (risk ${pending.recommendation.riskScore})`,
      state: 'done',
    })
  }

  steps.sort((first, second) => first.time.localeCompare(second.time))

  actions
    .filter((action) => action.alertId === alert.id)
    .forEach((action) =>
      steps.push({ time: 'Now', label: action.label, state: 'done' }),
    )

  if (needsDecision(alert, executions)) {
    steps.push({
      time: 'Now',
      label: pending
        ? `Waiting for a ${APPROVER_LABELS[pending.requiredRole]} to approve it, by ${clockOf(pending.recommendation.approvalDeadline)}`
        : alertResponseState(alert, executions) === 'Containment failed'
          ? 'Needs a new approval or an analyst decision'
          : `Analyst review in progress (${alert.assignedAnalyst})`,
      state: 'active',
    })
  }

  return steps
}

/* =========================================================
   RESPONSE POLICIES
   ========================================================= */

// "IF Severity = Critical AND Attack Type = Brute Force" -> ["Severity = Critical", "Attack Type = Brute Force"]
export function policyConditions(condition: string) {
  return condition
    .replace(/^\s*IF\s+/i, '')
    .split(/\s+AND\s+/i)
    .map((part) => part.trim())
    .filter(Boolean)
}

// The policy's latest response run today, in words ("Last ran 14:33 on ALT-001, completed")
export function policyLastRun(
  policyName: string,
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
) {
  const run = executions
    .filter((item) => item.policy === policyName)
    .sort((a, b) => b.startTime.localeCompare(a.startTime))[0]

  if (!run) {
    return 'Has not run today'
  }

  const approver = approvalForRun(run, approvals)?.decidedBy
  const approval = approver ? `, approved by ${approver.name}` : ''

  return `Last ran ${run.endTime} on ${run.triggeringAlert} (${run.id}), ${run.result.toLowerCase()}${approval}`
}

/* =========================================================
   ADMIN DASHBOARD
   Everything here is derived from the shared admin state, so the
   dashboard follows changes made on the other admin pages.
   ========================================================= */

const plural = (count: number, one: string, many: string) =>
  `${count} ${count === 1 ? one : many}`

// Worst first: what the grid shows for a technique several alerts used
const ACTIVITY_ORDER: ActivityState[] = ['failed', 'waiting', 'open', 'handled']

function activityOf(response: AlertResponseState): ActivityState {
  if (response === 'Containment failed') {
    return 'failed'
  }

  if (response === 'Awaiting approval') {
    return 'waiting'
  }

  return response === 'Open' ? 'open' : 'handled'
}

/*
  MITRE ATT&CK activity: for each tracked technique, the alerts that used
  it (matched on the technique id) and what the agent did about them. A
  technique is failed, waiting, open or handled by its worst alert, and
  quiet when no alert uses it. Everything follows the live alert,
  response and approval state.
*/
export function attackActivity(
  alerts: AlertRecord[],
  executions: ExecutionRecord[],
  approvals: ApprovalRecord[],
  assessments: Record<string, Assessment>,
): ActivityColumn[] {
  return mitreTactics.map((tactic) => {
    const cells = tactic.techniques.map((technique) => {
      const used = alerts
        .filter((alert) => mitreId(alert.mitre) === technique.id)
        .map((alert): ActivityAlert => {
          const assessment = assessments[alert.id]

          return {
            id: alert.id,
            title: alert.attackType,
            risk: assessment?.risk ?? alert.risk,
            outcome: assessment ? OUTCOME_LABELS[assessment.outcome] : 'Not assessed',
            response: alertResponseState(alert, executions, approvals),
            approvalId: approvals.find(
              (approval) => approval.recommendation.alertId === alert.id && approval.decision === 'Pending',
            )?.id,
          }
        })
      const worst = ACTIVITY_ORDER.find((state) => used.some((item) => activityOf(item.response) === state))

      return { ...technique, state: worst ?? ('quiet' as const), alerts: used }
    })

    return {
      tactic: tactic.name,
      cells,
      seenCount: cells.filter((cell) => cell.state !== 'quiet').length,
    }
  })
}

export function adminPosture(
  state: Pick<AdminState, 'responsePolicy' | 'users' | 'services' | 'configuration'>,
): PostureItem[] {
  const { responsePolicy, users, services, configuration } = state

  const healthy = services.filter(isHealthy).length
  const status = systemStatus(services)

  // The actions the agent may use: the whitelist, out of every action that is not prohibited
  const allowed = responsePolicy.whitelist.length
  const automatic = responsePolicy.whitelist.filter((entry) => entry.mode === 'Automatic').length
  const needApproval = allowed - automatic
  const usable = ACTION_CATALOGUE.filter((row) => row.tier !== 3).length
  // "9 automatic, 2 need approval"
  const policyNote = [
    automatic > 0 ? `${automatic} automatic` : '',
    needApproval > 0 ? `${needApproval} need approval` : '',
  ]
    .filter(Boolean)
    .join(', ')

  const withMfa = users.filter((user) => user.mfaEnabled).length
  const missingMfa = users.filter((user) => !user.mfaEnabled)

  return [
    {
      page: 'service-panel',
      view: 'health',
      value: String(healthy),
      total: `/${services.length}`,
      label: 'Services healthy',
      note: healthNote(services),
      tone: status.level === 'danger' ? 'danger' : status.level === 'ok' ? undefined : 'warn',
    },
    {
      page: 'response-policies',
      value: String(allowed),
      total: `/${usable}`,
      label: 'Actions on the whitelist',
      note: policyNote || 'None allowed',
    },
    {
      page: 'user-management',
      value: String(withMfa),
      total: `/${users.length}`,
      label: 'Users with MFA',
      note:
        missingMfa.length === 0
          ? 'Every account has MFA'
          : missingMfa.length === 1
            ? `${missingMfa[0].name} is missing MFA`
            : `${plural(missingMfa.length, 'user is', 'users are')} missing MFA`,
      tone: missingMfa.length > 0 ? 'danger' : undefined,
    },
    {
      page: 'audit-logs',
      value: `${auditStorage.storedPercent}%`,
      label: 'Audit events stored',
      note: `${auditStorage.store}, kept ${configuration.auditRetentionDays} days`,
    },
  ]
}

// User Management's "Account health": every figure is counted from the accounts
export function accountHealth(users: UserRecord[]) {
  const active = users.filter((user) => user.status === 'Active')

  return {
    total: users.length,
    activeWithMfa: active.filter((user) => user.mfaEnabled).length,
    activeWithoutMfa: active.filter((user) => !user.mfaEnabled).length,
    suspended: users.length - active.length,
    administrators: users.filter((user) => user.role === 'Administrator').length,
    analysts: users.filter((user) => user.role === 'Analyst').length,
  }
}

// Accounts that are suspended and have no MFA: remove them, or require MFA before reactivating
export function accessReview(users: UserRecord[]) {
  return users.filter((user) => user.status === 'Suspended' && !user.mfaEnabled)
}

const TASK_ORDER: Record<string, number> = { danger: 0, warn: 1, caution: 2, info: 3, neutral: 4, ok: 5 }

// Things only an administrator can resolve, most urgent first
export function needsAdministrator(
  state: Pick<AdminState, 'users' | 'services'>,
): AdminTask[] {
  const { users, services } = state
  const tasks: AdminTask[] = []

  users
    .filter((user) => !user.mfaEnabled)
    .forEach((user) =>
      tasks.push({
        id: `user-${user.id}`,
        tone: 'danger',
        text:
          user.status === 'Suspended'
            ? `${user.name} has MFA disabled and is suspended.`
            : `${user.name} has MFA disabled.`,
        linkLabel: 'Review user',
        page: 'user-management',
        recordId: user.id,
      }),
    )

  // Worst first; the sort below keeps this order within a tone
  attentionServices(services).forEach((service) => {
    const status = serviceStatus(service)
    const text =
      status === 'Degraded'
        ? service.latency !== null && service.latency > LATENCY_TARGET_MS
          ? `${service.name} latency is ${service.latency} ms, above the ${LATENCY_TARGET_MS} ms target.`
          : `${service.name} is degraded.`
        : status === 'Failed'
          ? `${service.name} has failed.`
          : status === 'Stopped'
            ? `${service.name} is stopped.`
            : status === 'Starting'
              ? `${service.name} is still starting.`
              : `${service.name} could not be verified.`

    tasks.push({
      id: `service-${service.id}`,
      tone: status === 'Failed' || status === 'Stopped' ? 'danger' : 'warn',
      text,
      linkLabel: 'Check health',
      page: 'service-panel',
      view: 'health',
      recordId: service.id,
    })
  })

  return tasks.sort((a, b) => TASK_ORDER[a.tone] - TASK_ORDER[b.tone])
}

// The latest administrator changes, newest first ("15:42" from the timestamp)
export function recentAdminChanges(auditLogs: AuditLogRecord[]) {
  return auditLogs
    .filter((log) => log.role === 'Administrator')
    .slice(0, RECENT_CHANGES_SHOWN)
    .map((log) => ({ ...log, time: log.timestamp.slice(11, 16) }))
}
