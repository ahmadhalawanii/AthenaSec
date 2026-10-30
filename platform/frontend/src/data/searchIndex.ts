import type { AdminState } from '../types/adminStateTypes'
import type { ApprovalRecord } from '../types/approvalTypes'
import type { AlertRecord } from '../types/alertsTypes'
import type { Role } from '../types/appTypes'
import type { CaseRecord } from '../types/casesTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'
import type { SearchResult } from '../types/searchTypes'

import { APPROVER_LABELS } from './agentPolicyData'
import { seedApprovalRecords } from './approvalData'
import { approvalActionTitle } from './approvalFlow'
import { initialAlerts } from './alertsData'
import { auditLogs as seedAuditLogs } from './auditLogsData'
import { initialCases } from './casesData'
import { executionRecords } from './incidentResponseData'
import { policyLabel } from './policyEngine'
import { initialResponsePolicy } from './responsePoliciesData'
import { alertResponseState, approvalForRun } from './statusSummary'
import { initialServices } from './systemHealthData'
import { initialUsers } from './userManagementData'

/*
  Records the top-bar search can find, per role. Each result opens its
  page and highlights the row whose data-record-id matches.

  Both sides are built from the current shared state: a closed,
  reassigned or retried alert, a closed case, a disabled policy, a
  suspended user or a degraded service shows its current
  status, and records added or deleted this session appear or go.
*/

const words = (...values: Array<string | number>) => values.join(' ')

type AnalystSources = {
  alerts: AlertRecord[]
  executions: ExecutionRecord[]
  cases: CaseRecord[]
  approvals: ApprovalRecord[]
}

type AdminSources = Pick<
  AdminState,
  'responsePolicy' | 'users' | 'auditLogs' | 'services'
>

// The approval queue is open to both roles, so both can find a request by id, alert, action or state
const approvalIndex = (approvals: ApprovalRecord[]): SearchResult[] =>
  approvals.map((approval) => {
    const { recommendation } = approval

    return {
      id: approval.id,
      page: 'approvals',
      pageLabel: 'Approvals',
      title: `${approval.id} · ${approvalActionTitle(approval)}`,
      detail: `${recommendation.alertId} · ${approval.decision} · ${APPROVER_LABELS[approval.requiredRole]}`,
      keywords: words(
        approval.id,
        recommendation.id,
        recommendation.alertId,
        approvalActionTitle(approval),
        approval.decision,
        APPROVER_LABELS[approval.requiredRole],
        policyLabel(approval.policy),
        approval.decidedBy?.name ?? '',
        approval.tokenId ?? '',
      ),
    }
  })

const analystIndex = ({ alerts, executions, cases, approvals }: AnalystSources): SearchResult[] => [
  ...alerts.map((alert) => {
    const state = alertResponseState(alert, executions, approvals)
    return {
      id: alert.id,
      page: 'alerts',
      pageLabel: 'Alerts',
      title: `${alert.id} · ${alert.attackType}`,
      detail: `${alert.severity} · ${state} · ${alert.endpoint} · ${alert.assignedAnalyst}`,
      keywords: words(alert.id, alert.attackType, alert.severity, alert.status, state, alert.endpoint, alert.sourceIp, alert.destinationIp, alert.assignedAnalyst),
    }
  }),
  ...cases.map((caseItem) => ({
    id: caseItem.id,
    page: 'cases',
    pageLabel: 'Cases',
    title: `${caseItem.id} · ${caseItem.attackType}`,
    detail: `From ${caseItem.sourceAlert} · ${caseItem.status} · ${caseItem.assignedAnalyst}`,
    keywords: words(caseItem.id, caseItem.sourceAlert, caseItem.attackType, caseItem.severity, caseItem.status, caseItem.endpoint, caseItem.sourceIp, caseItem.assignedAnalyst),
  })),
  ...executions.map((execution) => ({
    id: execution.id,
    page: 'incident',
    pageLabel: 'Incident Response',
    title: `${execution.id} · ${execution.action}`,
    detail: `${execution.target} · ${execution.result} · ${execution.policy}`,
    keywords: words(
      execution.id,
      execution.triggeringAlert,
      execution.action,
      execution.target,
      execution.policy,
      approvalForRun(execution, approvals)?.decidedBy?.name ?? '',
      execution.result,
    ),
  })),
  ...approvalIndex(approvals),
]

const adminIndex = ({ responsePolicy: policy, users, auditLogs, services }: AdminSources): SearchResult[] => [
  {
    id: 'response-policy',
    page: 'response-policies',
    pageLabel: 'Response Policies',
    title: `Response policy · version ${policy.version}`,
    detail: `${policy.whitelist.length} whitelisted · ${policy.blacklist.length} blacklisted`,
    keywords: words(
      'response policy whitelist blacklist protected targets',
      ...policy.whitelist.map((entry) => `${entry.action} ${entry.mode}`),
      ...policy.blacklist.map((entry) => entry.action),
      ...policy.neverBlock.map((target) => target.value),
      ...policy.neverIsolate.map((target) => target.value),
    ),
  },
  ...users.map((user) => ({
    id: user.id,
    page: 'user-management',
    pageLabel: 'Users',
    title: `${user.name}`,
    detail: `${user.email} · ${user.role} · ${user.status}`,
    keywords: words(user.id, user.name, user.email, user.role, user.status, user.department),
  })),
  ...auditLogs.map((log) => ({
    id: log.id,
    page: 'audit-logs',
    pageLabel: 'Audit Logs',
    title: `${log.id} · ${log.action}`,
    detail: `${log.user} · ${log.target} · ${log.result}`,
    keywords: words(log.id, log.action, log.user, log.target, log.category, log.result, log.sourceIp),
  })),
  ...services.map((service) => ({
    id: service.id,
    page: 'service-panel',
    view: 'health',
    pageLabel: 'Service Panel · System health',
    title: `${service.name}`,
    detail: `${service.category} · ${service.status} · ${service.id}`,
    keywords: words(service.id, service.name, service.category, service.status, service.endpoint),
  })),
]

/*
  Case-insensitive; every word typed must appear somewhere in the
  record. Results keep index order, so they arrive grouped by page.
*/
export function searchRecords(
  role: Role,
  query: string,
  // Current records on each side; both default to the seed data
  sources: AnalystSources = {
    alerts: initialAlerts,
    executions: executionRecords,
    cases: initialCases,
    approvals: seedApprovalRecords,
  },
  adminSources: AdminSources = {
    responsePolicy: initialResponsePolicy,
    users: initialUsers,
    auditLogs: seedAuditLogs,
    services: initialServices,
  },
  limit = 8,
): SearchResult[] {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)

  if (terms.length === 0) {
    return []
  }

  const index =
    role === 'Administrator'
      ? [...adminIndex(adminSources), ...approvalIndex(sources.approvals)]
      : analystIndex(sources)

  return index
    .filter((record) => {
      const haystack = record.keywords.toLowerCase()
      return terms.every((term) => haystack.includes(term))
    })
    .slice(0, limit)
}
