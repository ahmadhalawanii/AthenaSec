import type { ApprovalRecord } from '../types/approvalTypes'
import type { Role } from '../types/appTypes'
import type { AuditLogRecord } from '../types/auditLogsTypes'
import type { NotificationItem } from '../types/notificationTypes'

import { APPROVER_LABELS, DEMO_NOW, ROLE_RANK } from './agentPolicyData'
import { adminPages, analystPages } from './appData'
import { approvalActionTitle } from './approvalFlow'
import { windowState } from './policyEngine'

// Each notification opens a page its roles can reach (see appData.ts).
export const notifications: NotificationItem[] = [
  {
    id: 'NTF-001',
    title: 'New Alert',
    detail: 'ALT-004 Kernel Exploit Attempt scored Critical.',
    page: 'alerts',
    roles: ['Analyst'],
  },
  {
    id: 'NTF-002',
    title: 'Case Created',
    detail: 'CASE-008 was created from endpoint-09 telemetry.',
    page: 'cases',
    roles: ['Analyst'],
  },
  {
    id: 'NTF-003',
    title: 'Policy Updated',
    detail: 'The response policy now needs an Administrator to approve a host isolation.',
    page: 'response-policies',
    roles: ['Administrator'],
  },
  {
    id: 'NTF-004',
    title: 'System Warning',
    detail: 'Ollama Runtime latency is above the 400 ms target.',
    page: 'service-panel',
    view: 'health',
    roles: ['Administrator'],
  },
]

/*
  What the bell lists for a role: one "Approval needed" item for each
  request still waiting that this person can decide (not one they asked
  for themselves; time left measured from the demo clock), one notice
  for each request that timed out (an analyst-level one is escalated to
  the Administrator; an isolation, which the Administrator decides, gets
  its own notice), then the fixed items above.
*/
export function notificationsFor(
  role: Role,
  approvals: ApprovalRecord[] = [],
  now: string = DEMO_NOW,
  personId = '',
  audit: AuditLogRecord[] = [],
) {
  const reachable = role === 'Administrator' ? adminPages : analystPages
  const rank = ROLE_RANK[role === 'Administrator' ? 'soc_lead' : 'soc_analyst']

  const waiting: NotificationItem[] = approvals
    .filter(
      (approval) =>
        approval.decision === 'Pending' &&
        rank >= ROLE_RANK[approval.requiredRole] &&
        approval.recommendation.requestedBy !== personId,
    )
    .map((approval) => ({
      id: `NTF-${approval.id}`,
      title: 'Approval needed',
      detail: `${approvalActionTitle(approval)} (${approval.recommendation.alertId}) waits for a ${APPROVER_LABELS[approval.requiredRole]}, ${windowState(approval.recommendation.approvalDeadline, now).label.toLowerCase()}.`,
      page: 'approvals',
      roles: [role],
    }))

  const timedOut: NotificationItem[] = approvals
    .filter((approval) => approval.decision === 'Timed out')
    .map((approval) => {
      const lead = approval.requiredRole === 'soc_lead'
      const what = `${approvalActionTitle(approval)} (${approval.recommendation.alertId})`

      return {
        id: `NTF-${approval.id}-timeout`,
        title: lead ? 'Isolation approval timed out' : 'Approval timed out',
        detail:
          role === 'Administrator'
            ? lead
              ? `${what} needs an Administrator and was not decided in time. Nothing ran.`
              : `${what} was not decided in time and nothing ran. It is escalated to you.`
            : `${what} was not decided in time and nothing ran. It is escalated to the Administrator.`,
        page: 'approvals',
        roles: [role],
      }
    })

  // Policy PDF, page 5 (layer 3): every rejected attempt raises a high-severity alert to the SOC lead
  const violations: NotificationItem[] = audit
    .filter((log) => log.eventType === 'policy_violation_blocked')
    .map((log) => ({
      id: `NTF-${log.id}`,
      title: 'Policy violation blocked',
      detail: `${log.demo ? 'Demo, high severity' : 'High severity'}: ${log.target} was refused and nothing ran. ${log.metadata.Rule ?? ''}`.trim(),
      page: 'audit-logs',
      highlight: log.id,
      roles: ['Administrator'],
    }))

  return [...violations, ...waiting, ...timedOut, ...notifications].filter(
    (item) => item.roles.includes(role) && reachable.includes(item.page),
  )
}
