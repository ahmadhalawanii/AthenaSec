import type { AuditEventType } from '../types/auditLogsTypes'

/*
  The audit event types of the policy PDF (page 8), with a readable name
  for each, and which of the events the approval flow writes is which.
  An action not listed under a type here has none: the PDF has no type
  for it (see design/policy-pdf-gaps.md, gap 16 for token use).
*/
export const AUDIT_EVENT_TYPE_NAMES: Record<AuditEventType, string> = {
  recommendation_created: 'Recommendation created',
  decision_recorded: 'Decision recorded',
  action_executed: 'Action executed',
  action_failed: 'Action failed',
  action_expired: 'Action expired',
  approval_timed_out: 'Approval timed out',
  policy_violation_blocked: 'Policy violation blocked',
}

// In the PDF's order
export const AUDIT_EVENT_TYPES = Object.keys(AUDIT_EVENT_TYPE_NAMES) as AuditEventType[]

// Every action the approval flow writes, and its type (null: no PDF type)
export const FLOW_ACTION_EVENT_TYPE: Record<string, AuditEventType | null> = {
  'Requested approval': 'recommendation_created',
  'Approved action': 'decision_recorded',
  'Modified approval': 'decision_recorded',
  'Rejected action': 'decision_recorded',
  'Executed block': 'action_executed',
  'Executed host isolation': 'action_executed',
  'Execution failed': 'action_failed',
  'Action expired': 'action_expired',
  'Approval timed out': 'approval_timed_out',
  'Policy violation blocked': 'policy_violation_blocked',
  // Supporting events with no PDF type
  'Used approval token': null,
  'Advanced demo time': null,
  'Armed a failed execution': null,
  'Simulated an attempt': null,
}

export const eventTypeOf = (action: string): AuditEventType | undefined => FLOW_ACTION_EVENT_TYPE[action] ?? undefined
