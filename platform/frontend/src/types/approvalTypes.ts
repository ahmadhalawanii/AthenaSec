import type { AuditEventType, AuditRecordFields } from './auditLogsTypes'
import type { ExecutionRecord } from './incidentResponseTypes'
import type { ApprovalToken, ApproverRole, Recommendation, Tier2ActionName, Tier2Proposal } from './policyTypes'

/*
  Approval records: the human decision on one Tier 2 recommendation
  (design/agent-action-policy.pdf). Times are "2026-08-03T15:43:10"
  strings, as in policyEngine.ts. A token is stored separately
  (ApprovalToken in policyTypes.ts) and the record points to it.
*/

export type ApprovalDecision = 'Pending' | 'Approved' | 'Rejected' | 'Timed out'

// What the action's rule in the response policy was when the request was checked
export type PolicySnapshot = {
  version: number
  action: Tier2ActionName
  approver: ApproverRole
  minRisk: number
  // Not set for an action with no duration
  maxMinutes?: number
  windowMinutes: number
}

export type Decider = {
  id: string
  name: string
  role: ApproverRole
}

export type ApprovalRecord = {
  id: string
  recommendation: Recommendation
  // The role the action's catalogue row asks for
  requiredRole: ApproverRole
  policy: PolicySnapshot
  decision: ApprovalDecision
  // Set once a person has approved or rejected
  decidedBy?: Decider
  decidedAt?: string
  // Required to reject, and when the approver shortened the duration
  reason?: string
  // What was approved: the recommendation, or the same action with a shorter duration
  approvedAction?: Tier2Proposal
  tokenId?: string
  executionId?: string
}

// Who is acting: the signed-in person, as the approval rules see them
export type Actor = {
  id: string
  name: string
  // The role in the policy: Analyst is soc_analyst, Administrator is soc_lead
  role: ApproverRole
  sourceIp: string
}

// An audit event as the response flow produces it; the audit log numbers it and stamps its time
export type FlowEvent = {
  // Demo-clock time, "2026-08-03T15:46:00"
  at: string
  user: string
  role: 'Analyst' | 'Administrator' | 'System'
  sourceIp: string
  action: string
  target: string
  description: string
  changes: string[]
  metadata: Record<string, string>
  // Written by a Demo mode control
  demo?: boolean
  // 'Success' unless the event records a failure or a refusal
  result?: 'Success' | 'Failed' | 'Denied'
  // The policy PDF's event type and record fields, for the events it names
  eventType?: AuditEventType
  record?: AuditRecordFields
}

/*
  Everything the approval flow changes, as one value: the demo clock,
  the requests and their tokens, what has run, what is running, and the
  audit events so far. The flow functions (approvalFlow.ts) take one and
  return the next; nothing here reads the real clock.
*/
export type FlowState = {
  now: string
  approvals: ApprovalRecord[]
  tokens: ApprovalToken[]
  facts: ExecutionFacts[]
  runs: ExecutionRecord[]
  // Approved requests whose executor has started but not finished (token already used up)
  running: string[]
  // Why the guard refused to run an approved request, by approval id
  refusals: Record<string, string>
  // Demo mode: the next execution that starts will fail (its token is still used up)
  failNext: boolean
  // Approved requests whose run has started and will fail when it finishes
  failing: string[]
  events: FlowEvent[]
}

export type FlowResult =
  | { ok: true; state: FlowState }
  // A refusal; `state` carries the one change a refusal may leave (the reason on a request that never started)
  | { ok: false; code: string; reason: string; state?: FlowState }

// What an executor recorded when it ran an approved action
export type ExecutionFacts = {
  id: string
  approvalId: string
  startedAt: string
  // When the action reverses on its own (block lifted, host reconnected)
  expiresAt: string
  action: Tier2Proposal
}

// The first rule a record breaks, or ok
export type ApprovalCheck = {
  ok: boolean
  code:
    | 'ok'
    | 'role_mismatch'
    | 'mode_not_allowed'
    | 'unexpected_fields'
    | 'missing_decision'
    | 'self_approval'
    | 'wrong_role'
    | 'before_request'
    | 'after_deadline'
    | 'reason_required'
    | 'action_changed'
    | 'duration_not_shorter'
    | 'duration_over_max'
    | 'no_token'
    | 'token_mismatch'
    | 'digest_mismatch'
    | 'token_used_without_execution'
    | 'execution_without_token'
    | 'multiple_executions'
    | 'execution_outside_token'
    | 'execution_changed'
    | 'wrong_expiry'
  reason: string
}
