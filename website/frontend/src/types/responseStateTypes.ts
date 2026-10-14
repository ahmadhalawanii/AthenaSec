import type { Actor, ApprovalRecord, ExecutionFacts, FlowState } from './approvalTypes'
import type { AuditLogRecord } from './auditLogsTypes'
import type { ExecutionRecord } from './incidentResponseTypes'
import type { ApprovalToken, AttemptDecision, AttemptRequest } from './policyTypes'

export type DecisionRequest = {
  approvalId: string
  kind: 'approve' | 'modify' | 'reject'
  reason: string
  minutes?: number
}

export type DecisionOutcome = { ok: true } | { ok: false; reason: string }

export type AttemptOutcome = { ok: true; decision: AttemptDecision } | { ok: false; reason: string }

/*
  The approval flow's state for the whole session (ResponseStateProvider,
  mounted above the routes so a request survives signing out and in as
  someone else). It resets when the page reloads.
*/
export type ResponseState = {
  // False for a moment after load while the seed token's digest is computed
  ready: boolean
  // The demo clock; the only "now" any deadline is compared with
  now: string
  // The signed-in person as the approval rules see them, or null when signed out
  actor: Actor | null
  approvals: ApprovalRecord[]
  tokens: ApprovalToken[]
  facts: ExecutionFacts[]
  runs: ExecutionRecord[]
  // Approved requests whose executor has started and not finished
  running: FlowState['running']
  // Why the guard refused to run a request, by approval id
  refusals: FlowState['refusals']
  // Demo mode: the next execution is armed to fail
  failNext: boolean
  // The approval flow's audit events, numbered, newest first
  auditEvents: AuditLogRecord[]
  // The last thing the flow did, in words, for a screen-reader status region
  announcement: string
  // Why this person cannot decide on this request right now, or null when they can
  refusalFor: (approval: ApprovalRecord) => string | null
  // Why this run cannot be asked for again (alertOpen: the alert it belongs to is still open), or null
  requestAgainRefusal: (run: ExecutionRecord, alertOpen: boolean) => string | null
  decide: (request: DecisionRequest) => Promise<DecisionOutcome>
  // Demo mode, all on the demo clock: fixed steps of 5 or 15 minutes, an armed failure, asking again
  advance: (minutes: number) => DecisionOutcome
  armFailure: () => DecisionOutcome
  requestAgain: (runId: string, alertOpen: boolean) => DecisionOutcome
  // Demo mode: ask the policy guard what it would do with an action. Runs nothing; audited as Demo.
  simulateAttempt: (request: AttemptRequest) => AttemptOutcome
  // Back to the seed state (reloads the app)
  resetDemo: () => void
}
