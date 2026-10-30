import type { ApprovalRecord, ExecutionFacts } from './approvalTypes'
import type { AlertRecord } from './alertsTypes'
import type { CaseRecord } from './casesTypes'
import type { ApprovalToken } from './policyTypes'
import type { ExecutionRecord, ExecutionResult } from './incidentResponseTypes'

// Something an analyst did in this session, shown in the alert's timeline
export type AnalystAction = {
  alertId: string
  label: string
}

// Something an analyst did to a case in this session (case timeline)
export type CaseEvent = {
  caseId: string
  label: string
}

// A recommended action with its current state
export type CaseActionState = {
  label: string
  done: boolean
  // Set when a response run carries the action out (not ticked by hand)
  runId?: string
  runResult?: ExecutionResult
  // Set while the action waits on an approval and no run exists yet
  approvalId?: string
}

/*
  Shared analyst workspace state (SocStateProvider). It holds only
  changes made in this session on top of the seed data, so it resets on
  reload like the rest of the prototype.
*/
export type SocState = {
  alerts: AlertRecord[]
  executions: ExecutionRecord[]
  cases: CaseRecord[]
  // Per case id, its recommended actions with their current state
  caseActions: Record<string, CaseActionState[]>
  actions: AnalystAction[]
  caseEvents: CaseEvent[]
  currentUser: string
  // Tier 2 recommendations with their decisions, and what ran for the approved ones
  approvals: ApprovalRecord[]
  executionFacts: ExecutionFacts[]
  // Computed with Web Crypto, so empty for a moment after load
  tokens: ApprovalToken[]
  toggleAlertStatus: (alertId: string) => void
  assignToMe: (alertId: string) => void
  toggleCaseStatus: (caseId: string) => void
  // Manual actions only; run-linked ones follow their run
  toggleCaseAction: (caseId: string, index: number) => void
}
