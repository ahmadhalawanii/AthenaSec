export type CaseSeverity = 'Medium' | 'High' | 'Critical'
export type CaseStatus = 'Open' | 'Closed'

export type CaseTimelineItem = {
  time: string
  title: string
  description: string
  // A step that went wrong (shown as failed in the timeline)
  failed?: boolean
}

/*
  A recommended action. Actions that a response run carries out are
  linked to it (runId) and are done exactly when that run completed;
  the rest are ticked by the analyst (done is their starting state).
  An action that still waits on a person's approval points to it
  (approvalId) and is not done until a run completes.
*/
export type CaseAction = {
  label: string
  runId?: string
  approvalId?: string
  done?: boolean
}

export type CaseRecord = {
  id: string
  sourceAlert: string
  severity: CaseSeverity
  status: CaseStatus
  assignedAnalyst: string
  attackType: string
  endpoint: string
  sourceIp: string
  riskScore: number
  createdAt: string
  lastUpdated: string
  summary: string
  evidence: string[]
  recommendedActions: CaseAction[]
  mitre: string
  timeline: CaseTimelineItem[]
}
