export type ExecutionResult = 'Completed' | 'Failed'
export type ActionType = 'Block IP' | 'Isolate Host'

// One step of a response run in the pipeline (executionStages)
export type ExecutionStageName =
  | 'Detected'
  | 'Scored'
  | 'Policy matched'
  | 'Approved'
  | 'Executed'

// 'analyst' and 'lead' name who approved: no action runs without one of them
export type ExecutionStageState = 'done' | 'analyst' | 'lead' | 'failed'

export type ExecutionStage = {
  name: ExecutionStageName
  state: ExecutionStageState
  // Shown under the dot, so the stage never relies on colour
  label: string
}

// The figures above the pipeline
export type ResponseSummary = {
  succeeded: number
  total: number
  fastest?: { minutes: number; runId: string }
  approvedByAnalyst: number
  approvedByLead: number
  // Recommendations still waiting for a person
  awaiting: number
  failed: number
}

export type TimelineItem = {
  time: string
  event: string
}

/*
  What ran. Who asked, who approved, the token and the policy version
  are in the approval record it points to (approvalId, types/approvalTypes.ts).
*/
export type ExecutionRecord = {
  id: string
  triggeringAlert: string
  approvalId: string
  policy: string
  action: ActionType
  target: string
  startTime: string
  endTime: string
  duration: string
  result: ExecutionResult
  rollbackStatus: string
  failureReason: string
  happened: string
  classified: string
  responseReason: string
  evidence: string[]
  timeline: TimelineItem[]
  // Set when the block or isolation lapsed on its own (demo time passed its expiry), "2026-08-03T16:16:10"
  reversedAt?: string
}
