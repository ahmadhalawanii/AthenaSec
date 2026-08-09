export type ExecutionResult = 'Completed' | 'Failed'
export type ApprovalType = 'Automatic' | 'Analyst Approved'
export type ActionType = 'Block IP' | 'Isolate Host'

export type TimelineItem = {
  time: string
  event: string
}

export type ExecutionRecord = {
  id: string
  triggeringAlert: string
  policy: string
  action: ActionType
  target: string
  initiator: string
  approvalType: ApprovalType
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
}
