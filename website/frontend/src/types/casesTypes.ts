export type CaseSeverity = 'Medium' | 'High' | 'Critical'
export type CaseStatus = 'Open' | 'Closed'

export type CaseTimelineItem = {
  time: string
  title: string
  description: string
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
  recommendedActions: string[]
  mitre: string
  timeline: CaseTimelineItem[]
}
