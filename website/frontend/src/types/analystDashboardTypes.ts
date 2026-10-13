export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low'

export type DashboardAlert = {
  id: string
  type: string
  endpoint: string
  severity: AlertSeverity
  risk: number
  sourceIp: string
  destinationIp: string
  status: string
  assignedAnalyst: string
  time: string
  summary: string
  reasoning: string
  mitre: string
  explanation: string
}
