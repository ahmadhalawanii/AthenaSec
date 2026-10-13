export type RiskBand = 'low' | 'medium' | 'high' | 'critical'

export type AlertStatus = 'Open' | 'AI Handled' | 'Closed'

export type AlertRecord = {
  id: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  attackGroup: 'Brute Force' | 'Privilege Escalation'
  attackType: string
  sourceIp: string
  destinationIp: string
  endpoint: string
  risk: number
  riskBand: RiskBand
  status: AlertStatus
  assignedAnalyst: string
  time: string
  summary: string
  reasoning: string
  mitre: string
  explanation: string
}
