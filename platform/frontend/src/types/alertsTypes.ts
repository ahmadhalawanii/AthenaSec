export type RiskBand = 'low' | 'medium' | 'high' | 'critical'

export type AlertStatus = 'Open' | 'Closed'

// Where a piece of evidence came from (shown as a tag)
export type EvidenceSource =
  | 'Auth'
  | 'Intel'
  | 'Endpoint'
  | 'Network'
  | 'Response'
  | 'Policy'

export type AlertEvidence = {
  source: EvidenceSource
  text: string
}

/*
  Where an alert stands once its response is taken into account (see
  alertResponseState in statusSummary.ts). A response only exists once
  a person approved it; until then a recommendation is "Awaiting approval".
*/
export type AlertResponseState =
  | 'Open'
  | 'Awaiting approval'
  | 'Source blocked'
  | 'Containment failed'
  | 'Contained'
  | 'Closed'

export type AlertRecord = {
  id: string
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  attackGroup: 'Brute Force' | 'Privilege Escalation' | 'Command and Control' | 'Other'
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
