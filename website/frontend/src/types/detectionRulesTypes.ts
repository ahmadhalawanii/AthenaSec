export type RuleStatus = 'Enabled' | 'Disabled'

export type RuleCategory =
  | 'Authentication'
  | 'Privilege Escalation'
  | 'Network'
  | 'Endpoint'
  | 'Malware'

export type DetectionRule = {
  id: string
  name: string
  category: RuleCategory
  threshold: string
  policy: string
  status: RuleStatus
  severity: 'Low' | 'Medium' | 'High' | 'Critical'
  mitre: string
  description: string
  dataSource: string
  lastUpdated: string
}

export type RuleFormState = {
  name: string
  category: RuleCategory
  threshold: string
  policy: string
  status: RuleStatus
  severity: DetectionRule['severity']
  mitre: string
  description: string
  dataSource: string
}

export type ModalMode = 'add' | 'edit' | 'view' | 'delete' | null
