export type PolicyStatus = 'Enabled' | 'Disabled'

export type ApprovalMode =
  | 'Automatic'
  | 'Analyst Approval'
  | 'Administrator Approval'

export type PolicyAction =
  | 'Block IP'
  | 'Isolate Endpoint'
  | 'Lock Account'
  | 'Create Case'
  | 'Notify Administrator'
  | 'Capture Telemetry'
  | 'Record Response'

export type ResponsePolicy = {
  id: string
  name: string
  condition: string
  actions: PolicyAction[]
  approvalMode: ApprovalMode
  status: PolicyStatus
  riskThreshold: number
  description: string
  lastUpdated: string
}

export type PolicyFormState = {
  name: string
  condition: string
  actions: string
  approvalMode: ApprovalMode
  status: PolicyStatus
  riskThreshold: string
  description: string
}

export type ModalMode = 'add' | 'edit' | 'view' | 'delete' | null
