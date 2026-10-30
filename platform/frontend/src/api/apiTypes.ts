/*
  Response shapes from the backend, as defined in backend/app/schemas.py.
  snake_case, exactly as sent. Only the fields the website reads are listed.
*/

export type ApiRole = 'Analyst' | 'Administrator'

export type ApiSessionUser = {
  email: string
  name: string
  role: ApiRole
}

export type ApiSession = {
  user: ApiSessionUser
  csrf_token: string
  // Signed in with a temporary password: a new one must be chosen first
  must_change_password?: boolean
}

export type ApiRiskBand = 'low' | 'medium' | 'high' | 'critical'

export type ApiAlert = {
  alert_id: string
  incident_id: string | null
  investigation_id: string | null
  source: string
  alert_metadata: Record<string, unknown>
  status: string
  observed_at: string | null
  classification: string
  ml_prediction: { classification: string; confidence: number } | null
  risk_assessment: { score: number; band: ApiRiskBand; factors?: { name: string; reason: string }[] }
  // The analyst's handling (alert_workflow)
  analyst_status?: 'open' | 'closed'
  assigned_analyst?: string | null
}

export type ApiCase = {
  case_id: string
  incident_id: string
  alert_id: string | null
  classification: string | null
  risk_score: number | null
  risk_band: ApiRiskBand | null
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
  reason: string
  assigned_analyst: string | null
  summary: string | null
  endpoint: string | null
  source_ip: string | null
  evidence: { evidence_id: string; source: string; content: string }[]
  recommended_actions: { position: number; label: string; done: boolean; approval_id: string | null }[]
  mitre_ids: string[]
  timeline: { seq: number; occurred_at: string; title: string; description: string; failed: boolean }[]
  created_at: string
  updated_at: string
}

// GET /responses: one executed (or attempted) containment action and what followed
export type ApiResponseStep = { status: string; message: string; at: string }

export type ApiResponseRun = {
  response_action_id: string
  incident_id: string
  alert_id: string | null
  proposed_action_id: string
  approval_id: string | null
  policy_decision_id: string | null
  action_type: string | null
  target: string | null
  duration_minutes: number | null
  reason: string | null
  status: string
  executor: string
  created_at: string
  approved_by: string | null
  approver_role: 'soc_analyst' | 'soc_lead' | null
  approver_name: string | null
  approved_at: string | null
  result: ApiResponseStep | null
  verification: ApiResponseStep | null
  rollback: ApiResponseStep | null
  expires_at: string | null
}

export type ApiApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED'

export type ApiApproval = {
  approval_id: string
  incident_id: string
  proposed_action_id: string
  status: ApiApprovalStatus
  requested_by: string
  requested_at: string
  expires_at: string | null
  decided_at: string | null
  decided_by: string | null
  decision_reason: string | null
}

export type ApiApprovalAction = {
  approval: ApiApproval
  proposed_action: {
    action_type: string
    target_type: string
    target: string
    parameters: Record<string, unknown>
    reversible: boolean
    reason: string
  } | null
  policy_decision: { policy_id: string; outcome: string; reason: string } | null
}

export type ApiUser = {
  user_id: string
  email: string
  name: string
  role: ApiRole
  department: string
  phone: string
  active: boolean
  mfa_enabled: boolean
  can_read_approvals: boolean
  can_decide_approvals: boolean
  created_at: string | null
  last_login_at: string | null
}

export type ApiAuditEvent = {
  seq: number | null
  event_id: string
  occurred_at: string
  actor_id: string
  actor_role: string
  category: string
  action: string
  target: string
  result: string
  source_ip: string | null
  source: 'operator' | 'incident'
  event_type: string | null
  message: string | null
  row_hash: string | null
}

export type ApiChainVerification = {
  valid: boolean
  checked: number
  first_broken_seq: number | null
}

export type ApiHealthService = {
  check_key: string
  name: string
  group: string
  category: string
  status: 'up' | 'degraded' | 'down' | 'unknown' | string
  endpoint: string | null
  latency_ms: number | null
  checked_at: string | null
  detail: string | null
  uptime_seconds: number | null
  uptime_percent: number | null
}

export type ApiSystemHealth = {
  generated_at: string
  services: ApiHealthService[]
  summary: Record<string, number>
}

// ----- The action policy (GET/PUT /policies/actions): the whitelist and blacklist the agent enforces -----

export type ApiActionPolicyLimits = {
  default_minutes: number | null
  max_minutes: number | null
  approver: 'soc_analyst' | 'soc_lead'
  window_minutes: number
  min_risk: number
}

export type ApiActionPolicyContent = {
  whitelist: Array<{ action: string; mode: 'automatic' | 'approval'; limits: ApiActionPolicyLimits | null }>
  blacklist: Array<{ action: string; required: boolean }>
  never_block: Array<{ value: string; label: string; required: boolean }>
  never_isolate: Array<{ value: string; label: string; required: boolean }>
}

export type ApiActionPolicyDocument = ApiActionPolicyContent & {
  version: number
  is_default: boolean
  created_at: string | null
  created_by: string | null
  reason: string | null
}
