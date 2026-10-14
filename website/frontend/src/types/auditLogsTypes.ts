export type AuditResult = 'Success' | 'Failed' | 'Denied'

export type AuditCategory =
  | 'Authentication'
  | 'Response Policy'
  | 'User Management'
  | 'Incident Response'
  | 'System'

// The seven event types of the policy PDF's audit log (page 8)
export type AuditEventType =
  | 'recommendation_created'
  | 'decision_recorded'
  | 'action_executed'
  | 'action_failed'
  | 'action_expired'
  | 'approval_timed_out'
  | 'policy_violation_blocked'

/*
  The PDF's record fields (page 9) for an event about a recommendation or
  an attempt, as far as the app has a value for them. `model_version` is
  not recorded (the front end has no model).
*/
export type AuditRecordFields = {
  recommendation_id?: string
  alert_id?: string
  policy_id?: string
  // The agent, or the person's user id
  actor: string
  actor_role: 'agent' | 'soc_analyst' | 'soc_lead'
  tier?: 1 | 2 | 3
  outcome?: string
  action?: string
  params?: Record<string, string | number>
  evidence?: string[]
  risk_score?: number
  confidence?: number
  decision?: 'approved' | 'approved_with_changes' | 'rejected' | 'timed_out'
  decision_reason?: string
  execution_result?: 'success' | 'failed' | 'not_executed'
  expires_at?: string
}

// The result of checking the audit hash chain
export type AuditIntegrity = {
  status: 'intact' | 'broken'
  // Records checked
  count: number
  // The first record whose stored hash no longer matches its content
  brokenId?: string
}

export type AuditLogRecord = {
  id: string
  timestamp: string
  user: string
  role: 'Analyst' | 'Administrator' | 'System'
  category: AuditCategory
  action: string
  target: string
  result: AuditResult
  sourceIp: string
  description: string
  changes: string[]
  metadata: Record<string, string>
  // A Demo mode control (advance time, arm a failure), shown with a "Demo" label
  demo?: boolean
  // The PDF's event type, for the events it names; others have none
  eventType?: AuditEventType
  record?: AuditRecordFields
}
