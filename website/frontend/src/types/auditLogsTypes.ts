export type AuditResult = 'Success' | 'Failed' | 'Denied'

export type AuditCategory =
  | 'Authentication'
  | 'Detection Rule'
  | 'Response Policy'
  | 'Integration'
  | 'User Management'
  | 'Incident Response'
  | 'System'

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
}
