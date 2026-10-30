import type { StatusTone } from '../utils/statusTone'

export type AuditStorage = {
  storedPercent: number
  store: string
}

// One figure in the dashboard's posture strip; links to its page
export type PostureItem = {
  page: string
  // The page's tab to open (written as ?view=)
  view?: string
  value: string
  // Shown smaller after the value ("/6")
  total?: string
  label: string
  note: string
  tone?: StatusTone
}

// Something only an administrator can resolve, with a link to it
export type AdminTask = {
  id: string
  tone: StatusTone
  text: string
  linkLabel: string
  page: string
  // The page's tab to open (written as ?view=)
  view?: string
  // Record to select on that page
  recordId: string
}
