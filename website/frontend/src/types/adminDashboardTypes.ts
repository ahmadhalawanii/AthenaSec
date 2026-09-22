export type AdminDashboardPageProps = {
  onNavigate: (page: string) => void
}

export type IntegrationStatus =
  | 'Connected'
  | 'Warning'
  | 'Disconnected'

export type IntegrationRecord = {
  name: string
  status: IntegrationStatus
  lastCheck: string
}

export type ActivityRecord = {
  id: string
  time: string
  admin: string
  action: string
  target: string
  result: string
}
