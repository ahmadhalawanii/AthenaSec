export type IntegrationStatus = 'Connected' | 'Disconnected'

export type IntegrationRecord = {
  id: string
  name: string
  type: string
  status: IntegrationStatus
  version: string
  endpoint: string
  lastSync: string
  description: string
  dataFlow: string
}
