import type { Role } from './appTypes'

export type NotificationItem = {
  id: string
  title: string
  detail: string
  // App route slug the notification opens, e.g. 'alerts'
  page: string
  // The page's tab to open (written as ?view=), e.g. 'health' on the Service Panel
  view?: string
  // A record on that page to select when it opens (an audit event id)
  highlight?: string
  roles: Role[]
}
