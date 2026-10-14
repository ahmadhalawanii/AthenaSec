import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

/*
  The browser tab, the history list and a screen reader's page announcement all read
  document.title (WCAG 2.4.2), so each route sets its own: "Page name · AthenaSec".
  A page with tabs puts the tab in front: "MISP · Service Panel · AthenaSec". The tab is in
  the address (?view=...), so the title follows a tab change and a link to a tab.
*/
export const APP_TITLE = 'AthenaSec'

const PAGE_NAMES: Record<string, string> = {
  '/login': 'Sign in',
  '/mfa': 'Two-step verification',
  '/app/dashboard': 'Dashboard',
  '/app/alerts': 'Alerts',
  '/app/cases': 'Case Management',
  '/app/incident': 'Incident Response',
  '/app/approvals': 'Approvals',
  '/app/configuration': 'Configuration',
  '/app/response-policies': 'Response Policies',
  '/app/user-management': 'User Management',
  '/app/audit-logs': 'Audit Logs',
  '/app/service-panel': 'Service Panel',
  '/app/settings': 'Settings',
  '/app/profile': 'Profile',
}

// Tab names by page: the value after ?view=, and the tab shown when there is none
const TAB_NAMES: Record<string, { fallback: string; views: Record<string, string> }> = {
  '/app/response-policies': {
    fallback: 'Permissions',
    views: { catalogue: 'Action catalogue' },
  },
  '/app/service-panel': {
    fallback: 'Overview',
    views: {
      health: 'System health',
      wazuh: 'Wazuh',
      cortex: 'Cortex',
      misp: 'MISP',
    },
  },
}

export function pageTitle(pathname: string, search: string) {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  const page = PAGE_NAMES[path]

  if (!page) {
    return APP_TITLE
  }

  const tabs = TAB_NAMES[path]
  const view = new URLSearchParams(search).get('view') ?? ''
  const tab = tabs ? (tabs.views[view] ?? tabs.fallback) : null

  return [tab, page, APP_TITLE].filter(Boolean).join(' · ')
}

export function usePageTitle() {
  const { pathname, search } = useLocation()

  useEffect(() => {
    document.title = pageTitle(pathname, search)
  }, [pathname, search])
}
