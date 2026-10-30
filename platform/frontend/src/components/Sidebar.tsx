import { NavLink } from 'react-router-dom'

import { ROLE_RANK } from '../data/agentPolicyData'
import { servicesNeedingAttention } from '../data/statusSummary'
import { useAdminState } from '../hooks/useAdminState'
import { useResponsePolicy } from '../hooks/useResponsePolicy'
import { useResponseState } from '../hooks/useResponseState'
import { useSocState } from '../hooks/useSocState'
import type { StatusTone } from '../utils/statusTone'

import { NAV_ICONS, type NavIconName } from './navIcons'

type SidebarProps = {
  role: 'Analyst' | 'Administrator'
  onLogout: () => void
  // The phone drawer's state lives in AppLayout, which also draws the hamburger first in the page
  open: boolean
  onClose: (returnFocus?: boolean) => void
}

type NavEntry = {
  to: string
  label: string
  icon: NavIconName
  count?: number
  // Badge label for screen readers, singular and plural
  countLabel?: [string, string]
  countTone?: StatusTone
}

const analystNav: NavEntry[] = [
  { to: '/app/dashboard', label: 'Dashboard', icon: 'ops' },
  {
    to: '/app/alerts',
    label: 'Alerts',
    icon: 'alerts',
    // Filled in from the live alert state when rendering
    count: 0,
    countLabel: ['open alert', 'open alerts'],
    countTone: 'danger',
  },
  {
    to: '/app/cases',
    label: 'Case Management',
    icon: 'cases',
    // Filled in from the live case state when rendering
    count: 0,
    countLabel: ['open case', 'open cases'],
    countTone: 'neutral',
  },
  { to: '/app/incident', label: 'Incident Response', icon: 'response' },
  {
    to: '/app/approvals',
    label: 'Approvals',
    icon: 'approvals',
    // Filled in from the requests this role can decide when rendering
    count: 0,
    countLabel: ['request waiting for you', 'requests waiting for you'],
    countTone: 'warn',
  },
]

const adminNav: NavEntry[] = [
  { to: '/app/dashboard', label: 'Dashboard', icon: 'home' },
  { to: '/app/configuration', label: 'Configuration', icon: 'config' },
  { to: '/app/response-policies', label: 'Response Policies', icon: 'policies' },
  {
    to: '/app/approvals',
    label: 'Approvals',
    icon: 'approvals',
    count: 0,
    countLabel: ['request waiting for you', 'requests waiting for you'],
    countTone: 'warn',
  },
  { to: '/app/user-management', label: 'User Management', icon: 'users' },
  { to: '/app/audit-logs', label: 'Audit Logs', icon: 'audit' },
  {
    to: '/app/service-panel',
    label: 'Service Panel',
    icon: 'panel',
    // Filled in from the one service inventory when rendering (shown only above 0)
    count: 0,
    countLabel: ['service needs attention', 'services need attention'],
    countTone: 'warn',
  },
]

function Sidebar({
  role,
  open: sidebarOpen,
  onClose,
}: SidebarProps) {
  const isAdmin = role === 'Administrator'
  const { alerts, cases } = useSocState()
  const { services } = useAdminState()
  const { approvals, actor } = useResponseState()
  const { unsavedChanges } = useResponsePolicy()

  // Requests still waiting that this person may decide: their role is high enough (a lead may
  // decide an analyst's too) and they did not ask for it themselves
  const waitingForYou = approvals.filter(
    (approval) =>
      approval.decision === 'Pending' &&
      ROLE_RANK[isAdmin ? 'soc_lead' : 'soc_analyst'] >= ROLE_RANK[approval.requiredRole] &&
      approval.recommendation.requestedBy !== actor?.id,
  ).length

  // Badges follow changes made this session (Close and Reopen, service checks, decisions)
  const liveCounts: Record<string, number> = {
    '/app/alerts': alerts.filter((alert) => alert.status === 'Open').length,
    '/app/cases': cases.filter((caseItem) => caseItem.status === 'Open').length,
    '/app/service-panel': servicesNeedingAttention(services),
    '/app/approvals': waitingForYou,
  }
  const navEntries = (isAdmin ? adminNav : analystNav).map((entry) =>
    entry.to in liveCounts ? { ...entry, count: liveCounts[entry.to] } : entry,
  )
  // Unsaved Permissions edits: shown as a text tag (not colour alone) and named in the link's accessible name
  const hasUnsaved = (to: string) => to === '/app/response-policies' && unsavedChanges > 0

  function linkClass({
    isActive,
  }: {
    isActive: boolean
  }) {
    return isActive
      ? 'side-item active'
      : 'side-item'
  }

  return (
    <>
      {/* Sidebar (its hamburger is the first thing in the page, drawn by AppLayout) */}
      <nav
        id="app-sidebar"
        className={
          sidebarOpen
            ? 'sidebar sidebar-open'
            : 'sidebar'
        }
        aria-label="Main"
      >
        <div className="side-title">
          {isAdmin ? 'Security management' : 'Analyst'}
        </div>

        {navEntries.map((entry) => (
          <NavLink
            key={entry.to}
            to={entry.to}
            className={linkClass}
            aria-label={hasUnsaved(entry.to) ? `${entry.label}, unsaved changes` : undefined}
            onClick={() => onClose()}
          >
            <svg
              className="side-icon"
              width="17"
              height="17"
              viewBox="0 0 24 24"
              aria-hidden="true"
              focusable="false"
            >
              <path d={NAV_ICONS[entry.icon]} />
            </svg>

            {/* Unsaved Permissions edits: a text tag (not colour alone) on a second line, and the name says so too */}
            <span className="side-label">{entry.label}</span>

            {hasUnsaved(entry.to) && (
              <>
                <span className="side-break" aria-hidden="true" />
                <span className="unsaved-tag" aria-hidden="true">
                  <span className="unsaved-tag-dot" />
                  Unsaved
                </span>
              </>
            )}

            {entry.count !== undefined && entry.count > 0 && (
              <span
                className={`count ${entry.countTone ?? 'neutral'}`}
                aria-label={`${entry.count} ${
                  entry.countLabel?.[entry.count === 1 ? 0 : 1] ?? ''
                }`}
              >
                {entry.count}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Background overlay (below 1024px only) */}
      <div
        className={
          sidebarOpen
            ? 'sidebar-backdrop show'
            : 'sidebar-backdrop'
        }
        onClick={() => onClose(true)}
        aria-hidden="true"
      />
    </>
  )
}

export default Sidebar
