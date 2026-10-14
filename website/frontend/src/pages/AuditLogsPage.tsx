import { useMemo, useState } from 'react'

import AuditRecordDetails from '../components/AuditRecordDetails'
import AuditTamperPanel from '../components/AuditTamperPanel'
import IdText from '../components/IdText'
import ResponsiveDetail from '../components/ResponsiveDetail'
import { auditStorage } from '../data/adminDashboardData'
import { AUDIT_EVENT_TYPE_NAMES, AUDIT_EVENT_TYPES } from '../data/auditEventTypes'
import { AUDIT_CATEGORIES } from '../data/auditLogsData'
import { useAdminState } from '../hooks/useAdminState'
import { useSearchSelection } from '../hooks/useSearchSelection'
import { statusTone } from '../utils/statusTone'

function escapeCsvValue(value: string) {
  const escapedValue = value.replace(/"/g, '""')

  return `"${escapedValue}"`
}

// "2026-08-03 15:42:18" → "15:42"
const timeOf = (timestamp: string) => timestamp.slice(11, 16)

function AuditLogsPage() {
  // This session's admin changes (newest first), then the stored log
  const { auditLogs, configuration, auditIntegrity, auditLinks, alteredAuditIds, tamperAudit, restoreAudit } =
    useAdminState()

  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  // 'all', 'none' (events the policy has no type for) or one of the PDF's types
  const [typeFilter, setTypeFilter] = useState('all')
  const [userFilter, setUserFilter] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // Phones: the detail opens as a drawer only when an event is chosen
  const [detailOpen, setDetailOpen] = useState(false)
  const [pageMessage, setPageMessage] = useState('')

  const uniqueUsers = useMemo(() => {
    return Array.from(
      new Set(auditLogs.map((log) => log.user)),
    ).sort()
  }, [auditLogs])

  const visibleLogs = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return auditLogs.filter((log) => {
      const metadataText = Object.entries(log.metadata)
        .flat()
        .join(' ')
        .toLowerCase()

      const changesText = log.changes.join(' ').toLowerCase()

      const matchesSearch =
        normalizedQuery === '' ||
        log.id.toLowerCase().includes(normalizedQuery) ||
        log.timestamp.toLowerCase().includes(normalizedQuery) ||
        log.user.toLowerCase().includes(normalizedQuery) ||
        log.role.toLowerCase().includes(normalizedQuery) ||
        log.category.toLowerCase().includes(normalizedQuery) ||
        log.action.toLowerCase().includes(normalizedQuery) ||
        log.target.toLowerCase().includes(normalizedQuery) ||
        log.result.toLowerCase().includes(normalizedQuery) ||
        log.sourceIp.toLowerCase().includes(normalizedQuery) ||
        log.description.toLowerCase().includes(normalizedQuery) ||
        changesText.includes(normalizedQuery) ||
        metadataText.includes(normalizedQuery) ||
        (log.eventType ?? '').includes(normalizedQuery) ||
        (log.eventType ? AUDIT_EVENT_TYPE_NAMES[log.eventType].toLowerCase().includes(normalizedQuery) : false) ||
        (log.record?.recommendation_id ?? '').toLowerCase().includes(normalizedQuery)

      const matchesType =
        typeFilter === 'all' ||
        (typeFilter === 'none' ? !log.eventType : log.eventType === typeFilter)

      const matchesCategory =
        categoryFilter === 'all' ||
        log.category === categoryFilter

      const matchesResult =
        resultFilter === 'all' ||
        log.result === resultFilter

      const matchesUser =
        userFilter === 'all' ||
        log.user === userFilter

      return (
        matchesSearch &&
        matchesCategory &&
        matchesResult &&
        matchesUser &&
        matchesType
      )
    })
  }, [
    auditLogs,
    searchQuery,
    categoryFilter,
    resultFilter,
    userFilter,
    typeFilter,
  ])

  // The event shown in the panel: the chosen one, or the first in the list
  const shown =
    visibleLogs.find((log) => log.id === selectedId) ?? visibleLogs[0] ?? null

  const successCount = auditLogs.filter(
    (log) => log.result === 'Success',
  ).length

  const failedCount = auditLogs.filter(
    (log) => log.result === 'Failed',
  ).length

  const deniedCount = auditLogs.filter(
    (log) => log.result === 'Denied',
  ).length

  function choose(logId: string) {
    setSelectedId(logId)
    setDetailOpen(true)
  }

  function resetFilters() {
    setSearchQuery('')
    setCategoryFilter('all')
    setResultFilter('all')
    setUserFilter('all')
    setTypeFilter('all')
    setPageMessage('')
  }

  // Search and links from other pages: clear the filters, then select the event
  useSearchSelection(
    auditLogs.map((log) => log.id),
    (logId) => setSelectedId(logId),
    resetFilters,
  )

  function exportVisibleLogs() {
    if (visibleLogs.length === 0) {
      setPageMessage('There are no visible audit logs to export.')
      return
    }

    const headers = [
      'Event ID',
      'Timestamp',
      'User',
      'Role',
      'Category',
      'Action',
      'Target',
      'Result',
      'Source IP',
      'Description',
    ]

    const rows = visibleLogs.map((log) => [
      log.id,
      log.timestamp,
      log.user,
      log.role,
      log.category,
      log.action,
      log.target,
      log.result,
      log.sourceIp,
      log.description,
    ])

    const csvContent = [
      headers.map(escapeCsvValue).join(','),
      ...rows.map((row) =>
        row.map(escapeCsvValue).join(','),
      ),
    ].join('\n')

    const csvBlob = new Blob([csvContent], {
      type: 'text/csv;charset=utf-8',
    })

    const downloadUrl = URL.createObjectURL(csvBlob)
    const downloadLink = document.createElement('a')

    downloadLink.href = downloadUrl
    downloadLink.download = 'athenasec-audit-logs.csv'

    document.body.appendChild(downloadLink)
    downloadLink.click()
    document.body.removeChild(downloadLink)

    URL.revokeObjectURL(downloadUrl)

    setPageMessage(
      `${visibleLogs.length} audit ${
        visibleLogs.length === 1 ? 'record was' : 'records were'
      } exported successfully.`,
    )
  }

  return (
    <section
      className="page active"
      data-page="audit-logs"
      data-page-name="Audit Logs"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Audit Logs</h1>

          <p className="sub">
            Every sign-in, configuration change and response, recorded as it happened.
          </p>
        </div>

        <div className="headline-actions">
          <span className="pill ok audit-readonly" id="auditRetention">
            <svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <rect x="5" y="11" width="14" height="10" rx="2" />
              <path d="M8 11V7a4 4 0 0 1 8 0v4" />
            </svg>
            Read-only, kept {configuration.auditRetentionDays} days in {auditStorage.store}
          </span>

          <button
            className="btn"
            type="button"
            onClick={exportVisibleLogs}
          >
            Export shown events
          </button>
        </div>
      </div>

      <section className="response-summary audit-summary" aria-label="Event summary">
        <div>
          <strong>{auditLogs.length}</strong>
          <span>events recorded</span>
        </div>

        <div className="ok">
          <strong>{successCount}</strong>
          <span>successful</span>
        </div>

        <div className="danger">
          <strong>{failedCount}</strong>
          <span>failed {failedCount === 1 ? 'operation' : 'operations'}</span>
        </div>

        <div className="danger">
          <strong>{deniedCount}</strong>
          <span>denied security {deniedCount === 1 ? 'event' : 'events'}</span>
        </div>
      </section>

      <p
        className={`pill audit-integrity ${
          !auditIntegrity ? 'neutral' : auditIntegrity.status === 'intact' ? 'ok' : 'danger'
        }`}
        role="status"
        data-field="integrity"
        data-state={auditIntegrity?.status ?? 'verifying'}
        data-count={auditIntegrity?.count ?? ''}
      >
        {!auditIntegrity
          ? 'Checking the chain…'
          : auditIntegrity.status === 'intact'
            ? `Chain intact: ${auditIntegrity.count} events verified`
            : `Chain broken at ${auditIntegrity.brokenId}: this record or one before it was changed. Restore it, or reset the demo.`}
      </p>

      {pageMessage && (
        <div className="notice" role="status">
          {pageMessage}
        </div>
      )}

      <div className="audit-chips" role="group" aria-label="Filter by category">
        {['all', ...AUDIT_CATEGORIES].map((category) => (
          <button
            key={category}
            type="button"
            className="audit-chip"
            aria-pressed={categoryFilter === category}
            onClick={() => setCategoryFilter(category)}
            data-category={category}
          >
            {category === 'all' ? 'All' : category}
          </button>
        ))}
      </div>

      <div className="toolbar">
        <input
          className="field-input"
          type="search"
          name="auditSearch"
          autoComplete="off"
          aria-label="Search audit events"
          placeholder="Search audit events…"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          name="resultFilter"
          autoComplete="off"
          aria-label="Filter by result"
          value={resultFilter}
          onChange={(event) =>
            setResultFilter(event.target.value)
          }
        >
          <option value="all">All Results</option>
          <option value="Success">Success</option>
          <option value="Failed">Failed</option>
          <option value="Denied">Denied</option>
        </select>

        <select
          className="select-input"
          name="userFilter"
          autoComplete="off"
          aria-label="Filter by user"
          value={userFilter}
          onChange={(event) =>
            setUserFilter(event.target.value)
          }
        >
          <option value="all">All Users</option>

          {uniqueUsers.map((user) => (
            <option value={user} key={user}>
              {user}
            </option>
          ))}
        </select>

        <select
          className="select-input"
          name="typeFilter"
          autoComplete="off"
          aria-label="Filter by event type"
          value={typeFilter}
          onChange={(event) => setTypeFilter(event.target.value)}
        >
          <option value="all">All Event Types</option>

          {AUDIT_EVENT_TYPES.map((type) => (
            <option value={type} key={type}>
              {AUDIT_EVENT_TYPE_NAMES[type]}
            </option>
          ))}

          <option value="none">No event type</option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue" id="visibleAuditCount" role="status">
          {visibleLogs.length} visible
        </span>
      </div>

      <div className="split-layout">
        <section className="card queue audit-list-card" aria-label="Audit events">
          {visibleLogs.length === 0 ? (
            <div className="empty">
              <strong>No audit events found</strong>

              <p className="sub">
                No audit events match the current search and filters.
              </p>

              <button className="btn primary" type="button" onClick={resetFilters}>
                Clear Filters
              </button>
            </div>
          ) : (
            <ul className="audit-list">
              {visibleLogs.map((log) => (
                <li key={log.id}>
                  <button
                    type="button"
                    className="audit-pick"
                    aria-pressed={log.id === shown?.id}
                    onClick={() => choose(log.id)}
                    data-record-id={log.id}
                    data-result={log.result}
                  >
                    <span className="audit-time mono">{timeOf(log.timestamp)}</span>

                    <span className={`audit-dot ${statusTone(log.result)}`} aria-hidden="true" />

                    <span className="audit-what">
                      <span className="audit-action">
                        {log.demo && (
                          <>
                            <span className="audit-demo-tag">Demo</span>{' '}
                          </>
                        )}
                        {log.action}{' '}
                        <span className="audit-target">
                          <IdText>{log.target}</IdText>
                        </span>
                      </span>
                      <span className="audit-meta">
                        {log.user} · {log.category} · <span className="mono">{log.sourceIp}</span>
                      </span>
                    </span>

                    <span className={`pill ${statusTone(log.result)}`}>{log.result}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {shown && (
          <ResponsiveDetail
            open={detailOpen}
            onClose={() => setDetailOpen(false)}
            labelledBy="auditEventTitle"
            closeLabel="Close audit event details"
            className="audit-detail"
          >
            <div className="workspace-head" data-workspace-id={shown.id}>
              <div className="dash-path-meta">
                <span className="mono" data-field="id">{shown.id}</span>
                <span className={`pill ${statusTone(shown.result)}`} data-field="result">
                  {shown.result}
                </span>
                {shown.demo && (
                  <span className="audit-demo-tag" data-field="demo">
                    Demo
                  </span>
                )}
              </div>

              <h2 className="workspace-title" id="auditEventTitle" data-field="action">
                {shown.action}
              </h2>

              <p className="workspace-text" data-field="description">
                {shown.description}
              </p>
            </div>

            <dl className="facts">
              <div>
                <dt>When</dt>
                <dd className="mono" data-field="when">{shown.timestamp}</dd>
              </div>
              <div>
                <dt>Who</dt>
                <dd data-field="who">
                  {shown.user} <span className="sub">({shown.role})</span>
                </dd>
              </div>
              <div>
                <dt>Category</dt>
                <dd data-field="category">{shown.category}</dd>
              </div>
              <div>
                <dt>Target</dt>
                <dd data-field="target">
                  <IdText>{shown.target}</IdText>
                </dd>
              </div>
              <div>
                <dt>Source IP</dt>
                <dd className="mono" data-field="sourceIp">{shown.sourceIp}</dd>
              </div>
            </dl>

            <h3 className="workspace-subhead">Recorded changes</h3>

            <ul className="audit-changes" data-field="changes">
              {shown.changes.map((change) => (
                <li key={change}>{change}</li>
              ))}
            </ul>

            <h3 className="workspace-subhead">Event metadata</h3>

            <dl className="facts" data-field="metadata">
              {Object.entries(shown.metadata).map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>

            <AuditRecordDetails log={shown} links={auditLinks} integrity={auditIntegrity} />

            <p className="policy-note">
              Audit events can't be edited or deleted.
            </p>
          </ResponsiveDetail>
        )}
      </div>

      <AuditTamperPanel
        shownId={shown?.id ?? null}
        alteredIds={alteredAuditIds}
        integrity={auditIntegrity}
        onAlter={tamperAudit}
        onRestore={restoreAudit}
      />
    </section>
  )
}

export default AuditLogsPage
