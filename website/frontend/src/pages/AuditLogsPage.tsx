import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import type {
  AuditLogRecord,
  AuditResult,
} from '../types/auditLogsTypes'

import { auditLogs } from '../data/auditLogsData'

function resultClass(result: AuditResult) {
  if (result === 'Success') {
    return 'ok'
  }

  if (result === 'Failed') {
    return 'warn'
  }

  return 'danger'
}

function roleClass(role: AuditLogRecord['role']) {
  if (role === 'Administrator') {
    return 'warn'
  }

  if (role === 'Analyst') {
    return 'blue'
  }

  return 'muted'
}

function escapeCsvValue(value: string) {
  const escapedValue = value.replace(/"/g, '""')

  return `"${escapedValue}"`
}

function AuditLogsPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  const [userFilter, setUserFilter] = useState('all')
  const [selectedLog, setSelectedLog] =
    useState<AuditLogRecord | null>(null)
  const [pageMessage, setPageMessage] = useState('')

  const uniqueUsers = useMemo(() => {
    return Array.from(
      new Set(auditLogs.map((log) => log.user)),
    ).sort()
  }, [])

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
        metadataText.includes(normalizedQuery)

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
        matchesUser
      )
    })
  }, [
    searchQuery,
    categoryFilter,
    resultFilter,
    userFilter,
  ])

  const successCount = auditLogs.filter(
    (log) => log.result === 'Success',
  ).length

  const failedCount = auditLogs.filter(
    (log) => log.result === 'Failed',
  ).length

  const deniedCount = auditLogs.filter(
    (log) => log.result === 'Denied',
  ).length

  function resetFilters() {
    setSearchQuery('')
    setCategoryFilter('all')
    setResultFilter('all')
    setUserFilter('all')
    setPageMessage('')
  }

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
            Read-only record of authentication, configuration,
            response, integration, user-management, and system events.
          </p>
        </div>

        <button
          className="btn primary"
          type="button"
          onClick={exportVisibleLogs}
        >
          Export Visible Logs
        </button>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>{auditLogs.length}</strong>
          <span>Total Events</span>
          <small>Current static audit records</small>
        </div>

        <div className="stat">
          <strong>{successCount}</strong>
          <span>Successful</span>
          <small>Completed actions</small>
        </div>

        <div className="stat">
          <strong>{failedCount}</strong>
          <span>Failed</span>
          <small>Unsuccessful operations</small>
        </div>

        <div className="stat">
          <strong>{deniedCount}</strong>
          <span>Denied</span>
          <small>Blocked security events</small>
        </div>
      </div>

      {pageMessage && (
        <div
          className="notice"
          role="status"
          style={{ marginTop: '18px' }}
        >
          {pageMessage}
        </div>
      )}

      <div
        className="toolbar"
        style={{ marginTop: '18px' }}
      >
        <input
          className="field-input"
          type="search"
          placeholder="Search audit events"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          value={categoryFilter}
          onChange={(event) =>
            setCategoryFilter(event.target.value)
          }
        >
          <option value="all">All Categories</option>
          <option value="Authentication">
            Authentication
          </option>
          <option value="Detection Rule">
            Detection Rule
          </option>
          <option value="Response Policy">
            Response Policy
          </option>
          <option value="Integration">
            Integration
          </option>
          <option value="User Management">
            User Management
          </option>
          <option value="Incident Response">
            Incident Response
          </option>
          <option value="System">System</option>
        </select>

        <select
          className="select-input"
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

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue">
          {visibleLogs.length} visible
        </span>
      </div>

      <div className="card">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>User</th>
                <th>Category</th>
                <th>Action</th>
                <th>Target</th>
                <th>Result</th>
                <th>Source IP</th>
                <th>Details</th>
              </tr>
            </thead>

            <tbody>
              {visibleLogs.map((log) => (
                <tr
                  key={log.id}
                  className="data-row"
                  data-search-record
                  data-page-target="audit-logs"
                >
                  <td>{log.id}</td>
                  <td>{log.timestamp}</td>

                  <td>
                    <strong>{log.user}</strong>

                    <div
                      style={{
                        marginTop: '4px',
                      }}
                    >
                      <span
                        className={`pill ${roleClass(
                          log.role,
                        )}`}
                      >
                        {log.role}
                      </span>
                    </div>
                  </td>

                  <td>{log.category}</td>
                  <td>{log.action}</td>
                  <td>{log.target}</td>

                  <td>
                    <span
                      className={`pill ${resultClass(
                        log.result,
                      )}`}
                    >
                      {log.result}
                    </span>
                  </td>

                  <td>{log.sourceIp}</td>

                  <td>
                    <button
                      className="btn small primary"
                      type="button"
                      onClick={() => setSelectedLog(log)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}

              {visibleLogs.length === 0 && (
                <tr>
                  <td colSpan={9}>
                    <div className="empty">
                      <strong>No audit events found</strong>

                      <p className="sub">
                        No audit events match the current search and
                        filters.
                      </p>

                      <button
                        className="btn primary"
                        type="button"
                        onClick={resetFilters}
                        style={{ marginTop: '14px' }}
                      >
                        Clear Filters
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedLog &&
        createPortal(
          <div
            className="drawer-backdrop"
            role="presentation"
            onClick={() => setSelectedLog(null)}
          >
            <aside
              className="alert-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Audit event details"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="drawer-head">
                <div>
                  <span className="sub">
                    Audit Event
                  </span>

                  <h2>{selectedLog.id}</h2>
                </div>

                <button
                  className="icon-btn"
                  type="button"
                  aria-label="Close audit details"
                  onClick={() => setSelectedLog(null)}
                >
                  ×
                </button>
              </div>

              <div className="drawer-body">
                <div className="card">
                  <div className="headline">
                    <div>
                      <h3>Event Overview</h3>
                    </div>

                    <span
                      className={`pill ${resultClass(
                        selectedLog.result,
                      )}`}
                    >
                      {selectedLog.result}
                    </span>
                  </div>

                  <div className="kv">
                    <span>Event ID</span>
                    <strong>{selectedLog.id}</strong>
                  </div>

                  <div className="kv">
                    <span>Timestamp</span>
                    <strong>
                      {selectedLog.timestamp}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>User</span>
                    <strong>{selectedLog.user}</strong>
                  </div>

                  <div className="kv">
                    <span>Role</span>
                    <strong>{selectedLog.role}</strong>
                  </div>

                  <div className="kv">
                    <span>Category</span>
                    <strong>
                      {selectedLog.category}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Action</span>
                    <strong>{selectedLog.action}</strong>
                  </div>

                  <div className="kv">
                    <span>Target</span>
                    <strong>{selectedLog.target}</strong>
                  </div>

                  <div className="kv">
                    <span>Source IP</span>
                    <strong>{selectedLog.sourceIp}</strong>
                  </div>
                </div>

                <div className="card">
                  <h3>Description</h3>

                  <p className="sub">
                    {selectedLog.description}
                  </p>
                </div>

                <div className="card">
                  <h3>Recorded Changes</h3>

                  <div className="stack">
                    {selectedLog.changes.map(
                      (change, index) => (
                        <div
                          className="kv"
                          key={change}
                        >
                          <span>
                            Change {index + 1}
                          </span>

                          <strong>{change}</strong>
                        </div>
                      ),
                    )}
                  </div>
                </div>

                <div className="card">
                  <h3>Event Metadata</h3>

                  {Object.entries(
                    selectedLog.metadata,
                  ).map(([label, value]) => (
                    <div
                      className="kv"
                      key={label}
                    >
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </div>
                  ))}
                </div>

                <div className="notice">
                  Audit events are read-only. This frontend page does
                  not modify or delete stored audit records.
                </div>
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default AuditLogsPage
