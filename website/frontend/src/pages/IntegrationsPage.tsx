import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import type {
  IntegrationRecord,
  IntegrationStatus,
} from '../types/integrationsTypes'

import { initialIntegrations } from '../data/integrationsData'

function statusClass(status: IntegrationStatus) {
  return status === 'Connected' ? 'ok' : 'danger'
}

function IntegrationsPage() {
  const [integrations, setIntegrations] =
    useState<IntegrationRecord[]>(initialIntegrations)

  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const [selectedIntegration, setSelectedIntegration] =
    useState<IntegrationRecord | null>(null)

  const [syncingIds, setSyncingIds] = useState<string[]>([])
  const [pageMessage, setPageMessage] = useState('')

  const visibleIntegrations = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return integrations.filter((integration) => {
      const matchesSearch =
        normalizedQuery === '' ||
        integration.id.toLowerCase().includes(normalizedQuery) ||
        integration.name.toLowerCase().includes(normalizedQuery) ||
        integration.type.toLowerCase().includes(normalizedQuery) ||
        integration.status.toLowerCase().includes(normalizedQuery) ||
        integration.version.toLowerCase().includes(normalizedQuery) ||
        integration.endpoint.toLowerCase().includes(normalizedQuery)

      const matchesStatus =
        statusFilter === 'all' ||
        integration.status === statusFilter

      return matchesSearch && matchesStatus
    })
  }, [integrations, searchQuery, statusFilter])

  const connectedCount = integrations.filter(
    (integration) => integration.status === 'Connected',
  ).length

  const disconnectedCount =
    integrations.length - connectedCount

  function resetFilters() {
    setSearchQuery('')
    setStatusFilter('all')
  }

  function closeIntegrationDetails() {
    setSelectedIntegration(null)
  }

  function toggleIntegrationStatus(integrationId: string) {
    const currentIntegration = integrations.find(
      (integration) => integration.id === integrationId,
    )

    if (!currentIntegration) {
      return
    }

    const nextStatus: IntegrationStatus =
      currentIntegration.status === 'Connected'
        ? 'Disconnected'
        : 'Connected'

    const nextLastSync =
      nextStatus === 'Connected'
        ? 'Connected just now'
        : 'Not connected'

    setIntegrations((currentIntegrations) =>
      currentIntegrations.map((integration) =>
        integration.id === integrationId
          ? {
              ...integration,
              status: nextStatus,
              lastSync: nextLastSync,
            }
          : integration,
      ),
    )

    setSelectedIntegration((currentSelectedIntegration) => {
      if (
        !currentSelectedIntegration ||
        currentSelectedIntegration.id !== integrationId
      ) {
        return currentSelectedIntegration
      }

      return {
        ...currentSelectedIntegration,
        status: nextStatus,
        lastSync: nextLastSync,
      }
    })

    setPageMessage(
      nextStatus === 'Connected'
        ? `${currentIntegration.name} connected successfully.`
        : `${currentIntegration.name} disconnected for the current frontend session.`,
    )
  }

  function syncIntegration(integrationId: string) {
    const integration = integrations.find(
      (item) => item.id === integrationId,
    )

    if (!integration) {
      return
    }

    if (integration.status === 'Disconnected') {
      setPageMessage(
        `${integration.name} must be connected before it can be synchronized.`,
      )
      return
    }

    if (syncingIds.includes(integrationId)) {
      return
    }

    setSyncingIds((currentIds) => [
      ...currentIds,
      integrationId,
    ])

    setPageMessage(`Synchronizing ${integration.name}...`)

    window.setTimeout(() => {
      setIntegrations((currentIntegrations) =>
        currentIntegrations.map((currentIntegration) =>
          currentIntegration.id === integrationId
            ? {
                ...currentIntegration,
                lastSync: 'Just now',
              }
            : currentIntegration,
        ),
      )

      setSelectedIntegration((currentSelectedIntegration) => {
        if (
          !currentSelectedIntegration ||
          currentSelectedIntegration.id !== integrationId
        ) {
          return currentSelectedIntegration
        }

        return {
          ...currentSelectedIntegration,
          lastSync: 'Just now',
        }
      })

      setSyncingIds((currentIds) =>
        currentIds.filter(
          (currentId) => currentId !== integrationId,
        ),
      )

      setPageMessage(
        `${integration.name} synchronized successfully.`,
      )
    }, 700)
  }

  function testAllConnections() {
    const connectedIntegrations = integrations.filter(
      (integration) => integration.status === 'Connected',
    )

    if (connectedIntegrations.length === 0) {
      setPageMessage(
        'No connected integrations are available to test.',
      )
      return
    }

    const connectedIds = connectedIntegrations.map(
      (integration) => integration.id,
    )

    setSyncingIds(connectedIds)
    setPageMessage('Testing connected integrations...')

    window.setTimeout(() => {
      setIntegrations((currentIntegrations) =>
        currentIntegrations.map((integration) =>
          integration.status === 'Connected'
            ? {
                ...integration,
                lastSync: 'Just now',
              }
            : integration,
        ),
      )

      setSelectedIntegration((currentSelectedIntegration) => {
        if (
          !currentSelectedIntegration ||
          currentSelectedIntegration.status !== 'Connected'
        ) {
          return currentSelectedIntegration
        }

        return {
          ...currentSelectedIntegration,
          lastSync: 'Just now',
        }
      })

      setSyncingIds([])

      setPageMessage(
        `${connectedIntegrations.length} connected integrations passed the frontend connection test.`,
      )
    }, 900)
  }

  return (
    <section
      className="page active"
      data-page="integrations"
      data-page-name="Integrations"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Integrations</h1>

          <p className="sub">
            Connected telemetry, analysis, storage, AI, and response
            systems with synchronization status.
          </p>
        </div>

        <div className="actions-cell">
          <button
            className="btn primary"
            type="button"
            onClick={testAllConnections}
            disabled={syncingIds.length > 0}
          >
            {syncingIds.length > 1
              ? 'Testing Connections...'
              : 'Test All Connections'}
          </button>

          <span
            className={`pill ${
              disconnectedCount === 0 ? 'ok' : 'warn'
            }`}
          >
            {connectedCount}/{integrations.length} connected
          </span>
        </div>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>{integrations.length}</strong>
          <span>Total Integrations</span>
          <small>Configured frontend services</small>
        </div>

        <div className="stat">
          <strong>{connectedCount}</strong>
          <span>Connected</span>
          <small>Available services</small>
        </div>

        <div className="stat">
          <strong>{disconnectedCount}</strong>
          <span>Disconnected</span>
          <small>Require attention</small>
        </div>

        <div className="stat">
          <strong>{syncingIds.length}</strong>
          <span>Synchronizing</span>
          <small>Current connection tests</small>
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
          placeholder="Search integrations"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(event.target.value)
          }
        >
          <option value="all">All Statuses</option>
          <option value="Connected">Connected</option>
          <option value="Disconnected">Disconnected</option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue">
          {visibleIntegrations.length} visible
        </span>
      </div>

      <div className="card">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Integration</th>
                <th>Type</th>
                <th>Status</th>
                <th>Actions</th>
                <th>Last Sync</th>
              </tr>
            </thead>

            <tbody>
              {visibleIntegrations.map((integration) => {
                const isSyncing = syncingIds.includes(
                  integration.id,
                )

                return (
                  <tr
                    key={integration.id}
                    className="data-row"
                    data-search-record
                    data-page-target="integrations"
                  >
                    <td>
                      <strong>{integration.name}</strong>

                      <div
                        className="sub"
                        style={{
                          marginTop: '4px',
                          fontSize: '12px',
                        }}
                      >
                        {integration.id} · v{integration.version}
                      </div>
                    </td>

                    <td>{integration.type}</td>

                    <td>
                      <span
                        className={`pill ${statusClass(
                          integration.status,
                        )}`}
                      >
                        {integration.status}
                      </span>
                    </td>

                    <td className="actions-cell">
                      <button
                        className="btn small"
                        type="button"
                        onClick={() =>
                          setSelectedIntegration(integration)
                        }
                      >
                        View
                      </button>

                      <button
                        className="btn small primary"
                        type="button"
                        disabled={
                          integration.status === 'Disconnected' ||
                          isSyncing
                        }
                        onClick={() =>
                          syncIntegration(integration.id)
                        }
                      >
                        {isSyncing ? 'Syncing...' : 'Sync'}
                      </button>

                      <button
                        className={
                          integration.status === 'Connected'
                            ? 'btn small danger'
                            : 'btn small primary'
                        }
                        type="button"
                        disabled={isSyncing}
                        onClick={() =>
                          toggleIntegrationStatus(integration.id)
                        }
                      >
                        {integration.status === 'Connected'
                          ? 'Disconnect'
                          : 'Connect'}
                      </button>
                    </td>

                    <td>
                      {isSyncing
                        ? 'Synchronizing...'
                        : integration.lastSync}
                    </td>
                  </tr>
                )
              })}

              {visibleIntegrations.length === 0 && (
                <tr>
                  <td colSpan={5}>
                    <div className="empty">
                      <strong>No integrations found</strong>

                      <p className="sub">
                        No integrations match the current search and
                        status filter.
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

      {selectedIntegration &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeIntegrationDetails}
          >
            <div
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Integration details"
              onClick={(event) => event.stopPropagation()}
              style={{
                maxHeight: '90vh',
                overflowY: 'auto',
              }}
            >
              <div className="headline">
                <div>
                  <span className="sub">
                    Integration Details
                  </span>

                  <h2>{selectedIntegration.name}</h2>
                </div>

                <span
                  className={`pill ${statusClass(
                    selectedIntegration.status,
                  )}`}
                >
                  {selectedIntegration.status}
                </span>
              </div>

              <div className="modal-body">
                <div className="kv">
                  <span>Integration ID</span>
                  <strong>{selectedIntegration.id}</strong>
                </div>

                <div className="kv">
                  <span>Type</span>
                  <strong>{selectedIntegration.type}</strong>
                </div>

                <div className="kv">
                  <span>Version</span>
                  <strong>{selectedIntegration.version}</strong>
                </div>

                <div className="kv">
                  <span>Endpoint</span>
                  <strong>{selectedIntegration.endpoint}</strong>
                </div>

                <div className="kv">
                  <span>Last Sync</span>
                  <strong>
                    {syncingIds.includes(selectedIntegration.id)
                      ? 'Synchronizing...'
                      : selectedIntegration.lastSync}
                  </strong>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Description</h3>

                  <p className="sub">
                    {selectedIntegration.description}
                  </p>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Data Flow</h3>

                  <p className="sub">
                    {selectedIntegration.dataFlow}
                  </p>
                </div>

                <div
                  className="notice"
                  style={{ marginTop: '16px' }}
                >
                  Connection, disconnection, and synchronization
                  changes are temporary frontend demonstrations. No
                  external service is contacted.
                </div>
              </div>

              <div className="modal-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={closeIntegrationDetails}
                >
                  Close
                </button>

                <button
                  className="btn primary"
                  type="button"
                  disabled={
                    selectedIntegration.status === 'Disconnected' ||
                    syncingIds.includes(selectedIntegration.id)
                  }
                  onClick={() =>
                    syncIntegration(selectedIntegration.id)
                  }
                >
                  {syncingIds.includes(selectedIntegration.id)
                    ? 'Synchronizing...'
                    : 'Sync Integration'}
                </button>

                <button
                  className={
                    selectedIntegration.status === 'Connected'
                      ? 'btn danger'
                      : 'btn primary'
                  }
                  type="button"
                  disabled={syncingIds.includes(
                    selectedIntegration.id,
                  )}
                  onClick={() =>
                    toggleIntegrationStatus(
                      selectedIntegration.id,
                    )
                  }
                >
                  {selectedIntegration.status === 'Connected'
                    ? 'Disconnect'
                    : 'Connect'}
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default IntegrationsPage
