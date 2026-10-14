import { useMemo, useState, type CSSProperties } from 'react'
import { createPortal } from 'react-dom'

import type {
  HealthLevel,
  HealthMetric,
  ServiceRecord,
  ServiceStatus,
} from '../types/systemHealthTypes'

import {
  SERVICE_GROUPS,
  groupCount,
  isHealthy,
  probe,
  serviceStatus,
} from '../data/serviceInventory'
import { memoryPercent } from '../data/servicePanel'
import {
  initialMetrics,
  healthEvents,
  LATENCY_TARGET_MS,
  processingTotals,
} from '../data/systemHealthData'
import { getSystemStatus } from '../data/statusSummary'
import { useAdminState } from '../hooks/useAdminState'
import { useDialog } from '../hooks/useDialog'
import { statusTone } from '../utils/statusTone'

import Gauge from './Gauge'
import SeverityBadge from './SeverityBadge'
import TableScroll from './TableScroll'

function metricLevel(value: number, metricId: string): HealthLevel {
  if (
    metricId === 'services' ||
    metricId === 'hosts' ||
    metricId === 'alerts' ||
    metricId === 'cases'
  ) {
    if (value >= 80) {
      return 'Good'
    }

    if (value >= 65) {
      return 'Watch'
    }

    return 'Critical'
  }

  if (value < 60) {
    return 'Good'
  }

  if (value < 80) {
    return 'Watch'
  }

  return 'Critical'
}

function metricDescription(
  value: number,
  metricId: string,
): string {
  if (metricId === 'services') {
    return value >= 95
      ? 'Nearly all up'
      : value >= 80
        ? 'Some degradation'
        : 'Service disruption'
  }

  if (metricId === 'hosts') {
    return value >= 80
      ? 'Most online'
      : value >= 65
        ? 'Hosts unavailable'
        : 'Connectivity problem'
  }

  if (metricId === 'alerts') {
    return value >= 80
      ? 'Healthy throughput'
      : value >= 65
        ? 'Backlog forming'
        : 'Processing delayed'
  }

  if (metricId === 'cases') {
    return value >= 80
      ? 'Target achieved'
      : value >= 65
        ? 'Below target'
        : 'Needs attention'
  }

  if (value < 40) {
    return 'Low usage'
  }

  if (value < 60) {
    return 'Healthy load'
  }

  if (value < 80) {
    return 'Elevated'
  }

  return 'High usage'
}

const SERVICE_STATUSES: ServiceStatus[] = ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified']

// The drawer's assessment, one sentence per word
const ASSESSMENTS: Record<ServiceStatus, string> = {
  Running: 'The service is responding normally and remains available to AthenaSec.',
  Degraded:
    'The service is available, but its response latency is above the expected operational threshold.',
  Starting: 'The service is still starting. It may not respond yet, so check again shortly.',
  Failed: 'The service has failed (a failed unit or an error answer) and requires administrator investigation.',
  Stopped: 'The service is not currently running and requires administrator investigation.',
  Unverified: 'The service could not be verified, so its state is unknown.',
}

// Gauges worked out from the VM usage and the service inventory, not from this view's own state
const DERIVED_METRICS = ['cpu', 'memory', 'services']

/*
  The System health tab of the Service Panel: resource gauges, the one
  service inventory (both groups) with its checks, processing totals and
  recent events. The Panel's header carries the title and the summary
  sentence; the checks here are simulated in React.
*/
function SystemHealthView() {
  const [metrics, setMetrics] =
    useState<HealthMetric[]>(initialMetrics)

  // Shared admin state: checks reach the sidebar badge, top bar, search and audit log
  const { services, servicePanel, updateServices } = useAdminState()

  const [statusFilter, setStatusFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  const [selectedService, setSelectedService] =
    useState<ServiceRecord | null>(null)
  const dialogRef = useDialog(() => setSelectedService(null))

  const [refreshing, setRefreshing] = useState(false)
  const [checkingServiceIds, setCheckingServiceIds] = useState<
    string[]
  >([])

  const [lastRefresh, setLastRefresh] = useState(
    'When this page opened',
  )

  const [pageMessage, setPageMessage] = useState(
    'System health data is ready.',
  )

  const visibleServices = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return services.filter((service) => {
      const matchesSearch =
        normalizedQuery === '' ||
        service.id.toLowerCase().includes(normalizedQuery) ||
        service.name.toLowerCase().includes(normalizedQuery) ||
        service.category.toLowerCase().includes(normalizedQuery) ||
        serviceStatus(service).toLowerCase().includes(normalizedQuery) ||
        service.endpoint.toLowerCase().includes(normalizedQuery) ||
        service.version.toLowerCase().includes(normalizedQuery)

      const matchesStatus =
        statusFilter === 'all' ||
        serviceStatus(service) === statusFilter

      return matchesSearch && matchesStatus
    })
  }, [services, searchQuery, statusFilter])

  // "8 running, 1 degraded, 1 starting": the words with a count, Running always
  const statusCounts = SERVICE_STATUSES.map((status) => ({
    status,
    count: services.filter((service) => serviceStatus(service) === status).length,
  })).filter(({ status, count }) => status === 'Running' || count > 0)

  const systemStatus = getSystemStatus(services)

  const processedAlerts =
    metrics.find((metric) => metric.id === 'alerts')?.value ?? 0

  const caseAutomation =
    metrics.find((metric) => metric.id === 'cases')?.value ?? 0

  /*
    CPU and memory are the VM's usage (the same figures as the Overview's
    meters) and Running services is counted from the inventory; the other
    gauges are demo values of this tab.
  */
  const shownMetrics = metrics.map((metric) => {
    const value =
      metric.id === 'cpu'
        ? servicePanel.usage.cpuPercent
        : metric.id === 'memory'
          ? Number(memoryPercent(servicePanel.usage.memoryUsedBytes, servicePanel.usage.memoryTotalBytes).toFixed(1))
          : metric.id === 'services'
            ? Math.round((100 * services.filter(isHealthy).length) / services.length)
            : metric.value

    return DERIVED_METRICS.includes(metric.id)
      ? { ...metric, value, level: metricLevel(value, metric.id), description: metricDescription(value, metric.id) }
      : metric
  })

  function refreshHealth() {
    if (refreshing) {
      return
    }

    setRefreshing(true)
    setPageMessage('Refreshing health metrics…')

    window.setTimeout(() => {
      setMetrics((currentMetrics) =>
        currentMetrics.map((metric) => {
          const change = Math.floor(Math.random() * 9) - 4

          const nextValue = Math.min(
            100,
            Math.max(1, metric.value + change),
          )

          return {
            ...metric,
            value: nextValue,
            level: metricLevel(nextValue, metric.id),
            description: metricDescription(
              nextValue,
              metric.id,
            ),
          }
        }),
      )

      const refreshedServices = updateServices(
        (currentServices) =>
          currentServices.map((service) => {
            // A stopped service has no response time to move
            if (service.status === 'Stopped') {
              return service.group === 'pipeline'
                ? { ...service, lastCheck: 'Just now' }
                : service
            }

            // Only the pipeline is probed; the VM group stays the Service Panel snapshot
            return probe(service, Math.floor(Math.random() * 31) - 15)
          }),
        'refresh',
      )

      setSelectedService((currentService) => {
        if (!currentService) {
          return currentService
        }

        return (
          refreshedServices.find(
            (service) => service.id === currentService.id,
          ) ?? currentService
        )
      })

      setLastRefresh('Just now')
      setRefreshing(false)

      setPageMessage(
        'Health metrics refreshed.',
      )
    }, 850)
  }

  function checkService(serviceId: string) {
    const service = services.find(
      (currentService) => currentService.id === serviceId,
    )

    // Only the pipeline can be probed; the VM group is checked on the Service Panel
    if (!service || service.group !== 'pipeline' || checkingServiceIds.includes(serviceId)) {
      return
    }

    setCheckingServiceIds((currentIds) => [
      ...currentIds,
      serviceId,
    ])

    setPageMessage(`Checking ${service.name}…`)

    window.setTimeout(() => {
      const change = Math.floor(Math.random() * 41) - 20
      const probed = probe(service, change)
      const nextStatus = probed.status

      const updates: Partial<ServiceRecord> = {
        status: nextStatus,
        latency: probed.latency,
        lastCheck: 'Just now',
      }

      updateServices(
        (currentServices) =>
          currentServices.map((currentService) =>
            currentService.id === serviceId
              ? probe(currentService, change)
              : currentService,
          ),
        'check',
      )

      setSelectedService((currentService) => {
        if (
          !currentService ||
          currentService.id !== serviceId
        ) {
          return currentService
        }

        return {
          ...currentService,
          ...updates,
        }
      })

      setCheckingServiceIds((currentIds) =>
        currentIds.filter(
          (currentId) => currentId !== serviceId,
        ),
      )

      setPageMessage(
        `${service.name} check completed with status ${nextStatus}.`,
      )
    }, 700)
  }

  function checkAllServices() {
    if (checkingServiceIds.length > 0) {
      return
    }

    // Only the pipeline is probed; the VM group is a snapshot from the Service Panel
    const serviceIds = services
      .filter((service) => service.group === 'pipeline')
      .map((service) => service.id)

    setCheckingServiceIds(serviceIds)
    setPageMessage('Checking all services…')

    window.setTimeout(() => {
      const updatedServices = updateServices(
        (currentServices) =>
          currentServices.map((service) =>
            probe(service, Math.floor(Math.random() * 41) - 20),
          ),
        'check-all',
      )

      setSelectedService((currentService) => {
        if (!currentService) {
          return currentService
        }

        return (
          updatedServices.find(
            (service) => service.id === currentService.id,
          ) ?? currentService
        )
      })

      setCheckingServiceIds([])
      setLastRefresh('Just now')

      setPageMessage(
        `${serviceIds.length} service checks completed.`,
      )
    }, 950)
  }

  function resetFilters() {
    setSearchQuery('')
    setStatusFilter('all')
  }

  return (
    <div className="health-view" data-view="health">
      <div className="health-actions">
        <span className={`pill ${systemStatus.level}`} data-field="healthStatus">
          {systemStatus.level === 'ok'
            ? systemStatus.detail
            : systemStatus.title}
        </span>

        <button
          className="btn"
          type="button"
          onClick={refreshHealth}
          disabled={refreshing}
        >
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div className="notice" role="status">
        <strong>{pageMessage}</strong>

        <p className="sub">Last refresh: {lastRefresh}</p>
      </div>

      <section aria-labelledby="usageTitle">
        <h2 className="visually-hidden" id="usageTitle">
          Resource usage
        </h2>

        <ul className="gauge-grid">
          {shownMetrics.map((metric) => (
            <li className="card gauge-card" key={metric.id} data-metric={metric.id}>
              <Gauge value={metric.value} label={metric.name} state={metric.level} />

              <div className="gauge-text">
                <strong>{metric.name}</strong>
                <span>{metric.description}</span>
                <span className={`gauge-state ${statusTone(metric.level)}`}>
                  {metric.level === 'Critical' ? 'Needs attention' : metric.level}
                </span>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <div className="card health-services">
        <div className="headline">
          <div>
            <h2>Service Health</h2>

            <p className="sub" id="serviceCounts">
              {statusCounts.map(({ status, count }) => `${count} ${status.toLowerCase()}`).join(', ')}.
              Search, filter, inspect, and simulate service health checks.
            </p>

            <p className="sub" id="groupCounts">
              {SERVICE_GROUPS.map((group) => {
                const { healthy, total } = groupCount(services, group.key)

                return `${group.name}: ${healthy} of ${total} healthy`
              }).join(' · ')}
            </p>
          </div>

          <button
            className="btn primary"
            type="button"
            onClick={checkAllServices}
            disabled={checkingServiceIds.length > 0}
          >
            {checkingServiceIds.length > 1
              ? 'Checking Services…'
              : 'Check All Services'}
          </button>
        </div>

        <div className="toolbar">
          <input
            className="field-input"
            type="search"
            name="serviceSearch"
            autoComplete="off"
            aria-label="Search services"
            placeholder="Search services…"
            value={searchQuery}
            onChange={(event) =>
              setSearchQuery(event.target.value)
            }
          />

          <select
            className="select-input"
            name="statusFilter"
            autoComplete="off"
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(event.target.value)
            }
          >
            <option value="all">All Statuses</option>
            {SERVICE_STATUSES.map((status) => (
              <option key={status} value={status}>
                {status}
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
            {visibleServices.length} visible
          </span>
        </div>

        <TableScroll label="Service health">
          <table>
            <thead>
              <tr>
                <th>Service</th>
                <th>Group</th>
                <th>Category</th>
                <th>Status</th>
                <th>Uptime</th>
                <th>Latency</th>
                <th>Last Check</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>

            <tbody>
              {visibleServices.map((service) => {
                const isChecking =
                  checkingServiceIds.includes(service.id)

                return (
                  <tr
                    key={service.id}
                    className="data-row"
                    data-record-id={service.id}
                  >
                    <td>
                      <strong>{service.name}</strong>

                      <div
                        className="sub"
                        style={{
                          marginTop: '4px',
                          fontSize: '12px',
                        }}
                      >
                        {service.id} · v{service.version}
                      </div>
                    </td>

                    <td data-field="group">
                      {SERVICE_GROUPS.find((group) => group.key === service.group)?.name}
                    </td>

                    <td>{service.category}</td>

                    <td>
                      <span
                        className={`pill ${statusTone(serviceStatus(service))}`}
                      >
                        {serviceStatus(service)}
                      </span>
                    </td>

                    <td>{service.uptime}</td>
                    <td>
                      {service.latency === null ? (
                        <span className="sub" title="Checked for availability only">—</span>
                      ) : (
                        <span className="latency">
                          <span
                            className={`latency-bar${service.latency > LATENCY_TARGET_MS ? ' over' : ''}`}
                            aria-hidden="true"
                          >
                            <span
                              style={
                                {
                                  '--latency-pct': Math.min(
                                    100,
                                    Math.round((service.latency / LATENCY_TARGET_MS) * 100),
                                  ),
                                } as CSSProperties
                              }
                            />
                          </span>
                          <span className="latency-text">{service.latency} ms</span>
                        </span>
                      )}
                    </td>

                    <td>
                      {isChecking
                        ? 'Checking…'
                        : service.lastCheck}
                    </td>

                    <td className="actions-cell">
                      <button
                        className="btn small"
                        type="button"
                        aria-label={`View ${service.name}`}
                        onClick={() =>
                          setSelectedService(service)
                        }
                      >
                        View
                      </button>

                      {service.group === 'pipeline' && (
                        <button
                          className="btn small"
                          type="button"
                          disabled={isChecking}
                          aria-label={`${isChecking ? 'Checking' : 'Check'} ${service.name}`}
                          onClick={() =>
                            checkService(service.id)
                          }
                        >
                          {isChecking ? 'Checking…' : 'Check'}
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}

              {visibleServices.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <div className="empty">
                      <strong>No services found</strong>

                      <p className="sub">
                        No services match the current search and
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
        </TableScroll>
      </div>

      <div
        className="grid two"
        style={{ marginTop: '18px' }}
      >
        <div className="card">
          <h2>Processing Totals</h2>

          <div className="kv">
            <span>Alerts Processed</span>
            <strong>{processedAlerts}% capacity</strong>
          </div>

          <div className="metric">
            <span
              style={{
                width: `${processedAlerts}%`,
              }}
            />
          </div>

          <div className="kv">
            <span>Case Automation</span>
            <strong>{caseAutomation}% success</strong>
          </div>

          <div className="metric">
            <span
              style={{
                width: `${caseAutomation}%`,
              }}
            />
          </div>

          <div className="kv">
            <span>Events Indexed Today</span>
            <strong>{processingTotals.eventsIndexedToday}</strong>
          </div>

          <div className="kv">
            <span>Average Processing Time</span>
            <strong>{processingTotals.averageProcessingTime}</strong>
          </div>

          <div className="kv">
            <span>Connected Linux Hosts</span>
            <strong>{processingTotals.connectedHosts}</strong>
          </div>
        </div>

        <div className="card">
          <h2>Recent Health Events</h2>

          <ol className="health-events">
            {healthEvents.map((event) => (
              <li className="health-event" key={event.id}>
                <span className="health-event-when">
                  {event.time}
                  <SeverityBadge severity={event.severity} />
                </span>

                <strong className="health-event-what">
                  {event.source}
                  <span className="sub">{event.message}</span>
                </strong>
              </li>
            ))}
          </ol>
        </div>
      </div>

      {selectedService &&
        createPortal(
          <div
            className="drawer-backdrop"
            role="presentation"
            onClick={() => setSelectedService(null)}
          >
            <aside
              ref={dialogRef}
              className="alert-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Service health details"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="drawer-head">
                <div>
                  <span className="sub">
                    Service Health
                  </span>

                  <h2>{selectedService.name}</h2>
                </div>

                <button
                  className="icon-btn"
                  type="button"
                  aria-label="Close service details"
                  onClick={() => setSelectedService(null)}
                >
                  ×
                </button>
              </div>

              <div className="drawer-body">
                <div className="card">
                  <div className="headline">
                    <div>
                      <h3>Service Overview</h3>
                    </div>

                    <span
                      className={`pill ${statusTone(serviceStatus(selectedService))}`}
                    >
                      {serviceStatus(selectedService)}
                    </span>
                  </div>

                  <div className="kv">
                    <span>Service ID</span>
                    <strong>{selectedService.id}</strong>
                  </div>

                  <div className="kv">
                    <span>Group</span>
                    <strong>
                      {SERVICE_GROUPS.find((group) => group.key === selectedService.group)?.name}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Category</span>
                    <strong>
                      {selectedService.category}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Version</span>
                    <strong>
                      {selectedService.version}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Endpoint</span>
                    <strong>
                      {selectedService.endpoint}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Uptime</span>
                    <strong>
                      {selectedService.uptime}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Latency</span>
                    <strong>
                      {selectedService.latency === null
                        ? 'Not measured (availability only)'
                        : `${selectedService.latency} ms`}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Last Check</span>
                    <strong>
                      {checkingServiceIds.includes(
                        selectedService.id,
                      )
                        ? 'Checking…'
                        : selectedService.lastCheck}
                    </strong>
                  </div>
                </div>

                <div className="card">
                  <h3>Description</h3>

                  <p className="sub">
                    {selectedService.description}
                  </p>
                </div>

                <div className="card">
                  <h3>Operational Assessment</h3>

                  <p className="sub">
                    {ASSESSMENTS[serviceStatus(selectedService)]}
                  </p>
                </div>

                <div className="notice">
                  Service checks and health values on this page are
                  simulated in React. No real AthenaSec infrastructure
                  is contacted.
                </div>

                {selectedService.group === 'pipeline' && (
                  <button
                    className="btn primary"
                    type="button"
                    disabled={checkingServiceIds.includes(
                      selectedService.id,
                    )}
                    onClick={() =>
                      checkService(selectedService.id)
                    }
                  >
                    {checkingServiceIds.includes(
                      selectedService.id,
                    )
                      ? 'Checking Service…'
                      : 'Run Service Check'}
                  </button>
                )}
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </div>
  )
}

export default SystemHealthView
