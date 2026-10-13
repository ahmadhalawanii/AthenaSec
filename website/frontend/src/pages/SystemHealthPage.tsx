import {
  useMemo,
  useState,
  type CSSProperties,
} from 'react'
import { createPortal } from 'react-dom'
import type {
  EventSeverity,
  HealthLevel,
  HealthMetric,
  ServiceRecord,
  ServiceStatus,
} from '../types/systemHealthTypes'

import { initialMetrics, initialServices, healthEvents } from '../data/systemHealthData'



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

function donutClass(level: HealthLevel) {
  if (level === 'Good') {
    return 'good'
  }

  if (level === 'Watch') {
    return 'warn'
  }

  return 'bad'
}

function healthTagClass(level: HealthLevel) {
  if (level === 'Good') {
    return 'good'
  }

  if (level === 'Watch') {
    return 'warn'
  }

  return 'bad'
}

function serviceStatusClass(status: ServiceStatus) {
  if (status === 'Online') {
    return 'ok'
  }

  if (status === 'Degraded') {
    return 'warn'
  }

  return 'danger'
}

function eventSeverityClass(severity: EventSeverity) {
  if (severity === 'Info') {
    return 'blue'
  }

  if (severity === 'Warning') {
    return 'warn'
  }

  return 'danger'
}

function SystemHealthPage() {
  const [metrics, setMetrics] =
    useState<HealthMetric[]>(initialMetrics)

  const [services, setServices] =
    useState<ServiceRecord[]>(initialServices)

  const [statusFilter, setStatusFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  const [selectedService, setSelectedService] =
    useState<ServiceRecord | null>(null)

  const [refreshing, setRefreshing] = useState(false)
  const [checkingServiceIds, setCheckingServiceIds] = useState<
    string[]
  >([])

  const [lastRefresh, setLastRefresh] = useState(
    'Initial static snapshot',
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
        service.status.toLowerCase().includes(normalizedQuery) ||
        service.endpoint.toLowerCase().includes(normalizedQuery) ||
        service.version.toLowerCase().includes(normalizedQuery)

      const matchesStatus =
        statusFilter === 'all' ||
        service.status === statusFilter

      return matchesSearch && matchesStatus
    })
  }, [services, searchQuery, statusFilter])

  const onlineCount = services.filter(
    (service) => service.status === 'Online',
  ).length

  const degradedCount = services.filter(
    (service) => service.status === 'Degraded',
  ).length

  const offlineCount = services.filter(
    (service) => service.status === 'Offline',
  ).length

  const processedAlerts =
    metrics.find((metric) => metric.id === 'alerts')?.value ?? 0

  const caseAutomation =
    metrics.find((metric) => metric.id === 'cases')?.value ?? 0

  function refreshHealth() {
    if (refreshing) {
      return
    }

    setRefreshing(true)
    setPageMessage('Refreshing frontend health metrics...')

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

      setServices((currentServices) =>
        currentServices.map((service) => {
          if (service.status === 'Offline') {
            return {
              ...service,
              lastCheck: 'Just now',
            }
          }

          const latencyChange =
            Math.floor(Math.random() * 31) - 15

          return {
            ...service,
            latency: Math.max(
              10,
              service.latency + latencyChange,
            ),
            lastCheck: 'Just now',
          }
        }),
      )

      setSelectedService((currentService) => {
        if (!currentService) {
          return currentService
        }

        const updatedService = services.find(
          (service) => service.id === currentService.id,
        )

        return updatedService
          ? {
              ...updatedService,
              lastCheck: 'Just now',
            }
          : currentService
      })

      setLastRefresh('Just now')
      setRefreshing(false)

      setPageMessage(
        'Frontend system-health metrics refreshed successfully.',
      )
    }, 850)
  }

  function checkService(serviceId: string) {
    const service = services.find(
      (currentService) => currentService.id === serviceId,
    )

    if (!service || checkingServiceIds.includes(serviceId)) {
      return
    }

    setCheckingServiceIds((currentIds) => [
      ...currentIds,
      serviceId,
    ])

    setPageMessage(`Checking ${service.name}...`)

    window.setTimeout(() => {
      const nextLatency = Math.max(
        10,
        service.latency +
          (Math.floor(Math.random() * 41) - 20),
      )

      const nextStatus: ServiceStatus =
        nextLatency > 600
          ? 'Offline'
          : nextLatency > 300
            ? 'Degraded'
            : 'Online'

      const updates: Partial<ServiceRecord> = {
        status: nextStatus,
        latency: nextLatency,
        lastCheck: 'Just now',
      }

      setServices((currentServices) =>
        currentServices.map((currentService) =>
          currentService.id === serviceId
            ? {
                ...currentService,
                ...updates,
              }
            : currentService,
        ),
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

    const serviceIds = services.map((service) => service.id)

    setCheckingServiceIds(serviceIds)
    setPageMessage('Checking all frontend services...')

    window.setTimeout(() => {
      const updatedServices = services.map((service) => {
        const latencyChange =
          Math.floor(Math.random() * 41) - 20

        const nextLatency = Math.max(
          10,
          service.latency + latencyChange,
        )

        const nextStatus: ServiceStatus =
          nextLatency > 600
            ? 'Offline'
            : nextLatency > 300
              ? 'Degraded'
              : 'Online'

        return {
          ...service,
          status: nextStatus,
          latency: nextLatency,
          lastCheck: 'Just now',
        }
      })

      setServices(updatedServices)

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
        `${updatedServices.length} frontend service checks completed.`,
      )
    }, 950)
  }

  function resetFilters() {
    setSearchQuery('')
    setStatusFilter('all')
  }

  return (
    <section
      className="page active"
      data-page="system-health"
      data-page-name="System Health"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>System Health</h1>

          <p className="sub">
            Operational health across infrastructure, services,
            alert processing, and case automation.
          </p>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            flexWrap: 'wrap',
          }}
        >
          <span
            className={`pill ${
              offlineCount > 0
                ? 'danger'
                : degradedCount > 0
                  ? 'warn'
                  : 'ok'
            }`}
          >
            {offlineCount > 0
              ? 'Service Outage'
              : degradedCount > 0
                ? 'Attention Required'
                : 'All Systems Operational'}
          </span>

          <button
            className="btn primary"
            type="button"
            onClick={refreshHealth}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div
        className="notice"
        role="status"
        style={{ marginBottom: '18px' }}
      >
        <strong>{pageMessage}</strong>

        <p
          className="sub"
          style={{ marginTop: '6px' }}
        >
          Last refresh: {lastRefresh}
        </p>
      </div>

      <div className="grid four">
        {metrics.map((metric) => (
          <div
            className="stat health-stat"
            key={metric.id}
          >
            <div
              className={`donut ${donutClass(metric.level)}`}
              style={
                {
                  '--donut-pct': metric.value,
                } as CSSProperties
              }
            >
              <div className="donut-label">
                {metric.value}%
              </div>
            </div>

            <div className="health-info">
              <strong
                style={{
                  fontSize: '15px',
                  color: '#fff',
                }}
              >
                {metric.name}
              </strong>

              <span>{metric.description}</span>

              <span
                className={`health-tag ${healthTagClass(
                  metric.level,
                )}`}
              >
                {metric.level === 'Critical'
                  ? 'Needs attention'
                  : metric.level}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div
        className="grid stats"
        style={{ marginTop: '18px' }}
      >
        <div className="stat">
          <strong>{services.length}</strong>
          <span>Total Services</span>
          <small>Configured health checks</small>
        </div>

        <div className="stat">
          <strong>{onlineCount}</strong>
          <span>Online</span>
          <small>Operating normally</small>
        </div>

        <div className="stat">
          <strong>{degradedCount}</strong>
          <span>Degraded</span>
          <small>Require monitoring</small>
        </div>

        <div className="stat">
          <strong>{offlineCount}</strong>
          <span>Offline</span>
          <small>Require immediate review</small>
        </div>
      </div>

      <div
        className="card"
        style={{ marginTop: '18px' }}
      >
        <div className="headline">
          <div>
            <h2>Service Health</h2>

            <p className="sub">
              Search, filter, inspect, and simulate service
              health checks.
            </p>
          </div>

          <button
            className="btn primary"
            type="button"
            onClick={checkAllServices}
            disabled={checkingServiceIds.length > 0}
          >
            {checkingServiceIds.length > 1
              ? 'Checking Services...'
              : 'Check All Services'}
          </button>
        </div>

        <div className="toolbar">
          <input
            className="field-input"
            type="search"
            placeholder="Search services"
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
            <option value="Online">Online</option>
            <option value="Degraded">Degraded</option>
            <option value="Offline">Offline</option>
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

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Service</th>
                <th>Category</th>
                <th>Status</th>
                <th>Uptime</th>
                <th>Latency</th>
                <th>Last Check</th>
                <th>Actions</th>
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
                    data-search-record
                    data-page-target="system-health"
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

                    <td>{service.category}</td>

                    <td>
                      <span
                        className={`pill ${serviceStatusClass(
                          service.status,
                        )}`}
                      >
                        {service.status}
                      </span>
                    </td>

                    <td>{service.uptime}</td>
                    <td>{service.latency} ms</td>

                    <td>
                      {isChecking
                        ? 'Checking...'
                        : service.lastCheck}
                    </td>

                    <td className="actions-cell">
                      <button
                        className="btn small"
                        type="button"
                        onClick={() =>
                          setSelectedService(service)
                        }
                      >
                        View
                      </button>

                      <button
                        className="btn small primary"
                        type="button"
                        disabled={isChecking}
                        onClick={() =>
                          checkService(service.id)
                        }
                      >
                        {isChecking ? 'Checking...' : 'Check'}
                      </button>
                    </td>
                  </tr>
                )
              })}

              {visibleServices.length === 0 && (
                <tr>
                  <td colSpan={7}>
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
        </div>
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
            <strong>18,462</strong>
          </div>

          <div className="kv">
            <span>Average Processing Time</span>
            <strong>1.8 seconds</strong>
          </div>

          <div className="kv">
            <span>Connected Linux Hosts</span>
            <strong>41 / 50</strong>
          </div>
        </div>

        <div className="card">
          <h2>Recent Health Events</h2>

          <div className="stack">
            {healthEvents.map((event) => (
              <div
                className="kv"
                key={event.id}
              >
                <span>
                  {event.time}
                  <br />
                  <span
                    className={`pill ${eventSeverityClass(
                      event.severity,
                    )}`}
                    style={{ marginTop: '6px' }}
                  >
                    {event.severity}
                  </span>
                </span>

                <strong>
                  {event.source}
                  <span
                    className="sub"
                    style={{
                      display: 'block',
                      marginTop: '5px',
                    }}
                  >
                    {event.message}
                  </span>
                </strong>
              </div>
            ))}
          </div>
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
                      className={`pill ${serviceStatusClass(
                        selectedService.status,
                      )}`}
                    >
                      {selectedService.status}
                    </span>
                  </div>

                  <div className="kv">
                    <span>Service ID</span>
                    <strong>{selectedService.id}</strong>
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
                      {selectedService.latency} ms
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Last Check</span>
                    <strong>
                      {checkingServiceIds.includes(
                        selectedService.id,
                      )
                        ? 'Checking...'
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
                    {selectedService.status === 'Online'
                      ? 'The service is responding normally and remains available to AthenaSec.'
                      : selectedService.status === 'Degraded'
                        ? 'The service is available, but its response latency is above the expected operational threshold.'
                        : 'The service is not currently responding and requires administrator investigation.'}
                  </p>
                </div>

                <div className="notice">
                  Service checks and health values on this page are
                  simulated in React. No real AthenaSec infrastructure
                  is contacted.
                </div>

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
                    ? 'Checking Service...'
                    : 'Run Service Check'}
                </button>
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default SystemHealthPage
