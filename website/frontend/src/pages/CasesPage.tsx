import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import type {
  CaseRecord,
  CaseSeverity,
  CaseStatus,
} from '../types/casesTypes'

import { initialCases } from '../data/casesData'

function severityClass(severity: CaseSeverity) {
  if (severity === 'Critical') {
    return 'danger'
  }

  if (severity === 'High') {
    return 'warn'
  }

  return 'blue'
}

function statusClass(status: CaseStatus) {
  return status === 'Closed' ? 'ok' : 'blue'
}

function CasesPage() {
  const [cases, setCases] = useState<CaseRecord[]>(initialCases)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [selectedCase, setSelectedCase] =
    useState<CaseRecord | null>(null)

  const visibleCases = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return cases.filter((caseItem) => {
      const matchesSearch =
        normalizedQuery === '' ||
        caseItem.id.toLowerCase().includes(normalizedQuery) ||
        caseItem.sourceAlert.toLowerCase().includes(normalizedQuery) ||
        caseItem.assignedAnalyst
          .toLowerCase()
          .includes(normalizedQuery) ||
        caseItem.attackType.toLowerCase().includes(normalizedQuery) ||
        caseItem.endpoint.toLowerCase().includes(normalizedQuery) ||
        caseItem.sourceIp.toLowerCase().includes(normalizedQuery)

      const matchesSeverity =
        severityFilter === 'all' ||
        caseItem.severity === severityFilter

      const matchesStatus =
        statusFilter === 'all' ||
        caseItem.status === statusFilter

      return matchesSearch && matchesSeverity && matchesStatus
    })
  }, [cases, searchQuery, severityFilter, statusFilter])

  const activeCaseCount = cases.filter(
    (caseItem) => caseItem.status === 'Open',
  ).length

  function toggleCaseStatus(caseId: string) {
    setCases((currentCases) =>
      currentCases.map((caseItem) => {
        if (caseItem.id !== caseId) {
          return caseItem
        }

        return {
          ...caseItem,
          status:
            caseItem.status === 'Closed' ? 'Open' : 'Closed',
          lastUpdated: 'Just now',
        }
      }),
    )

    setSelectedCase((currentCase) => {
      if (!currentCase || currentCase.id !== caseId) {
        return currentCase
      }

      return {
        ...currentCase,
        status:
          currentCase.status === 'Closed' ? 'Open' : 'Closed',
        lastUpdated: 'Just now',
      }
    })
  }

  function resetFilters() {
    setSearchQuery('')
    setSeverityFilter('all')
    setStatusFilter('all')
  }

  return (
    <section
      className="page active"
      data-page="incidents"
      data-page-name="Case Management"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Case Management</h1>

          <p className="sub">
            Analyst-owned cases created from validated Brute Force and
            Privilege Escalation alerts.
          </p>
        </div>

        <span className="pill blue">
          {activeCaseCount} active{' '}
          {activeCaseCount === 1 ? 'case' : 'cases'}
        </span>
      </div>

      <div className="toolbar">
        <input
          className="field-input"
          id="incidentSearch"
          type="search"
          placeholder="Search cases"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />

        <select
          className="select-input"
          id="incidentSeverity"
          value={severityFilter}
          onChange={(event) =>
            setSeverityFilter(event.target.value)
          }
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
        </select>

        <select
          className="select-input"
          id="incidentStatus"
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(event.target.value)
          }
        >
          <option value="all">All Statuses</option>
          <option value="Open">Open</option>
          <option value="Closed">Closed</option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>
      </div>

      <div className="card">
        <div className="headline">
          <div>
            <h2>Case Queue</h2>

            <p className="sub">
              {visibleCases.length} visible{' '}
              {visibleCases.length === 1 ? 'case' : 'cases'}
            </p>
          </div>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Source Alert</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assigned Analyst</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody id="incidentRows">
              {visibleCases.map((caseItem) => (
                <tr
                  key={caseItem.id}
                  className="data-row"
                  data-search-record
                  data-page-target="incidents"
                  data-case-id={caseItem.id}
                  data-severity={caseItem.severity}
                  data-status={caseItem.status}
                >
                  <td>{caseItem.id}</td>
                  <td>{caseItem.sourceAlert}</td>

                  <td>
                    <span
                      className={`pill ${severityClass(
                        caseItem.severity,
                      )}`}
                    >
                      {caseItem.severity}
                    </span>
                  </td>

                  <td className="incident-status">
                    <span
                      className={`pill ${statusClass(
                        caseItem.status,
                      )}`}
                    >
                      {caseItem.status}
                    </span>
                  </td>

                  <td className="incident-assigned">
                    {caseItem.assignedAnalyst}
                  </td>

                  <td className="actions-cell">
                    <button
                      className="btn small"
                      type="button"
                      onClick={() => setSelectedCase(caseItem)}
                    >
                      View
                    </button>

                    <button
                      className={
                        caseItem.status === 'Closed'
                          ? 'btn small primary'
                          : 'btn small danger'
                      }
                      type="button"
                      onClick={() =>
                        toggleCaseStatus(caseItem.id)
                      }
                    >
                      {caseItem.status === 'Closed'
                        ? 'Reopen Case'
                        : 'Close Case'}
                    </button>
                  </td>
                </tr>
              ))}

              {visibleCases.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">
                      <strong>No cases found</strong>

                      <p className="sub">
                        No cases match the current search and filters.
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

      {selectedCase &&
        createPortal(
          <div
            className="drawer-backdrop"
            role="presentation"
            onClick={() => setSelectedCase(null)}
          >
            <aside
              className="alert-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Case details"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="drawer-head">
                <div>
                  <span className="sub">Case Details</span>
                  <h2>{selectedCase.id}</h2>
                </div>

                <button
                  className="icon-btn"
                  type="button"
                  aria-label="Close case details"
                  onClick={() => setSelectedCase(null)}
                >
                  ×
                </button>
              </div>

              <div className="drawer-body">
                <div className="card">
                  <div className="headline">
                    <div>
                      <h3>Case Overview</h3>
                    </div>

                    <span
                      className={`pill ${statusClass(
                        selectedCase.status,
                      )}`}
                    >
                      {selectedCase.status}
                    </span>
                  </div>

                  <div className="kv">
                    <span>Case ID</span>
                    <strong>{selectedCase.id}</strong>
                  </div>

                  <div className="kv">
                    <span>Source Alert</span>
                    <strong>{selectedCase.sourceAlert}</strong>
                  </div>

                  <div className="kv">
                    <span>Severity</span>
                    <strong>{selectedCase.severity}</strong>
                  </div>

                  <div className="kv">
                    <span>Assigned Analyst</span>
                    <strong>
                      {selectedCase.assignedAnalyst}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Attack Type</span>
                    <strong>{selectedCase.attackType}</strong>
                  </div>

                  <div className="kv">
                    <span>Endpoint</span>
                    <strong>{selectedCase.endpoint}</strong>
                  </div>

                  <div className="kv">
                    <span>Source IP</span>
                    <strong>{selectedCase.sourceIp}</strong>
                  </div>

                  <div className="kv">
                    <span>Risk Score</span>
                    <strong>
                      {selectedCase.riskScore} / 100
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Created</span>
                    <strong>{selectedCase.createdAt}</strong>
                  </div>

                  <div className="kv">
                    <span>Last Updated</span>
                    <strong>{selectedCase.lastUpdated}</strong>
                  </div>
                </div>

                <div className="card">
                  <h3>Case Summary</h3>

                  <p className="sub">{selectedCase.summary}</p>
                </div>

                <div className="card">
                  <h3>MITRE ATT&amp;CK Mapping</h3>

                  <span className="pill blue">
                    {selectedCase.mitre}
                  </span>
                </div>

                <div className="card">
                  <h3>Collected Evidence</h3>

                  <div className="stack">
                    {selectedCase.evidence.map((item) => (
                      <div className="kv" key={item}>
                        <span>Evidence</span>
                        <strong>{item}</strong>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="card">
                  <h3>Recommended Actions</h3>

                  <div className="stack">
                    {selectedCase.recommendedActions.map(
                      (action, index) => (
                        <div className="kv" key={action}>
                          <span>Action {index + 1}</span>
                          <strong>{action}</strong>
                        </div>
                      ),
                    )}
                  </div>
                </div>

                <div className="card">
                  <h3>Case Timeline</h3>

                  <div className="timeline">
                    {selectedCase.timeline.map((item) => (
                      <div
                        className="timeline-item"
                        key={`${item.time}-${item.title}`}
                      >
                        <div className="timeline-dot" />

                        <div>
                          <div className="timeline-head">
                            <strong>{item.title}</strong>
                            <span className="sub">
                              {item.time}
                            </span>
                          </div>

                          <p className="sub">
                            {item.description}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="card">
                  <h3>Case Action</h3>

                  <p className="sub">
                    {selectedCase.status === 'Closed'
                      ? 'Reopen this case and return it to the active investigation queue.'
                      : 'Close this case after the investigation and response have been reviewed.'}
                  </p>

                  <button
                    className={
                      selectedCase.status === 'Closed'
                        ? 'btn primary'
                        : 'btn danger'
                    }
                    type="button"
                    onClick={() =>
                      toggleCaseStatus(selectedCase.id)
                    }
                    style={{ marginTop: '14px' }}
                  >
                    {selectedCase.status === 'Closed'
                      ? 'Reopen Case'
                      : 'Close Case'}
                  </button>
                </div>
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default CasesPage
