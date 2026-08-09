import { useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import type {
  ActionType,
  ApprovalType,
  ExecutionRecord,
  ExecutionResult,
} from '../types/incidentResponseTypes'

import { executionRecords } from '../data/incidentResponseData'

function resultClass(result: ExecutionResult) {
  return result === 'Completed' ? 'ok' : 'danger'
}

function approvalClass(approvalType: ApprovalType) {
  return approvalType === 'Automatic' ? 'blue' : 'warn'
}

function actionClass(action: ActionType) {
  return action === 'Isolate Host' ? 'danger' : 'blue'
}

function IncidentResponsePage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [resultFilter, setResultFilter] = useState('all')
  const [selectedExecution, setSelectedExecution] =
    useState<ExecutionRecord | null>(null)

  const visibleExecutions = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return executionRecords.filter((execution) => {
      const matchesSearch =
        normalizedQuery === '' ||
        execution.id.toLowerCase().includes(normalizedQuery) ||
        execution.triggeringAlert
          .toLowerCase()
          .includes(normalizedQuery) ||
        execution.policy.toLowerCase().includes(normalizedQuery) ||
        execution.action.toLowerCase().includes(normalizedQuery) ||
        execution.target.toLowerCase().includes(normalizedQuery) ||
        execution.initiator.toLowerCase().includes(normalizedQuery) ||
        execution.approvalType
          .toLowerCase()
          .includes(normalizedQuery) ||
        execution.result.toLowerCase().includes(normalizedQuery)

      const matchesAction =
        actionFilter === 'all' ||
        execution.action === actionFilter

      const matchesResult =
        resultFilter === 'all' ||
        execution.result === resultFilter

      return matchesSearch && matchesAction && matchesResult
    })
  }, [searchQuery, actionFilter, resultFilter])

  const completedCount = executionRecords.filter(
    (execution) => execution.result === 'Completed',
  ).length

  const failedCount = executionRecords.filter(
    (execution) => execution.result === 'Failed',
  ).length

  const automaticCount = executionRecords.filter(
    (execution) => execution.approvalType === 'Automatic',
  ).length

  function resetFilters() {
    setSearchQuery('')
    setActionFilter('all')
    setResultFilter('all')
  }

  return (
    <section
      className="page active"
      data-page="response-activity"
      data-page-name="Incident Response"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Incident Response</h1>

          <p className="sub">
            Permanent history of AI-executed and analyst-approved
            containment actions.
          </p>
        </div>

        <span className="pill ok">
          {completedCount} completed
        </span>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>{executionRecords.length}</strong>
          <span>Total Executions</span>
          <small>Recorded response actions</small>
        </div>

        <div className="stat">
          <strong>{completedCount}</strong>
          <span>Completed</span>
          <small>Successful actions</small>
        </div>

        <div className="stat">
          <strong>{automaticCount}</strong>
          <span>Automatic</span>
          <small>AI-approved by policy</small>
        </div>

        <div className="stat">
          <strong>{failedCount}</strong>
          <span>Failed</span>
          <small>Require analyst review</small>
        </div>
      </div>

      <div className="card" style={{ marginTop: '18px' }}>
        <div className="headline">
          <div>
            <h2>Response History</h2>

            <p className="sub">
              Completed response records are read-only and retained for
              investigation and audit review.
            </p>
          </div>

          <span className="pill blue">
            {visibleExecutions.length} visible
          </span>
        </div>

        <div className="toolbar">
          <input
            className="field-input"
            type="search"
            placeholder="Search executions, alerts, policies, or targets"
            value={searchQuery}
            onChange={(event) =>
              setSearchQuery(event.target.value)
            }
          />

          <select
            className="select-input"
            value={actionFilter}
            onChange={(event) =>
              setActionFilter(event.target.value)
            }
          >
            <option value="all">All Actions</option>
            <option value="Block IP">Block IP</option>
            <option value="Isolate Host">Isolate Host</option>
          </select>

          <select
            className="select-input"
            value={resultFilter}
            onChange={(event) =>
              setResultFilter(event.target.value)
            }
          >
            <option value="all">All Results</option>
            <option value="Completed">Completed</option>
            <option value="Failed">Failed</option>
          </select>

          <button
            className="btn"
            type="button"
            onClick={resetFilters}
          >
            Reset Filters
          </button>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Execution ID</th>
                <th>Alert</th>
                <th>Action</th>
                <th>Target</th>
                <th>Policy</th>
                <th>Initiator</th>
                <th>Approval</th>
                <th>Result</th>
                <th>Time</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {visibleExecutions.map((execution) => (
                <tr
                  key={execution.id}
                  className="data-row"
                  data-search-record
                  data-page-target="response-activity"
                  data-execution-id={execution.id}
                >
                  <td>{execution.id}</td>
                  <td>{execution.triggeringAlert}</td>

                  <td>
                    <span
                      className={`pill ${actionClass(
                        execution.action,
                      )}`}
                    >
                      {execution.action}
                    </span>
                  </td>

                  <td>{execution.target}</td>
                  <td>{execution.policy}</td>
                  <td>{execution.initiator}</td>

                  <td>
                    <span
                      className={`pill ${approvalClass(
                        execution.approvalType,
                      )}`}
                    >
                      {execution.approvalType}
                    </span>
                  </td>

                  <td>
                    <span
                      className={`pill ${resultClass(
                        execution.result,
                      )}`}
                    >
                      {execution.result}
                    </span>
                  </td>

                  <td>{execution.endTime}</td>

                  <td>
                    <button
                      className="btn small primary"
                      type="button"
                      onClick={() =>
                        setSelectedExecution(execution)
                      }
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}

              {visibleExecutions.length === 0 && (
                <tr>
                  <td colSpan={10}>
                    <div className="empty">
                      <strong>No response executions found</strong>

                      <p className="sub">
                        No records match the current search and filters.
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

      {selectedExecution &&
        createPortal(
          <div
            className="drawer-backdrop"
            role="presentation"
            onClick={() => setSelectedExecution(null)}
          >
            <aside
              className="alert-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="AI execution details"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="drawer-head">
                <div>
                  <span className="sub">
                    AI Execution Details
                  </span>

                  <h2>{selectedExecution.id}</h2>
                </div>

                <button
                  className="icon-btn"
                  type="button"
                  aria-label="Close execution details"
                  onClick={() => setSelectedExecution(null)}
                >
                  ×
                </button>
              </div>

              <div className="drawer-body">
                <div className="card">
                  <div className="headline">
                    <div>
                      <h3>Execution Overview</h3>
                    </div>

                    <span
                      className={`pill ${resultClass(
                        selectedExecution.result,
                      )}`}
                    >
                      {selectedExecution.result}
                    </span>
                  </div>

                  <div className="kv">
                    <span>Execution ID</span>
                    <strong>{selectedExecution.id}</strong>
                  </div>

                  <div className="kv">
                    <span>Triggering Alert</span>
                    <strong>
                      {selectedExecution.triggeringAlert}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Action</span>
                    <strong>{selectedExecution.action}</strong>
                  </div>

                  <div className="kv">
                    <span>Target</span>
                    <strong>{selectedExecution.target}</strong>
                  </div>

                  <div className="kv">
                    <span>Initiator</span>
                    <strong>{selectedExecution.initiator}</strong>
                  </div>

                  <div className="kv">
                    <span>Approval Type</span>
                    <strong>
                      {selectedExecution.approvalType}
                    </strong>
                  </div>

                  <div className="kv">
                    <span>Start Time</span>
                    <strong>{selectedExecution.startTime}</strong>
                  </div>

                  <div className="kv">
                    <span>End Time</span>
                    <strong>{selectedExecution.endTime}</strong>
                  </div>

                  <div className="kv">
                    <span>Duration</span>
                    <strong>{selectedExecution.duration}</strong>
                  </div>

                  <div className="kv">
                    <span>Rollback Status</span>
                    <strong>
                      {selectedExecution.rollbackStatus}
                    </strong>
                  </div>
                </div>

                <div className="card">
                  <h3>What Happened</h3>

                  <p className="sub">
                    {selectedExecution.happened}
                  </p>
                </div>

                <div className="card">
                  <h3>Why It Was Malicious</h3>

                  <p className="sub">
                    {selectedExecution.classified}
                  </p>
                </div>

                <div className="card">
                  <h3>Why This Response Was Executed</h3>

                  <p className="sub">
                    {selectedExecution.responseReason}
                  </p>
                </div>

                <div className="card">
                  <h3>Policy / Rule Triggered</h3>

                  <span className="pill blue">
                    {selectedExecution.policy}
                  </span>
                </div>

                <div className="card">
                  <h3>Supporting Evidence</h3>

                  <div className="split-list">
                    {selectedExecution.evidence.map((item) => (
                      <span className="pill blue" key={item}>
                        {item}
                      </span>
                    ))}
                  </div>
                </div>

                {selectedExecution.result === 'Failed' && (
                  <div className="card">
                    <h3>Failure Reason</h3>

                    <p className="sub">
                      {selectedExecution.failureReason}
                    </p>
                  </div>
                )}

                <div className="card">
                  <h3>Execution Timeline</h3>

                  <div className="timeline">
                    {selectedExecution.timeline.map((item) => (
                      <div
                        className="timeline-item"
                        key={`${item.time}-${item.event}`}
                      >
                        <strong>{item.time}</strong>
                        <span>{item.event}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="notice">
                  This response record is read-only. Completed security
                  actions should not be modified after execution.
                </div>
              </div>
            </aside>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default IncidentResponsePage
