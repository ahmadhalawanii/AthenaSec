import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import AttackPathMap from '../components/AttackPathMap'
import RiskRing from '../components/RiskRing'
import Segmented from '../components/Segmented'
import SeverityBadge from '../components/SeverityBadge'
import Timeline from '../components/Timeline'
import { OUTCOME_LABELS } from '../data/agentPolicyData'
import { alertEvidence } from '../data/alertDetailsData'
import {
  buildDecisionQueue,
  buildPosture,
  buildResponseLog,
  latestEventTime,
  mostUrgentPath,
} from '../data/analystDashboardData'
import { buildAttackMap } from '../data/attackPathData'
import { alertTimeline, executionFor, needsDecision } from '../data/statusSummary'
import { useAssessments } from '../hooks/useAssessments'
import { PHONE_QUERY, useMediaQuery } from '../hooks/useMediaQuery'
import { useSocState } from '../hooks/useSocState'
import type { SearchNavigationState } from '../types/searchTypes'
import { statusTone } from '../utils/statusTone'

type MapView = 'map' | 'list'

const alertsLinkStateFor = (alertId: string): SearchNavigationState => ({ highlight: alertId })

const MAP_VIEWS = [
  { value: 'map' as const, label: 'Map' },
  { value: 'list' as const, label: 'List' },
]

function AnalystDashboardPage() {
  const {
    alerts,
    executions,
    cases,
    actions,
    currentUser,
    approvals,
    toggleAlertStatus,
    assignToMe,
  } = useSocState()

  const assessments = useAssessments()

  const isPhone = useMediaQuery(PHONE_QUERY)
  const [view, setView] = useState<MapView>('map')
  // Phones always get the list; the map needs the room.
  const showMap = view === 'map' && !isPhone

  const attackMap = useMemo(
    () => buildAttackMap(alerts, executions, approvals),
    [alerts, executions, approvals],
  )
  const queue = useMemo(
    () => buildDecisionQueue(alerts, executions, approvals),
    [alerts, executions, approvals],
  )
  const posture = useMemo(
    () => buildPosture(alerts, executions, cases, approvals),
    [alerts, executions, cases, approvals],
  )
  const responseLog = useMemo(() => buildResponseLog(executions, approvals), [executions, approvals])

  // Start on the path that most needs attention: an active one waiting for approval, then by risk
  const [selectedId, setSelectedId] = useState(() => mostUrgentPath(attackMap.paths, queue))

  /*
    The attack-path map is drawn from mapped network paths (attackPathData.ts),
    which only exist for the sample alerts. Live alerts have none yet, so the
    dashboard lists the latest alerts instead of drawing a map.
  */
  if (attackMap.paths.length === 0) {
    const latest = [...alerts].sort((a, b) => b.risk - a.risk).slice(0, 8)

    return (
      <section className="page active" data-page="dashboard" data-page-name="Security Dashboard">
        <div className="headline">
          <div>
            <h1>Security Dashboard</h1>
            <p className="sub">
              {alerts.length === 0
                ? 'No alerts yet. New Wazuh alerts appear here once the agent has assessed them.'
                : `${alerts.length} ${alerts.length === 1 ? 'alert' : 'alerts'} from the agent, highest risk first.`}
            </p>
          </div>
          <p className="dash-latest">
            Latest event <span className="mono">{latestEventTime(alerts)}</span>
          </p>
        </div>

        <section className="card queue" aria-label="Latest alerts">
          {latest.length === 0 ? (
            <div className="empty">
              <p>Nothing to review right now.</p>
            </div>
          ) : (
            <ul className="queue-list">
              {latest.map((alert) => (
                <li key={alert.id}>
                  <Link className="queue-item" to="/app/alerts" state={alertsLinkStateFor(alert.id)}>
                    <RiskRing score={alert.risk} />
                    <span className="queue-text">
                      <span className="queue-title">
                        <span className="queue-name">{alert.attackType}</span>
                        <SeverityBadge severity={alert.severity} />
                      </span>
                      <span className="queue-meta">
                        <span className="mono">{alert.id}</span> at{' '}
                        <span className="mono">{alert.time}</span> on {alert.endpoint}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </section>
    )
  }

  const selectedPath = attackMap.paths.find((path) => path.alert.id === selectedId) ?? attackMap.paths[0]
  const selected = selectedPath.alert
  const selectedDecision = queue.find((item) => item.alert.id === selected.id)
  const selectedEvidence = alertEvidence[selected.id]?.[0]?.text ?? selected.summary
  const timeline = alertTimeline(selected, executions, cases, actions, approvals)
  const activePaths = attackMap.paths.filter((path) => path.status === 'active').length

  const alertsLinkState = (alertId: string): SearchNavigationState => ({ highlight: alertId })

  function decisionButtons(alertId: string, assignedAnalyst: string, where: string) {
    return (
      <>
        <button
          className="btn"
          type="button"
          aria-label={`Close alert ${alertId}${where}`}
          onClick={() => toggleAlertStatus(alertId)}
        >
          Close alert
        </button>
        {assignedAnalyst === currentUser ? (
          <span className="assigned-note">Assigned to you</span>
        ) : (
          <button
            className="btn ghost"
            type="button"
            aria-label={`Assign to me: ${alertId}${where}`}
            onClick={() => assignToMe(alertId)}
          >
            Assign to me
          </button>
        )}
      </>
    )
  }

  return (
    <section className="page active" data-page="dashboard" data-page-name="Security Dashboard">
      <div className="headline">
        <div>
          <h1>Security Dashboard</h1>
          <p className="sub">
            {activePaths === 0
              ? 'No attack path is active. Everything is blocked, contained or closed.'
              : `${activePaths} attack ${activePaths === 1 ? 'path is' : 'paths are'} still active. Everything else is blocked, contained or closed.`}
          </p>
        </div>
        <p className="dash-latest">
          Latest event <span className="mono">{latestEventTime(alerts)}</span>
        </p>
      </div>

      <div className="card key dash-hero">
        <section className="dash-map" aria-labelledby="mapTitle">
          <div className="dash-map-head">
            <h2 id="mapTitle">Attack paths today</h2>
            {!isPhone && (
              <Segmented label="Show attack paths as" options={MAP_VIEWS} value={view} onChange={setView} />
            )}
          </div>

          <p className="visually-hidden" id="pathSummary">
            {attackMap.summary}
          </p>

          {showMap ? (
            <AttackPathMap
              map={attackMap}
              selectedId={selected.id}
              onSelect={setSelectedId}
              describedBy="pathSummary"
            />
          ) : (
            <ul className="path-list" aria-label="Attack paths" aria-describedby="pathSummary">
              {attackMap.paths.map((path) => (
                <li key={path.alert.id}>
                  <button
                    type="button"
                    className={`path-list-item ${path.status}`}
                    aria-pressed={path.alert.id === selected.id}
                    onClick={() => setSelectedId(path.alert.id)}
                    data-path-id={path.alert.id}
                  >
                    <span className="path-list-top">
                      <span className="mono">{path.alert.id}</span>
                      <SeverityBadge severity={path.alert.severity} />
                      <span className={`path-status ${statusTone(path.statusLabel)}`}>{path.statusLabel}</span>
                    </span>
                    <span className="path-list-title">{path.alert.attackType}</span>
                    <span className="path-list-route mono">{path.route}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="dash-path" aria-labelledby="pathTitle" data-selected-path={selected.id}>
          <p className="visually-hidden" role="status">
            Showing {selected.id}, {selected.attackType}, {selectedPath.statusLabel}
          </p>

          <div className="dash-path-meta">
            <SeverityBadge severity={selected.severity} />
            <span className="mono">{selected.id}</span>
            <span className={`path-status ${statusTone(selectedPath.statusLabel)}`}>{selectedPath.statusLabel}</span>
          </div>

          <h2 className="dash-path-title" id="pathTitle">{selected.attackType}</h2>
          <p className="dash-path-route mono">{selectedPath.route}</p>

          <div className="dash-risk">
            <RiskRing score={selected.risk} size={54} />
            <div>
              <p className="dash-risk-score">
                {selected.risk}
                <span> / 100 risk</span>
              </p>
              <p className="dash-risk-evidence">{selectedEvidence}</p>
              {assessments[selected.id] && (
                <p className="dash-risk-outcome" data-field="outcome">
                  {OUTCOME_LABELS[assessments[selected.id].outcome]}, confidence{' '}
                  {assessments[selected.id].confidence.toFixed(2)}
                </p>
              )}
            </div>
          </div>

          <dl className="dash-path-facts">
            <div>
              <dt>Assigned</dt>
              <dd className="dash-assigned">{selected.assignedAnalyst}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{selected.status}</dd>
            </div>
            <div>
              <dt>Response</dt>
              <dd className="mono">{executionFor(selected, executions)?.id ?? 'None'}</dd>
            </div>
          </dl>

          <Timeline steps={timeline} label={`${selected.id} timeline`} />

          <div className="dash-path-actions">
            {needsDecision(selected, executions) && selectedDecision ? (
              decisionButtons(selected.id, selected.assignedAnalyst, '')
            ) : (
              <button className="btn" type="button" onClick={() => toggleAlertStatus(selected.id)}>
                {selected.status === 'Closed' ? 'Reopen alert' : 'Close alert'}
              </button>
            )}
            <Link className="btn ghost" to="/app/alerts" state={alertsLinkState(selected.id)}>
              Open in Alerts
            </Link>
          </div>
        </section>
      </div>

      <ul className="card posture" aria-label="Current posture">
        {posture.map((item) => (
          <li key={item.label} className={item.tone ? `posture-${item.tone}` : undefined}>
            <strong>{item.value}</strong>
            <span className="posture-label">{item.label}</span>
            <span className="posture-note">{item.note}</span>
          </li>
        ))}
      </ul>

      <div className="dash-lower">
        <section className="card dash-queue" aria-labelledby="queueTitle">
          <div className="dash-card-head">
            <h2 id="queueTitle">Needs a decision</h2>
            <Link className="text-link" to="/app/alerts">Open Alerts</Link>
          </div>

          {queue.length === 0 ? (
            <p className="dash-empty">Nothing needs a decision right now.</p>
          ) : (
            <ul className="decision-list">
              {queue.map((item) => (
                <li key={item.alert.id} className="decision-item" data-decision-id={item.alert.id}>
                  <RiskRing score={item.alert.risk} size={38} />
                  <div className="decision-text">
                    <p className="decision-title">
                      <span>{item.alert.attackType} on {item.alert.endpoint}</span>
                      <SeverityBadge severity={item.alert.severity} />
                    </p>
                    <p className="decision-detail">
                      <span className="mono">{item.alert.id}</span> {item.detail}
                    </p>
                    <p className="decision-detail">
                      Assigned to <span className="decision-assigned">{item.alert.assignedAnalyst}</span>
                    </p>
                  </div>
                  <div className="decision-actions">
                    {decisionButtons(item.alert.id, item.alert.assignedAnalyst, ' (from the queue)')}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card dash-log" aria-labelledby="logTitle">
          <div className="dash-card-head">
            <h2 id="logTitle">Automated response log</h2>
            <Link className="text-link" to="/app/incident">Incident Response</Link>
          </div>

          <ol className="response-log">
            {responseLog.map((item) => (
              <li key={item.id} data-log-id={item.id}>
                <span className="mono response-log-time">{item.time}</span>
                <span className="response-log-text">
                  <span>{item.action}</span>
                  <span className="response-log-by">{item.by}</span>
                </span>
                <span className={`response-log-result ${item.result === 'Done' ? 'ok' : 'danger'}`}>
                  {item.result}
                </span>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </section>
  )
}

export default AnalystDashboardPage
