import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import SystemHealthView from '../components/SystemHealthView'
import Tabs from '../components/Tabs'
import {
  CONSOLES,
  GROUP_COUNT,
  OVERVIEW_GROUPS,
  SERVICE_STATES,
  issueCount,
  memoryDetail,
  memoryPercent,
  percentText,
  runningCount,
  stateTone,
  statusSentence,
  summarizeWazuh,
  uptimeLine,
  wazuhDetail,
} from '../data/servicePanel'
import {
  STATE_WORDS,
  attentionServices,
  inDisplayWords,
  systemStatus,
  vmChecks,
} from '../data/serviceInventory'
import { healthSummary } from '../data/statusSummary'
import { LATENCY_TARGET_MS } from '../data/systemHealthData'
import { useAdminState } from '../hooks/useAdminState'
import { statusTone } from '../utils/statusTone'
import type {
  CheckKey,
  ConsoleKey,
  GroupKey,
  GroupResult,
  ServiceState,
  StateTone,
} from '../types/servicePanelTypes'

type View = 'overview' | 'health' | ConsoleKey

const VIEWS: View[] = ['overview', 'health', 'wazuh', 'cortex', 'misp']

const isView = (value: string | null): value is View => VIEWS.includes(value as View)

// Icon outlines on a 24-unit grid, from the design
const ICONS: Record<GroupKey, string> = {
  wazuh: 'M12 3 4 6v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V6l-8-3z',
  misp: 'M12 5a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM5 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM19 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 5v6M12 11l-6 7M12 11l6 7',
  cortex: 'M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3M7.5 15h9',
  docker: 'M3 13h18c0 4-3 7-8 7s-8-2-10-7zM5 10h3v3H5zM8 10h3v3H8zM11 10h3v3h-3zM8 7h3v3H8zM11 7h3v3h-3z',
}

// What each state means, for the "Status meanings" list
const LEGEND: Array<{ state: ServiceState; name: string; note: string }> = [
  { state: 'running', name: 'Running', note: 'Active, or the endpoint answered' },
  { state: 'partial', name: 'Partial', note: 'Some Wazuh components are down' },
  { state: 'starting', name: 'Starting', note: 'Coming up after a restart' },
  { state: 'stopped', name: 'Stopped', note: 'Service is inactive' },
  { state: 'unhealthy', name: 'Failed', note: 'A failed unit, or the endpoint returned an error' },
  { state: 'unknown', name: 'Unverified', note: 'Couldn’t be verified' },
]

const WAZUH_PARTS: Array<{ key: CheckKey; name: string }> = [
  { key: 'manager', name: 'Manager' },
  { key: 'indexer', name: 'Indexer' },
  { key: 'dashboard', name: 'Dashboard' },
]

const pad = (value: number) => String(value).padStart(2, '0')

// "15:42:08"
function clockTime() {
  const now = new Date()

  return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`
}

// How full a usage meter is: green, then amber, then red
function usageTone(percent: number): StateTone {
  if (percent >= 85) {
    return 'danger'
  }

  return percent >= 60 ? 'caution' : 'ok'
}

// The Panel's pure module keeps its own titles ("Unhealthy — 0/3 running"); the page shows the shared words
const statusWord = (group: GroupResult) => inDisplayWords(group.displayStatus || STATE_WORDS[group.state])

function ServicePanelPage() {
  const { servicePanel, services } = useAdminState()
  const [searchParams, setSearchParams] = useSearchParams()

  // The time the demo data was last refreshed: set on load, changed only by Refresh
  const [refreshedAt, setRefreshedAt] = useState(clockTime)
  const [announcement, setAnnouncement] = useState('')

  // The six checks are the VM group of the service inventory, so this page and System Health agree
  const results = vmChecks(services)
  const { usage } = servicePanel
  const groups = summarizeWazuh(results)
  const running = runningCount(groups)
  const issues = issueCount(groups)
  const byGroup = Object.fromEntries(groups.map((group) => [group.key, group])) as Record<GroupKey, GroupResult>
  const resultByKey = Object.fromEntries(results.map((item) => [item.key, item])) as Record<CheckKey, (typeof results)[number]>

  // The selected tab lives in the URL (?view=misp) so a link opens the right tab
  const requested = searchParams.get('view')
  const view: View = isView(requested) ? requested : 'overview'

  function selectView(next: View) {
    setSearchParams(next === 'overview' ? {} : { view: next }, { replace: true })
  }

  function refresh() {
    const time = clockTime()

    setRefreshedAt(time)
    setAnnouncement(`Demo data refreshed at ${time}`)
  }

  // The System health tab reads the same inventory as the badge and the top bar
  const health = systemStatus(services)
  const attention = attentionServices(services).length

  const tabs = [
    {
      value: 'overview' as const,
      label: 'Overview',
      tone: issues > 0 ? ('caution' as const) : ('ok' as const),
      status: issues > 0 ? `${issues} ${issues === 1 ? 'issue' : 'issues'}` : 'no issues',
    },
    {
      value: 'health' as const,
      label: 'System health',
      tone: health.level === 'danger' ? ('danger' as const) : attention > 0 ? ('caution' as const) : ('ok' as const),
      status: attention > 0 ? `${attention} ${attention === 1 ? 'needs' : 'need'} attention` : 'all healthy',
    },
    ...(['wazuh', 'cortex', 'misp'] as const).map((key) => ({
      value: key,
      label: CONSOLES[key].name,
      tone: stateTone(byGroup[key].state),
      status: statusWord(byGroup[key]),
    })),
  ]

  const cpu = usage.cpuPercent
  const ram = memoryPercent(usage.memoryUsedBytes, usage.memoryTotalBytes)

  const meters = [
    { label: 'CPU', percent: cpu, note: 'All cores, user and system time' },
    {
      label: 'RAM',
      percent: ram,
      note: `${memoryDetail(usage.memoryUsedBytes, usage.memoryTotalBytes)} in use (cache excluded)`,
    },
  ]

  return (
    <section
      className="page active"
      data-page="service-panel"
      data-page-name="Service Panel"
      data-admin-only
    >
      <div className="headline">
        <div>
          <h1>Service Panel</h1>

          {view === 'health' ? (
            <p className="sub" id="healthSummary">
              {healthSummary(services)}
            </p>
          ) : (
            <p className="sub" id="servicePanelSummary">
              {inDisplayWords(statusSentence(results))}
            </p>
          )}
        </div>

        {/* The time and Refresh are for the VM snapshot on the Overview; the health tab has its own */}
        {view !== 'health' && (
          <div className="headline-actions">
            <span className="sp-refreshed" id="servicePanelRefreshed">
              Demo data · last refreshed{' '}
              <span className="mono" data-field="refreshed">
                {refreshedAt}
              </span>
            </span>

            <button className="btn primary" type="button" onClick={refresh}>
              Refresh
            </button>

            <span className="visually-hidden" role="status">
              {announcement}
            </span>
          </div>
        )}
      </div>

      <Tabs label="Service panel views" tabs={tabs} value={view} onChange={selectView}>
        {view === 'health' ? (
          <SystemHealthView />
        ) : view === 'overview' ? (
          <div className="sp-layout">
            <div className="sp-main">
              <section className="card key sp-summary" aria-label="Summary">
                <div data-stat="groups">
                  <span className="sp-stat-label">Service groups</span>
                  <strong>{GROUP_COUNT}</strong>
                  <span className="sp-stat-note">Six checks</span>
                </div>

                <div data-stat="running">
                  <span className="sp-stat-label">Running</span>
                  <strong className="ok">{running}</strong>
                  <span className="sp-stat-note">Includes MISP web availability</span>
                </div>

                <div data-stat="issues">
                  <span className="sp-stat-label">Issues</span>
                  <strong className={issues > 0 ? 'caution' : 'ok'}>{issues}</strong>
                  <span className="sp-stat-note">Partial, starting, stopped, failed or unverified</span>
                </div>
              </section>

              <section className="sp-cards" aria-labelledby="spServicesTitle">
                <h2 className="visually-hidden" id="spServicesTitle">
                  Services
                </h2>

                {OVERVIEW_GROUPS.map((info) => {
                  const group = byGroup[info.key]
                  const tone = stateTone(group.state)
                  const consoleKey = info.key !== 'docker' ? (info.key as ConsoleKey) : null

                  return (
                    <article
                      key={info.key}
                      className={`card sp-card${group.state === 'running' ? '' : ' has-issue'}`}
                      data-service={info.key}
                      data-state={group.state}
                    >
                      <div className="sp-card-head">
                        <span className="sp-icon" aria-hidden="true">
                          <svg width="20" height="20" viewBox="0 0 24 24" focusable="false">
                            <path d={ICONS[info.key]} />
                          </svg>
                        </span>

                        <div className="sp-card-title">
                          <h3>{info.name}</h3>
                          <span className="sp-ports mono">{info.ports}</span>
                        </div>

                        <span className={`pill ${tone}`} data-field="status">
                          {statusWord(group)}
                        </span>
                      </div>

                      <p className="sp-detail" data-field="detail">
                        {info.key === 'wazuh' ? inDisplayWords(wazuhDetail(results)) : group.detail}
                      </p>

                      {info.key === 'wazuh' && (
                        <ul className="sp-parts" aria-label="Wazuh components">
                          {WAZUH_PARTS.map((part) => {
                            const check = resultByKey[part.key]

                            return (
                              <li key={part.key} data-part={part.key}>
                                <span className="sp-part-name">{part.name}</span>
                                <span className={`sp-part-state ${stateTone(check.state)}`}>
                                  <span className="sp-dot" aria-hidden="true" />
                                  {STATE_WORDS[check.state]}
                                </span>
                              </li>
                            )
                          })}
                        </ul>
                      )}

                      <div className="sp-card-foot">
                        <span className="sp-uptime" data-field="uptime">
                          {uptimeLine(info.key, group.uptime)}
                        </span>

                        {consoleKey && (
                          <button
                            className="btn small"
                            type="button"
                            aria-label={`Open console for ${info.name}`}
                            onClick={() => selectView(consoleKey)}
                          >
                            Open console
                          </button>
                        )}
                      </div>
                    </article>
                  )
                })}
              </section>

              <p className="sp-footnote">
                MISP and Cortex report endpoint availability only. They don’t prove that every
                worker, module, database or queue is healthy.
              </p>
            </div>

            <aside className="sp-side">
              <section className="card sp-device" aria-labelledby="spDeviceTitle">
                <h2 id="spDeviceTitle">This device</h2>

                {meters.map((meter) => (
                  <div key={meter.label} className="sp-meter-row" data-meter={meter.label}>
                    <div className="sp-meter-head">
                      <span>{meter.label}</span>
                      <span className="mono sp-meter-value">{percentText(meter.percent)}%</span>
                    </div>

                    <div
                      className="sp-meter"
                      role="meter"
                      aria-label={`${meter.label} usage`}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={Number(percentText(meter.percent))}
                    >
                      <span
                        className={usageTone(meter.percent)}
                        style={{ width: `${Math.min(100, Math.max(0, meter.percent))}%` }}
                      />
                    </div>

                    <span className="sp-meter-note">{meter.note}</span>
                  </div>
                ))}

                <p className="sp-device-note">
                  Ubuntu VM guest, not the physical host. These figures are demo values.
                </p>
              </section>

              <section className="card sp-legend" aria-labelledby="spLegendTitle">
                <h2 id="spLegendTitle">Status meanings</h2>

                <dl>
                  {SERVICE_STATES.map((state) => {
                    const entry = LEGEND.find((item) => item.state === state)

                    return entry ? (
                      <div key={state} data-state={state}>
                        <dt>
                          <span className={`pill ${stateTone(state)}`}>{entry.name}</span>
                        </dt>
                        <dd>{entry.note}</dd>
                      </div>
                    ) : null
                  })}

                  <div data-state="degraded">
                    <dt>
                      <span className={`pill ${statusTone('Degraded')}`}>Degraded</span>
                    </dt>
                    <dd>Working, but slower than the {LATENCY_TARGET_MS} ms target</dd>
                  </div>
                </dl>
              </section>
            </aside>
          </div>
        ) : (
          <ConsoleView
            consoleKey={view}
            group={byGroup[view]}
            detail={view === 'wazuh' ? inDisplayWords(wazuhDetail(results)) : byGroup[view].detail}
            tone={stateTone(byGroup[view].state)}
          />
        )}
      </Tabs>

      <p className="demo-panel demo-inline sp-demo" id="servicePanelDemoNote">
        <span className="demo-badge">Demo mode</span> Demo data, live checks run in the desktop
        Service Panel on the VM.
      </p>
    </section>
  )
}

type ConsoleViewProps = {
  consoleKey: ConsoleKey
  group: GroupResult
  detail: string
  tone: StateTone
}

/*
  A service's web console. These consoles refuse to be shown inside other
  sites and use self-signed certificates, so the web page opens them in
  their own tab (there is no iframe); the desktop panel embeds them.
*/
function ConsoleView({ consoleKey, group, detail, tone }: ConsoleViewProps) {
  const { name, origin } = CONSOLES[consoleKey]

  return (
    <section className="card sp-console" aria-label={`${name} console`} data-console={consoleKey}>
      <div className="sp-toolbar">
        <span className="visually-hidden" id={`spToolbarHint-${consoleKey}`}>
          Available in the desktop Service Panel, which embeds the console.
        </span>

        {['Back', 'Reload', 'Home'].map((label) => (
          <button
            key={label}
            className="btn small"
            type="button"
            disabled
            aria-describedby={`spToolbarHint-${consoleKey}`}
          >
            {label}
          </button>
        ))}

        <span className="sp-origin mono" data-field="origin">
          <svg width="13" height="13" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <rect x="5" y="11" width="14" height="10" rx="2" />
            <path d="M8 11V7a4 4 0 0 1 8 0v4" />
          </svg>
          {origin}
        </span>

        <a
          className="btn primary small"
          href={origin}
          target="_blank"
          rel="noopener noreferrer"
          data-field="open"
        >
          Open in new tab
          <svg width="13" height="13" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
            <path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
          </svg>
        </a>
      </div>

      <div className="notice sp-cert">
        Self-signed certificate on the local network. Your browser will ask you to confirm it
        the first time you open {name}.
      </div>

      <div className="sp-placeholder">
        <span className="sp-icon large" aria-hidden="true">
          <svg width="28" height="28" viewBox="0 0 24 24" focusable="false">
            <path d={ICONS[consoleKey]} />
          </svg>
        </span>

        <h2>{name} console</h2>

        <span className={`pill ${tone}`} data-field="status">
          {statusWord(group)}
        </span>

        <p data-field="detail">{detail}</p>

        <p className="sp-explain">
          {name} blocks being shown inside other sites, so the web console opens it in its own
          tab. The desktop Service Panel on the VM embeds it with a separate session per service.
        </p>
      </div>
    </section>
  )
}

export default ServicePanelPage
