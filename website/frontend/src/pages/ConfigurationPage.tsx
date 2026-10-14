import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import type {
  ConfigurationState,
  ConfigurationValues,
} from '../types/configurationTypes'

import {
  configurationLimits,
  destinationOptions,
  environmentOptions,
  initialConfiguration,
  modeOptions,
  notificationOptions,
} from '../data/configurationData'
import { useAdminState } from '../hooks/useAdminState'
import { statusTone } from '../utils/statusTone'

const { correlationWindowMinutes: windowLimits, criticalRiskThreshold: criticalLimits, retentionDays } =
  configurationLimits

// A number field's value, or null when it is empty or not a number
function numberOf(value: string) {
  const parsed = Number(value)

  return value.trim() === '' || Number.isNaN(parsed) ? null : parsed
}

function ConfigurationPage() {
  // The saved values live in shared admin state; saving is audited
  const {
    configuration: savedConfiguration,
    saveConfiguration: storeConfiguration,
  } = useAdminState()

  const [configuration, setConfiguration] =
    useState<ConfigurationValues>(savedConfiguration)

  const [configurationState, setConfigurationState] =
    useState<ConfigurationState>('Saved')

  const [validationError, setValidationError] = useState('')
  const [pageMessage, setPageMessage] = useState('')

  const hasUnsavedChanges = useMemo(() => {
    return (
      JSON.stringify(configuration) !==
      JSON.stringify(savedConfiguration)
    )
  }, [configuration, savedConfiguration])

  function setField(name: keyof ConfigurationValues, value: string) {
    setConfiguration((currentConfiguration) => ({
      ...currentConfiguration,
      [name]: value,
    }))

    setConfigurationState('Draft')
    setValidationError('')
    // The unsaved-changes banner already says so
    setPageMessage('')
  }

  function handleConfigurationChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>,
  ) {
    setField(
      event.target.name as keyof ConfigurationValues,
      event.target.value,
    )
  }

  function validateConfiguration() {
    if (!configuration.organization.trim()) {
      return 'Organization is required.'
    }

    if (!configuration.workspace.trim()) {
      return 'Workspace is required.'
    }

    const correlationWindow = Number(
      configuration.correlationWindowMinutes,
    )

    if (
      Number.isNaN(correlationWindow) ||
      correlationWindow < windowLimits.min ||
      correlationWindow > windowLimits.max
    ) {
      return `Correlation window must be between ${windowLimits.min} and ${windowLimits.max} minutes.`
    }

    const criticalRiskThreshold = Number(
      configuration.criticalRiskThreshold,
    )

    if (
      Number.isNaN(criticalRiskThreshold) ||
      criticalRiskThreshold < criticalLimits.min ||
      criticalRiskThreshold > criticalLimits.max
    ) {
      return `Critical risk threshold must be between ${criticalLimits.min} and ${criticalLimits.max}.`
    }

    const hotStorageDays = Number(
      configuration.hotStorageDays,
    )

    if (
      Number.isNaN(hotStorageDays) ||
      hotStorageDays < retentionDays.min ||
      hotStorageDays > retentionDays.max
    ) {
      return `Hot storage retention must be between ${retentionDays.min} and ${retentionDays.max} days.`
    }

    const auditRetentionDays = Number(
      configuration.auditRetentionDays,
    )

    if (
      Number.isNaN(auditRetentionDays) ||
      auditRetentionDays < retentionDays.min ||
      auditRetentionDays > retentionDays.max
    ) {
      return `Audit retention must be between ${retentionDays.min} and ${retentionDays.max} days.`
    }

    if (auditRetentionDays < hotStorageDays) {
      return 'Audit retention cannot be shorter than hot storage retention.'
    }

    return ''
  }

  function saveConfiguration(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const error = validateConfiguration()

    if (error) {
      setValidationError(error)
      setConfigurationState('Error')
      setPageMessage('Configuration could not be saved.')
      return
    }

    storeConfiguration(configuration)
    setConfigurationState('Saved')
    setValidationError('')
    setPageMessage(
      'Configuration saved.',
    )
  }

  function cancelChanges() {
    setConfiguration(savedConfiguration)
    setConfigurationState('Saved')
    setValidationError('')
    setPageMessage('Unsaved changes were discarded.')
  }

  function restoreDefaults() {
    setConfiguration(initialConfiguration)
    setConfigurationState('Draft')
    setValidationError('')
    setPageMessage(
      'Default values restored. Save to keep these changes.',
    )
  }

  // Bars: the critical score out of 100, and hot storage inside audit retention
  const criticalValue = numberOf(configuration.criticalRiskThreshold)
  const hotDays = numberOf(configuration.hotStorageDays)
  const auditDays = numberOf(configuration.auditRetentionDays)
  const retentionValid =
    hotDays !== null && auditDays !== null && hotDays > 0 && auditDays >= hotDays

  return (
    <section
      className="page active"
      data-page="configuration"
      data-page-name="Configuration"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Configuration</h1>

          <p className="sub">
            How AthenaSec detects, stores and notifies across the workspace.
          </p>
        </div>

        <div className="headline-actions">
          <span
            className={`pill ${statusTone(configurationState)}`}
            id="configState"
          >
            {configurationState}
          </span>

          <button
            className="btn danger"
            type="button"
            onClick={restoreDefaults}
          >
            Restore Defaults
          </button>
        </div>
      </div>

      {pageMessage && (
        <div className="notice" role="status">
          {pageMessage}
        </div>
      )}

      {validationError && (
        <div className="notice" role="alert">
          <strong>Configuration error</strong>

          <p className="sub" style={{ marginTop: '6px' }}>
            {validationError}
          </p>
        </div>
      )}

      <form onSubmit={saveConfiguration} className="cfg-form" noValidate>
        {hasUnsavedChanges && (
          <div className="cfg-unsaved" role="status" id="configUnsaved">
            <span className="cfg-unsaved-dot" aria-hidden="true" />

            <span className="cfg-unsaved-text">
              You have unsaved changes. Saving is recorded in the audit log.
            </span>

            <button className="btn" type="button" onClick={cancelChanges}>
              Discard
            </button>

            <button className="btn primary" type="submit">
              Save configuration
            </button>
          </div>
        )}

        <div className="cfg-grid">
          <section className="card cfg-card" aria-labelledby="cfgWorkspaceTitle">
            <h2 id="cfgWorkspaceTitle">Workspace</h2>

            <div className="cfg-field">
              <label className="form-label" htmlFor="organization">
                Organization name
              </label>

              <input
                className="field-input"
                id="organization"
                name="organization"
                value={configuration.organization}
                onChange={handleConfigurationChange}
                autoComplete="off"
                placeholder="AthenaSec SOC…"
              />
            </div>

            <div className="cfg-field">
              <label className="form-label" htmlFor="workspace">
                Environment
              </label>

              <select
                className="select-input"
                id="workspace"
                name="workspace"
                autoComplete="off"
                value={configuration.workspace}
                onChange={handleConfigurationChange}
              >
                {environmentOptions.map((option) => (
                  <option value={option} key={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
          </section>

          <section className="card cfg-card" aria-labelledby="cfgDetectionTitle">
            <h2 id="cfgDetectionTitle">Detection</h2>

            <div className="cfg-field">
              <label className="form-label" htmlFor="correlationWindowMinutes">
                Correlation window
              </label>

              <div className="cfg-number">
                <input
                  className="field-input"
                  id="correlationWindowMinutes"
                  name="correlationWindowMinutes"
                  autoComplete="off"
                  type="number"
                  min={windowLimits.min}
                  max={windowLimits.max}
                  value={configuration.correlationWindowMinutes}
                  onChange={handleConfigurationChange}
                />

                <span className="unit">minutes</span>
              </div>

              <p className="sub cfg-hint">
                Allowed: {windowLimits.min} to {windowLimits.max}. Events from
                the same source inside this window are grouped into one alert.
              </p>
            </div>

            <div className="cfg-field">
              <label className="form-label" htmlFor="criticalRiskThreshold">
                Critical risk threshold
              </label>

              <div className="cfg-number">
                <input
                  className="field-input"
                  id="criticalRiskThreshold"
                  name="criticalRiskThreshold"
                  autoComplete="off"
                  type="number"
                  min={criticalLimits.min}
                  max={criticalLimits.max}
                  value={configuration.criticalRiskThreshold}
                  onChange={handleConfigurationChange}
                />

                <span className="unit">/ 100</span>
              </div>

              <div
                className="cfg-bar cfg-threshold"
                role="img"
                aria-label={
                  criticalValue === null
                    ? 'Critical risk threshold not set'
                    : `Critical risk threshold ${criticalValue} out of 100`
                }
              >
                <span
                  className="cfg-threshold-fill"
                  style={{
                    width: `${Math.min(100, Math.max(0, criticalValue ?? 0))}%`,
                  }}
                />
              </div>

              <p className="sub cfg-hint">
                Allowed: {criticalLimits.min} to {criticalLimits.max}. Alerts at
                or above this score are treated as critical.
              </p>
            </div>
          </section>

          <section className="card cfg-card" aria-labelledby="cfgLoggingTitle">
            <h2 id="cfgLoggingTitle">Logging and retention</h2>

            <div className="cfg-pair">
              <div className="cfg-field">
                <label className="form-label" htmlFor="loggingDestination">
                  Destination
                </label>

                <select
                  className="select-input"
                  id="loggingDestination"
                  name="loggingDestination"
                  autoComplete="off"
                  value={configuration.loggingDestination}
                  onChange={handleConfigurationChange}
                >
                  {destinationOptions.map((option) => (
                    <option value={option} key={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>

              <div className="cfg-field">
                <label className="form-label" htmlFor="loggingMode">
                  Mode
                </label>

                <select
                  className="select-input"
                  id="loggingMode"
                  name="loggingMode"
                  autoComplete="off"
                  value={configuration.loggingMode}
                  onChange={handleConfigurationChange}
                >
                  {modeOptions.map((option) => (
                    <option value={option} key={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <p className="sub cfg-hint">
              This controls how AthenaSec sends audit and security events to
              the configured destination.
            </p>

            <div className="cfg-pair">
              <div className="cfg-field">
                <label className="form-label" htmlFor="hotStorageDays">
                  Hot storage
                </label>

                <div className="cfg-number">
                  <input
                    className="field-input"
                    id="hotStorageDays"
                    name="hotStorageDays"
                    autoComplete="off"
                    type="number"
                    min={retentionDays.min}
                    max={retentionDays.max}
                    value={configuration.hotStorageDays}
                    onChange={handleConfigurationChange}
                  />

                  <span className="unit">days</span>
                </div>
              </div>

              <div className="cfg-field">
                <label className="form-label" htmlFor="auditRetentionDays">
                  Audit retention
                </label>

                <div className="cfg-number">
                  <input
                    className="field-input"
                    id="auditRetentionDays"
                    name="auditRetentionDays"
                    autoComplete="off"
                    type="number"
                    min={retentionDays.min}
                    max={retentionDays.max}
                    value={configuration.auditRetentionDays}
                    onChange={handleConfigurationChange}
                  />

                  <span className="unit">days</span>
                </div>
              </div>
            </div>

            {retentionValid && hotDays !== null && auditDays !== null ? (
              <div
                className="cfg-bar cfg-retention"
                role="img"
                aria-label={`Hot storage ${hotDays} days, audit retention ${auditDays} days`}
              >
                <span className="cfg-retention-hot" style={{ flexGrow: hotDays }}>
                  Hot, {hotDays} days
                </span>

                {auditDays > hotDays && (
                  <span
                    className="cfg-retention-audit"
                    style={{ flexGrow: auditDays - hotDays }}
                  >
                    Audit retention, {auditDays} days
                  </span>
                )}
              </div>
            ) : (
              <p className="sub cfg-hint" data-field="retention-bar-off">
                Enter hot storage and audit retention days to see them side by side.
              </p>
            )}

            <p className="sub cfg-hint">
              Allowed: {retentionDays.min} to {retentionDays.max} days. Audit
              retention must be equal to or longer than hot-storage retention.
            </p>
          </section>

          <section className="card cfg-card" aria-labelledby="cfgNotifyTitle">
            <h2 id="cfgNotifyTitle">Critical alert notifications</h2>

            <div
              className="cfg-choices"
              role="group"
              aria-label="Critical alert notifications"
            >
              {notificationOptions.map((option) => (
                <button
                  key={option}
                  type="button"
                  className="cfg-choice"
                  aria-pressed={configuration.criticalAlertNotification === option}
                  onClick={() => setField('criticalAlertNotification', option)}
                >
                  {option}
                </button>
              ))}
            </div>

            <div className="notice">
              Notifications are simulated in this demo. No email
              or external message is sent.
            </div>
          </section>
        </div>
      </form>
    </section>
  )
}

export default ConfigurationPage
