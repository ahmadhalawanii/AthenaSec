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

import { initialConfiguration } from '../data/configurationData'

function ConfigurationPage() {
  const [configuration, setConfiguration] =
    useState<ConfigurationValues>(initialConfiguration)

  const [savedConfiguration, setSavedConfiguration] =
    useState<ConfigurationValues>(initialConfiguration)

  const [configurationState, setConfigurationState] =
    useState<ConfigurationState>('Saved')

  const [validationError, setValidationError] = useState('')
  const [pageMessage, setPageMessage] = useState(
    'Configuration loaded successfully.',
  )

  const hasUnsavedChanges = useMemo(() => {
    return (
      JSON.stringify(configuration) !==
      JSON.stringify(savedConfiguration)
    )
  }, [configuration, savedConfiguration])

  function handleConfigurationChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>,
  ) {
    const { name, value } = event.target

    setConfiguration((currentConfiguration) => ({
      ...currentConfiguration,
      [name]: value,
    }))

    setConfigurationState('Draft')
    setValidationError('')
    setPageMessage('Unsaved configuration changes detected.')
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
      correlationWindow < 1 ||
      correlationWindow > 1440
    ) {
      return 'Correlation window must be between 1 and 1440 minutes.'
    }

    const criticalRiskThreshold = Number(
      configuration.criticalRiskThreshold,
    )

    if (
      Number.isNaN(criticalRiskThreshold) ||
      criticalRiskThreshold < 0 ||
      criticalRiskThreshold > 100
    ) {
      return 'Critical risk threshold must be between 0 and 100.'
    }

    const hotStorageDays = Number(
      configuration.hotStorageDays,
    )

    if (
      Number.isNaN(hotStorageDays) ||
      hotStorageDays < 1 ||
      hotStorageDays > 3650
    ) {
      return 'Hot storage retention must be between 1 and 3650 days.'
    }

    const auditRetentionDays = Number(
      configuration.auditRetentionDays,
    )

    if (
      Number.isNaN(auditRetentionDays) ||
      auditRetentionDays < 1 ||
      auditRetentionDays > 3650
    ) {
      return 'Audit retention must be between 1 and 3650 days.'
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

    setSavedConfiguration(configuration)
    setConfigurationState('Saved')
    setValidationError('')
    setPageMessage(
      'Configuration saved for the current frontend session.',
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

  function stateClass(state: ConfigurationState) {
    if (state === 'Saved') {
      return 'ok'
    }

    if (state === 'Error') {
      return 'danger'
    }

    return 'blue'
  }

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
          <h1>Configuration Management</h1>

          <p className="sub">
            Edit general, detection, logging, retention, and
            notification settings.
          </p>
        </div>

        <span
          className={`pill ${stateClass(configurationState)}`}
          id="configState"
        >
          {configurationState}
        </span>
      </div>

      {pageMessage && (
        <div
          className="notice"
          role="status"
          style={{ marginBottom: '18px' }}
        >
          {pageMessage}
        </div>
      )}

      {validationError && (
        <div
          className="notice"
          role="alert"
          style={{ marginBottom: '18px' }}
        >
          <strong>Configuration error</strong>

          <p
            className="sub"
            style={{ marginTop: '6px' }}
          >
            {validationError}
          </p>
        </div>
      )}

      <form onSubmit={saveConfiguration}>
        <div className="grid two">
          <div className="card">
            <h2>General Settings</h2>

            <label
              className="form-label"
              htmlFor="organization"
            >
              Organization
            </label>

            <input
              className="field-input"
              id="organization"
              name="organization"
              value={configuration.organization}
              onChange={handleConfigurationChange}
              placeholder="AthenaSec SOC"
            />

            <label
              className="form-label"
              htmlFor="workspace"
            >
              Workspace
            </label>

            <select
              className="select-input"
              id="workspace"
              name="workspace"
              value={configuration.workspace}
              onChange={handleConfigurationChange}
            >
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Development">Development</option>
              <option value="Testing">Testing</option>
            </select>
          </div>

          <div className="card">
            <h2>Detection Settings</h2>

            <label
              className="form-label"
              htmlFor="correlationWindowMinutes"
            >
              Correlation Window
            </label>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr auto',
                gap: '10px',
                alignItems: 'center',
              }}
            >
              <input
                className="field-input"
                id="correlationWindowMinutes"
                name="correlationWindowMinutes"
                type="number"
                min="1"
                max="1440"
                value={
                  configuration.correlationWindowMinutes
                }
                onChange={handleConfigurationChange}
              />

              <span className="pill blue">minutes</span>
            </div>

            <label
              className="form-label"
              htmlFor="criticalRiskThreshold"
            >
              Critical Risk Threshold
            </label>

            <input
              className="field-input"
              id="criticalRiskThreshold"
              name="criticalRiskThreshold"
              type="number"
              min="0"
              max="100"
              value={configuration.criticalRiskThreshold}
              onChange={handleConfigurationChange}
            />

            <p className="sub">
              Alerts at or above this score are treated as
              critical.
            </p>
          </div>

          <div className="card">
            <h2>Logging Settings</h2>

            <label
              className="form-label"
              htmlFor="loggingDestination"
            >
              Destination
            </label>

            <select
              className="select-input"
              id="loggingDestination"
              name="loggingDestination"
              value={configuration.loggingDestination}
              onChange={handleConfigurationChange}
            >
              <option value="OpenSearch">OpenSearch</option>
              <option value="Local File">Local File</option>
              <option value="Syslog">Syslog</option>
            </select>

            <label
              className="form-label"
              htmlFor="loggingMode"
            >
              Mode
            </label>

            <select
              className="select-input"
              id="loggingMode"
              name="loggingMode"
              value={configuration.loggingMode}
              onChange={handleConfigurationChange}
            >
              <option value="Realtime">Realtime</option>
              <option value="Batch">Batch</option>
              <option value="Manual">Manual</option>
            </select>

            <p className="sub">
              This controls how AthenaSec sends audit and
              security events to the configured destination.
            </p>
          </div>

          <div className="card">
            <h2>Retention</h2>

            <label
              className="form-label"
              htmlFor="hotStorageDays"
            >
              Hot Storage
            </label>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr auto',
                gap: '10px',
                alignItems: 'center',
              }}
            >
              <input
                className="field-input"
                id="hotStorageDays"
                name="hotStorageDays"
                type="number"
                min="1"
                max="3650"
                value={configuration.hotStorageDays}
                onChange={handleConfigurationChange}
              />

              <span className="pill blue">days</span>
            </div>

            <label
              className="form-label"
              htmlFor="auditRetentionDays"
            >
              Audit Retention
            </label>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr auto',
                gap: '10px',
                alignItems: 'center',
              }}
            >
              <input
                className="field-input"
                id="auditRetentionDays"
                name="auditRetentionDays"
                type="number"
                min="1"
                max="3650"
                value={configuration.auditRetentionDays}
                onChange={handleConfigurationChange}
              />

              <span className="pill blue">days</span>
            </div>

            <p className="sub">
              Audit retention must be equal to or longer than
              hot-storage retention.
            </p>
          </div>

          <div className="card">
            <h2>Notifications</h2>

            <label
              className="form-label"
              htmlFor="criticalAlertNotification"
            >
              Critical Alerts
            </label>

            <select
              className="select-input"
              id="criticalAlertNotification"
              name="criticalAlertNotification"
              value={
                configuration.criticalAlertNotification
              }
              onChange={handleConfigurationChange}
            >
              <option value="Email + In-App">
                Email + In-App
              </option>

              <option value="Email Only">
                Email Only
              </option>

              <option value="In-App Only">
                In-App Only
              </option>

              <option value="Disabled">
                Disabled
              </option>
            </select>

            <div className="notice">
              Notification delivery is currently simulated in
              the frontend. No real email or external message is
              sent.
            </div>
          </div>

          <div className="card">
            <h2>Configuration Actions</h2>

            <div className="kv">
              <span>Current State</span>

              <strong>
                <span
                  className={`pill ${stateClass(
                    configurationState,
                  )}`}
                >
                  {configurationState}
                </span>
              </strong>
            </div>

            <div className="kv">
              <span>Unsaved Changes</span>

              <strong>
                {hasUnsavedChanges ? 'Yes' : 'No'}
              </strong>
            </div>

            <div className="kv">
              <span>Persistence</span>
              <strong>Frontend session only</strong>
            </div>

            <div
              className="actions-cell"
              style={{
                marginTop: '8px',
                display: 'flex',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <button
                className="btn primary"
                type="submit"
                disabled={!hasUnsavedChanges}
              >
                Save Configuration
              </button>

              <button
                className="btn"
                type="button"
                disabled={!hasUnsavedChanges}
                onClick={cancelChanges}
              >
                Cancel Changes
              </button>

              <button
                className="btn danger"
                type="button"
                onClick={restoreDefaults}
              >
                Restore Defaults
              </button>
            </div>
          </div>
        </div>
      </form>
    </section>
  )
}

export default ConfigurationPage
