import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import type {
  SettingsState,
  SettingsValues,
} from '../types/settingsTypes'

import { initialSettings } from '../data/settingsData'

function settingsStateClass(state: SettingsState) {
  if (state === 'Saved') {
    return 'ok'
  }

  if (state === 'Error') {
    return 'danger'
  }

  return 'blue'
}

function SettingsPage() {
  const [settings, setSettings] =
    useState<SettingsValues>(initialSettings)

  const [savedSettings, setSavedSettings] =
    useState<SettingsValues>(initialSettings)

  const [settingsState, setSettingsState] =
    useState<SettingsState>('Saved')

  const [pageMessage, setPageMessage] = useState(
    'Settings loaded successfully.',
  )

  const [validationError, setValidationError] = useState('')

  const hasUnsavedChanges = useMemo(() => {
    return (
      JSON.stringify(settings) !==
      JSON.stringify(savedSettings)
    )
  }, [settings, savedSettings])

  function updateSettingsState() {
    setSettingsState('Draft')
    setValidationError('')
    setPageMessage('Unsaved settings changes detected.')
  }

  function handleFieldChange(
    event:
      | ChangeEvent<HTMLSelectElement>
      | ChangeEvent<HTMLInputElement>,
  ) {
    const { name, value, type } = event.target

    const nextValue =
      type === 'checkbox'
        ? (event.target as HTMLInputElement).checked
        : value

    setSettings((currentSettings) => ({
      ...currentSettings,
      [name]: nextValue,
    }))

    updateSettingsState()
  }

  function validateSettings() {
    if (
      settings.requireMfaForSensitiveActions &&
      !settings.mfaEnabled
    ) {
      return 'MFA must be enabled before it can be required for sensitive actions.'
    }

    if (
      !settings.notificationsEnabled &&
      (
        settings.criticalAlertNotifications ||
        settings.caseNotifications ||
        settings.systemHealthNotifications ||
        settings.emailNotifications
      )
    ) {
      return 'Enable general notifications before selecting individual notification channels.'
    }

    return ''
  }

  function saveSettings(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const error = validateSettings()

    if (error) {
      setValidationError(error)
      setSettingsState('Error')
      setPageMessage('Settings could not be saved.')
      return
    }

    setSavedSettings(settings)
    setSettingsState('Saved')
    setValidationError('')

    setPageMessage(
      'Settings saved for the current frontend session.',
    )
  }

  function cancelChanges() {
    setSettings(savedSettings)
    setSettingsState('Saved')
    setValidationError('')
    setPageMessage('Unsaved settings changes were discarded.')
  }

  function restoreDefaults() {
    setSettings(initialSettings)
    setSettingsState('Draft')
    setValidationError('')

    setPageMessage(
      'Default settings restored. Save to keep these changes.',
    )
  }

  function toggleGeneralNotifications() {
    const nextEnabled = !settings.notificationsEnabled

    setSettings((currentSettings) => ({
      ...currentSettings,
      notificationsEnabled: nextEnabled,
      criticalAlertNotifications: nextEnabled
        ? currentSettings.criticalAlertNotifications
        : false,
      caseNotifications: nextEnabled
        ? currentSettings.caseNotifications
        : false,
      systemHealthNotifications: nextEnabled
        ? currentSettings.systemHealthNotifications
        : false,
      emailNotifications: nextEnabled
        ? currentSettings.emailNotifications
        : false,
    }))

    updateSettingsState()
  }

  function toggleMfa() {
    const nextMfaState = !settings.mfaEnabled

    setSettings((currentSettings) => ({
      ...currentSettings,
      mfaEnabled: nextMfaState,
      requireMfaForSensitiveActions: nextMfaState
        ? currentSettings.requireMfaForSensitiveActions
        : false,
    }))

    updateSettingsState()
  }

  return (
    <section
      className="page active"
      data-page="settings"
      data-page-name="Settings"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Settings</h1>

          <p className="sub">
            Console preferences, notifications, MFA controls,
            and security-session settings.
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
          <span className="pill ok">
            Administrator Only
          </span>

          <span
            className={`pill ${settingsStateClass(
              settingsState,
            )}`}
          >
            {settingsState}
          </span>
        </div>
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
          <strong>Settings error</strong>

          <p
            className="sub"
            style={{ marginTop: '6px' }}
          >
            {validationError}
          </p>
        </div>
      )}

      <form onSubmit={saveSettings}>
        <div className="grid two">
          <div className="card">
            <h2>Console Preferences</h2>

            <label
              className="form-label"
              htmlFor="settingsTheme"
            >
              Theme
            </label>

            <select
              className="select-input"
              id="settingsTheme"
              name="theme"
              value={settings.theme}
              onChange={handleFieldChange}
            >
              <option value="Dark Enterprise">
                Dark Enterprise
              </option>

              <option value="High Contrast">
                High Contrast
              </option>
            </select>

            <label
              className="form-label"
              htmlFor="settingsLanguage"
              style={{ marginTop: '16px' }}
            >
              Language
            </label>

            <select
              className="select-input"
              id="settingsLanguage"
              name="language"
              value={settings.language}
              onChange={handleFieldChange}
            >
              <option value="English">English</option>
              <option value="Arabic">Arabic</option>
            </select>

            <div
              className="notice"
              style={{ marginTop: '18px' }}
            >
              Theme and language changes are stored in React
              state only. Full application-wide theme and
              translation support will be connected later.
            </div>
          </div>

          <div className="card">
            <h2>General Notifications</h2>

            <label className="check-row">
              <input
                type="checkbox"
                checked={settings.notificationsEnabled}
                onChange={toggleGeneralNotifications}
              />

              Enable notifications
            </label>

            <p
              className="sub"
              style={{ marginTop: '10px' }}
            >
              Controls whether AthenaSec displays security and
              operational notifications.
            </p>

            <div className="kv">
              <span>Notification Status</span>

              <strong>
                <span
                  className={`pill ${
                    settings.notificationsEnabled
                      ? 'ok'
                      : 'muted'
                  }`}
                >
                  {settings.notificationsEnabled
                    ? 'Enabled'
                    : 'Disabled'}
                </span>
              </strong>
            </div>
          </div>

          <div className="card">
            <h2>Notification Preferences</h2>

            <label className="check-row">
              <input
                name="criticalAlertNotifications"
                type="checkbox"
                checked={
                  settings.criticalAlertNotifications
                }
                disabled={!settings.notificationsEnabled}
                onChange={handleFieldChange}
              />

              Critical alert notifications
            </label>

            <label
              className="check-row"
              style={{ marginTop: '14px' }}
            >
              <input
                name="caseNotifications"
                type="checkbox"
                checked={settings.caseNotifications}
                disabled={!settings.notificationsEnabled}
                onChange={handleFieldChange}
              />

              Case creation and assignment notifications
            </label>

            <label
              className="check-row"
              style={{ marginTop: '14px' }}
            >
              <input
                name="systemHealthNotifications"
                type="checkbox"
                checked={
                  settings.systemHealthNotifications
                }
                disabled={!settings.notificationsEnabled}
                onChange={handleFieldChange}
              />

              System health warnings
            </label>

            <label
              className="check-row"
              style={{ marginTop: '14px' }}
            >
              <input
                name="emailNotifications"
                type="checkbox"
                checked={settings.emailNotifications}
                disabled={!settings.notificationsEnabled}
                onChange={handleFieldChange}
              />

              Email notifications
            </label>

            <div
              className="notice"
              style={{ marginTop: '18px' }}
            >
              Notification delivery is simulated. No real email
              or external notification is sent.
            </div>
          </div>

          <div className="card">
            <h2>Session Security</h2>

            <label
              className="form-label"
              htmlFor="sessionTimeout"
            >
              Session Timeout
            </label>

            <select
              className="select-input"
              id="sessionTimeout"
              name="sessionTimeout"
              value={settings.sessionTimeout}
              onChange={handleFieldChange}
            >
              <option value="30 minutes">
                30 minutes
              </option>

              <option value="60 minutes">
                60 minutes
              </option>

              <option value="4 hours">
                4 hours
              </option>
            </select>

            <label
              className="check-row"
              style={{ marginTop: '18px' }}
            >
              <input
                name="autoLogoutWarning"
                type="checkbox"
                checked={settings.autoLogoutWarning}
                onChange={handleFieldChange}
              />

              Show warning before automatic logout
            </label>

            <div className="kv">
              <span>Selected Timeout</span>
              <strong>{settings.sessionTimeout}</strong>
            </div>

            <div className="kv">
              <span>Logout Warning</span>

              <strong>
                {settings.autoLogoutWarning
                  ? 'Enabled'
                  : 'Disabled'}
              </strong>
            </div>
          </div>

          <div className="card">
            <h2>Multi-Factor Authentication</h2>

            <label className="check-row">
              <input
                type="checkbox"
                checked={settings.mfaEnabled}
                onChange={toggleMfa}
              />

              Enable MFA
            </label>

            <label
              className="check-row"
              style={{ marginTop: '14px' }}
            >
              <input
                name="requireMfaForSensitiveActions"
                type="checkbox"
                checked={
                  settings.requireMfaForSensitiveActions
                }
                disabled={!settings.mfaEnabled}
                onChange={handleFieldChange}
              />

              Require MFA for sensitive administrator actions
            </label>

            <div className="kv">
              <span>MFA Status</span>

              <strong>
                <span
                  className={`pill ${
                    settings.mfaEnabled
                      ? 'ok'
                      : 'danger'
                  }`}
                >
                  {settings.mfaEnabled
                    ? 'Enabled'
                    : 'Disabled'}
                </span>
              </strong>
            </div>

            <div className="notice">
              The current prototype still uses the static MFA
              verification code configured in the authentication
              flow.
            </div>
          </div>

          <div className="card">
            <h2>Settings Summary</h2>

            <div className="kv">
              <span>Theme</span>
              <strong>{settings.theme}</strong>
            </div>

            <div className="kv">
              <span>Language</span>
              <strong>{settings.language}</strong>
            </div>

            <div className="kv">
              <span>Notifications</span>

              <strong>
                {settings.notificationsEnabled
                  ? 'Enabled'
                  : 'Disabled'}
              </strong>
            </div>

            <div className="kv">
              <span>Session Timeout</span>
              <strong>{settings.sessionTimeout}</strong>
            </div>

            <div className="kv">
              <span>MFA</span>

              <strong>
                {settings.mfaEnabled
                  ? 'Enabled'
                  : 'Disabled'}
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
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '10px',
                marginTop: '18px',
              }}
            >
              <button
                className="btn primary"
                type="submit"
                disabled={!hasUnsavedChanges}
              >
                Save Settings
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

export default SettingsPage
