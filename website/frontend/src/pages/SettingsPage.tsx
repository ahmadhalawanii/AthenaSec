import {
  useMemo,
  useState,
  type FormEvent,
} from 'react'
import { Link } from 'react-router-dom'
import type {
  LanguagePreference,
  SessionTimeout,
  SettingsBooleanKey,
  SettingsState,
  SettingsToggle,
  SettingsValues,
  ThemePreference,
} from '../types/settingsTypes'

import Switch from '../components/Switch'
import { DEFAULT_TIMEZONE } from '../data/profileData'
import {
  initialSettings,
  languageOptions,
  notificationToggles,
  sessionToggles,
  themeOptions,
  timeoutOptions,
} from '../data/settingsData'
import { useAdminState } from '../hooks/useAdminState'
import { initialsOf } from '../utils/initials'
import { statusTone } from '../utils/statusTone'

function SettingsPage() {
  // The signed-in account's live record: edits on User Management show here
  const { users, currentUserId } = useAdminState()
  const me = users.find((user) => user.id === currentUserId)

  const [settings, setSettings] =
    useState<SettingsValues>(initialSettings)

  const [savedSettings, setSavedSettings] =
    useState<SettingsValues>(initialSettings)

  const [settingsState, setSettingsState] =
    useState<SettingsState>('Saved')

  const [pageMessage, setPageMessage] = useState('')

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
      'Settings saved.',
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

  function setTheme(theme: ThemePreference) {
    setSettings((currentSettings) => ({ ...currentSettings, theme }))
    updateSettingsState()
  }

  function setLanguage(language: LanguagePreference) {
    setSettings((currentSettings) => ({ ...currentSettings, language }))
    updateSettingsState()
  }

  function setSessionTimeout(sessionTimeout: SessionTimeout) {
    setSettings((currentSettings) => ({ ...currentSettings, sessionTimeout }))
    updateSettingsState()
  }

  /*
    One handler for every switch. Two are linked: turning notifications
    off clears the channels, and turning MFA off clears the requirement
    for sensitive actions.
  */
  function setToggle(key: SettingsBooleanKey, next: boolean) {
    setSettings((currentSettings) => {
      const updated = { ...currentSettings, [key]: next }

      if (key === 'notificationsEnabled' && !next) {
        updated.criticalAlertNotifications = false
        updated.caseNotifications = false
        updated.systemHealthNotifications = false
        updated.emailNotifications = false
      }

      if (key === 'mfaEnabled' && !next) {
        updated.requireMfaForSensitiveActions = false
      }

      return updated
    })

    updateSettingsState()
  }

  function renderToggle(toggle: SettingsToggle) {
    const linkedOff =
      (toggle.key === 'requireMfaForSensitiveActions' && !settings.mfaEnabled) ||
      (toggle.key !== 'notificationsEnabled' &&
        notificationToggles.some((item) => item.key === toggle.key) &&
        !settings.notificationsEnabled)

    return (
      <li className="set-toggle" key={toggle.key} data-setting={toggle.key}>
        <div className="set-toggle-text">
          <span className="set-toggle-label">{toggle.label}</span>
          <span className="set-toggle-note">{toggle.note}</span>
        </div>

        <Switch
          checked={settings[toggle.key]}
          onChange={(next) => setToggle(toggle.key, next)}
          label={settings[toggle.key] ? 'On' : 'Off'}
          accessibleName={toggle.label}
          disabled={linkedOff}
        />
      </li>
    )
  }

  const yesNo = (value: boolean) => (value ? 'Enabled' : 'Disabled')

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

        <div className="headline-actions">
          <span
            className={`pill ${statusTone(
              settingsState,
            )}`}
            id="settingsState"
          >
            {settingsState}
          </span>
        </div>
      </div>

      {me && (
        <section className="card key set-profile" aria-label="Your profile" id="settingsProfile">
          <span className="set-profile-avatar" aria-hidden="true">
            {initialsOf(me.name)}
          </span>

          <div className="set-profile-text">
            <span className="set-profile-name" data-field="name">{me.name}</span>
            <span className="set-profile-email mono" data-field="email">{me.email}</span>

            <span className="set-profile-tags">
              <span className="pill danger" data-field="role">{me.role}</span>
              <span
                className={me.mfaEnabled ? 'pill ok' : 'pill danger'}
                data-field="mfa"
              >
                {me.mfaEnabled ? 'MFA on' : 'MFA off'}
              </span>
              <span className="pill neutral" data-field="where">
                {me.department}, {DEFAULT_TIMEZONE}
              </span>
            </span>
          </div>

          <Link className="btn" to="/app/profile" id="editProfileLink">
            Edit profile
          </Link>
        </section>
      )}

      {pageMessage && (
        <div
          className="notice"
          role="status"
        >
          {pageMessage}
        </div>
      )}

      {validationError && (
        <div
          className="notice"
          role="alert"
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
        <div className="set-grid">
          <section className="card set-card" aria-labelledby="setPrefTitle">
            <h2 id="setPrefTitle">Console preferences</h2>

            <div className="set-field">
              <span className="form-label" id="setThemeLabel">Theme</span>

              <div className="set-themes" role="group" aria-labelledby="setThemeLabel">
                {themeOptions.map((theme) => (
                  <button
                    key={theme.value}
                    type="button"
                    className="set-theme"
                    aria-pressed={settings.theme === theme.value}
                    onClick={() => setTheme(theme.value)}
                    data-theme={theme.value}
                  >
                    <span className="set-swatch" aria-hidden="true">
                      <span style={{ background: theme.sidebar }} />
                      <span style={{ background: theme.main }} />
                      <span className="set-swatch-accent" />
                    </span>

                    <span>{theme.value}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="set-field">
              <label className="form-label" htmlFor="settingsLanguage">
                Language
              </label>

              <select
                className="select-input"
                id="settingsLanguage"
                name="language"
                autoComplete="off"
                value={settings.language}
                onChange={(event) =>
                  setLanguage(event.target.value as LanguagePreference)
                }
              >
                {languageOptions.map((option) => (
                  <option value={option} key={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <p className="sub">
              Theme and language are saved with your settings
              but don’t change the console yet.
            </p>
          </section>

          <section className="card set-card" aria-labelledby="setSessionTitle">
            <h2 id="setSessionTitle">Session security</h2>

            <div className="set-field">
              <label className="form-label" htmlFor="sessionTimeout">
                Session timeout
              </label>

              <select
                className="select-input"
                id="sessionTimeout"
                name="sessionTimeout"
                autoComplete="off"
                value={settings.sessionTimeout}
                onChange={(event) =>
                  setSessionTimeout(event.target.value as SessionTimeout)
                }
              >
                {timeoutOptions.map((option) => (
                  <option value={option} key={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <ul className="set-toggles">
              {sessionToggles.map(renderToggle)}
            </ul>

            <div className="notice">
              In this demo every sign-in uses the same MFA code,
              123456.
            </div>
          </section>

          <section className="card set-card set-wide" aria-labelledby="setNotifyTitle">
            <h2 id="setNotifyTitle">Notify me about</h2>

            <ul className="set-toggles set-toggles-grid">
              {notificationToggles.map(renderToggle)}
            </ul>

            <div className="notice">
              Notification delivery is simulated. No real email
              or external notification is sent.
            </div>
          </section>

          <section className="card set-card set-wide" aria-labelledby="setSummaryTitle">
            <h2 id="setSummaryTitle">Settings Summary</h2>

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
              <strong>{yesNo(settings.notificationsEnabled)}</strong>
            </div>

            <div className="kv">
              <span>Session Timeout</span>
              <strong>{settings.sessionTimeout}</strong>
            </div>

            <div className="kv">
              <span>MFA</span>

              {/*
                Deliberately not statusTone('Disabled') (grey):
                MFA being off is a security risk, so it shows red.
              */}
              <strong>
                <span
                  className={`pill ${
                    settings.mfaEnabled
                      ? 'ok'
                      : 'danger'
                  }`}
                >
                  {yesNo(settings.mfaEnabled)}
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
              <strong>Until you leave this page (demo)</strong>
            </div>

            <div className="set-actions">
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
          </section>
        </div>
      </form>
    </section>
  )
}

export default SettingsPage
