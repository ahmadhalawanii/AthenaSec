import {
  useEffect,
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import type {
  ProfilePageProps,
  ProfileState,
  ProfileValues,
} from '../types/profileTypes'

import { api } from '../api/client'
import { friendlyTime } from '../api/adapters'
import { useLiveData } from '../api/liveDataContext'
import { fromProfile, toProfile, type ApiProfile } from '../api/settingsApi'
import { DEFAULT_TIMEZONE, timezoneOptions } from '../data/profileData'

// The backend's sign-in events, in words
const ACTIVITY_LABELS: Record<string, string> = {
  user_created: 'Account created',
  user_updated: 'Account details changed',
  password_accepted: 'Password accepted',
  login_rejected: 'Sign-in rejected',
  mfa_verified_session_started: 'Signed in with two-factor code',
  mfa_rejected: 'Two-factor code rejected',
  session_revoked: 'Signed out',
  password_changed: 'Password changed',
  password_change_rejected: 'Password change refused',
  password_reset: 'Password reset by an administrator',
  user_disabled: 'Account suspended',
  user_enabled: 'Account reactivated',
}

type Activity = { label: string; time: string }
import { statusTone } from '../utils/statusTone'

function ProfilePage({
  userName = 'Current User',
  userEmail = 'user@athenasec.com',
  role = 'Analyst',
}: ProfilePageProps) {
  const initialProfile: ProfileValues = {
    displayName: userName,
    email: userEmail,
    department:
      role === 'Administrator'
        ? 'Security Management'
        : 'Security Operations',
    phone: '+971 50 555 0100',
    timezone: DEFAULT_TIMEZONE,
  }

  const [profile, setProfile] =
    useState<ProfileValues>(initialProfile)

  const [savedProfile, setSavedProfile] =
    useState<ProfileValues>(initialProfile)

  const [profileState, setProfileState] =
    useState<ProfileState>('Saved')

  const [validationError, setValidationError] = useState('')

  const [pageMessage, setPageMessage] = useState('')

  // Live mode: the profile, password and activity are the backend's
  const isLive = useLiveData().mode === 'live'
  const [saving, setSaving] = useState(false)
  const [activity, setActivity] = useState<Activity[] | null>(null)
  const [passwords, setPasswords] = useState({ current: '', next: '', confirm: '' })
  const [passwordMessage, setPasswordMessage] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)

  function loadActivity() {
    api<{ items: { event_type: string; recorded_at: string }[] }>('/me/activity')
      .then((doc) =>
        setActivity(doc.items.map((item) => ({
          label: ACTIVITY_LABELS[item.event_type] ?? item.event_type.replace(/_/g, ' '),
          time: friendlyTime(item.recorded_at),
        }))),
      )
      .catch(() => setActivity([]))
  }

  useEffect(() => {
    if (!isLive) {
      return undefined
    }

    let cancelled = false

    api<ApiProfile>('/me/profile')
      .then((doc) => {
        if (!cancelled) {
          setProfile(toProfile(doc))
          setSavedProfile(toProfile(doc))
        }
      })
      .catch(() => {})
    loadActivity()

    return () => {
      cancelled = true
    }
  }, [isLive])

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (passwords.next.length < 14) {
      setPasswordMessage('The new password must be at least 14 characters.')
      return
    }

    if (passwords.next !== passwords.confirm) {
      setPasswordMessage('The new passwords do not match.')
      return
    }

    setChangingPassword(true)

    try {
      await api('/me/password', {
        method: 'POST',
        body: { current_password: passwords.current, new_password: passwords.next },
      })
      setPasswords({ current: '', next: '', confirm: '' })
      setPasswordMessage('Password changed. Use the new one next time you sign in.')
      loadActivity()
    } catch (error) {
      setPasswordMessage(`Not changed: ${error instanceof Error ? error.message : 'unknown error'}`)
    } finally {
      setChangingPassword(false)
    }
  }

  const hasUnsavedChanges = useMemo(() => {
    return (
      JSON.stringify(profile) !==
      JSON.stringify(savedProfile)
    )
  }, [profile, savedProfile])

  function handleProfileChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>,
  ) {
    const { name, value } = event.target

    setProfile((currentProfile) => ({
      ...currentProfile,
      [name]: value,
    }))

    setProfileState('Draft')
    setValidationError('')
    setPageMessage('Unsaved profile changes detected.')
  }

  function validateProfile() {
    if (!profile.displayName.trim()) {
      return 'Display name is required.'
    }

    if (!profile.email.trim()) {
      return 'Email address is required.'
    }

    const emailPattern =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    if (!emailPattern.test(profile.email.trim())) {
      return 'Enter a valid email address.'
    }

    if (!profile.department.trim()) {
      return 'Department is required.'
    }

    if (!profile.phone.trim()) {
      return 'Phone number is required.'
    }

    if (!profile.timezone.trim()) {
      return 'Timezone is required.'
    }

    return ''
  }

  async function saveProfile(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    if (saving) {
      return
    }

    const error = validateProfile()

    if (error) {
      setValidationError(error)
      setProfileState('Error')
      setPageMessage('Profile changes could not be saved.')
      return
    }

    const normalizedProfile: ProfileValues = {
      displayName: profile.displayName.trim(),
      email: profile.email.trim().toLowerCase(),
      department: profile.department.trim(),
      phone: profile.phone.trim(),
      timezone: profile.timezone,
    }

    if (isLive) {
      setSaving(true)

      try {
        const doc = await api<ApiProfile>('/me/profile', { method: 'PUT', body: fromProfile(normalizedProfile) })
        setProfile(toProfile(doc))
        setSavedProfile(toProfile(doc))
      } catch (failure) {
        setProfileState('Error')
        setPageMessage(`Profile could not be saved: ${failure instanceof Error ? failure.message : 'unknown error'}`)
        return
      } finally {
        setSaving(false)
      }

      setProfileState('Saved')
      setValidationError('')
      setPageMessage('Profile saved. Your new name shows everywhere after you next sign in.')
      loadActivity()
      return
    }

    setProfile(normalizedProfile)
    setSavedProfile(normalizedProfile)
    setProfileState('Saved')
    setValidationError('')

    setPageMessage(
      'Profile saved.',
    )
  }

  function cancelChanges() {
    setProfile(savedProfile)
    setProfileState('Saved')
    setValidationError('')
    setPageMessage('Unsaved profile changes were discarded.')
  }

  function restoreOriginalProfile() {
    setProfile(initialProfile)
    setProfileState('Draft')
    setValidationError('')

    setPageMessage(
      'Original profile values restored. Save to keep these changes.',
    )
  }

  return (
    <section
      className="page active"
      data-page="profile"
      data-page-name="Profile"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Profile</h1>

          <p className="sub">
            Current authenticated user, role, session, and contact
            preferences.
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
            className={`pill ${statusTone(role)}`}
            id="profileRole"
          >
            {role}
          </span>

          <span
            className={`pill ${statusTone(
              profileState,
            )}`}
          >
            {profileState}
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
          <strong>Profile error</strong>

          <p
            className="sub"
            style={{ marginTop: '6px' }}
          >
            {validationError}
          </p>
        </div>
      )}

      <div className="grid two">
        <div className="card">
          <h2>Account</h2>

          <div id="profileAccount">
            <div className="kv">
              <span>Display Name</span>
              <strong>{savedProfile.displayName}</strong>
            </div>

            <div className="kv">
              <span>Email</span>
              <strong>{savedProfile.email}</strong>
            </div>

            <div className="kv">
              <span>Role</span>

              <strong>
                <span className={`pill ${statusTone(role)}`}>
                  {role}
                </span>
              </strong>
            </div>

            <div className="kv">
              <span>Department</span>
              <strong>{savedProfile.department}</strong>
            </div>

            <div className="kv">
              <span>MFA</span>

              <strong>
                <span className="pill ok">
                  Enabled
                </span>
              </strong>
            </div>

            <div className="kv">
              <span>Account Status</span>

              <strong>
                <span className="pill ok">
                  Active
                </span>
              </strong>
            </div>
          </div>

          <div
            className="notice"
            style={{ marginTop: '18px' }}
          >
            The account role and MFA status are read-only on the
            profile page. Administrators manage account access from
            User Management.
          </div>
        </div>

        <form
          className="card profile-details-card"
          onSubmit={saveProfile}
        >
          <h2>Profile Details</h2>

          <label
            className="form-label"
            htmlFor="profileName"
          >
            Display Name
          </label>

          <input
            className="field-input"
            id="profileName"
            name="displayName"
            autoComplete="name"
            value={profile.displayName}
            onChange={handleProfileChange}
            placeholder="Display name…"
          />

          <label
            className="form-label"
            htmlFor="profileEmail"
          >
            Email Address
          </label>

          <input
            className="field-input"
            id="profileEmail"
            name="email"
            type="email"
            autoComplete="email"
            spellCheck={false}
            value={profile.email}
            onChange={handleProfileChange}
            placeholder="user@athenasec.com…"
          />

          <label
            className="form-label"
            htmlFor="profileDepartment"
          >
            Department
          </label>

          <input
            className="field-input"
            id="profileDepartment"
            name="department"
            autoComplete="organization"
            value={profile.department}
            onChange={handleProfileChange}
            placeholder="Security Operations…"
          />

          <label
            className="form-label"
            htmlFor="profilePhone"
          >
            Phone
          </label>

          <input
            className="field-input"
            id="profilePhone"
            name="phone"
            type="tel"
            autoComplete="tel"
            value={profile.phone}
            onChange={handleProfileChange}
            placeholder="+971 50 555 0100…"
          />

          <label
            className="form-label"
            htmlFor="profileTimezone"
          >
            Timezone
          </label>

          <select
            className="select-input"
            id="profileTimezone"
            name="timezone"
            autoComplete="off"
            value={profile.timezone}
            onChange={handleProfileChange}
          >
            {timezoneOptions.map((timezone) => (
              <option
                value={timezone}
                key={timezone}
              >
                {timezone}
              </option>
            ))}
          </select>

          <div className="kv">
            <span>Unsaved Changes</span>
            <strong>
              {hasUnsavedChanges ? 'Yes' : 'No'}
            </strong>
          </div>

          <div className="kv">
            <span>Persistence</span>
            <strong>{isLive ? 'Saved to your account' : 'Until you leave this page (demo)'}</strong>
          </div>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '10px',
              marginTop: '10px',
            }}
          >
            <button
              className="btn primary"
              type="submit"
              disabled={!hasUnsavedChanges || saving}
            >
              {saving ? 'Saving…' : 'Save Profile'}
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
              onClick={restoreOriginalProfile}
            >
              Restore Original
            </button>
          </div>
        </form>
      </div>

      <div
        className="grid two"
        style={{ marginTop: '18px' }}
      >
        <div className="card">
          <h2>Current Session</h2>

          <div className="kv">
            <span>Session Status</span>

            <strong>
              <span className="pill ok">
                Active
              </span>
            </strong>
          </div>

          <div className="kv">
            <span>Authenticated Role</span>
            <strong>{role}</strong>
          </div>

          <div className="kv">
            <span>Authentication</span>
            <strong>Password + MFA</strong>
          </div>

          <div className="kv">
            <span>Session Started</span>
            <strong>Current browser session</strong>
          </div>

          <div className="kv">
            <span>Timezone</span>
            <strong>{savedProfile.timezone}</strong>
          </div>

          <div className="kv">
            <span>Device</span>
            <strong>Web Console</strong>
          </div>
        </div>

        <div className="card">
          <h2>Recent Account Activity</h2>

          {isLive ? (
            <>
              {activity === null && <p className="sub">Loading…</p>}
              {activity?.length === 0 && <p className="sub">No sign-in activity recorded yet.</p>}
              {activity?.map((entry, index) => (
                <div className="kv" key={`${entry.time}-${index}`}>
                  <span>{entry.time}</span>
                  <strong>{entry.label}</strong>
                </div>
              ))}
            </>
          ) : (
          <>
          <div className="kv">
            <span>Today, 20:46</span>

            <strong>
              Successful MFA authentication
            </strong>
          </div>

          <div className="kv">
            <span>Today, 20:45</span>

            <strong>
              Successful password authentication
            </strong>
          </div>

          <div className="kv">
            <span>Yesterday, 18:32</span>

            <strong>
              Profile viewed
            </strong>
          </div>

          <div className="notice">
            Session and activity records are sample data in this
            demo.
          </div>
          </>
          )}
        </div>
      </div>

      {isLive && (
        <div className="card" style={{ marginTop: '18px' }} data-section="change-password">
          <h2>Change Password</h2>
          <p className="sub">
            At least 14 characters. Your two-factor app keeps working.
          </p>

          <form onSubmit={changePassword} style={{ marginTop: '12px' }}>
            <label className="form-label" htmlFor="currentPassword">Current password</label>
            <input
              className="field-input"
              id="currentPassword"
              type="password"
              autoComplete="current-password"
              value={passwords.current}
              onChange={(event) => setPasswords((current) => ({ ...current, current: event.target.value }))}
              required
            />
            <label className="form-label" htmlFor="newPassword">New password</label>
            <input
              className="field-input"
              id="newPassword"
              type="password"
              autoComplete="new-password"
              value={passwords.next}
              onChange={(event) => setPasswords((current) => ({ ...current, next: event.target.value }))}
              required
            />
            <label className="form-label" htmlFor="confirmPassword">Confirm new password</label>
            <input
              className="field-input"
              id="confirmPassword"
              type="password"
              autoComplete="new-password"
              value={passwords.confirm}
              onChange={(event) => setPasswords((current) => ({ ...current, confirm: event.target.value }))}
              required
            />

            {passwordMessage && (
              <div className="notice" role="status" data-field="passwordMessage">{passwordMessage}</div>
            )}

            <div style={{ marginTop: '12px' }}>
              <button className="btn primary" type="submit" disabled={changingPassword}>
                {changingPassword ? 'Changing…' : 'Change password'}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  )
}

export default ProfilePage
