import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import type {
  ProfilePageProps,
  ProfileState,
  ProfileValues,
  UserRole,
} from '../types/profileTypes'

import { timezoneOptions } from '../data/profileData'

function profileStateClass(state: ProfileState) {
  if (state === 'Saved') {
    return 'ok'
  }

  if (state === 'Error') {
    return 'danger'
  }

  return 'blue'
}

function roleClass(role: UserRole) {
  return role === 'Administrator' ? 'warn' : 'blue'
}

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
    timezone: 'Asia/Dubai',
  }

  const [profile, setProfile] =
    useState<ProfileValues>(initialProfile)

  const [savedProfile, setSavedProfile] =
    useState<ProfileValues>(initialProfile)

  const [profileState, setProfileState] =
    useState<ProfileState>('Saved')

  const [validationError, setValidationError] = useState('')

  const [pageMessage, setPageMessage] = useState(
    'Profile information loaded successfully.',
  )

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

  function saveProfile(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

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

    setProfile(normalizedProfile)
    setSavedProfile(normalizedProfile)
    setProfileState('Saved')
    setValidationError('')

    setPageMessage(
      'Profile saved for the current frontend session.',
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
            className={`pill ${roleClass(role)}`}
            id="profileRole"
          >
            {role}
          </span>

          <span
            className={`pill ${profileStateClass(
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
                <span className={`pill ${roleClass(role)}`}>
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
            value={profile.displayName}
            onChange={handleProfileChange}
            placeholder="Display name"
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
            value={profile.email}
            onChange={handleProfileChange}
            placeholder="user@athenasec.com"
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
            value={profile.department}
            onChange={handleProfileChange}
            placeholder="Security Operations"
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
            value={profile.phone}
            onChange={handleProfileChange}
            placeholder="+971 50 555 0100"
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
            <strong>Frontend session only</strong>
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
              disabled={!hasUnsavedChanges}
            >
              Save Profile
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
            These session and activity records are static frontend
            examples until authentication and audit APIs are connected.
          </div>
        </div>
      </div>
    </section>
  )
}

export default ProfilePage
