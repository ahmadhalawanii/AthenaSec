import { useState } from 'react'

import { api } from '../api/client'
import BrandMark from '../components/BrandMark'

type NewPasswordPageProps = {
  name: string
  // The password was changed: open the console
  onDone: () => void
  onLogout: () => void
}

/*
  Live mode, straight after signing in with a temporary password (a new account,
  or one an administrator reset). The backend refuses everything else until a new
  password is chosen, so this screen stands in for the whole console.
*/
function NewPasswordPage({ name, onDone, onLogout }: NewPasswordPageProps) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (submitting) {
      return
    }

    if (next.length < 14) {
      setError('The new password must be at least 14 characters.')
      return
    }

    if (next !== confirm) {
      setError('The new passwords do not match.')
      return
    }

    if (next === current) {
      setError('Choose a password different from the temporary one.')
      return
    }

    setSubmitting(true)

    try {
      await api('/me/password', { method: 'POST', body: { current_password: current, new_password: next } })
      onDone()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The password could not be changed.')
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-split login-split" id="newPasswordView">
      <section className="auth-brand" aria-label="AthenaSec">
        <div className="auth-logo">
          <BrandMark size={36} />
          <span className="auth-wordmark">AthenaSec</span>
        </div>
      </section>

      <main className="auth-panel" aria-labelledby="newPasswordTitle">
        <div className="auth-panel-inner">
          <h2 className="auth-title" id="newPasswordTitle">
            Choose your own password
          </h2>
          <p className="auth-lead">
            Welcome, {name}. You signed in with a temporary password from an administrator.
            Choose a new one to open the console.
          </p>

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && (
              <p className="auth-error" role="alert">
                {error}
              </p>
            )}

            <div className="auth-field">
              <label className="auth-label" htmlFor="temporaryPassword">
                Temporary password
              </label>
              <input
                className="auth-input"
                id="temporaryPassword"
                type="password"
                autoComplete="current-password"
                value={current}
                onChange={(event) => {
                  setCurrent(event.target.value)
                  setError('')
                }}
                required
              />
            </div>

            <div className="auth-field">
              <label className="auth-label" htmlFor="chosenPassword">
                New password (at least 14 characters)
              </label>
              <input
                className="auth-input"
                id="chosenPassword"
                type="password"
                autoComplete="new-password"
                value={next}
                onChange={(event) => {
                  setNext(event.target.value)
                  setError('')
                }}
                required
              />
            </div>

            <div className="auth-field">
              <label className="auth-label" htmlFor="confirmChosenPassword">
                Confirm new password
              </label>
              <input
                className="auth-input"
                id="confirmChosenPassword"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(event) => {
                  setConfirm(event.target.value)
                  setError('')
                }}
                required
              />
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={submitting}>
              {submitting ? 'Saving…' : 'Save and continue'}
            </button>
          </form>

          <button className="text-button" type="button" onClick={onLogout} style={{ marginTop: '18px' }}>
            Sign out
          </button>
        </div>
      </main>
    </div>
  )
}

export default NewPasswordPage
