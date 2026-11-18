import { useEffect, useState } from 'react'
import QRCode from 'qrcode'

import { api, setCsrfToken } from '../api/client'
import type { ApiSession } from '../api/apiTypes'
import BrandMark from '../components/BrandMark'

// A brand-new authenticator secret from the backend, as a QR code image and a setup key
async function requestQr() {
  const { totp_uri: uri } = await api<{ totp_uri: string }>('/me/mfa/setup', { method: 'POST' })
  const image = await QRCode.toDataURL(uri, { margin: 1, width: 220 })

  return { image, key: new URL(uri).searchParams.get('secret') }
}

type MfaSetupPageProps = {
  name: string
  email: string
  // Two-factor is set up and a full session started: open the console
  onDone: (session: ApiSession) => void
  onLogout: () => void
}

/*
  Live mode, a new account's first sign-in, right after choosing their own password.
  The backend makes a brand-new authenticator secret for this screen (never one used
  before, by this or any other account), shows it once as a QR code, and only turns it
  on after the user types a code from their app. Everything else stays locked until then.
*/
function MfaSetupPage({ name, email, onDone, onLogout }: MfaSetupPageProps) {
  const [qr, setQr] = useState<string | null>(null)
  const [setupKey, setSetupKey] = useState<string | null>(null)
  const [showKey, setShowKey] = useState(false)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  // Bumped by "Show a new QR code"; each value asks the backend for a fresh one
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    // Only the newest QR code can be confirmed, so an older answer is never shown
    let current = true

    requestQr()
      .then(({ image, key }) => {
        if (current) {
          setQr(image)
          setSetupKey(key)
          setError('')
        }
      })
      .catch((failure: unknown) => {
        if (current) {
          setError(failure instanceof Error ? failure.message : 'The QR code could not be created.')
        }
      })
      .finally(() => {
        if (current) {
          setLoading(false)
        }
      })

    return () => {
      current = false
    }
  }, [attempt])

  function newQr() {
    setLoading(true)
    setError('')
    setQr(null)
    setSetupKey(null)
    setCode('')
    setAttempt((value) => value + 1)
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (submitting) {
      return
    }

    if (!/^\d{6}$/.test(code)) {
      setError('Type the 6-digit code your authenticator app shows for AthenaSec.')
      return
    }

    setSubmitting(true)

    try {
      const session = await api<ApiSession>('/me/mfa/confirm', { method: 'POST', body: { code } })
      setCsrfToken(session.csrf_token)
      onDone(session)
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'That code could not be checked.')
      setCode('')
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-split login-split" id="mfaSetupView">
      <section className="auth-brand" aria-label="AthenaSec">
        <div className="auth-logo">
          <BrandMark size={36} />
          <span className="auth-wordmark">AthenaSec</span>
        </div>
      </section>

      <main className="auth-panel" aria-labelledby="mfaSetupTitle">
        <div className="auth-panel-inner">
          <h2 className="auth-title" id="mfaSetupTitle">
            Connect your authenticator app
          </h2>
          <p className="auth-lead">
            Welcome, {name}. Every sign-in to AthenaSec needs a code from your phone. Set it up
            once now.
          </p>

          <ol className="mfa-setup-steps">
            <li>
              Open an authenticator app on your phone: <strong>Google Authenticator</strong>,{' '}
              <strong>Microsoft Authenticator</strong> or <strong>1Password</strong>. Install one
              first if you have none.
            </li>
            <li>
              Tap <strong>+</strong> (Add account), then <strong>Scan a QR code</strong>.
            </li>
            <li>Point your camera at the code below. The app adds <strong>AthenaSec</strong> ({email}).</li>
            <li>Type the 6-digit code the app now shows for AthenaSec.</li>
          </ol>

          <div className="mfa-setup-qr" aria-live="polite">
            {qr ? (
              <img src={qr} width={220} height={220} alt="QR code to add AthenaSec to your authenticator app" />
            ) : (
              <span>{loading ? 'Creating your QR code…' : 'No QR code'}</span>
            )}
          </div>

          {setupKey && (
            <p className="mfa-setup-key">
              Can't scan?{' '}
              <button className="text-button" type="button" onClick={() => setShowKey((shown) => !shown)}>
                {showKey ? 'Hide the setup key' : 'Type a setup key instead'}
              </button>
              {showKey && <code data-field="setupKey">{setupKey.replace(/(.{4})/g, '$1 ').trim()}</code>}
            </p>
          )}

          <form className="auth-form" onSubmit={handleSubmit}>
            {error && (
              <p className="auth-error" role="alert">
                {error}
              </p>
            )}

            <div className="auth-field">
              <label className="auth-label" htmlFor="setupCode">
                6-digit code from the app
              </label>
              <input
                className="auth-input mono"
                id="setupCode"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="\d{6}"
                maxLength={6}
                value={code}
                onChange={(event) => {
                  setCode(event.target.value.replace(/\D/g, '').slice(0, 6))
                  setError('')
                }}
                disabled={!qr}
                required
              />
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={submitting || !qr}>
              {submitting ? 'Checking…' : 'Connect and continue'}
            </button>
          </form>

          <p className="sub mfa-setup-note">
            This QR code is new and belongs only to your account. Don't share it or take a
            screenshot. If you reload this page you get a new one, and only the newest works.
          </p>

          <div className="mfa-setup-actions">
            <button className="text-button" type="button" onClick={newQr} disabled={loading}>
              Show a new QR code
            </button>
            <button className="text-button" type="button" onClick={onLogout}>
              Sign out
            </button>
          </div>
        </div>
      </main>
    </div>
  )
}

export default MfaSetupPage
