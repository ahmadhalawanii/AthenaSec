import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'

import { ROLE_LABELS } from '../data/appData'
import { DEMO_MFA_CODE } from '../data/loginData'
import type { MfaPageProps } from '../types/mfaTypes'

const CODE_LENGTH = 6

function MfaPage({ onVerify, accountEmail, accountRole, demoMode }: MfaPageProps) {
  const [digits, setDigits] = useState<string[]>(
    Array(CODE_LENGTH).fill(''),
  )
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [resendMessage, setResendMessage] = useState('')
  const inputRefs = useRef<Array<HTMLInputElement | null>>([])

  /*
    One digit when typing; several when the code is pasted or
    autofilled (autocomplete="one-time-code"). Several digits fill
    this box and the ones after it. There is no maxLength because the
    browser would cut a pasted code down to its first digit.
  */
  function updateDigit(index: number, value: string) {
    let incoming = value.replace(/\D/g, '')

    /*
      Letters, spaces and symbols are ignored. Returning without a
      state change lets React put the box back to its current digit;
      otherwise a stray key on a filled (selected) box would clear it.
      An empty value is a real deletion and falls through.
    */
    if (value !== '' && incoming === '') {
      return
    }
    const updatedDigits = [...digits]
    const current = digits[index]

    // Typed into a filled box without the old digit selected: keep the new one.
    if (current && incoming.length === 2 && incoming.includes(current)) {
      incoming = incoming.startsWith(current) ? incoming[1] : incoming[0]
    }

    if (incoming.length <= 1) {
      updatedDigits[index] = incoming

      setDigits(updatedDigits)
      setError('')

      if (incoming && index < CODE_LENGTH - 1) {
        inputRefs.current[index + 1]?.focus()
      }
      return
    }

    const spread = incoming.slice(0, CODE_LENGTH - index).split('')

    spread.forEach((digit, offset) => {
      updatedDigits[index + offset] = digit
    })

    setDigits(updatedDigits)
    setError('')

    const nextEmpty = updatedDigits.findIndex((digit) => digit === '')
    inputRefs.current[nextEmpty === -1 ? CODE_LENGTH - 1 : nextEmpty]?.focus()
  }

  function handleKeyDown(
    index: number,
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (
      event.key === 'Backspace' &&
      event.currentTarget.value === '' &&
      index > 0
    ) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const code = digits.join('')

    if (code.length !== CODE_LENGTH) {
      setError('Please enter all 6 digits')
      return
    }

    if (demoMode && code !== DEMO_MFA_CODE) {
      setError('Invalid authentication code')
      return
    }

    if (submitting) {
      return
    }

    setSubmitting(true)
    const failure = await onVerify(code)
    setSubmitting(false)

    if (failure) {
      setError(failure)
      setDigits(Array(CODE_LENGTH).fill(''))
      inputRefs.current[0]?.focus()
    }
  }

  return (
    /* Reading order matches the layout at every width: identity panel, then the form. */
    <div className="auth-split mfa-split" id="mfaView">
      <section className="auth-brand mfa-brand" aria-label="Identity check">
        <svg
          className="mfa-emblem"
          width="300"
          height="300"
          viewBox="0 0 300 300"
          aria-hidden="true"
          focusable="false"
        >
          <circle className="mfa-ring-track" cx="150" cy="150" r="138" />
          <g className="mfa-ring">
            <circle className="mfa-ring-dash" cx="150" cy="150" r="138" />
          </g>
          <g className="mfa-ring reverse">
            <circle className="mfa-ring-dots" cx="150" cy="150" r="112" />
          </g>
          <path
            className="mfa-shield"
            d="M150 70 94 93v38c0 36 24 64 56 72 32-8 56-36 56-72V93L150 70z"
          />
          <path className="mfa-check" d="M126 136l16 16 32-34" />
        </svg>

        <div className="mfa-pitch">
          <h1>Prove it's you.</h1>
          <p>A stolen password alone will never open the SOC console.</p>
        </div>
      </section>

      <main className="auth-panel" aria-labelledby="mfaTitle">
        <div className="auth-panel-inner">
          <Link className="auth-back" to="/login">
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              aria-hidden="true"
              focusable="false"
            >
              <path d="m15 18-6-6 6-6" />
            </svg>
            Use a different account
          </Link>

          <h2 className="auth-title" id="mfaTitle">
            Enter your 6-digit code
          </h2>
          <p className="auth-lead">
            Open your authenticator app and enter the code for AthenaSec.
          </p>

          <form className="auth-form" id="mfaForm" onSubmit={handleSubmit}>
            {error && (
              <p className="auth-error" id="mfaError" role="alert">
                {error}
              </p>
            )}

            <fieldset className="code-fieldset">
              <legend className="visually-hidden">Authentication code</legend>

              <div className="code-row">
                {digits.map((digit, index) => (
                  <input
                    key={index}
                    ref={(element) => {
                      inputRefs.current[index] = element
                    }}
                    className={digit ? 'code filled' : 'code'}
                    name={`code-${index + 1}`}
                    inputMode="numeric"
                    autoComplete={index === 0 ? 'one-time-code' : 'off'}
                    aria-label={`Digit ${index + 1} of ${CODE_LENGTH}`}
                    value={digit}
                    onChange={(event) => updateDigit(index, event.target.value)}
                    onFocus={(event) => event.currentTarget.select()}
                    onKeyDown={(event) => handleKeyDown(index, event)}
                    data-mfa-digit
                  />
                ))}
              </div>
            </fieldset>

            <button className="btn primary auth-submit" type="submit" disabled={submitting}>
              {submitting ? 'Verifying…' : 'Verify and sign in'}
            </button>

            <div className="mfa-resend">
              <button
                className="text-button"
                type="button"
                onClick={() =>
                  setResendMessage(
                    demoMode
                      ? `A new code has been sent. In this demo the code is still ${DEMO_MFA_CODE}.`
                      : 'Your authenticator app shows a new code every 30 seconds. Use the current one.',
                  )
                }
                data-action="resend-code"
              >
                Send a new code
              </button>
            </div>

            <p className="auth-status" role="status" aria-live="polite">
              {resendMessage}
            </p>
          </form>

          <dl className="mfa-account">
            <div>
              <dt>Account</dt>
              <dd className="mono">{accountEmail}</dd>
            </div>
            {accountRole && (
              <div>
                <dt>Role</dt>
                <dd>{ROLE_LABELS[accountRole]}</dd>
              </div>
            )}
            <div>
              <dt>Device</dt>
              <dd>Web console</dd>
            </div>
          </dl>

          {demoMode && (
            <p className="demo-panel demo-inline">
              <span className="demo-badge">Demo mode</span> Use code{' '}
              <span className="mono">{DEMO_MFA_CODE}</span>.
            </p>
          )}
        </div>
      </main>
    </div>
  )
}

export default MfaPage
