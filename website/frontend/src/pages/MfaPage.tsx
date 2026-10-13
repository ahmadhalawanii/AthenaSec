import { useState } from 'react'
import type { MfaPageProps } from '../types/mfaTypes'

function MfaPage({ onVerify }: MfaPageProps) {
  const [digits, setDigits] = useState(['', '', '', '', '', ''])
  const [error, setError] = useState('')

  function updateDigit(
    index: number,
    value: string,
    input: HTMLInputElement,
  ) {
    const digit = value.replace(/\D/g, '').slice(-1)

    const updatedDigits = [...digits]
    updatedDigits[index] = digit

    setDigits(updatedDigits)
    setError('')

    if (digit && input.nextElementSibling instanceof HTMLInputElement) {
      input.nextElementSibling.focus()
    }
  }

  function handleKeyDown(
    event: React.KeyboardEvent<HTMLInputElement>,
  ) {
    if (
      event.key === 'Backspace' &&
      event.currentTarget.value === '' &&
      event.currentTarget.previousElementSibling instanceof HTMLInputElement
    ) {
      event.currentTarget.previousElementSibling.focus()
    }
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const code = digits.join('')

    if (code.length !== 6) {
      setError('Please enter all 6 digits')
      return
    }

    if (code !== '123456') {
      setError('Invalid authentication code')
      return
    }

    onVerify()
  }

  return (
    <section className="section auth-view" id="mfaView">
      <div className="label">
        <span>AthenaSec High Fidelity</span>
        <span className="prototype-note">
          Multi-Factor Authentication
        </span>
      </div>

      <div className="screen">
        <div className="login-body">
          <div className="hero">
            <div>
              <div className="big-logo"></div>
              <h1>Secure Access</h1>
              <p className="sub">
                MFA protects analyst and administrator sessions
              </p>
            </div>
          </div>

          <div className="form-area">
            <form
              className="form"
              id="mfaForm"
              onSubmit={handleSubmit}
            >
              <h1>Two-Factor Authentication</h1>

              <p className="sub">
                Enter the 6-digit demo code from your authenticator app.
              </p>

              <p className="sub">
                Demo code:{' '}
                <strong style={{ color: '#e5e7eb' }}>
                  123456
                </strong>
              </p>

              {error && (
                <div className="auth-error" id="mfaError">
                  {error}
                </div>
              )}

              <div className="code-row">
                <input
                  className="code"
                  maxLength={1}
                  value={digits[0]}
                  onChange={(event) => updateDigit(0, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
                <input
                  className="code"
                  maxLength={1}
                  value={digits[1]}
                  onChange={(event) => updateDigit(1, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
                <input
                  className="code"
                  maxLength={1}
                  value={digits[2]}
                  onChange={(event) => updateDigit(2, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
                <input
                  className="code"
                  maxLength={1}
                  value={digits[3]}
                  onChange={(event) => updateDigit(3, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
                <input
                  className="code"
                  maxLength={1}
                  value={digits[4]}
                  onChange={(event) => updateDigit(4, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
                <input
                  className="code"
                  maxLength={1}
                  value={digits[5]}
                  onChange={(event) => updateDigit(5, event.target.value, event.currentTarget)}
                  onKeyDown={handleKeyDown}
                  data-mfa-digit
                />
              </div>

              <button
                className="btn primary"
                type="submit"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                }}
              >
                Verify &amp; Sign In
              </button>

              <button
                className="btn ghost"
                type="button"
                onClick={() => alert('A new demo code has been sent')}
                data-action="resend-code"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  marginTop: '10px',
                }}
              >
                Resend code
              </button>
            </form>
          </div>
        </div>
      </div>
    </section>
  )
}

export default MfaPage
