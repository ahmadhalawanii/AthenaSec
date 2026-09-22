import { useState } from 'react'
import type { LoginPageProps } from '../types/loginTypes'

function LoginPage({ onSignIn }: LoginPageProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const success = onSignIn(email, password)

    if (!success) {
      setError('Invalid email or password')
      return
    }

    setError('')
  }

  return (
    <section className="section auth-view" id="loginView">
      <div className="label">
        <span>AthenaSec High Fidelity</span>
        <span className="prototype-note">Interactive SOC Login</span>
      </div>

      <div className="screen">
        <div className="login-body">
          <div className="hero">
            <div>
              <div className="big-logo"></div>
              <h1>AthenaSec</h1>
              <p className="sub">
                Security Monitoring &amp; Automated Incident Response
              </p>
            </div>
          </div>

          <div className="form-area">
            <form
              className="form auth-form login-form"
              id="loginForm"
              onSubmit={handleSubmit}
            >
              <h1>Welcome back</h1>

              <p className="sub">
                Sign in to continue to the SOC console.
              </p>

              {error && (
                <div className="auth-error" id="loginError">
                  {error}
                </div>
              )}

              <div className="auth-fields">
                <div className="auth-field">
                  <label className="form-label" htmlFor="loginEmail">
                    Email address
                  </label>

                  <input
                    className="field-input"
                    id="loginEmail"
                    type="email"
                    placeholder="analyst@athenasec.com"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value)
                      setError('')
                    }}
                    autoComplete="email"
                    required
                  />
                </div>

                <div className="auth-field">
                  <label className="form-label" htmlFor="loginPassword">
                    Password
                  </label>

                  <input
                    className="field-input"
                    id="loginPassword"
                    type="password"
                    placeholder="Enter password"
                    value={password}
                    onChange={(event) => {
                      setPassword(event.target.value)
                      setError('')
                    }}
                    autoComplete="current-password"
                    required
                  />
                </div>
              </div>

              <div className="login-options">
                <label className="check-row">
                  <input type="checkbox" id="rememberMe" />
                  Remember Me
                </label>

                <button
                  className="forgot-password"
                  type="button"
                  data-action="forgot-password"
                >
                  Forgot password
                </button>
              </div>

              <button
                className="btn primary login-submit"
                type="submit"
              >
                Sign In
              </button>

              <p className="sub demo-accounts">
                Demo accounts: analyst@athenasec.com / admin@athenasec.com
              </p>
            </form>
          </div>
        </div>
      </div>
    </section>
  )
}

export default LoginPage
