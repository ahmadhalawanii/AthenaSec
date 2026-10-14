import { useState } from 'react'

import BrandMark from '../components/BrandMark'
import { ROLE_LABELS } from '../data/appData'
import {
  DEMO_ACCOUNTS,
  LOGIN_STATS,
  RADAR_BLIPS,
  RADAR_LABEL,
} from '../data/loginData'
import type { DemoAccount } from '../types/appTypes'
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

  function fillDemoAccount(account: DemoAccount) {
    setEmail(account.email)
    setPassword(account.password)
    setError('')
  }

  return (
    /*
      DOM order is the reading order at every width: brand panel, then
      the sign-in panel. Phones stack them the same way (the brand
      panel shrinks to a strip), so nothing is reordered with CSS.
    */
    <div className="auth-split login-split" id="loginView">
      <section className="auth-brand" aria-label="AthenaSec">
        <div className="auth-logo">
          <BrandMark size={36} />
          <span className="auth-wordmark">AthenaSec</span>
        </div>

        <div className="login-hero">
          <svg
            className="radar"
            width="400"
            height="400"
            viewBox="0 0 400 400"
            role="img"
            aria-label={RADAR_LABEL}
          >
            <defs>
              <radialGradient id="radarGlow" cx="0.5" cy="0.5" r="0.5">
                <stop offset="0" stopColor="#3A0F17" />
                <stop offset="1" stopColor="#120607" stopOpacity="0" />
              </radialGradient>
              <linearGradient id="radarWedge" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0" stopColor="#E8344C" stopOpacity="0" />
                <stop offset="1" stopColor="#E8344C" stopOpacity="0.45" />
              </linearGradient>
            </defs>
            <circle cx="200" cy="200" r="190" fill="url(#radarGlow)" />
            <circle className="radar-ring outer" cx="200" cy="200" r="180" />
            <circle className="radar-ring" cx="200" cy="200" r="130" />
            <circle className="radar-ring" cx="200" cy="200" r="80" />
            <circle className="radar-ring" cx="200" cy="200" r="30" />
            <path className="radar-axes" d="M200 20v360M20 200h360" />
            <g className="radar-sweep">
              <path
                d="M200 200 L380 200 A180 180 0 0 0 327 73 Z"
                fill="url(#radarWedge)"
              />
              <line className="radar-beam" x1="200" y1="200" x2="380" y2="200" />
            </g>
            {RADAR_BLIPS.map((blip) => (
              <g key={blip.id}>
                <circle
                  className={`radar-blip ${blip.tone}`}
                  cx={blip.x}
                  cy={blip.y}
                  r="4"
                />
                {blip.open && (
                  <circle
                    className={`radar-ping ${blip.tone}`}
                    cx={blip.x}
                    cy={blip.y}
                    r="4"
                  />
                )}
              </g>
            ))}
            <circle className="radar-centre" cx="200" cy="200" r="5" />
          </svg>

          <div className="login-pitch">
            <h1>
              <span>Detect.</span> <span>Decide.</span>{' '}
              <span className="accent">Contain.</span>
            </h1>
            <p>
              Security monitoring and automated incident response for the
              SOC, with an analyst in control of every decision that
              matters.
            </p>
          </div>
        </div>

        {/* Value then caption, in the order they appear on screen */}
        <ul className="login-stats" aria-label="AthenaSec today">
          {LOGIN_STATS.map((stat) => (
            <li key={stat.label}>
              <strong>{stat.value}</strong>
              <span>{stat.label}</span>
            </li>
          ))}
        </ul>
      </section>

      <main className="auth-panel" aria-labelledby="loginTitle">
        <div className="auth-panel-inner">
          <h2 className="auth-title" id="loginTitle">
            Sign in to the SOC console
          </h2>
          <p className="auth-lead">
            Two-factor authentication is required for every account.
          </p>

          <form className="auth-form" id="loginForm" onSubmit={handleSubmit}>
            {error && (
              <p className="auth-error" id="loginError" role="alert">
                {error}
              </p>
            )}

            <div className="auth-field">
              <label className="auth-label" htmlFor="loginEmail">
                Work email
              </label>
              <input
                className="auth-input"
                id="loginEmail"
                name="email"
                type="email"
                placeholder="name@company.com…"
                value={email}
                onChange={(event) => {
                  setEmail(event.target.value)
                  setError('')
                }}
                autoComplete="username"
                spellCheck={false}
                required
              />
            </div>

            <div className="auth-field">
              <label className="auth-label" htmlFor="loginPassword">
                Password
              </label>
              <input
                className="auth-input"
                id="loginPassword"
                name="password"
                type="password"
                placeholder="Enter your password…"
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value)
                  setError('')
                }}
                autoComplete="current-password"
                required
              />
            </div>

            <div className="login-options">
              <label className="check-row">
                <input type="checkbox" id="rememberMe" name="rememberMe" />
                Keep me signed in
              </label>

              <button
                className="text-button forgot-password"
                type="button"
                data-action="forgot-password"
              >
                Forgot password?
              </button>
            </div>

            <button className="btn primary auth-submit login-submit" type="submit">
              Continue
            </button>
          </form>

          <section className="demo-panel" aria-labelledby="demoModeTitle">
            <div className="demo-head">
              <h3 className="demo-badge" id="demoModeTitle">
                Demo mode
              </h3>
              <span>Pick an account to fill the form</span>
            </div>

            <div className="demo-accounts">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.email}
                  type="button"
                  className="demo-account"
                  aria-pressed={
                    email === account.email && password === account.password
                  }
                  onClick={() => fillDemoAccount(account)}
                >
                  <span className="demo-role">{ROLE_LABELS[account.role]}</span>
                  <span className="demo-email">{account.email}</span>
                </button>
              ))}
            </div>

            <p className="demo-note">
              Demo accounts use sample data. Remove this panel before a
              public release.
            </p>
          </section>
        </div>
      </main>
    </div>
  )
}

export default LoginPage
