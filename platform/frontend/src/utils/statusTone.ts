/*
  One place that decides which colour a status, severity, result
  or role gets, so the same word looks the same on every page.
  Each tone is a CSS class (.pill.ok, .donut.warn, .health-tag.danger,
  ...) backed by the --tone-* tokens in athenasec.css.

  Rules of thumb:
  - danger:  something is wrong or blocked (Critical, Failed)
  - warn:    needs someone's attention (High, Open, Degraded)
  - caution: medium severity, or coming up (Medium, Starting)
  - info:    in progress or already done by a response (Contained, Executing)
  - ok:      healthy or done (Closed, Completed, Running, Enabled)
  - neutral: inactive or lowest priority (Disabled, Low)
*/

export type StatusTone = 'ok' | 'warn' | 'caution' | 'danger' | 'info' | 'neutral'

const TONES: Record<string, StatusTone> = {
  // Severity (alerts, cases, health events)
  Critical: 'danger',
  High: 'warn',
  Medium: 'caution',
  Low: 'neutral',
  Warning: 'warn',
  Info: 'info',

  // Alert and case workflow
  Open: 'warn',
  Closed: 'ok',

  // Alert response state (alertResponseState in statusSummary.ts)
  'Awaiting approval': 'warn',
  'Containment failed': 'danger',
  'Source blocked': 'ok',
  Contained: 'info',

  // Outcomes
  Completed: 'ok',
  Success: 'ok',
  Created: 'ok',
  Validated: 'ok',
  Failed: 'danger',
  Denied: 'danger',

  // On / off
  Enabled: 'ok',
  Disabled: 'neutral',
  Active: 'ok',
  Suspended: 'danger',
  Connected: 'ok',
  Disconnected: 'danger',

  // Service states (serviceInventory.ts; "Failed" is above). Same colours as the Service Panel's own states.
  Running: 'ok',
  Starting: 'caution',
  Degraded: 'warn',
  Stopped: 'neutral',
  Unverified: 'neutral',

  // Resource gauges
  Good: 'ok',
  Watch: 'warn',

  // Approval requests and the executor's steps (Approvals page)
  Waiting: 'warn',
  Approved: 'ok',
  Executing: 'info',
  Done: 'ok',
  Rejected: 'danger',
  'Timed out': 'warn',
  'Not run': 'danger',
  Reversed: 'neutral',

  // ATT&CK activity on the admin dashboard ("Containment failed" and "Open" are above)
  'Waiting for approval': 'warn',
  Handled: 'ok',
  'Not seen': 'neutral',

  // What the policy guard says about an attempt (Demo mode, Response Policies)
  Allowed: 'ok',
  'Needs approval': 'warn',
  Refused: 'danger',

  // Where an action stands in the response policy ("Automatic" and "Needs approval" are above)
  Blacklisted: 'danger',
  'Not listed': 'neutral',

  // Response actions and approvals
  'Block IP': 'info',
  'Isolate Host': 'danger',
  'Lock Account': 'warn',
  'Capture Telemetry': 'neutral',
  Automatic: 'info',
  'Analyst Approved': 'warn',
  'Analyst Approval': 'warn',
  'Administrator Approval': 'danger',

  // Roles
  Administrator: 'warn',
  Analyst: 'info',
  System: 'neutral',

  // Top bar threat level ("Low" and "High" reuse the severity tones)
  Guarded: 'caution',
  Elevated: 'warn',
  Severe: 'danger',

  // Form save state (Configuration, Settings, Profile)
  Saved: 'ok',
  Draft: 'info',
  Error: 'danger',
}

// Risk scores (0-100) use the severity colours: lowest score for each tone.
const RISK_TONES: Array<[number, StatusTone]> = [
  [85, 'danger'],
  [60, 'warn'],
  [40, 'caution'],
]

export function statusTone(value: string | number): StatusTone {
  if (typeof value === 'number') {
    return RISK_TONES.find(([min]) => value >= min)?.[1] ?? 'neutral'
  }

  return TONES[value] ?? 'neutral'
}
