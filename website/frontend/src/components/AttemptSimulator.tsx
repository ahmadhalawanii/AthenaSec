import { useState, type FormEvent } from 'react'

import { ATTEMPT_LABELS } from '../data/approvalFlow'
import { ACTION_CATALOGUE, formatMinutes, type CatalogueRow } from '../data/agentPolicyData'
import { useResponseState } from '../hooks/useResponseState'
import type { AssetClass, AttemptDecision, AttemptRequest } from '../types/policyTypes'
import { statusTone } from '../utils/statusTone'

const OTHER = '__other__'

// What a Tier 2 action needs as its target, and a sensible starting value
const TARGETS: Record<string, { label: string; param: string; start: string }> = {
  block_ip: { label: 'IP address', param: 'ip', start: '203.0.113.45' },
  isolate_host: { label: 'Host', param: 'host', start: 'endpoint-09' },
  suspend_user_session: { label: 'User account', param: 'user', start: 'j.smith' },
  kill_process: { label: 'Host', param: 'host', start: 'endpoint-09' },
  quarantine_file: { label: 'Host', param: 'host', start: 'endpoint-09' },
  reset_password: { label: 'User account', param: 'user', start: 'j.smith' },
}

const ASSET_CLASSES: AssetClass[] = ['Critical', 'Business', 'Standard']

const TIER_GROUPS: Record<number, string> = {
  1: 'Tier 1: runs automatically',
  2: 'Tier 2: needs approval',
  3: 'Tier 3: never allowed',
}

type Shown = { request: AttemptRequest; decision: AttemptDecision }

const rowOf = (key: string) => ACTION_CATALOGUE.find((row) => row.key === key)

function optionLabel(row: CatalogueRow) {
  return row.tier === 3 ? `${row.action} (${row.key})` : row.action
}

/*
  Demo mode: ask the policy guard what it would do if the agent tried an
  action. The answer is the guard's own (the same checks run for a real
  request), with the rule it came from. Nothing runs, no request or token
  is touched, and the attempt is written to the audit log as a Demo event.
*/
function AttemptSimulator() {
  const { simulateAttempt } = useResponseState()

  const [action, setAction] = useState('block_ip')
  const [otherName, setOtherName] = useState('format_disk')
  const [target, setTarget] = useState(TARGETS.block_ip.start)
  const [duration, setDuration] = useState(String(rowOf('block_ip')?.defaultMinutes ?? 30))
  const [risk, setRisk] = useState('90')
  const [confidence, setConfidence] = useState('0.90')
  const [assetClass, setAssetClass] = useState<AssetClass>('Business')
  const [privileged, setPrivileged] = useState(false)
  const [error, setError] = useState('')
  const [shown, setShown] = useState<Shown | null>(null)

  const row = action === OTHER ? undefined : rowOf(action)
  const tier2 = row?.tier === 2
  // The assumption actions have no duration
  const hasDuration = tier2 && row?.maxMinutes !== undefined
  const targetSpec = TARGETS[action]

  function chooseAction(next: string) {
    setAction(next)
    setError('')

    const spec = TARGETS[next]

    if (spec) {
      setTarget(spec.start)
      setDuration(String(rowOf(next)?.defaultMinutes ?? 30))
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const name = action === OTHER ? otherName.trim() : action
    const riskScore = Number(risk)
    const confidenceValue = Number(confidence)
    const minutes = Number(duration)

    if (!name) {
      setError('Enter the name of the function to try.')
      return
    }

    if (risk.trim() === '' || Number.isNaN(riskScore) || riskScore < 0 || riskScore > 100) {
      setError('Risk must be a number from 0 to 100.')
      return
    }

    if (confidence.trim() === '' || Number.isNaN(confidenceValue) || confidenceValue < 0 || confidenceValue > 1) {
      setError('Confidence must be a number from 0 to 1.')
      return
    }

    if (hasDuration && (!Number.isInteger(minutes) || minutes < 1)) {
      setError('Duration must be a whole number of minutes, 1 or more.')
      return
    }

    if (targetSpec && !target.trim()) {
      setError(`Enter the ${targetSpec.label.toLowerCase()} to try.`)
      return
    }

    const params: AttemptRequest['params'] = {}

    if (targetSpec) {
      params[targetSpec.param] = target.trim()

      if (name === 'isolate_host') {
        params.path = 'edr_network_isolation'
      }
    } else if (target.trim()) {
      params.target = target.trim()
    }

    if (hasDuration) {
      params.duration_min = minutes
    }

    const request: AttemptRequest = {
      actionName: name,
      params,
      riskScore,
      confidence: confidenceValue,
      assetClass,
      privilegedAccount: privileged,
    }

    const outcome = simulateAttempt(request)

    if (!outcome.ok) {
      setError(outcome.reason)
      return
    }

    setError('')
    setShown({ request, decision: outcome.decision })
  }

  const decision = shown?.decision

  return (
    <section className="demo-panel attempt-demo" aria-labelledby="attemptDemoTitle" data-demo-panel data-attempt-panel>
      <div className="demo-head">
        <h2 className="demo-badge" id="attemptDemoTitle">
          Demo mode
        </h2>
        <span>
          Simulate an attempt: pick an action and a target and see what the policy guard would do. Nothing is executed, and
          each attempt is written to the audit log as a Demo event.
        </span>
      </div>

      <form className="attempt-form" onSubmit={submit} noValidate>
        <div className="attempt-grid">
          <div>
            <label className="form-label" htmlFor="attemptAction">
              Action
            </label>
            <select
              className="select-input"
              id="attemptAction"
              name="attemptAction"
              autoComplete="off"
              value={action}
              onChange={(event) => chooseAction(event.target.value)}
            >
              {[1, 2, 3].map((tier) => (
                <optgroup key={tier} label={TIER_GROUPS[tier]}>
                  {ACTION_CATALOGUE.filter((item) => item.tier === tier).map((item) => (
                    <option key={item.key} value={item.key}>
                      {optionLabel(item)}
                    </option>
                  ))}
                </optgroup>
              ))}
              <option value={OTHER}>Not in the catalogue</option>
            </select>
          </div>

          {action === OTHER && (
            <div>
              <label className="form-label" htmlFor="attemptName">
                Function name
              </label>
              <input
                className="field-input mono"
                id="attemptName"
                name="attemptName"
                value={otherName}
                onChange={(event) => setOtherName(event.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          )}

          <div>
            <label className="form-label" htmlFor="attemptTarget">
              {targetSpec ? targetSpec.label : 'Target (optional)'}
            </label>
            <input
              className="field-input mono"
              id="attemptTarget"
              name="attemptTarget"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          {hasDuration && (
            <div>
              <label className="form-label" htmlFor="attemptDuration">
                Duration (minutes)
              </label>
              <input
                className="field-input"
                id="attemptDuration"
                name="attemptDuration"
                autoComplete="off"
                type="number"
                min="1"
                value={duration}
                onChange={(event) => setDuration(event.target.value)}
                aria-describedby="attemptDurationHint"
              />
              <p className="approval-hint" id="attemptDurationHint">
                Default {formatMinutes(row?.defaultMinutes ?? 0)}, maximum {formatMinutes(row?.maxMinutes ?? 0)}.
              </p>
            </div>
          )}
        </div>

        <fieldset className="attempt-context">
          <legend>What the alert looks like (used by the checks that need them)</legend>
          <div className="attempt-grid">
            <div>
              <label className="form-label" htmlFor="attemptRisk">
                Risk (0 to 100)
              </label>
              <input
                className="field-input"
                id="attemptRisk"
                name="attemptRisk"
                autoComplete="off"
                type="number"
                min="0"
                max="100"
                value={risk}
                onChange={(event) => setRisk(event.target.value)}
              />
            </div>

            <div>
              <label className="form-label" htmlFor="attemptConfidence">
                Confidence (0 to 1)
              </label>
              <input
                className="field-input"
                id="attemptConfidence"
                name="attemptConfidence"
                autoComplete="off"
                type="number"
                min="0"
                max="1"
                step="0.01"
                value={confidence}
                onChange={(event) => setConfidence(event.target.value)}
              />
            </div>

            <div>
              <label className="form-label" htmlFor="attemptAsset">
                Asset class
              </label>
              <select
                className="select-input"
                id="attemptAsset"
                name="attemptAsset"
                autoComplete="off"
                value={assetClass}
                onChange={(event) => setAssetClass(event.target.value as AssetClass)}
              >
                {ASSET_CLASSES.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
            </div>

            <label className="approval-choice attempt-check" htmlFor="attemptPrivileged">
              <input
                id="attemptPrivileged"
                name="attemptPrivileged"
                type="checkbox"
                checked={privileged}
                onChange={(event) => setPrivileged(event.target.checked)}
              />
              The account is privileged
            </label>
          </div>
        </fieldset>

        {error && (
          <p className="approval-message attempt-error" role="alert" data-field="attemptError">
            {error}
          </p>
        )}

        <div className="attempt-actions">
          <button className="btn primary small" type="submit">
            Simulate attempt
          </button>
        </div>
      </form>

      <div className="attempt-result" role="status" data-field="attemptResult" data-decision={decision?.decision ?? 'none'}>
        {shown && decision && (
          <>
            <p className="attempt-verdict">
              <span className={`pill ${statusTone(ATTEMPT_LABELS[decision.decision])}`} data-field="attemptDecision">
                {ATTEMPT_LABELS[decision.decision]}
              </span>{' '}
              <span className="mono">{shown.request.actionName}</span>
            </p>
            <p data-field="attemptReason">{decision.reason}</p>
            <p className="approval-hint" data-field="attemptRule">
              Rule: {decision.rule}
            </p>
            <p className="attempt-nothing" data-field="attemptExecuted">
              Nothing was executed.
            </p>
          </>
        )}
      </div>
    </section>
  )
}

export default AttemptSimulator
