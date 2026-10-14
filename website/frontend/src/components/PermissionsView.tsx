import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

import {
  ACTION_CATALOGUE,
  APPROVER_LABELS,
  formatMinutes,
  POLICY_CAPS,
  tier2Actions,
  type CatalogueRow,
} from '../data/agentPolicyData'
import { limitProblems, listChanges, protectedTargetRefusal, type LimitField } from '../data/policyEngine'
import { useAdminState } from '../hooks/useAdminState'
import { useResponsePolicy } from '../hooks/useResponsePolicy'
import type { ApproverRole, Tier2ActionName } from '../types/policyTypes'
import type {
  ApprovalLimits,
  PolicyMode,
  ProtectedTarget,
  ResponsePolicy,
} from '../types/responsePoliciesTypes'

type TargetKind = 'block' | 'isolate'

type Errors = Record<string, string>

const MODES: PolicyMode[] = ['Automatic', 'Needs approval']

const TARGET_LISTS = {
  block: { key: 'neverBlock', title: 'Never block', field: 'Address or range', hint: 'An IP address or a range, such as 198.51.100.0/24' },
  isolate: { key: 'neverIsolate', title: 'Never isolate', field: 'Host name', hint: 'A host name, such as siem-02 (capitals do not matter)' },
} as const

const rowOf = (key: string) => ACTION_CATALOGUE.find((row) => row.key === key) as CatalogueRow

// The limits an action starts with when it is whitelisted: the PDF's own
function startingLimits(name: Tier2ActionName): ApprovalLimits {
  const spec = tier2Actions.find((action) => action.name === name)!

  return {
    defaultMinutes: spec.defaultMinutes,
    maxMinutes: spec.maxMinutes,
    approver: spec.approver,
    windowMinutes: spec.approvalWindowMinutes,
    minRisk: spec.floor.risk,
  }
}

const numberText = (value: number | undefined) => (typeof value === 'number' && Number.isFinite(value) ? String(value) : '')

// The signature as a name and its arguments, so the name can be set in monospace
const nameOf = (row: CatalogueRow) => row.action

/*
  One approval limit: a labelled control with the PDF's cap beside it and, after a Save
  that was refused, the reason. The cap and the reason are both tied to the control.
*/
type LimitFieldProps = {
  id: string
  label: string
  cap: string
  error?: string
  children: (describedBy: string) => ReactNode
}

function LimitControl({ id, label, cap, error, children }: LimitFieldProps) {
  const describedBy = error ? `${id}-cap ${id}-error` : `${id}-cap`

  return (
    <div className="perm-limit">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      {children(describedBy)}
      <p className="approval-hint" id={`${id}-cap`}>
        {cap}
      </p>
      {error && (
        <p className="approval-message perm-error" id={`${id}-error`} data-field="limitError">
          {error}
        </p>
      )}
    </div>
  )
}

// The three row icons (a sliders icon for the limits, a blocked circle for the blacklist, an X for remove), drawn at 18px
const ICONS = {
  limits: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M13 4v4M9 10v4M17 16v4',
  blacklist: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18zM5.6 5.6l12.8 12.8',
  remove: 'M6 6l12 12M18 6L6 18',
  lock: 'M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6z',
} as const

function Icon({ name }: { name: keyof typeof ICONS }) {
  return (
    <svg className="perm-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={ICONS[name]} />
    </svg>
  )
}

type IconButtonProps = {
  icon: 'limits' | 'blacklist' | 'remove'
  // The full accessible name ("Move block_ip to the blacklist") and the short tooltip ("Move to blacklist")
  label: string
  tip: string
  onClick: () => void
  expanded?: boolean
  controls?: string
}

/*
  An icon-only button at the 40px minimum: it has its full name for assistive technology and a visible
  tooltip on hover and on keyboard focus (data-tip, drawn by the stylesheet).
*/
function IconButton({ icon, label, tip, onClick, expanded, controls }: IconButtonProps) {
  return (
    <button
      className={`btn small icon-only${icon === 'remove' ? ' ghost' : ''}`}
      type="button"
      aria-label={label}
      data-tip={tip}
      aria-expanded={expanded}
      aria-controls={controls}
      onClick={onClick}
    >
      <Icon name={icon} />
    </button>
  )
}

/*
  Response Policies, "Permissions" tab: which catalogue actions the agent may use
  (whitelist, Automatic or Needs approval), which it may never use (blacklist),
  the actions on neither list (denied), and the protected targets. Edits are held
  in a draft; Save checks every limit against the PDF's caps and writes one audit
  event with each change old → new, Discard puts the saved policy back.
*/
function PermissionsView({ actionsSlot }: { actionsSlot: HTMLElement | null }) {
  const { responsePolicy, saveResponsePolicy, auditLogs } = useAdminState()

  // The draft lives above the routes (ResponsePolicyProvider), so it survives a change of tab or page;
  // with nothing edited the screen shows the saved policy
  const { draft: storedDraft, editDraft, discardDraft } = useResponsePolicy()
  const draft: ResponsePolicy = storedDraft ?? responsePolicy

  const [open, setOpen] = useState<string[]>([])
  const [errors, setErrors] = useState<Errors>({})
  const [message, setMessage] = useState('')
  const [adding, setAdding] = useState<TargetKind | null>(null)
  const [addValue, setAddValue] = useState('')
  const [addError, setAddError] = useState('')
  const statusId = useId()

  const changes = listChanges(responsePolicy, draft)
  const dirty = changes.length

  const tier = (key: string) => rowOf(key).tier
  const whitelisted = new Set(draft.whitelist.map((entry) => entry.action))
  const blacklisted = new Set(draft.blacklist.map((entry) => entry.action))
  const unlisted = ACTION_CATALOGUE.filter((row) => row.tier !== 3 && !whitelisted.has(row.key) && !blacklisted.has(row.key))

  // "Whitelisted, needs approval" counts the entries that need approval (Tier 2 only: Tier 1 stays Automatic for now)
  const automaticCount = draft.whitelist.filter((entry) => entry.mode === 'Automatic').length
  const approvalCount = draft.whitelist.length - automaticCount

  function edit(change: (next: ResponsePolicy) => void) {
    editDraft(change)
    setMessage('')
  }

  function setMode(action: string, mode: PolicyMode) {
    edit((next) => {
      const entry = next.whitelist.find((item) => item.action === action)

      if (entry) {
        entry.mode = mode
      }
    })
  }

  function setLimit(action: string, field: LimitField, value: number | ApproverRole) {
    setErrors((current) => {
      const rest = { ...current }

      delete rest[`${action}.${field}`]

      return rest
    })
    edit((next) => {
      const limits = next.whitelist.find((item) => item.action === action)?.limits

      if (limits) {
        Object.assign(limits, { [field]: value })
      }
    })
  }

  function whitelist(action: string) {
    edit((next) => {
      next.whitelist.push(
        tier(action) === 2
          ? { action, mode: 'Needs approval', limits: startingLimits(action as Tier2ActionName) }
          : { action, mode: 'Automatic' },
      )
    })
  }

  function blacklist(action: string) {
    edit((next) => {
      next.whitelist = next.whitelist.filter((item) => item.action !== action)
      next.blacklist.push({ action, required: false })
    })
  }

  function removeFromWhitelist(action: string) {
    edit((next) => {
      next.whitelist = next.whitelist.filter((item) => item.action !== action)
    })
  }

  function removeFromBlacklist(action: string) {
    edit((next) => {
      next.blacklist = next.blacklist.filter((item) => item.action !== action)
    })
  }

  function removeTarget(kind: TargetKind, value: string) {
    edit((next) => {
      const key = TARGET_LISTS[kind].key

      next[key] = next[key].filter((target) => target.value !== value)
    })
  }

  function startAdding(kind: TargetKind) {
    setAdding(adding === kind ? null : kind)
    setAddValue('')
    setAddError('')
  }

  function submitTarget(event: FormEvent<HTMLFormElement>, kind: TargetKind) {
    event.preventDefault()

    const list = draft[TARGET_LISTS[kind].key]
    const problem = protectedTargetRefusal(kind, addValue, list)

    if (problem) {
      setAddError(problem)
      return
    }

    const value = addValue.trim()

    edit((next) => {
      next[TARGET_LISTS[kind].key].push({ value, label: 'Added by an administrator', required: false })
    })
    setAdding(null)
    setAddValue('')
    setAddError('')
  }

  function discard() {
    discardDraft()
    setErrors({})
    setMessage('')
    setAdding(null)
    setAddError('')
  }

  function save() {
    const found: Errors = {}

    for (const entry of draft.whitelist) {
      if (entry.limits) {
        for (const [field, text] of Object.entries(limitProblems(entry.action as Tier2ActionName, entry.limits))) {
          found[`${entry.action}.${field}`] = text
        }
      }
    }

    setErrors(found)

    if (Object.keys(found).length > 0) {
      // Show the limits that were refused
      setOpen((current) => [...new Set([...current, ...Object.keys(found).map((key) => key.split('.')[0])])])
      setMessage(`Not saved: ${Object.keys(found).length === 1 ? 'a limit is' : `${Object.keys(found).length} limits are`} past what the Agent Action Policy allows.`)
      return
    }

    const refusal = saveResponsePolicy(draft)

    if (refusal) {
      setMessage(`Not saved: ${refusal}`)
      return
    }

    setMessage(dirty > 0 ? 'Saved. The change is in the audit log.' : 'Nothing to save.')
  }

  const history = auditLogs.filter((log) => log.category === 'Response Policy')

  // The unsaved line, Discard and Save are drawn beside the page title (the page's slot), not in this view
  const bar = (
    <>
      <span className="perm-version" data-field="version">
        Version {responsePolicy.version}
      </span>
      <p className="perm-unsaved" role="status" id={statusId} data-field="unsaved">
        {dirty === 0 ? 'No unsaved changes' : `${dirty} unsaved ${dirty === 1 ? 'change' : 'changes'}`}
      </p>
      <button className="btn" type="button" onClick={discard} disabled={dirty === 0 && Object.keys(errors).length === 0}>
        Discard
      </button>
      <button className="btn primary" type="button" onClick={save} disabled={dirty === 0} aria-describedby={statusId}>
        Save changes
      </button>
    </>
  )

  return (
    <div className="perm" data-view="permissions">
      {actionsSlot && createPortal(bar, actionsSlot)}

      {message && (
        <div className="notice" role="status" data-field="policyMessage">
          {message}
        </div>
      )}

      <section className="response-summary perm-summary" aria-label="Policy summary" data-record-id="response-policy">
        <div className="perm-tone-info">
          <span>Whitelisted, runs automatically</span>
          <strong data-field="automaticCount">{automaticCount}</strong>
        </div>
        <div className="perm-tone-caution">
          <span>Whitelisted, needs approval</span>
          <strong data-field="approvalCount">{approvalCount}</strong>
        </div>
        <div className="attention">
          <span>Blacklisted</span>
          <strong data-field="blacklistCount">{draft.blacklist.length}</strong>
        </div>
        <div className="perm-tone-neutral">
          <span>Anything not listed</span>
          <strong className="perm-denied" data-field="unlisted">
            <Icon name="lock" />
            Denied
          </strong>
        </div>
      </section>

      <div className="perm-lists">
        <section className="card perm-card" aria-labelledby="whitelistTitle" data-list="whitelist">
          <div className="perm-card-head">
            <h2 id="whitelistTitle">Whitelist</h2>
            <span className="pill info">Agent may use</span>
          </div>
          <p className="sub">
            For each action, choose whether the agent can run it on its own or must get a person&rsquo;s approval first.
            Needs approval: available later for Tier 1 actions.
          </p>

          <ul className="perm-rows">
            {draft.whitelist.map((entry) => {
              const row = rowOf(entry.action)
              const tier2 = row.tier === 2
              const expanded = open.includes(entry.action)
              const limits = entry.limits
              const name = entry.action as Tier2ActionName
              const cap = tier2 ? POLICY_CAPS[name] : undefined
              const fieldId = (field: LimitField) => `limit-${entry.action}-${field}`
              const fieldError = (field: LimitField) => errors[`${entry.action}.${field}`]

              return (
                <li key={entry.action} data-record-id={entry.action} data-action={entry.action} data-mode={entry.mode}>
                  <div className="perm-row">
                    <div className="perm-name">
                      <span className="mono">{nameOf(row)}</span>
                      <span className="catalogue-does">{row.does}</span>
                    </div>

                    <div className="segmented" role="group" aria-label={`${entry.action}: how it runs`}>
                      {MODES.map((mode) => {
                        const locked = tier2 ? mode === 'Automatic' : mode === 'Needs approval'
                        const reason = tier2
                          ? 'Automatic: a Tier 2 action always needs a person to approve it'
                          : 'Needs approval: available later'

                        return (
                          <button
                            key={mode}
                            type="button"
                            className="segmented-option"
                            data-mode={mode}
                            aria-pressed={entry.mode === mode}
                            disabled={locked}
                            title={locked ? reason : undefined}
                            aria-label={locked ? reason : undefined}
                            onClick={() => setMode(entry.action, mode)}
                          >
                            {mode}
                          </button>
                        )
                      })}
                    </div>

                    <div className="perm-buttons">
                      {tier2 && (
                        <IconButton
                          icon="limits"
                          label={`Approval limits for ${entry.action}`}
                          tip="Approval limits"
                          expanded={expanded}
                          controls={`limits-${entry.action}`}
                          onClick={() =>
                            setOpen((current) =>
                              current.includes(entry.action) ? current.filter((item) => item !== entry.action) : [...current, entry.action],
                            )
                          }
                        />
                      )}
                      <IconButton icon="blacklist" label={`Move ${entry.action} to the blacklist`} tip="Move to blacklist" onClick={() => blacklist(entry.action)} />
                      <IconButton icon="remove" label={`Remove ${entry.action} from the whitelist`} tip="Remove from whitelist" onClick={() => removeFromWhitelist(entry.action)} />
                    </div>
                  </div>

                  {tier2 && limits && cap && expanded && (
                    <div className="perm-limits" id={`limits-${entry.action}`} role="group" aria-label={`Approval limits for ${entry.action}`}>
                      <p className="perm-limits-title">Approval limits</p>
                      <div className="perm-limit-grid">
                        {cap.maxMinutes !== undefined && (
                          <>
                            <LimitControl id={fieldId('defaultMinutes')} label="Default duration (minutes)" cap="At most the longest allowed" error={fieldError('defaultMinutes')}>
                              {(describedBy) => (
                                <input
                                  className="field-input"
                                  id={fieldId('defaultMinutes')}
                                  name={fieldId('defaultMinutes')}
                                  autoComplete="off"
                                  type="number"
                                  min="1"
                                  value={numberText(limits.defaultMinutes)}
                                  aria-invalid={fieldError('defaultMinutes') ? true : undefined}
                                  aria-describedby={describedBy}
                                  onChange={(event) => setLimit(entry.action, 'defaultMinutes', event.target.value === '' ? Number.NaN : Number(event.target.value))}
                                />
                              )}
                            </LimitControl>

                            <LimitControl id={fieldId('maxMinutes')} label="Longest allowed (minutes)" cap={`At most ${formatMinutes(cap.maxMinutes)}`} error={fieldError('maxMinutes')}>
                              {(describedBy) => (
                                <input
                                  className="field-input"
                                  id={fieldId('maxMinutes')}
                                  name={fieldId('maxMinutes')}
                                  autoComplete="off"
                                  type="number"
                                  min="1"
                                  value={numberText(limits.maxMinutes)}
                                  aria-invalid={fieldError('maxMinutes') ? true : undefined}
                                  aria-describedby={describedBy}
                                  onChange={(event) => setLimit(entry.action, 'maxMinutes', event.target.value === '' ? Number.NaN : Number(event.target.value))}
                                />
                              )}
                            </LimitControl>
                          </>
                        )}

                        <LimitControl id={fieldId('approver')} label="Who approves" cap={`${APPROVER_LABELS[cap.approver]} or higher`} error={fieldError('approver')}>
                          {(describedBy) => (
                            <select
                              className="select-input"
                              id={fieldId('approver')}
                              name={fieldId('approver')}
                              autoComplete="off"
                              value={limits.approver}
                              aria-invalid={fieldError('approver') ? true : undefined}
                              aria-describedby={describedBy}
                              onChange={(event) => setLimit(entry.action, 'approver', event.target.value as ApproverRole)}
                            >
                              <option value="soc_analyst">{APPROVER_LABELS.soc_analyst}</option>
                              <option value="soc_lead">{APPROVER_LABELS.soc_lead}</option>
                            </select>
                          )}
                        </LimitControl>

                        <LimitControl id={fieldId('windowMinutes')} label="Time to decide (minutes)" cap={`At most ${cap.windowMinutes} min`} error={fieldError('windowMinutes')}>
                          {(describedBy) => (
                            <input
                              className="field-input"
                              id={fieldId('windowMinutes')}
                              name={fieldId('windowMinutes')}
                              autoComplete="off"
                              type="number"
                              min="1"
                              value={numberText(limits.windowMinutes)}
                              aria-invalid={fieldError('windowMinutes') ? true : undefined}
                              aria-describedby={describedBy}
                              onChange={(event) => setLimit(entry.action, 'windowMinutes', event.target.value === '' ? Number.NaN : Number(event.target.value))}
                            />
                          )}
                        </LimitControl>

                        <LimitControl id={fieldId('minRisk')} label="Minimum risk" cap={`At least ${cap.minRisk}`} error={fieldError('minRisk')}>
                          {(describedBy) => (
                            <input
                              className="field-input"
                              id={fieldId('minRisk')}
                              name={fieldId('minRisk')}
                              autoComplete="off"
                              type="number"
                              min="0"
                              max="100"
                              value={numberText(limits.minRisk)}
                              aria-invalid={fieldError('minRisk') ? true : undefined}
                              aria-describedby={describedBy}
                              onChange={(event) => setLimit(entry.action, 'minRisk', event.target.value === '' ? Number.NaN : Number(event.target.value))}
                            />
                          )}
                        </LimitControl>
                      </div>
                      <p className="approval-hint">{tier2Note(name)}</p>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        </section>

        <section className="card perm-card perm-black" aria-labelledby="blacklistTitle" data-list="blacklist">
          <div className="perm-card-head">
            <h2 id="blacklistTitle">Blacklist</h2>
            <span className="pill danger">Agent may never use</span>
          </div>
          <p className="sub">
            These are blocked, not performed. The agent has no tool for them, and any attempt is stopped, logged and reported.
          </p>

          <ul className="perm-rows">
            {draft.blacklist.map((entry) => {
              const row = rowOf(entry.action)

              return (
                <li key={entry.action} data-record-id={entry.action} data-action={entry.action} data-required={entry.required}>
                  <div className="perm-row">
                    <div className="perm-name">
                      <span className={row.tier === 3 ? 'perm-prohibited' : 'mono'}>{nameOf(row)}</span>
                      <span className="catalogue-does">{row.tier === 3 ? row.why : row.does}</span>
                    </div>

                    {entry.required ? (
                      <span className="perm-required" data-field="required">
                        Required
                      </span>
                    ) : (
                      <IconButton icon="remove" label={`Remove ${entry.action} from the blacklist`} tip="Remove from blacklist" onClick={() => removeFromBlacklist(entry.action)} />
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
          <p className="approval-hint">Required entries come from the security policy and cannot be removed from this page.</p>
        </section>
      </div>

      <section className="card perm-card" aria-labelledby="unlistedTitle" data-list="unlisted">
        <div className="perm-card-head">
          <h2 id="unlistedTitle">Not on either list</h2>
          <span className="pill neutral">Denied</span>
        </div>
        <p className="sub">The agent cannot use these until you whitelist them. Whitelisting only makes an action available.</p>

        {unlisted.length === 0 ? (
          <p className="approval-hint" data-field="noUnlisted">
            Every action is on a list.
          </p>
        ) : (
          <ul className="perm-rows perm-unlisted">
            {unlisted.map((row) => (
              <li key={row.key} data-record-id={row.key} data-action={row.key}>
                <div className="perm-row">
                  <div className="perm-name">
                    <span className="mono">{nameOf(row)}</span>
                    <span className="catalogue-does">{row.does}</span>
                  </div>
                  <div className="perm-buttons">
                    <button className="btn small" type="button" aria-label={`Whitelist ${row.key}`} onClick={() => whitelist(row.key)}>
                      Whitelist
                    </button>
                    <button className="btn small danger" type="button" aria-label={`Blacklist ${row.key}`} onClick={() => blacklist(row.key)}>
                      Blacklist
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="perm-lower">
        <section className="card perm-card" aria-labelledby="protectedTitle" data-list="protected">
          <h2 id="protectedTitle">Protected targets</h2>
          <p className="sub">Even a whitelisted action can never be used against these.</p>

          <div className="perm-targets">
            {(['block', 'isolate'] as const).map((kind) => {
              const spec = TARGET_LISTS[kind]
              const list: ProtectedTarget[] = draft[spec.key]
              const formId = `add-${kind}`

              return (
                <div key={kind} data-targets={kind}>
                  <div className="perm-targets-head">
                    <h3 className="perm-targets-title">{spec.title}</h3>
                    <button className="btn small" type="button" aria-expanded={adding === kind} aria-controls={formId} onClick={() => startAdding(kind)}>
                      + Add<span className="visually-hidden"> to {spec.title}</span>
                    </button>
                  </div>

                  {adding === kind && (
                    <form className="perm-add" id={formId} onSubmit={(event) => submitTarget(event, kind)} noValidate>
                      <label className="form-label" htmlFor={`${formId}-value`}>
                        {spec.field}
                      </label>
                      <input
                        className="field-input mono"
                        id={`${formId}-value`}
                        name={`${formId}-value`}
                        value={addValue}
                        onChange={(event) => setAddValue(event.target.value)}
                        autoComplete="off"
                        spellCheck={false}
                        aria-invalid={addError ? true : undefined}
                        aria-describedby={`${formId}-hint${addError ? ` ${formId}-error` : ''}`}
                      />
                      <p className="approval-hint" id={`${formId}-hint`}>
                        {spec.hint}
                      </p>
                      {addError && (
                        <p className="approval-message perm-error" id={`${formId}-error`} role="alert" data-field="addError">
                          {addError}
                        </p>
                      )}
                      <div className="perm-buttons">
                        <button className="btn small primary" type="submit">
                          Add
                        </button>
                        <button className="btn small ghost" type="button" onClick={() => startAdding(kind)}>
                          Cancel
                        </button>
                      </div>
                    </form>
                  )}

                  <ul className="perm-rows perm-target-list">
                    {list.map((target) => (
                      <li key={target.value} data-record-id={target.value} data-target={target.value} data-required={target.required}>
                        <div className="perm-row">
                          <span className="mono perm-target-value">{target.value}</span>
                          <span className="catalogue-does perm-target-label">{target.label}</span>
                          {target.required ? (
                            <span className="perm-required" data-field="required">
                              Required
                            </span>
                          ) : (
                            <IconButton icon="remove" label={`Remove ${target.value} from ${spec.title}`} tip={`Remove from ${spec.title}`} onClick={() => removeTarget(kind, target.value)} />
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )
            })}
          </div>
        </section>

        <section className="card perm-card" aria-labelledby="historyTitle" data-list="history">
          <h2 id="historyTitle">Change history</h2>
          {history.length === 0 ? (
            <p className="approval-hint">No changes yet.</p>
          ) : (
            <ul className="perm-history">
              {history.map((log) => (
                <li key={log.id} data-record-id={log.id} data-event={log.id}>
                  <span className="mono perm-time">{log.timestamp.slice(0, 16)}</span>
                  <span>
                    {log.changes[0] ?? log.action}
                    {log.changes.length > 1 ? ` (+${log.changes.length - 1} more)` : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  )
}

// What an action's limits mean, under its limits box
function tier2Note(name: Tier2ActionName) {
  const notes: Partial<Record<Tier2ActionName, string>> = {
    block_ip: 'External IPs only. Never anything under Protected targets. Removed automatically at expiry.',
    isolate_host: 'Never a Critical host or anything under Protected targets. Reconnects automatically at expiry.',
    suspend_user_session: 'Non-privileged accounts only. Expires automatically.',
  }

  return notes[name] ?? 'Does not reverse on its own, so it has no duration. A person undoes it.'
}

export default PermissionsView
