import { useState } from 'react'

import type { AuditLinks } from '../data/auditChain'
import { AUDIT_EVENT_TYPE_NAMES } from '../data/auditEventTypes'
import type { AuditIntegrity, AuditLogRecord, AuditRecordFields } from '../types/auditLogsTypes'

type AuditRecordDetailsProps = {
  log: AuditLogRecord
  links: AuditLinks
  integrity: AuditIntegrity | null
}

const GENESIS = '0'.repeat(64)

// A hash in full, with a Copy button; it says what happened, since the clipboard may be blocked
function HashValue({ label, value }: { label: string; value: string }) {
  const [message, setMessage] = useState('')

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setMessage('Copied')
    } catch {
      setMessage('Select the text to copy it')
    }
  }

  return (
    <dd className="audit-hash-cell">
      <span className="mono audit-hash" data-field={label === 'Hash' ? 'hash' : 'prevHash'}>
        {value}
      </span>
      <button className="btn small" type="button" onClick={copy} aria-label={`Copy ${label.toLowerCase()}`}>
        Copy
      </button>
      <span className="approval-hint" role="status" data-field="copyMessage">
        {message}
      </span>
    </dd>
  )
}

// The PDF's page 9 field names, in its order, with the value this record has (if any)
function recordRows(record: AuditRecordFields): Array<[string, string | string[]]> {
  const rows: Array<[string, string | string[] | undefined]> = [
    ['recommendation_id', record.recommendation_id],
    ['alert_id', record.alert_id],
    ['policy_id', record.policy_id],
    ['actor', record.actor],
    ['actor_role', record.actor_role],
    ['tier', record.tier === undefined ? undefined : String(record.tier)],
    ['outcome', record.outcome],
    ['action', record.action],
    ['params', record.params ? Object.entries(record.params).map(([key, value]) => `${key}: ${value}`) : undefined],
    ['risk_score', record.risk_score === undefined ? undefined : String(record.risk_score)],
    ['confidence', record.confidence === undefined ? undefined : record.confidence.toFixed(2)],
    ['decision', record.decision],
    ['decision_reason', record.decision_reason],
    ['execution_result', record.execution_result],
    ['expires_at', record.expires_at],
    ['evidence', record.evidence],
  ]

  return rows.filter((row): row is [string, string | string[]] => row[1] !== undefined)
}

/*
  What an audit record adds to its panel beyond what every event has: its
  type in the policy PDF's list, the PDF's structured record for events
  about a recommendation, and where it sits in the hash chain, so a
  person can check it by hand. A record whose content no longer matches
  its hash says so.
*/
function AuditRecordDetails({ log, links, integrity }: AuditRecordDetailsProps) {
  const link = links[log.id]
  const broken = integrity?.status === 'broken' && integrity.brokenId === log.id

  return (
    <>
      <dl className="facts">
        <div>
          <dt>Event type</dt>
          <dd data-field="eventType">
            {log.eventType ? (
              <>
                <span className="mono">{log.eventType}</span> {AUDIT_EVENT_TYPE_NAMES[log.eventType]}
              </>
            ) : (
              'No PDF event type'
            )}
          </dd>
        </div>
      </dl>

      {log.record && (
        <>
          <h3 className="workspace-subhead">Structured record</h3>

          <dl className="facts" data-field="record">
            {recordRows(log.record).map(([name, value]) => (
              <div key={name} data-record-field={name}>
                <dt className="mono">{name}</dt>
                <dd>
                  {Array.isArray(value) ? (
                    <ul className="audit-record-list">
                      {value.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  ) : (
                    value
                  )}
                </dd>
              </div>
            ))}
            <div data-record-field="model_version">
              <dt className="mono">model_version</dt>
              <dd>Not recorded</dd>
            </div>
          </dl>
        </>
      )}

      <h3 className="workspace-subhead">Integrity</h3>

      {broken && (
        <p className="audit-mismatch" data-field="mismatch">
          This record no longer matches its hash.
        </p>
      )}

      <dl className="facts audit-hashes" data-field="integrityRecord">
        <div>
          <dt>Previous hash</dt>
          {link ? <HashValue label="Previous hash" value={link.prev_hash} /> : <dd>Computing…</dd>}
          {link?.prev_hash === GENESIS && <dd className="approval-hint">The first record: it follows no other.</dd>}
        </div>
        <div>
          <dt>Hash</dt>
          {link ? <HashValue label="Hash" value={link.hash} /> : <dd>Computing…</dd>}
        </div>
      </dl>
    </>
  )
}

export default AuditRecordDetails
