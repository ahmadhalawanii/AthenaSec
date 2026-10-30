import type { AuditIntegrity } from '../types/auditLogsTypes'

type AuditTamperPanelProps = {
  // The record shown in the panel above, if any
  shownId: string | null
  // Records altered after they were hashed
  alteredIds: string[]
  integrity: AuditIntegrity | null
  onAlter: (id: string) => void
  onRestore: (id: string) => void
}

/*
  Demo mode, Administrator only (Audit Logs is not reachable for anyone
  else): alter the record being shown so the chain stops verifying, then
  restore it. Each use is written to the audit log as a Demo event, and
  the chain is checked again from the recorded hashes after each change.
*/
function AuditTamperPanel({ shownId, alteredIds, integrity, onAlter, onRestore }: AuditTamperPanelProps) {
  const altered = alteredIds[0] ?? null
  const checking = integrity === null

  const alterReason = altered
    ? `${altered} is altered. Restore it first.`
    : checking
      ? 'Wait for the chain to be checked.'
      : shownId
        ? ''
        : 'Choose an event first.'

  return (
    <section className="demo-panel audit-tamper" aria-labelledby="auditTamperTitle" data-tamper-panel>
      <div className="demo-head">
        <h2 className="demo-badge" id="auditTamperTitle">
          Demo mode
        </h2>
        <span>
          Alter the stored content of the event shown above, without touching the hashes recorded for it, to see the
          chain notice. Each use is written to the audit log as a Demo event.
        </span>
      </div>

      <div className="approval-demo-buttons audit-tamper-buttons">
        <button
          className="btn small"
          type="button"
          disabled={Boolean(alterReason)}
          aria-describedby="auditTamperHint"
          onClick={() => shownId && onAlter(shownId)}
        >
          Alter this record (demo)
        </button>

        {altered && (
          <button className="btn small" type="button" onClick={() => onRestore(altered)}>
            Restore {altered}
          </button>
        )}
      </div>

      <p className="approval-hint" id="auditTamperHint" data-field="tamperHint">
        {alterReason ||
          (shownId ? `This alters ${shownId}. Restore puts it back and the chain is checked again.` : '')}
      </p>
    </section>
  )
}

export default AuditTamperPanel
