import type { AuditLogRecord } from '../types/auditLogsTypes'

/*
  The audit events Demo mode's tamper control writes. They are ordinary
  records in the chain (so they stay in the trail whatever happens to the
  record they are about), have no PDF event type, and are marked Demo.
*/
export type DemoAuditKind = 'tamper' | 'restore'

export function demoAuditEvent(
  kind: DemoAuditKind,
  targetId: string,
): Omit<AuditLogRecord, 'id' | 'timestamp' | 'user' | 'role' | 'result' | 'sourceIp'> {
  const altered = kind === 'tamper'

  return {
    category: 'System',
    action: altered ? 'Tampered with a record' : 'Restored a record',
    target: targetId,
    description: altered
      ? `Demo mode altered the stored content of ${targetId} without changing the hashes recorded for it, to show that the audit chain detects a changed record. Nothing else was changed.`
      : `Demo mode put the stored content of ${targetId} back. The chain was checked again from the recorded hashes.`,
    changes: [altered ? `${targetId}: Original → Altered` : `${targetId}: Altered → Original`],
    metadata: { 'Record ID': targetId },
    demo: true,
  }
}
