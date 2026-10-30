import type { AuditIntegrity, AuditLogRecord } from '../types/auditLogsTypes'

import { GENESIS_HASH, hashRecord, verifyChain } from './policyEngine'

/*
  The audit log as a hash chain (design/agent-action-policy.pdf, page 8:
  "each record carries the hash of the previous one so tampering is
  detectable"). A record's hash is SHA-256 of the previous hash and the
  record's own content, in append order (the order of the AUD ids).
  Altering, deleting, inserting or reordering any record changes a hash
  that was already recorded, and the chain stops verifying at that
  record. All of it is pure: no React and no clock.
*/

// The hashes recorded for each record when it was added, by record id
export type AuditLinks = Record<string, { prev_hash: string; hash: string }>

const numberOf = (log: AuditLogRecord) => Number(log.id.replace('AUD-', ''))

const inAppendOrder = (logs: AuditLogRecord[]) => [...logs].sort((a, b) => numberOf(a) - numberOf(b))

// Everything a record says, as plain data (an absent field is absent, not undefined)
export const auditBody = (log: AuditLogRecord): Record<string, unknown> => JSON.parse(JSON.stringify(log))

/*
  Hashes every record that has no recorded link yet, each onto the one
  before it. Records already linked keep their links, so a record altered
  afterwards is still checked against what was recorded. Returns the same
  object when there was nothing to add.
*/
export async function extendLinks(links: AuditLinks, logs: AuditLogRecord[]): Promise<AuditLinks> {
  let next = links
  let prev = GENESIS_HASH

  for (const log of inAppendOrder(logs)) {
    const recorded = next[log.id]

    if (recorded) {
      prev = recorded.hash
      continue
    }

    const hash = await hashRecord(auditBody(log), prev)

    if (next === links) {
      next = { ...links }
    }

    next[log.id] = { prev_hash: prev, hash }
    prev = hash
  }

  return next
}

// Checks the whole chain against the recorded links; names the first record that does not verify
export async function verifyAuditLogs(links: AuditLinks, logs: AuditLogRecord[]): Promise<AuditIntegrity> {
  const ordered = inAppendOrder(logs)
  const missing = ordered.find((log) => !links[log.id])

  // A record with no recorded hashes was inserted after the fact
  if (missing) {
    return { status: 'broken', count: ordered.length, brokenId: missing.id }
  }

  // Hashes recorded for a record that is no longer there: it was deleted (even the newest one)
  const present = new Set(ordered.map((log) => log.id))
  const deleted = Object.keys(links).find((id) => !present.has(id))

  if (deleted) {
    return { status: 'broken', count: ordered.length, brokenId: deleted }
  }

  const result = await verifyChain(
    ordered.map((log) => ({ body: auditBody(log), prev_hash: links[log.id].prev_hash, hash: links[log.id].hash })),
  )

  return result.ok
    ? { status: 'intact', count: ordered.length }
    : { status: 'broken', count: ordered.length, brokenId: ordered[result.brokenAt ?? 0].id }
}

// What an attacker changing a stored record might do: rewrite what it says
export const tamperLog = (log: AuditLogRecord): AuditLogRecord => ({
  ...log,
  description: `${log.description} (altered after it was recorded)`,
})
