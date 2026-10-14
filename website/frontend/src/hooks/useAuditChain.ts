import { useEffect, useState } from 'react'

import { extendLinks, verifyAuditLogs, type AuditLinks } from '../data/auditChain'
import type { AuditIntegrity, AuditLogRecord } from '../types/auditLogsTypes'

type Verified = { logs: AuditLogRecord[]; result: AuditIntegrity }

/*
  Keeps the audit hash chain for these records: each new record is hashed
  onto the one before it (Web Crypto, so a moment after it appears), and
  the whole chain is then verified against what was recorded. `integrity`
  is null until the hashes for exactly these records have been checked,
  so it never describes an older set of records (or older content: after
  a record is restored, the answer comes from checking it again).
*/
export function useAuditChain(logs: AuditLogRecord[]): { integrity: AuditIntegrity | null; links: AuditLinks } {
  const [links, setLinks] = useState<AuditLinks>({})
  const [verified, setVerified] = useState<Verified | null>(null)

  useEffect(() => {
    let cancelled = false

    async function run() {
      const next = await extendLinks(links, logs)

      if (cancelled) {
        return
      }

      // New records were hashed: this effect runs again with them and then verifies
      if (next !== links) {
        setLinks(next)
        return
      }

      const result = await verifyAuditLogs(links, logs)

      if (!cancelled) {
        setVerified({ logs, result })
      }
    }

    run()

    return () => {
      cancelled = true
    }
  }, [links, logs])

  return { integrity: verified && verified.logs === logs ? verified.result : null, links }
}
