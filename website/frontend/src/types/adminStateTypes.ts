import type { AuditLinks } from '../data/auditChain'

import type { AuditIntegrity, AuditLogRecord } from './auditLogsTypes'
import type { ConfigurationValues } from './configurationTypes'
import type { ResponsePolicy } from './responsePoliciesTypes'
import type { ServicePanelState } from './servicePanelTypes'
import type { ServiceRecord } from './systemHealthTypes'
import type { UserRecord } from './userManagementTypes'

// Who is signed in, for audit events and self-protection
export type AdminSessionUser = {
  name: string
  email: string
  role: 'Analyst' | 'Administrator'
}

/*
  Shared admin workspace state (AdminStateProvider). It starts from the
  seed data and holds this session's changes, so it resets on reload like
  the rest of the prototype. Every change also records an audit event.
*/
export type AdminState = {
  responsePolicy: ResponsePolicy
  users: UserRecord[]
  services: ServiceRecord[]
  // The Service Panel page's demo snapshot (checks and device usage)
  servicePanel: ServicePanelState
  configuration: ConfigurationValues
  // Session events (newest first) followed by the seed audit log
  auditLogs: AuditLogRecord[]
  // Whether the audit hash chain verifies for exactly these records; null while it is being computed
  auditIntegrity: AuditIntegrity | null
  // The hashes recorded for each record when it was added, by record id
  auditLinks: AuditLinks
  // Records whose stored content was altered after they were hashed (Demo)
  alteredAuditIds: string[]
  // Demo, Administrator only: writes a Demo event, then alters the record's stored content
  tamperAudit: (id: string) => void
  // Demo, Administrator only: writes a Demo event, then puts the content back; the chain is then checked again
  restoreAudit: (id: string) => void
  // The signed-in user's record id, or '' when they have none (analysts)
  currentUserId: string

  // Returns the reason it was refused (a value past a PDF cap), or null when it was saved or nothing changed.
  // A save with changes adds 1 to the version and writes one "Updated response policy" audit event.
  saveResponsePolicy: (next: ResponsePolicy) => string | null

  // Self edits keep their role and status; returns false when refused
  saveUser: (user: UserRecord) => boolean
  // Refuses the signed-in user's own account
  toggleUserStatus: (userId: string) => boolean
  deleteUser: (userId: string) => boolean
  // Turns MFA on; false when the account is missing or already has it
  requireMfa: (userId: string) => boolean
  resetPassword: (userId: string) => void
  nextUserId: () => string

  // Applies a check or refresh to the current services and returns them; `label` names what ran
  updateServices: (
    update: (services: ServiceRecord[]) => ServiceRecord[],
    label: 'check' | 'check-all' | 'refresh',
  ) => ServiceRecord[]

  saveConfiguration: (values: ConfigurationValues) => void
}
