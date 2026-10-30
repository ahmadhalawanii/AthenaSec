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

  // Resolves to the reason it was refused (a value past a PDF cap, or the backend's answer), or null when
  // it was saved or nothing changed. A save with changes adds 1 to the version and writes one audit event:
  // in this tab in demo mode, or on the backend (PUT /policies/actions), which the agent then enforces.
  saveResponsePolicy: (next: ResponsePolicy) => Promise<string | null>

  // Self edits keep their role and status; returns false when refused
  saveUser: (user: UserRecord) => boolean
  // Refuses the signed-in user's own account
  toggleUserStatus: (userId: string) => boolean
  deleteUser: (userId: string) => boolean
  // Turns MFA on; false when the account is missing or already has it
  requireMfa: (userId: string) => boolean
  resetPassword: (userId: string) => void
  nextUserId: () => string
  // Live mode only (null in demo mode): the same changes, made on the backend
  liveUsers: LiveUserActions | null

  // Applies a check or refresh to the current services and returns them; `label` names what ran
  updateServices: (
    update: (services: ServiceRecord[]) => ServiceRecord[],
    label: 'check' | 'check-all' | 'refresh',
  ) => ServiceRecord[]

  // Resolves to why it was not saved, or null. Live mode saves it on the backend (audited there).
  saveConfiguration: (values: ConfigurationValues) => Promise<string | null>
}

// What an administrator fills in for an account
export type UserFields = {
  name: string
  email: string
  role: UserRecord['role']
  department: string
  phone: string
}

// Shown once after creating an account or resetting its password
export type IssuedCredentials = {
  user: UserRecord
  // null for a two-factor reset (the password stays)
  temporaryPassword: string | null
  // otpauth:// link for the authenticator app (new accounts only)
  totpUri: string | null
}

// Each resolves to an error message, or null (or the credentials) when the backend saved it
export type LiveUserActions = {
  create: (fields: UserFields, active: boolean) => Promise<{ error: string } | { credentials: IssuedCredentials }>
  // active null leaves the status alone (always the case for your own account)
  update: (userId: string, fields: UserFields, active: boolean | null) => Promise<string | null>
  setActive: (userId: string, active: boolean) => Promise<string | null>
  remove: (userId: string) => Promise<string | null>
  resetPassword: (userId: string) => Promise<{ error: string } | { credentials: IssuedCredentials }>
  resetMfa: (userId: string) => Promise<{ error: string } | { credentials: IssuedCredentials }>
}
