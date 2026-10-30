import type { ApproverRole } from './policyTypes'

/*
  The response policy: one document that says which catalogue actions the
  agent may use (whitelist), which it may never use (blacklist) and which
  targets are protected. An action on neither list is denied.
  Actions are named by their catalogue key (block_ip, get_logs,
  block_ip_permanent).
*/

// Automatic runs on its own; Needs approval waits for a person. A Tier 2 action is never Automatic.
export type PolicyMode = 'Automatic' | 'Needs approval'

// The limits of a Tier 2 action. Every one is capped by the PDF (POLICY_CAPS in agentPolicyData.ts).
export type ApprovalLimits = {
  // Not set for an action that does not reverse on its own
  defaultMinutes?: number
  maxMinutes?: number
  approver: ApproverRole
  // Minutes a person has to decide
  windowMinutes: number
  // The agent recommends the action only at this risk or more (at least the PDF's floor)
  minRisk: number
}

export type WhitelistEntry = {
  action: string
  mode: PolicyMode
  // Tier 2 entries only
  limits?: ApprovalLimits
}

export type BlacklistEntry = {
  action: string
  // From the security policy: locked, cannot be removed here
  required: boolean
}

export type ProtectedTarget = {
  // An IP, a CIDR range or a host name (matched without regard to case)
  value: string
  label: string
  required: boolean
}

export type ResponsePolicy = {
  // 1 when created; every saved change adds 1
  version: number
  whitelist: WhitelistEntry[]
  blacklist: BlacklistEntry[]
  neverBlock: ProtectedTarget[]
  neverIsolate: ProtectedTarget[]
}

// Where an action stands in a policy
export type ListStanding = 'whitelisted' | 'blacklisted' | 'unlisted'
