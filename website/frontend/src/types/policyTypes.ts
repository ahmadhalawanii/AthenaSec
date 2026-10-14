/*
  Types for the Agent Action Catalogue and Approval Policy
  (design/agent-action-policy.pdf). "Tier" always means an action tier
  (1 allowed, 2 approval-required, 3 prohibited). Assets are
  classed Critical / Business / Standard so the two never mix.
*/

export type ActionTier = 1 | 2 | 3

export type AssetClass = 'Critical' | 'Business' | 'Standard'

// The five outcomes, lowest to highest impact
export type Outcome =
  | 'monitor'
  | 'investigate_further'
  | 'create_alert_and_ticket'
  | 'recommend_block_ip'
  | 'recommend_host_isolation'

export type ConfidenceBand = 'Low' | 'Medium' | 'High'

export type Tier2ActionName =
  | 'block_ip'
  | 'isolate_host'
  | 'suspend_user_session'
  | 'kill_process'
  | 'quarantine_file'
  | 'reset_password'

// Approver roles in the policy; Analyst maps to soc_analyst, Administrator to soc_lead
export type ApproverRole = 'soc_analyst' | 'soc_lead'

// What the agent assesses for one alert
export type AssessmentInput = {
  alertId: string
  // Wazuh rule level, 0-15
  ruleLevel: number
  // Independent signals that agree (each one a short statement), capped at 5 in the score
  signals: string[]
  // 0.00-1.00; 0 when no reputation lookup applies (internal source) or none returned
  reputation: number
  // Where the reputation came from, shown in the breakdown
  reputationSource: string
  // The source IP, when it is external or internal alike
  sourceIp?: string
  // Host the alert is about, and its asset class
  asset: string
  assetClass: AssetClass
  // The agent's own confidence, 0.00-1.00
  confidence: number
  failedLogins?: { count: number; accounts: number; windowMin: number }
  // Exploit, malware or ransomware evidence on the host
  hostExploitEvidence: boolean
}

export type ScoreKey = 'S' | 'E' | 'R' | 'A'

export type ScorePart = {
  key: ScoreKey
  label: string
  // What the input is, in words ("Wazuh rule level 13 of 15")
  rawLabel: string
  // Normalised to 0-1
  normalised: number
  weight: number
  // weight x normalised x 100: the points this input adds
  points: number
}

export type RiskBreakdown = {
  parts: ScorePart[]
  // Rounded total, 0-100
  risk: number
}

// An outcome the agent did not choose, and why (alternatives_considered)
export type RejectedOutcome = {
  outcome: Outcome
  // 'higher': its conditions were not met; 'lower': it would under-react
  direction: 'higher' | 'lower'
  reason: string
}

export type Tier2Proposal = {
  name: Tier2ActionName
  params: Record<string, string | number>
}

export type Assessment = {
  alertId: string
  risk: number
  breakdown: RiskBreakdown
  confidence: number
  confidenceBand: ConfidenceBand
  outcome: Outcome
  // Higher outcomes the agent rejected, each with the reason (alternatives_considered)
  alternativesConsidered: RejectedOutcome[]
  // Set for the two outcomes that need a human
  proposal?: Tier2Proposal
  // Set when a Critical asset sends isolation to a ticket plus escalation
  escalation?: string
  rationale: string
}

// A Tier 2 recommendation waiting for, or carrying, a human decision
export type Recommendation = {
  id: string
  alertId: string
  outcome: Outcome
  action: Tier2Proposal
  tier: 2
  evidence: string[]
  riskScore: number
  confidence: number
  alternativesConsidered: string[]
  rationale: string
  // Who asked for it: 'agent', or a user id when an analyst requested it (retry)
  requestedBy: string
  createdAt: string
  approvalDeadline: string
}

// Issued on approval; single-use and bound to one recommendation and its exact parameters
export type ApprovalToken = {
  id: string
  recommendationId: string
  // SHA-256 of the canonical JSON of the approved action (name + params)
  paramsDigest: string
  approverId: string
  approverRole: ApproverRole
  issuedAt: string
  expiresAt: string
  usedAt?: string
}

export type GuardRequest = {
  // Name of the function the executor was asked to run
  actionName: string
  params: Record<string, string | number>
  recommendationId?: string
  tokenId?: string
  // Who asked for the recommendation (for the self-approval rule)
  requestedBy?: string
  riskScore?: number
  confidence?: number
  // Class of the asset an isolate_host would touch
  assetClass?: AssetClass
  // True when the account a suspend_user_session would touch is privileged
  privilegedAccount?: boolean
  now: string
}

export type GuardCode =
  | 'ok'
  | 'prohibited'
  | 'not_in_catalogue'
  | 'no_token'
  | 'token_reused'
  | 'wrong_recommendation'
  | 'params_changed'
  | 'token_expired'
  | 'wrong_role'
  | 'self_approval'
  | 'below_threshold'
  | 'internal_ip'
  | 'allow_listed'
  | 'duration_over_max'
  | 'critical_asset'
  | 'privileged_account'
  | 'not_listed'
  | 'blacklisted'
  | 'protected_target'

export type GuardResult = {
  allowed: boolean
  code: GuardCode
  reason: string
}

// What the agent would be told if it tried an action now (Demo mode "Simulate an attempt")
export type AttemptRequest = {
  actionName: string
  params: Record<string, string | number>
  riskScore?: number
  confidence?: number
  assetClass?: AssetClass
  privilegedAccount?: boolean
}

export type AttemptDecision = {
  decision: 'allowed' | 'needs_approval' | 'refused'
  // The guard's code for a refusal, 'ok' for Tier 1, 'needs_approval' for a Tier 2 that passes every check
  code: GuardCode | 'needs_approval'
  reason: string
  // The catalogue rule it came from, for example "Never allowed - Permanent blocking ... - PDF p.5"
  rule: string
  approver?: ApproverRole
  approvalWindowMinutes?: number
  // An attempt never runs anything
  executed: false
}

// One link of the audit hash chain
export type ChainRecord = {
  // The record's own fields, hashed in canonical order
  body: Record<string, unknown>
  prev_hash: string
  hash: string
}

export type ChainVerification = {
  ok: boolean
  count: number
  // Index (0 = oldest) of the first record that does not verify
  brokenAt?: number
}
