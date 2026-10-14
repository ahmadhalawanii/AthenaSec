import type { ApprovalRecord, ExecutionFacts, PolicySnapshot } from '../types/approvalTypes'
import type { ApprovalToken, Recommendation, Tier2ActionName } from '../types/policyTypes'

import { OUTCOME_LABELS, seedAssessmentInputs } from './agentPolicyData'
import { actionDigest, addMinutes, assess, policySnapshot, tier2Spec } from './policyEngine'
import { initialResponsePolicy } from './responsePoliciesData'

/*
  The approval records the demo starts with, on the data's day. Each
  recommendation is the agent's own assessment of its alert (nothing is
  typed in), and each token's digest is computed here with Web Crypto.

  Timeline of the day, in order:
    15:10:42  AUD-203   response policy version 2: isolate_host needs approval (it ran Automatic in version 1)
    15:41     ALT-006   raised on endpoint-12
    15:42:00  REC-001   the agent recommends isolating endpoint-12 (risk 90, confidence 0.92), under version 2
    15:43:10  APR-001   System Administrator (SOC lead) approves as recommended; TKN-001 issued
    15:44:00  EXE-001   the isolation runs and uses up TKN-001; it reverses at 17:44:00 (120 min)
    15:44:07  AUD-206   response policy version 3: block_ip needs approval, minimum risk 90 → 70
    15:44:30  REC-002   the agent re-assesses ALT-001 under version 3 and recommends blocking 203.0.113.45
              APR-002   waits for a SOC analyst until 15:59:30
    15:46:00            "now" in the demo (DEMO_NOW in agentPolicyData.ts)

  Every time here is a local "YYYY-MM-DDTHH:MM:SS" string with no zone.
*/

export const SCENARIO_DAY = '2026-08-03'

const at = (time: string) => `${SCENARIO_DAY}T${time}`

const windowMinutes = (name: Recommendation['action']['name']) => tier2Spec(name).approvalWindowMinutes

// The agent's recommendation for a seed alert, straight from its assessment
function recommendationFor(alertId: string, id: string, createdAt: string): Recommendation {
  const input = seedAssessmentInputs.find((item) => item.alertId === alertId)

  if (!input) {
    throw new Error(`No assessment inputs for ${alertId}`)
  }

  const assessment = assess(input)

  if (!assessment.proposal) {
    throw new Error(`${alertId} has no Tier 2 recommendation`)
  }

  return {
    id,
    alertId,
    outcome: assessment.outcome,
    action: assessment.proposal,
    tier: 2,
    evidence: input.signals,
    riskScore: assessment.risk,
    confidence: assessment.confidence,
    alternativesConsidered: assessment.alternativesConsidered.map(
      (item) => `${OUTCOME_LABELS[item.outcome]}: ${item.reason}`,
    ),
    rationale: assessment.rationale,
    requestedBy: 'agent',
    createdAt,
    approvalDeadline: addMinutes(createdAt, windowMinutes(assessment.proposal.name)),
  }
}

/*
  The action's rule at the version the recommendation was checked against.
  The seed policy is version 3 (after AUD-206); the isolation was checked at
  15:42, under version 2, which set the same limits for isolate_host.
*/
function snapshotOf(name: Tier2ActionName, version: number): PolicySnapshot {
  return { ...policySnapshot(initialResponsePolicy, name), version }
}

const isolation = recommendationFor('ALT-006', 'REC-001', at('15:42:00'))
const block = recommendationFor('ALT-001', 'REC-002', at('15:44:30'))

const decidedAt = at('15:43:10')
const startedAt = at('15:44:00')

// Available at once; nothing here needs hashing
export const seedApprovalRecords: ApprovalRecord[] = [
  {
    id: 'APR-001',
    recommendation: isolation,
    requiredRole: 'soc_lead',
    policy: snapshotOf('isolate_host', 2),
    decision: 'Approved',
    decidedBy: { id: 'USR-001', name: 'System Administrator', role: 'soc_lead' },
    decidedAt,
    reason: 'Beaconing to a known-bad address with EDR findings; isolate as recommended.',
    approvedAction: isolation.action,
    tokenId: 'TKN-001',
    executionId: 'EXE-001',
  },
  {
    id: 'APR-002',
    recommendation: block,
    requiredRole: 'soc_analyst',
    policy: snapshotOf('block_ip', initialResponsePolicy.version),
    decision: 'Pending',
  },
]

export const seedExecutionFacts: ExecutionFacts[] = [
  {
    id: 'EXE-001',
    approvalId: 'APR-001',
    startedAt,
    expiresAt: addMinutes(startedAt, Number(isolation.action.params.duration_min)),
    action: isolation.action,
  },
]

// The token carries a SHA-256 of the approved action, so it is computed with Web Crypto
export async function buildSeedTokens(): Promise<ApprovalToken[]> {
  return [
    {
      id: 'TKN-001',
      recommendationId: isolation.id,
      paramsDigest: await actionDigest(isolation.action),
      approverId: 'USR-001',
      approverRole: 'soc_lead',
      issuedAt: decidedAt,
      expiresAt: addMinutes(decidedAt, 5),
      usedAt: startedAt,
    },
  ]
}

export type SeedApprovals = {
  records: ApprovalRecord[]
  tokens: ApprovalToken[]
  executions: ExecutionFacts[]
}

export async function buildSeedApprovals(): Promise<SeedApprovals> {
  return { records: seedApprovalRecords, tokens: await buildSeedTokens(), executions: seedExecutionFacts }
}
