import type {
  ApprovalToken,
  ApproverRole,
  AttemptDecision,
  AttemptRequest,
  Assessment,
  AssessmentInput,
  ChainRecord,
  ChainVerification,
  ConfidenceBand,
  GuardRequest,
  GuardResult,
  Outcome,
  Recommendation,
  RejectedOutcome,
  RiskBreakdown,
  ScorePart,
  Tier2ActionName,
  Tier2Proposal,
} from '../types/policyTypes'
import type { ApprovalCheck, ApprovalRecord, ExecutionFacts, PolicySnapshot } from '../types/approvalTypes'
import type {
  ApprovalLimits,
  ListStanding,
  ProtectedTarget,
  ResponsePolicy,
} from '../types/responsePoliciesTypes'

import type { CatalogueRow, Tier2Action } from './agentPolicyData'
import {
  ACTION_CATALOGUE,
  ALLOW_LIST,
  APPROVER_LABELS,
  ASSET_WEIGHT,
  CONFIDENCE_HIGH_FROM,
  CONFIDENCE_MEDIUM_FROM,
  formatMinutes,
  OUTCOME_LABELS,
  POLICY_CAPS,
  PROTECTED_BLOCK_SEEDS,
  PROTECTED_ISOLATE_SEEDS,
  REPUTATION_MALICIOUS,
  RISK_WEIGHTS,
  ROLE_RANK,
  RULE_LEVEL_MAX,
  SEVERITY_BANDS,
  SIGNALS_MAX,
  THRESHOLDS,
  tier2Actions,
} from './agentPolicyData'
import { initialResponsePolicy } from './responsePoliciesData'

/*
  The policy, applied in code. Thresholds are checked here, never
  trusted to the model. Everything is a pure function except the two
  that hash (Web Crypto, asynchronous).
*/

// ===== Addresses =====

function ipToNumber(ip: string) {
  const parts = ip.split('.')

  if (parts.length !== 4) {
    return null
  }

  let value = 0

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) {
      return null
    }

    value = value * 256 + Number(part)
  }

  return value
}

function inRange(ip: string, cidr: string) {
  const [base, bitsText] = cidr.split('/')
  const address = ipToNumber(ip)
  const network = ipToNumber(base)
  const bits = Number(bitsText)

  if (address === null || network === null || Number.isNaN(bits)) {
    return false
  }

  const size = 2 ** (32 - bits)

  return Math.floor(address / size) === Math.floor(network / size)
}

export function isValidIp(ip: string) {
  return ipToNumber(ip) !== null
}

export function isInternalIp(ip: string) {
  return ALLOW_LIST.internal.some((range) => inRange(ip, range))
}

// Internal ranges, partners, cloud providers and the SIEM's own addresses
export function isAllowListed(ip: string) {
  return [
    ...ALLOW_LIST.internal,
    ...ALLOW_LIST.partners,
    ...ALLOW_LIST.cloud,
    ...ALLOW_LIST.siem,
  ].some((range) => inRange(ip, range))
}

// A block may only target a valid IP that is outside every allow-list range
export function isBlockableIp(ip: string | undefined) {
  return !!ip && isValidIp(ip) && !isAllowListed(ip)
}

// ===== Scoring =====

export function severityBand(ruleLevel: number) {
  return (
    SEVERITY_BANDS.find((band) => ruleLevel >= band.min && ruleLevel <= band.max)?.label ?? 'Low'
  )
}

export function confidenceBand(confidence: number): ConfidenceBand {
  if (confidence >= CONFIDENCE_HIGH_FROM) {
    return 'High'
  }

  return confidence >= CONFIDENCE_MEDIUM_FROM ? 'Medium' : 'Low'
}

const clamp01 = (value: number) => Math.min(1, Math.max(0, value))

/*
  Each input to 0-1: severity is the Wazuh level over 15, evidence is
  independent signals over 5 (capped), reputation is already 0-1, and
  the asset class maps to 1.0 / 0.6 / 0.3.
*/
export function scoreRisk(input: AssessmentInput): RiskBreakdown {
  const signals = Math.min(SIGNALS_MAX, input.signals.length)

  const inputs: Array<Omit<ScorePart, 'points'>> = [
    {
      key: 'S',
      label: 'Severity',
      rawLabel: `Wazuh rule level ${input.ruleLevel} of ${RULE_LEVEL_MAX} (${severityBand(input.ruleLevel)})`,
      normalised: clamp01(input.ruleLevel / RULE_LEVEL_MAX),
      weight: RISK_WEIGHTS.S,
    },
    {
      key: 'E',
      label: 'Evidence',
      rawLabel: `${signals} independent ${signals === 1 ? 'signal' : 'signals'} agree (capped at ${SIGNALS_MAX})`,
      normalised: clamp01(signals / SIGNALS_MAX),
      weight: RISK_WEIGHTS.E,
    },
    {
      key: 'R',
      label: 'Reputation',
      rawLabel: `${input.reputation.toFixed(2)} (${input.reputationSource})`,
      normalised: clamp01(input.reputation),
      weight: RISK_WEIGHTS.R,
    },
    {
      key: 'A',
      label: 'Asset criticality',
      rawLabel: `${input.asset} is a ${input.assetClass} asset`,
      normalised: ASSET_WEIGHT[input.assetClass],
      weight: RISK_WEIGHTS.A,
    },
  ]

  const parts: ScorePart[] = inputs.map((part) => ({
    ...part,
    points: part.weight * part.normalised * 100,
  }))

  // (The parts are shown to the cent; see displayedParts and displayedPartsTotal below.)

  const total = parts.reduce((sum, part) => sum + part.points, 0)

  // The small offset keeps a value like 69.9999999 from rounding down
  return { parts, risk: Math.round(total + 1e-9) }
}

/*
  What the score table shows. Each part is shown to the cent, and the
  sum shown is the sum of those displayed cents (not of the unrounded
  parts), so the parts on screen always add up to the total on screen
  ("32.67 + 25.00 + 23.75 + 9.00 = 90.42"), and that total rounds to
  the risk score shown ("90.42, shown as 90").
*/
const cents = (points: number) => Math.round(points * 100)

export function displayedParts(parts: ScorePart[]) {
  return parts.map((part) => (cents(part.points) / 100).toFixed(2))
}

export function displayedPartsTotal(parts: ScorePart[]) {
  return (parts.reduce((sum, part) => sum + cents(part.points), 0) / 100).toFixed(2)
}

// ===== The decision ladder =====

// ===== The response policy =====

// The policy the demo starts with; every function below that takes a policy defaults to it
export const DEFAULT_POLICY: ResponsePolicy = initialResponsePolicy

export function listStanding(policy: ResponsePolicy, key: string): ListStanding {
  if (policy.blacklist.some((entry) => entry.action === key)) {
    return 'blacklisted'
  }

  return policy.whitelist.some((entry) => entry.action === key) ? 'whitelisted' : 'unlisted'
}

export const whitelistEntry = (policy: ResponsePolicy, key: string) =>
  policy.whitelist.find((entry) => entry.action === key)

export type StandingLabel = 'Automatic' | 'Needs approval' | 'Blacklisted' | 'Not listed'

// Where an action stands, in the words the page and the audit lines use
export function standingLabel(policy: ResponsePolicy, key: string): StandingLabel {
  const standing = listStanding(policy, key)

  if (standing === 'blacklisted') {
    return 'Blacklisted'
  }

  return standing === 'whitelisted' ? whitelistEntry(policy, key)!.mode : 'Not listed'
}

const pdfSpec = (name: Tier2ActionName): Tier2Action => {
  const spec = tier2Actions.find((action) => action.name === name)

  if (!spec) {
    throw new Error(`Unknown Tier 2 action: ${name}`)
  }

  return spec
}

/*
  The Tier 2 row with the policy's limits in place of the PDF's own
  (default and longest time, who approves, time to decide, Minimum risk).
  An action with no limits in the policy keeps the PDF's values. The
  confidence floor is always the PDF's.
*/
export function tier2Spec(name: Tier2ActionName, policy: ResponsePolicy = DEFAULT_POLICY): Tier2Action {
  const base = pdfSpec(name)
  const limits = whitelistEntry(policy, name)?.limits

  if (!limits) {
    return base
  }

  return {
    ...base,
    defaultMinutes: limits.defaultMinutes,
    maxMinutes: limits.maxMinutes,
    approver: limits.approver,
    approvalWindowMinutes: limits.windowMinutes,
    floor: { ...base.floor, risk: Math.max(base.floor.risk, limits.minRisk) },
  }
}

// What the action's rule was when a request was checked (kept on the approval record)
export function policySnapshot(policy: ResponsePolicy, name: Tier2ActionName): PolicySnapshot {
  const spec = tier2Spec(name, policy)

  return {
    version: policy.version,
    action: name,
    approver: spec.approver,
    minRisk: spec.floor.risk,
    maxMinutes: spec.maxMinutes,
    windowMinutes: spec.approvalWindowMinutes,
  }
}

// "Response policy v3: isolate_host"
export const policyLabel = (snapshot: Pick<PolicySnapshot, 'version' | 'action'>) =>
  `Response policy v${snapshot.version}: ${snapshot.action}`

// A block target is an address or a range (an address alone is a range of one); a host name ignores case
function blockTargetMatches(target: ProtectedTarget, ip: string) {
  return inRange(ip, target.value.includes('/') ? target.value : `${target.value}/32`)
}

const hostTargetMatches = (target: ProtectedTarget, host: string) =>
  target.value.trim().toLowerCase() === host.trim().toLowerCase()

// The policy's own Never block entry that covers this IP, if any
export function protectedBlockEntry(policy: ResponsePolicy, ip: string) {
  return isValidIp(ip) ? policy.neverBlock.find((target) => blockTargetMatches(target, ip)) : undefined
}

export function protectedIsolateEntry(policy: ResponsePolicy, host: string) {
  return policy.neverIsolate.find((target) => hostTargetMatches(target, host))
}

export type LimitField = 'maxMinutes' | 'defaultMinutes' | 'approver' | 'windowMinutes' | 'minRisk'

/*
  Each limit past its cap, with the reason in the PDF's own numbers, keyed by the
  field so the page can show it beside the control. A field with no problem is absent.
*/
export function limitProblems(name: Tier2ActionName, limits: ApprovalLimits): Partial<Record<LimitField, string>> {
  const cap = POLICY_CAPS[name]
  const problems: Partial<Record<LimitField, string>> = {}
  const whole = (value: number | undefined): value is number =>
    typeof value === 'number' && Number.isInteger(value) && value >= 1

  if (cap.maxMinutes === undefined) {
    if (limits.maxMinutes !== undefined || limits.defaultMinutes !== undefined) {
      problems.maxMinutes = `${name} has no duration, so it has no default or longest time.`
    }
  } else {
    if (!whole(limits.maxMinutes)) {
      problems.maxMinutes = 'Enter a whole number of minutes for the longest allowed, 1 or more.'
    } else if (limits.maxMinutes > cap.maxMinutes) {
      problems.maxMinutes = `${name} can run for ${formatMinutes(cap.maxMinutes)} at most (Agent Action Policy), so the longest allowed cannot be more than that.`
    }

    if (!whole(limits.defaultMinutes)) {
      problems.defaultMinutes = 'Enter a whole number of minutes for the default duration, 1 or more.'
    } else if (whole(limits.maxMinutes) && limits.defaultMinutes > limits.maxMinutes) {
      problems.defaultMinutes = 'The default duration cannot be longer than the longest allowed.'
    }
  }

  if (!roleSatisfies(limits.approver, cap.approver)) {
    problems.approver = `${name} needs a ${APPROVER_LABELS[cap.approver]} or higher to approve it (Agent Action Policy).`
  }

  if (!whole(limits.windowMinutes)) {
    problems.windowMinutes = 'Enter a whole number of minutes to decide, 1 or more.'
  } else if (limits.windowMinutes > cap.windowMinutes) {
    problems.windowMinutes = `A person has ${cap.windowMinutes} min to decide at most (Agent Action Policy), so the time to decide cannot be more than that.`
  }

  if (typeof limits.minRisk !== 'number' || Number.isNaN(limits.minRisk) || limits.minRisk > 100) {
    problems.minRisk = 'Enter a minimum risk from 0 to 100.'
  } else if (limits.minRisk < cap.minRisk) {
    problems.minRisk = `${name} needs a minimum risk of ${cap.minRisk} or more (Agent Action Policy), so the minimum cannot be lower.`
  }

  return problems
}

// The first limit past a cap, in the order the page lists them, or null
export function limitRefusal(name: Tier2ActionName, limits: ApprovalLimits): string | null {
  const problems = limitProblems(name, limits)
  const first = (['maxMinutes', 'defaultMinutes', 'approver', 'windowMinutes', 'minRisk'] as const).find((field) => problems[field])

  return first ? problems[first]! : null
}

// An IP address, or a range such as 198.51.100.0/24
function isBlockTarget(value: string) {
  const [base, bits] = value.split('/')

  return isValidIp(base) && (!value.includes('/') || (/^\d+$/.test(bits) && Number(bits) <= 32))
}

/*
  Why this cannot be added to a protected list, or null when it can: an address or a range for
  Never block, a host name for Never isolate, and not already there (host names ignore case).
*/
export function protectedTargetRefusal(
  kind: 'block' | 'isolate',
  value: string,
  list: ProtectedTarget[],
): string | null {
  const text = value.trim()

  if (!text) {
    return kind === 'block' ? 'Enter an IP address or range.' : 'Enter a host name.'
  }

  if (kind === 'block' && !isBlockTarget(text)) {
    return `${text} is not an IP address or range (for example 198.51.100.7 or 198.51.100.0/24).`
  }

  if (list.some((target) => target.value.toLowerCase() === text.toLowerCase())) {
    return `${text} is already on the ${kind === 'block' ? 'Never block' : 'Never isolate'} list.`
  }

  return null
}

const rowsOfTier = (tier: 1 | 2 | 3) => ACTION_CATALOGUE.filter((row) => row.tier === tier)

/*
  Why this policy cannot be saved, or null when it can. What the PDF fixes
  cannot be changed here: a Tier 2 action is never Automatic and keeps its
  limits within the PDF's caps, a Tier 3 action is always blacklisted, and
  the PDF's protected targets stay on their lists.
*/
// saved is the policy as last saved: its required protected targets must stay. Without it, the
// demo's seeded targets are the required ones.
export function policyRefusal(policy: ResponsePolicy, saved?: ResponsePolicy): string | null {
  for (const entry of policy.whitelist) {
    const row = catalogueRowFor(entry.action)

    if (!row) {
      return `${entry.action} is not in the action catalogue.`
    }

    if (row.tier === 3) {
      return `${entry.action} is a prohibited action and can never be on the whitelist.`
    }

    if (policy.blacklist.some((other) => other.action === entry.action)) {
      return `${entry.action} is on both lists.`
    }

    if (row.tier === 2) {
      if (entry.mode === 'Automatic') {
        return `${entry.action} always needs a person to approve it, so it cannot run automatically (Agent Action Policy).`
      }

      if (!entry.limits) {
        return `${entry.action} needs its approval limits.`
      }

      const problem = limitRefusal(entry.action as Tier2ActionName, entry.limits)

      if (problem) {
        return problem
      }
    } else if (entry.mode === 'Needs approval') {
      return `Needs approval: available later. ${entry.action} can only run automatically for now.`
    }
  }

  for (const row of rowsOfTier(3)) {
    if (!policy.blacklist.some((entry) => entry.action === row.key && entry.required)) {
      return 'The six prohibited actions stay on the blacklist.'
    }
  }

  const lists = [
    ['Never block', policy.neverBlock, saved ? saved.neverBlock.filter((target) => target.required) : PROTECTED_BLOCK_SEEDS],
    ['Never isolate', policy.neverIsolate, saved ? saved.neverIsolate.filter((target) => target.required) : PROTECTED_ISOLATE_SEEDS],
  ] as const

  for (const [title, list, seeds] of lists) {
    if (seeds.some((seed) => !list.some((target) => target.value === seed.value && target.required))) {
      return `The Agent Action Policy's entries stay on the ${title} list.`
    }
  }

  const bad = policy.neverBlock.find((target) => !isBlockTarget(target.value))

  if (bad) {
    return `${bad.value} is not an IP address or range.`
  }

  const emptyHost = policy.neverIsolate.find((target) => !target.value.trim())

  return emptyHost ? 'A host name is needed.' : null
}

const minutesWord = (minutes: number | undefined) => (minutes === undefined ? 'none' : formatMinutes(minutes))

/*
  What changed between two versions of a policy, as old → new lines for the
  audit event ("block_ip: Needs approval → Blacklisted", "isolate_host longest
  allowed: 4 h → 2 h", "Never isolate: added SIEM-02"). Empty when nothing changed.
*/
export function listChanges(before: ResponsePolicy, after: ResponsePolicy): string[] {
  const changes: string[] = []
  const keys = [
    ...new Set([
      ...ACTION_CATALOGUE.map((row) => row.key),
      ...before.whitelist.map((entry) => entry.action),
      ...after.whitelist.map((entry) => entry.action),
      ...before.blacklist.map((entry) => entry.action),
      ...after.blacklist.map((entry) => entry.action),
    ]),
  ]

  for (const key of keys) {
    const was = standingLabel(before, key)
    const now = standingLabel(after, key)

    if (was !== now) {
      changes.push(`${key}: ${was} → ${now}`)
    }

    const oldLimits = whitelistEntry(before, key)?.limits
    const newLimits = whitelistEntry(after, key)?.limits

    if (oldLimits && newLimits) {
      const rows: Array<[string, string, string]> = [
        ['default duration', minutesWord(oldLimits.defaultMinutes), minutesWord(newLimits.defaultMinutes)],
        ['longest allowed', minutesWord(oldLimits.maxMinutes), minutesWord(newLimits.maxMinutes)],
        ['approver', APPROVER_LABELS[oldLimits.approver], APPROVER_LABELS[newLimits.approver]],
        ['time to decide', formatMinutes(oldLimits.windowMinutes), formatMinutes(newLimits.windowMinutes)],
        ['minimum risk', String(oldLimits.minRisk), String(newLimits.minRisk)],
      ]

      for (const [label, old, next] of rows) {
        if (old !== next) {
          changes.push(`${key} ${label}: ${old} → ${next}`)
        }
      }
    }
  }

  const targets = [
    ['Never block', before.neverBlock, after.neverBlock],
    ['Never isolate', before.neverIsolate, after.neverIsolate],
  ] as const

  for (const [title, was, now] of targets) {
    for (const target of now.filter((item) => !was.some((old) => old.value === item.value))) {
      changes.push(`${title}: added ${target.value}`)
    }

    for (const target of was.filter((item) => !now.some((next) => next.value === item.value))) {
      changes.push(`${title}: removed ${target.value}`)
    }
  }

  return changes
}

// The block_ip row's reputation-or-burst condition
function hasBlockEvidence(input: AssessmentInput) {
  const burst = input.failedLogins

  return (
    input.reputation >= REPUTATION_MALICIOUS ||
    (!!burst && burst.count >= 10 && burst.accounts >= 3 && burst.windowMin <= 5)
  )
}

// Why the policy does not let the agent recommend this action, in the words the agent records
function notAllowedByPolicy(policy: ResponsePolicy, name: Tier2ActionName, risk: number) {
  const missing: string[] = []
  const standing = listStanding(policy, name)

  if (standing === 'blacklisted') {
    missing.push(`${name} is on the blacklist`)
  } else if (standing === 'unlisted') {
    missing.push(`${name} is not on the whitelist`)
  } else {
    const minimum = tier2Spec(name, policy).floor.risk

    // Below the PDF's own floor is reported once, as the PDF's number; only a raised minimum is the policy's
    if (minimum > pdfSpec(name).floor.risk && risk < minimum) {
      missing.push(`risk ${risk} is below the policy's minimum of ${minimum}`)
    }
  }

  return missing
}

// Why a Tier 2 outcome's conditions do not hold, or an empty list when they all do
function missingForIsolation(input: AssessmentInput, risk: number, policy: ResponsePolicy) {
  const missing: string[] = []

  if (!input.hostExploitEvidence) {
    missing.push('no exploit, malware or ransomware evidence on the host')
  }

  if (risk < THRESHOLDS.isolate.risk) {
    missing.push(`risk ${risk} is below ${THRESHOLDS.isolate.risk}`)
  }

  if (input.confidence < THRESHOLDS.isolate.confidence) {
    missing.push(`confidence ${input.confidence.toFixed(2)} is below ${THRESHOLDS.isolate.confidence.toFixed(2)}`)
  }

  if (protectedIsolateEntry(policy, input.asset)) {
    missing.push(`${input.asset} is on the Never isolate list`)
  }

  missing.push(...notAllowedByPolicy(policy, 'isolate_host', risk))

  return missing
}

function missingForBlock(input: AssessmentInput, risk: number, policy: ResponsePolicy) {
  const missing: string[] = []

  if (!input.sourceIp || !isValidIp(input.sourceIp)) {
    missing.push('no source IP to block')
  } else if (isAllowListed(input.sourceIp)) {
    missing.push(`${input.sourceIp} is internal or on the allow-list`)
  } else if (protectedBlockEntry(policy, input.sourceIp)) {
    missing.push(`${input.sourceIp} is on the Never block list`)
  }

  if (!hasBlockEvidence(input)) {
    missing.push(
      `reputation ${input.reputation.toFixed(2)} is below ${REPUTATION_MALICIOUS.toFixed(2)} and there is no burst of 10 or more failed logins across 3 or more accounts in 5 min`,
    )
  }

  if (risk < THRESHOLDS.block.risk) {
    missing.push(`risk ${risk} is below ${THRESHOLDS.block.risk}`)
  }

  if (input.confidence < THRESHOLDS.block.confidence) {
    missing.push(`confidence ${input.confidence.toFixed(2)} is below ${THRESHOLDS.block.confidence.toFixed(2)}`)
  }

  missing.push(...notAllowedByPolicy(policy, 'block_ip', risk))

  return missing
}

const LADDER: Outcome[] = [
  'recommend_host_isolation',
  'recommend_block_ip',
  'create_alert_and_ticket',
  'investigate_further',
  'monitor',
]

/*
  The agent ends at exactly one outcome. Checked from the highest down;
  an outcome is taken only if every condition in its row holds,
  otherwise the agent falls to the next one below. Low confidence (under
  0.50) sends anything of risk 40 or more to "investigate further".
  A Critical asset is never isolated: it becomes a ticket plus an
  escalation. Every other outcome is recorded with the reason it was
  not chosen.
*/
export function assess(input: AssessmentInput, policy: ResponsePolicy = DEFAULT_POLICY): Assessment {
  const breakdown = scoreRisk(input)
  const { risk } = breakdown
  const { confidence } = input

  const isolation = missingForIsolation(input, risk, policy)
  const block = missingForBlock(input, risk, policy)

  // Isolation would otherwise qualify, but the asset is Critical
  const criticalEscalation =
    input.assetClass === 'Critical' &&
    input.hostExploitEvidence &&
    risk >= THRESHOLDS.isolate.risk &&
    confidence >= THRESHOLDS.isolate.confidence

  let outcome: Outcome
  let escalation: string | undefined

  if (isolation.length === 0 && input.assetClass !== 'Critical') {
    outcome = 'recommend_host_isolation'
  } else if (block.length === 0) {
    outcome = 'recommend_block_ip'
  } else if (confidence < THRESHOLDS.lowConfidence && risk >= THRESHOLDS.investigateRisk) {
    outcome = 'investigate_further'
  } else if (risk >= THRESHOLDS.ticketRisk) {
    outcome = 'create_alert_and_ticket'
  } else if (risk >= THRESHOLDS.investigateRisk) {
    outcome = 'investigate_further'
  } else {
    outcome = 'monitor'
  }

  if (criticalEscalation) {
    escalation = `${input.asset} is a Critical asset: the agent raises a ticket and escalates to a person, and never isolates it.`

    if (LADDER.indexOf(outcome) < LADDER.indexOf('create_alert_and_ticket')) {
      outcome = 'create_alert_and_ticket'
    }
  }

  const chosen = LADDER.indexOf(outcome)

  const alternatives: RejectedOutcome[] = LADDER.filter((item) => item !== outcome).map((item) => {
    const above = LADDER.indexOf(item) < chosen
    let reason: string

    if (item === 'recommend_host_isolation') {
      reason = criticalEscalation
        ? 'Critical asset: never isolated, becomes a ticket plus escalation'
        : above
          ? `Not met: ${isolation.join('; ')}`
          : 'Not needed'
    } else if (item === 'recommend_block_ip') {
      reason = above ? `Not met: ${block.join('; ')}` : 'Not needed'
    } else if (above && item === 'create_alert_and_ticket') {
      reason = `Not chosen: ${
        risk < THRESHOLDS.ticketRisk
          ? `risk ${risk} is below ${THRESHOLDS.ticketRisk}`
          : `confidence ${confidence.toFixed(2)} is below ${THRESHOLDS.lowConfidence.toFixed(2)}, so the agent investigates first`
      }`
    } else if (above) {
      reason = `Not chosen: risk ${risk} is below ${THRESHOLDS.investigateRisk}`
    } else {
      reason = `Rejected: risk ${risk} and confidence ${confidence.toFixed(2)} call for a stronger response`
    }

    return { outcome: item, direction: above ? ('higher' as const) : ('lower' as const), reason }
  })

  let proposal: Tier2Proposal | undefined

  if (outcome === 'recommend_block_ip' && input.sourceIp) {
    proposal = {
      name: 'block_ip',
      params: { ip: input.sourceIp, duration_min: tier2Spec('block_ip', policy).defaultMinutes! },
    }
  }

  if (outcome === 'recommend_host_isolation') {
    proposal = {
      name: 'isolate_host',
      params: {
        host: input.asset,
        path: 'edr_network_isolation',
        duration_min: tier2Spec('isolate_host', policy).defaultMinutes!,
      },
    }
  }

  return {
    alertId: input.alertId,
    risk,
    breakdown,
    confidence,
    confidenceBand: confidenceBand(confidence),
    outcome,
    alternativesConsidered: alternatives,
    proposal,
    escalation,
    rationale: `${OUTCOME_LABELS[outcome]}: risk ${risk}/100, confidence ${confidence.toFixed(2)} (${confidenceBand(confidence).toLowerCase()}).`,
  }
}

// ===== Durations: an approver may only make an action safer =====

export type DurationCheck = { ok: boolean; minutes: number; reason?: string }

/*
  `limit` is the longest allowed time: the policy's, unless the caller gives
  the one the request was checked against (its snapshot's maxMinutes).
*/
export function checkDurationChange(
  name: Tier2ActionName,
  recommendedMinutes: number,
  requestedMinutes: number,
  limit: number | undefined = tier2Spec(name).maxMinutes,
): DurationCheck {
  if (!Number.isInteger(requestedMinutes) || requestedMinutes < 1) {
    return { ok: false, minutes: recommendedMinutes, reason: 'Enter a whole number of minutes, 1 or more.' }
  }

  if (requestedMinutes > recommendedMinutes) {
    return {
      ok: false,
      minutes: recommendedMinutes,
      reason: `A duration can only be shortened: ${recommendedMinutes} min is the most you can approve.`,
    }
  }

  if (limit !== undefined && requestedMinutes > limit) {
    return {
      ok: false,
      minutes: recommendedMinutes,
      reason: `${name} can never run longer than ${limit} min.`,
    }
  }

  return { ok: true, minutes: requestedMinutes }
}

// ===== Approval =====

export function roleSatisfies(role: ApproverRole, required: ApproverRole) {
  return ROLE_RANK[role] >= ROLE_RANK[required]
}

// Why this person may not approve the recommendation, or null when they may
export function approvalRefusal(
  recommendation: Pick<Recommendation, 'action' | 'requestedBy'>,
  approverId: string,
  approverRole: ApproverRole,
  policy: ResponsePolicy = DEFAULT_POLICY,
): string | null {
  if (recommendation.requestedBy === approverId) {
    return 'You requested this action, so you cannot approve it.'
  }

  const required = tier2Spec(recommendation.action.name, policy).approver

  if (!roleSatisfies(approverRole, required)) {
    return `This action needs a ${required === 'soc_lead' ? 'SOC lead' : 'SOC analyst'} to approve it.`
  }

  return null
}

// ===== Hashing (Web Crypto) =====

// Same text, same JSON: object keys sorted, so a digest does not depend on key order
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`
  }

  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>

    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(',')}}`
  }

  return JSON.stringify(value)
}

export async function sha256Hex(text: string) {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)

  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

// The exact action an approval covers: name and every parameter
export function actionDigest(action: Tier2Proposal) {
  return sha256Hex(canonicalJson({ name: action.name, params: action.params }))
}

// ===== Time: "2026-08-03T15:45:00" strings, read and written as UTC so they compare the same everywhere =====

export function parseTime(time: string) {
  return Date.parse(time.endsWith('Z') ? time : `${time}Z`)
}

export function addMinutes(time: string, minutes: number) {
  return new Date(parseTime(time) + minutes * 60_000).toISOString().slice(0, 19)
}

// "2026-08-03T15:59:30" to "15:59"
export function clockOf(time: string) {
  return time.slice(11, 16)
}

export type WindowState = { open: boolean; label: string }

/*
  How long a request has left, as of `now` (always passed in, never read
  from the clock): "13 min left", "40 s left", or "Overdue" once the
  deadline has passed.
*/
export function windowState(deadline: string, now: string): WindowState {
  const left = parseTime(deadline) - parseTime(now)

  if (left < 0) {
    return { open: false, label: 'Overdue' }
  }

  const minutes = Math.floor(left / 60_000)

  return { open: true, label: minutes > 0 ? `${minutes} min left` : `${Math.floor(left / 1000)} s left` }
}

export type TokenState = 'Unused' | 'Used' | 'Expired'

// A used token stays Used; an unused one expires with its time
export function tokenState(token: ApprovalToken, now: string): TokenState {
  if (token.usedAt) {
    return 'Used'
  }

  return parseTime(now) > parseTime(token.expiresAt) ? 'Expired' : 'Unused'
}

// ===== Approval tokens: single-use, bound to one recommendation and its exact action =====

export async function issueToken(options: {
  recommendation: Recommendation
  // The action as approved; a shorter duration for "approve with changes"
  approvedAction: Tier2Proposal
  approverId: string
  approverRole: ApproverRole
  now: string
  ttlMinutes?: number
  // A readable id (TKN-002); a random one when none is given
  id?: string
}): Promise<ApprovalToken> {
  const { recommendation, approvedAction, approverId, approverRole, now, ttlMinutes = 5 } = options

  return {
    id: options.id ?? crypto.randomUUID(),
    recommendationId: recommendation.id,
    paramsDigest: await actionDigest(approvedAction),
    approverId,
    approverRole,
    issuedAt: now,
    expiresAt: addMinutes(now, ttlMinutes),
  }
}

// Marks a token used; a used token never passes the guard again
export function consumeToken(tokens: ApprovalToken[], tokenId: string, now: string): ApprovalToken[] {
  return tokens.map((token) => (token.id === tokenId && !token.usedAt ? { ...token, usedAt: now } : token))
}

// ===== Approval records =====

const accepted: ApprovalCheck = { ok: true, code: 'ok', reason: 'The record follows the policy.' }

const broken = (code: ApprovalCheck['code'], reason: string): ApprovalCheck => ({ ok: false, code, reason })

const minutesOf = (action: Tier2Proposal) => Number(action.params.duration_min)

// Everything but the duration, which an approver may shorten
const fixedParams = (action: Tier2Proposal) =>
  canonicalJson({
    name: action.name,
    params: Object.fromEntries(Object.entries(action.params).filter(([key]) => key !== 'duration_min')),
  })

/*
  Checks one approval record, its token and the executions that used
  it against the policy, and returns the first rule it breaks. A
  request still pending, or timed out, carries no decision, token or
  execution. A rejection needs a reason. An approval needs a token
  bound to this recommendation and to exactly the approved action, and
  one execution at most may consume it, between the decision and the
  token's expiry.
*/
export async function validateApprovalRecord(
  record: ApprovalRecord,
  token: ApprovalToken | undefined,
  executions: ExecutionFacts[],
): Promise<ApprovalCheck> {
  const { recommendation, decision } = record
  // The PDF's own row, and the rule the response policy had for this action when the request was checked
  const spec = pdfSpec(recommendation.action.name)
  const rule = record.policy

  if (record.requiredRole !== rule.approver) {
    return broken('role_mismatch', `${spec.name} needs a ${rule.approver === 'soc_lead' ? 'SOC lead' : 'SOC analyst'}.`)
  }

  if (!roleSatisfies(rule.approver, spec.approver)) {
    return broken(
      'mode_not_allowed',
      `Response policy v${rule.version} lets a ${APPROVER_LABELS[rule.approver]} approve ${spec.name}, which needs a ${APPROVER_LABELS[spec.approver]}.`,
    )
  }

  if (decision === 'Pending' || decision === 'Timed out') {
    return record.decidedBy || record.decidedAt || record.approvedAction || record.tokenId || record.executionId || token || executions.length > 0
      ? broken('unexpected_fields', `A ${decision.toLowerCase()} request has no decision, token or execution.`)
      : accepted
  }

  const { decidedBy, decidedAt } = record

  if (!decidedBy || !decidedAt) {
    return broken('missing_decision', 'A decision names who decided and when.')
  }

  if (recommendation.requestedBy === decidedBy.id) {
    return broken('self_approval', 'The person who requested an action cannot decide on it.')
  }

  if (!roleSatisfies(decidedBy.role, rule.approver)) {
    return broken('wrong_role', `${spec.name} needs a ${rule.approver === 'soc_lead' ? 'SOC lead' : 'SOC analyst'} to decide.`)
  }

  if (parseTime(decidedAt) < parseTime(recommendation.createdAt)) {
    return broken('before_request', 'The decision is earlier than the request.')
  }

  if (parseTime(decidedAt) > parseTime(recommendation.approvalDeadline)) {
    return broken('after_deadline', 'The decision came after the approval window closed.')
  }

  if (decision === 'Rejected') {
    if (!record.reason?.trim()) {
      return broken('reason_required', 'A rejection needs a reason.')
    }

    return record.approvedAction || record.tokenId || record.executionId || token || executions.length > 0
      ? broken('unexpected_fields', 'A rejection issues no token and runs nothing.')
      : accepted
  }

  const approved = record.approvedAction

  if (!approved) {
    return broken('missing_decision', 'An approval names the action that was approved.')
  }

  if (fixedParams(approved) !== fixedParams(recommendation.action)) {
    return broken('action_changed', 'An approver can shorten the duration but cannot change anything else.')
  }

  if (!record.reason?.trim()) {
    return broken('reason_required', 'An approval needs a reason.')
  }

  const recommended = minutesOf(recommendation.action)
  const minutes = minutesOf(approved)

  if (rule.maxMinutes !== undefined && minutes > rule.maxMinutes) {
    return broken('duration_over_max', `${spec.name} can never run longer than ${rule.maxMinutes} min.`)
  }

  if (!checkDurationChange(spec.name, recommended, minutes, rule.maxMinutes).ok) {
    return broken('duration_not_shorter', 'An approved duration can only be shorter than the recommended one.')
  }

  if (minutes !== recommended && !record.reason?.trim()) {
    return broken('reason_required', 'Shortening the duration needs a reason.')
  }

  if (!record.tokenId || !token || token.id !== record.tokenId) {
    return broken('no_token', 'An approval carries the token it issued.')
  }

  if (
    token.recommendationId !== recommendation.id ||
    token.approverId !== decidedBy.id ||
    token.approverRole !== decidedBy.role ||
    token.issuedAt !== decidedAt ||
    parseTime(token.expiresAt) <= parseTime(token.issuedAt)
  ) {
    return broken('token_mismatch', 'The token does not match this recommendation and decision.')
  }

  if (token.paramsDigest !== (await actionDigest(approved))) {
    return broken('digest_mismatch', 'The token is bound to a different action than the one approved.')
  }

  if (executions.length > 1) {
    return broken('multiple_executions', 'One approval token runs one action once.')
  }

  const [run] = executions

  if (!run) {
    return token.usedAt || record.executionId
      ? broken('token_used_without_execution', 'The token is marked used but no execution is recorded.')
      : accepted
  }

  if (run.approvalId !== record.id || record.executionId !== run.id) {
    return broken('execution_changed', 'The execution is not the one this approval was for.')
  }

  if (!token.usedAt || token.usedAt !== run.startedAt) {
    return broken('execution_without_token', 'The execution did not use up the token.')
  }

  if (parseTime(run.startedAt) < parseTime(decidedAt) || parseTime(run.startedAt) > parseTime(token.expiresAt)) {
    return broken('execution_outside_token', 'The execution ran before the decision or after the token expired.')
  }

  if (token.paramsDigest !== (await actionDigest(run.action))) {
    return broken('execution_changed', 'The action that ran differs from the one approved.')
  }

  if (run.expiresAt !== addMinutes(run.startedAt, minutes)) {
    return broken('wrong_expiry', `The action should reverse ${minutes} min after it started.`)
  }

  return accepted
}

// ===== The policy guard =====

const refuse = (code: GuardResult['code'], reason: string): GuardResult => ({ allowed: false, code, reason })

// The catalogue row for a requested function name, or undefined when it is not in the catalogue
export function catalogueRowFor(actionName: string) {
  return ACTION_CATALOGUE.find((row) => row.key === actionName)
}

// "Tier 2 - block_ip(ip, duration) - PDF p.4": the rule a decision came from
export function ruleLabel(row: CatalogueRow) {
  return `Tier ${row.tier} · ${row.action} · ${row.source}`
}

type StaticResult = { guard: GuardResult; row?: CatalogueRow }

/*
  The first half of every decision, shared by the guard and by Demo mode's
  "Simulate an attempt" so the two cannot disagree: Tier 3 is refused, an
  unknown name is refused, an action on the blacklist or on neither list is
  refused, Tier 1 is allowed. A Tier 2 action carries on to tier2Checks
  (after the guard's token checks).
*/
function tierCheck(actionName: string, policy: ResponsePolicy): StaticResult & { spec?: Tier2Action } {
  const row = catalogueRowFor(actionName)

  if (row?.tier === 3) {
    return { row, guard: refuse('prohibited', `${actionName} is a prohibited action and is never executed.`) }
  }

  if (!row) {
    return { guard: refuse('not_in_catalogue', `${actionName} is not in the action catalogue.`) }
  }

  const standing = listStanding(policy, actionName)

  if (standing === 'blacklisted') {
    return { row, guard: refuse('blacklisted', `${actionName} is on the response policy's blacklist, so it is never executed.`) }
  }

  if (standing === 'unlisted') {
    return {
      row,
      guard: refuse('not_listed', `${actionName} is not on the response policy's whitelist, so it is denied.`),
    }
  }

  if (row.tier === 1) {
    return { row, guard: { allowed: true, code: 'ok', reason: 'Tier 1: allowed without approval.' } }
  }

  return {
    row,
    spec: tier2Spec(actionName as Tier2ActionName, policy),
    guard: { allowed: true, code: 'ok', reason: 'Tier 2: needs a human approval.' },
  }
}

// A Tier 1 action the policy has set to Needs approval (not available yet: the page keeps Tier 1 on Automatic)
const tier1NeedsApproval = (policy: ResponsePolicy, row: CatalogueRow) =>
  row.tier === 1 && whitelistEntry(policy, row.key)?.mode === 'Needs approval'

type Tier2Request = Pick<GuardRequest, 'params' | 'riskScore' | 'confidence' | 'assetClass' | 'privilegedAccount'>

// The second half: a Tier 2 action's own limits, in this order. Null when every one holds.
function tier2Checks(spec: Tier2Action, request: Tier2Request, policy: ResponsePolicy): GuardResult | null {
  const { params } = request
  const minutes = Number(params.duration_min)

  if (spec.maxMinutes !== undefined && (Number.isNaN(minutes) || minutes > spec.maxMinutes)) {
    return refuse('duration_over_max', `${spec.name} can never run longer than ${spec.maxMinutes} min.`)
  }

  if (
    (request.riskScore !== undefined && request.riskScore < spec.floor.risk) ||
    (request.confidence !== undefined && request.confidence < spec.floor.confidence)
  ) {
    // A minimum the policy raised above the PDF's floor is the policy's own, and says so
    const raised = spec.floor.risk > pdfSpec(spec.name).floor.risk

    if (raised && request.riskScore !== undefined && request.riskScore < spec.floor.risk) {
      return refuse(
        'below_threshold',
        `Risk ${request.riskScore} is below the response policy's minimum risk of ${spec.floor.risk} for ${spec.name}.`,
      )
    }

    return refuse('below_threshold', `Risk or confidence is below the ${spec.name} thresholds.`)
  }

  if (spec.name === 'block_ip') {
    const ip = String(params.ip ?? '')

    if (isInternalIp(ip)) {
      return refuse('internal_ip', `${ip} is an internal address and can never be blocked.`)
    }

    if (!isBlockableIp(ip)) {
      return refuse('allow_listed', `${ip} is on the allow-list (or not a valid IP) and can never be blocked.`)
    }

    // The administrator's own Never block entries (the PDF's are the allow-list above)
    const protectedEntry = protectedBlockEntry(policy, ip)

    if (protectedEntry) {
      return refuse('protected_target', `${ip} is on the Never block list (${protectedEntry.label}) and can never be blocked.`)
    }
  }

  if (spec.name === 'isolate_host') {
    if (request.assetClass === 'Critical') {
      return refuse('critical_asset', 'A Critical asset is never isolated by the agent.')
    }

    const host = String(params.host ?? '')
    const protectedEntry = protectedIsolateEntry(policy, host)

    if (protectedEntry) {
      return refuse('protected_target', `${host} is on the Never isolate list (${protectedEntry.label}) and can never be isolated.`)
    }
  }

  if (spec.name === 'kill_process' && request.assetClass === 'Critical') {
    return refuse('critical_asset', 'A process on a Critical asset is never killed by the agent.')
  }

  if (spec.name === 'suspend_user_session' && request.privilegedAccount) {
    return refuse('privileged_account', 'A privileged account is never suspended by the agent.')
  }

  if (spec.name === 'reset_password' && request.privilegedAccount) {
    return refuse('privileged_account', 'The password of a privileged account is never reset by the agent.')
  }

  return null
}

// The response policy's list a refusal came from, added to the catalogue rule ("... · Response policy: Blacklist")
function withList(rule: string, code: GuardResult['code'], request: AttemptRequest) {
  if (code === 'not_listed') {
    return `${rule} · Response policy: not on either list`
  }

  if (code === 'blacklisted') {
    return `${rule} · Response policy: Blacklist`
  }

  if (code === 'protected_target') {
    return `${rule} · Response policy: ${request.actionName === 'block_ip' ? 'Never block' : 'Never isolate'}`
  }

  return rule
}

/*
  What would happen if the agent tried this action now. It runs the same
  checks as the guard, but a Tier 2 action with every check passing is
  "needs approval" (what the agent may do: recommend it) instead of "no
  token" (what the executor refuses). Pure: it changes nothing, reads no
  clock and executes nothing.
*/
export function attemptDecision(request: AttemptRequest, policy: ResponsePolicy = DEFAULT_POLICY): AttemptDecision {
  const first = tierCheck(request.actionName, policy)
  const none = { executed: false } as const

  if (!first.row) {
    return {
      ...none,
      decision: 'refused',
      code: first.guard.code,
      reason: first.guard.reason,
      rule: 'Anything outside the catalogue is refused · PDF p.5',
    }
  }

  const rule = ruleLabel(first.row)

  // Prohibited, blacklisted or on neither list
  if (!first.guard.allowed) {
    return { ...none, decision: 'refused', code: first.guard.code, reason: first.guard.reason, rule: withList(rule, first.guard.code, request) }
  }

  if (tier1NeedsApproval(policy, first.row)) {
    return {
      ...none,
      decision: 'needs_approval',
      code: 'needs_approval',
      reason: `${first.row.key} is set to Needs approval in the response policy. A Tier 1 request cannot reach the approval queue yet, so it does not run.`,
      rule,
      approver: 'soc_analyst',
      approvalWindowMinutes: 15,
    }
  }

  if (first.row.tier === 1) {
    return { ...none, decision: 'allowed', code: 'ok', reason: first.guard.reason, rule }
  }

  const spec = first.spec!
  const refusal = tier2Checks(spec, request, policy)

  if (refusal) {
    return { ...none, decision: 'refused', code: refusal.code, reason: refusal.reason, rule: withList(rule, refusal.code, request) }
  }

  return {
    ...none,
    decision: 'needs_approval',
    code: 'needs_approval',
    reason: `${spec.name} is a Tier 2 action: it runs only after a ${APPROVER_LABELS[spec.approver]} approves it within ${spec.approvalWindowMinutes} min.`,
    rule,
    approver: spec.approver,
    approvalWindowMinutes: spec.approvalWindowMinutes,
  }
}

/*
  Whether the policy as it stands now still lets this recommendation be
  decided or run: the same checks as an attempt (lists, protected targets,
  minimum risk, the PDF's rules). The duration is not held against it: an
  approver can shorten it, so it is checked at the policy's longest time.
  Null when it still qualifies.
*/
export function requestPolicyRefusal(
  recommendation: Pick<Recommendation, 'action' | 'riskScore' | 'confidence'>,
  assetClass: AttemptRequest['assetClass'],
  policy: ResponsePolicy = DEFAULT_POLICY,
): { code: GuardResult['code']; reason: string } | null {
  const { name, params } = recommendation.action
  const longest = tier2Spec(name, policy).maxMinutes
  const minutes = Number(params.duration_min)
  const decision = attemptDecision(
    {
      actionName: name,
      params: longest !== undefined && minutes > longest ? { ...params, duration_min: longest } : params,
      riskScore: recommendation.riskScore,
      confidence: recommendation.confidence,
      assetClass,
    },
    policy,
  )

  return decision.decision === 'refused' ? { code: decision.code as GuardResult['code'], reason: decision.reason } : null
}

/*
  Sits between the agent and every executor. Anything outside Tier 1 or
  an approved Tier 2 action is rejected. A Tier 2 action needs a valid
  token: unused, issued for this recommendation, bound to exactly these
  parameters, unexpired, from the right role and not from the person who
  asked for it. The guard only checks; the caller consumes the token.
*/
export async function guard(
  request: GuardRequest,
  tokens: ApprovalToken[],
  policy: ResponsePolicy = DEFAULT_POLICY,
): Promise<GuardResult> {
  const { actionName, params } = request
  const first = tierCheck(actionName, policy)
  const { spec } = first

  if (first.row && tier1NeedsApproval(policy, first.row)) {
    return refuse('no_token', `${actionName} is set to Needs approval, which has no approval path yet.`)
  }

  if (!spec) {
    return first.guard
  }

  const token = tokens.find((item) => item.id === request.tokenId)

  if (!request.tokenId || !token) {
    return refuse('no_token', `${actionName} needs a human approval token.`)
  }

  if (token.usedAt) {
    return refuse('token_reused', 'This approval was already used. Each approval runs one action once.')
  }

  if (token.recommendationId !== request.recommendationId) {
    return refuse('wrong_recommendation', 'This approval belongs to a different recommendation.')
  }

  if (parseTime(request.now) > parseTime(token.expiresAt)) {
    return refuse('token_expired', 'This approval has expired.')
  }

  if (token.paramsDigest !== (await actionDigest({ name: spec.name, params }))) {
    return refuse('params_changed', 'The action differs from what was approved.')
  }

  if (!roleSatisfies(token.approverRole, spec.approver)) {
    return refuse('wrong_role', `${actionName} needs a ${spec.approver === 'soc_lead' ? 'SOC lead' : 'SOC analyst'}.`)
  }

  if (request.requestedBy && request.requestedBy === token.approverId) {
    return refuse('self_approval', 'The person who requested an action cannot approve it.')
  }

  return tier2Checks(spec, request, policy) ?? { allowed: true, code: 'ok', reason: 'Approved Tier 2 action.' }
}

// ===== Audit hash chain =====

export const GENESIS_HASH = '0'.repeat(64)

// Each record's hash covers its own fields and the previous record's hash
export async function hashRecord(body: Record<string, unknown>, prevHash: string) {
  return sha256Hex(`${prevHash}|${canonicalJson(body)}`)
}

// Oldest first
export async function buildChain(bodies: Record<string, unknown>[]): Promise<ChainRecord[]> {
  const chain: ChainRecord[] = []
  let prev = GENESIS_HASH

  for (const body of bodies) {
    const hash = await hashRecord(body, prev)
    chain.push({ body, prev_hash: prev, hash })
    prev = hash
  }

  return chain
}

export async function verifyChain(chain: ChainRecord[]): Promise<ChainVerification> {
  let prev = GENESIS_HASH

  for (let index = 0; index < chain.length; index += 1) {
    const record = chain[index]

    if (record.prev_hash !== prev || record.hash !== (await hashRecord(record.body, prev))) {
      return { ok: false, count: chain.length, brokenAt: index }
    }

    prev = record.hash
  }

  return { ok: true, count: chain.length }
}
