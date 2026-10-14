import type {
  Actor,
  ApprovalRecord,
  ExecutionFacts,
  FlowEvent,
  FlowResult,
  FlowState,
} from '../types/approvalTypes'
import type { ExecutionRecord } from '../types/incidentResponseTypes'
import type { AuditRecordFields } from '../types/auditLogsTypes'
import type { AttemptDecision, AttemptRequest, Tier2Proposal } from '../types/policyTypes'
import type { ResponsePolicy } from '../types/responsePoliciesTypes'

import { APPROVER_LABELS, assessmentInputs } from './agentPolicyData'
import { eventTypeOf } from './auditEventTypes'
import {
  addMinutes,
  attemptDecision,
  catalogueRowFor,
  checkDurationChange,
  clockOf,
  consumeToken,
  DEFAULT_POLICY,
  guard,
  issueToken,
  parseTime,
  policyLabel,
  policySnapshot,
  requestPolicyRefusal,
  roleSatisfies,
  validateApprovalRecord,
  windowState,
} from './policyEngine'
import { initialUsers } from './userManagementData'

/*
  The approval flow as pure functions: a person decides on a request,
  the executor starts and uses up the token, then finishes. Each takes a
  FlowState and returns the next one with the audit events it caused.
  No React and no real clock: "now" is state.now, and every step moves
  it on by a fixed number of seconds, so the times are the demo clock's.
*/

// A step the executor takes, in seconds on the demo clock
export const STEP_SECONDS = 10
// How long the action itself takes, exactly, so a run always lasts "1 minute"
export const RUN_SECONDS = 60

// How long each executor step stays on screen (Approved, then Executing, then Done); a pause for the
// eye, never compared with any time
export const STEP_HOLD_MS = 700

export type DecisionKind = 'approve' | 'modify' | 'reject'

export type DecisionInput = {
  approvalId: string
  actor: Actor
  kind: DecisionKind
  reason: string
  // Modify only: the shorter duration, in minutes
  minutes?: number
}

const refused = (code: string, reason: string): FlowResult => ({ ok: false, code, reason })

function addSeconds(time: string, seconds: number) {
  return new Date(parseTime(time) + seconds * 1000).toISOString().slice(0, 19)
}

// "TKN-002" after the highest TKN- number in use
export function nextNumber(prefix: string, ids: string[]) {
  const highest = ids.reduce((max, id) => {
    const number = Number(id.replace(`${prefix}-`, ''))
    return Number.isNaN(number) ? max : Math.max(max, number)
  }, 0)

  return `${prefix}-${String(highest + 1).padStart(3, '0')}`
}

// Who asked, in words: the agent, or the person (their user id is stored, their name is shown)
export const requesterName = (requestedBy: string) =>
  requestedBy === 'agent' ? 'AthenaSec AI' : (initialUsers.find((user) => user.id === requestedBy)?.name ?? requestedBy)

// "Block 203.0.113.45" or "Isolate endpoint-12"
export function approvalActionTitle(approval: ApprovalRecord) {
  const { name, params } = approval.recommendation.action

  if (name === 'block_ip') {
    return `Block ${params.ip}`
  }

  return name === 'isolate_host' ? `Isolate ${params.host}` : `Suspend ${params.user}`
}

const appRole = (actor: Actor) => (actor.role === 'soc_lead' ? ('Administrator' as const) : ('Analyst' as const))

// Adds the policy PDF's event type to an event the flow writes (none for the supporting events it has no type for)
function typed(event: FlowEvent): FlowEvent {
  const eventType = eventTypeOf(event.action)

  return eventType ? { ...event, eventType } : event
}

type RecordActor = { id: string; role: AuditRecordFields['actor_role'] }

const AGENT: RecordActor = { id: 'agent', role: 'agent' }
const personOf = (actor: Actor): RecordActor => ({ id: actor.id, role: actor.role })

// The PDF's record fields (page 9) for an event about a request, from the request itself
function recordOf(approval: ApprovalRecord, by: RecordActor, extra: Partial<AuditRecordFields> = {}): AuditRecordFields {
  const { recommendation } = approval

  return {
    recommendation_id: recommendation.id,
    alert_id: recommendation.alertId,
    policy_id: `response-policy-v${approval.policy.version}`,
    actor: by.id,
    actor_role: by.role,
    tier: 2,
    outcome: recommendation.outcome,
    action: recommendation.action.name,
    params: recommendation.action.params,
    evidence: recommendation.evidence,
    risk_score: recommendation.riskScore,
    confidence: recommendation.confidence,
    ...extra,
  }
}

/*
  Why this person cannot decide on this request right now, or null when
  they can. The buttons use it for their reason text, and decide() asks
  it again, so the rule holds even when a handler is called directly.
*/
export function decisionRefusal(
  approval: ApprovalRecord,
  actor: Actor,
  now: string,
  policy?: ResponsePolicy,
): { code: string; reason: string } | null {
  if (approval.decision !== 'Pending') {
    return { code: 'not_pending', reason: `This request was already ${approval.decision.toLowerCase()}.` }
  }

  const { recommendation } = approval

  // The policy as it stands now: a request it no longer allows (blacklisted, off the whitelist,
  // a protected target, below the minimum risk) cannot be approved
  const lapsed = requestPolicyRefusal(recommendation, assetClassOf(recommendation.alertId), policy)

  if (lapsed) {
    return { code: lapsed.code, reason: `The response policy no longer allows this: ${lapsed.reason}` }
  }

  if (recommendation.requestedBy === actor.id) {
    return { code: 'self_approval', reason: 'You requested this action, so you cannot decide on it.' }
  }

  if (!roleSatisfies(actor.role, approval.requiredRole)) {
    return {
      code: 'wrong_role',
      reason: `Only a ${APPROVER_LABELS[approval.requiredRole]} can decide this request.`,
    }
  }

  if (!windowState(recommendation.approvalDeadline, now).open) {
    return {
      code: 'window_closed',
      reason: `The approval window closed at ${clockOf(recommendation.approvalDeadline)}.`,
    }
  }

  return null
}

// The class of the asset an alert is about, which the guard's Critical-asset rule needs
const assetClassOf = (alertId: string) => assessmentInputs.find((input) => input.alertId === alertId)?.assetClass

function replaceApproval(state: FlowState, record: ApprovalRecord) {
  return state.approvals.map((item) => (item.id === record.id ? record : item))
}

// Approve, modify (shorten) or reject a pending request
export async function decide(state: FlowState, input: DecisionInput, policy?: ResponsePolicy): Promise<FlowResult> {
  const { actor, kind } = input
  const approval = state.approvals.find((item) => item.id === input.approvalId)

  if (!approval) {
    return refused('unknown_request', 'There is no such request.')
  }

  const refusal = decisionRefusal(approval, actor, state.now, policy)

  if (refusal) {
    return refused(refusal.code, refusal.reason)
  }

  const reason = input.reason.trim()

  if (!reason) {
    return refused('reason_required', `Enter a reason to ${kind === 'reject' ? 'reject' : 'approve'} this request.`)
  }

  const { recommendation } = approval
  const recommended = Number(recommendation.action.params.duration_min)
  const title = approvalActionTitle(approval)
  const decidedBy = { id: actor.id, name: actor.name, role: actor.role }
  const base = {
    at: state.now,
    user: actor.name,
    role: appRole(actor),
    sourceIp: actor.sourceIp,
    target: `${approval.id} · ${title}`,
  }
  const metadata = {
    'Approval ID': approval.id,
    'Recommendation ID': recommendation.id,
    'Alert ID': recommendation.alertId,
    Policy: `Response policy version ${approval.policy.version}`,
    Reason: reason,
  }

  if (kind === 'reject') {
    const record: ApprovalRecord = { ...approval, decision: 'Rejected', decidedBy, decidedAt: state.now, reason }
    const check = await validateApprovalRecord(record, undefined, [])

    if (!check.ok) {
      return refused(check.code, check.reason)
    }

    const event: FlowEvent = typed({
      ...base,
      action: 'Rejected action',
      description: `${actor.name} rejected the recommendation to ${title.toLowerCase()}. Nothing ran and no token was issued.`,
      changes: ['Decision: Pending → Rejected'],
      metadata,
      record: recordOf(approval, personOf(actor), {
        decision: 'rejected',
        decision_reason: reason,
        execution_result: 'not_executed',
      }),
    })

    return { ok: true, state: { ...state, approvals: replaceApproval(state, record), events: [...state.events, event] } }
  }

  let approvedAction: Tier2Proposal = recommendation.action

  if (kind === 'modify') {
    const minutes = input.minutes ?? Number.NaN
    const check = checkDurationChange(recommendation.action.name, recommended, minutes, approval.policy.maxMinutes)

    if (!check.ok) {
      return refused('duration_not_shorter', check.reason ?? 'Enter a shorter duration.')
    }

    if (minutes === recommended) {
      return refused('duration_not_shorter', `Modify needs a duration shorter than the recommended ${recommended} min.`)
    }

    approvedAction = { ...recommendation.action, params: { ...recommendation.action.params, duration_min: minutes } }
  }

  const tokenId = nextNumber('TKN', state.tokens.map((token) => token.id))
  const token = await issueToken({
    id: tokenId,
    recommendation,
    approvedAction,
    approverId: actor.id,
    approverRole: actor.role,
    now: state.now,
  })
  const record: ApprovalRecord = {
    ...approval,
    decision: 'Approved',
    decidedBy,
    decidedAt: state.now,
    reason,
    approvedAction,
    tokenId,
  }
  const check = await validateApprovalRecord(record, token, [])

  if (!check.ok) {
    return refused(check.code, check.reason)
  }

  const minutes = Number(approvedAction.params.duration_min)
  const changes = ['Decision: Pending → Approved']

  if (minutes !== recommended) {
    changes.push(`Duration: ${recommended} → ${minutes} min`)
  }

  changes.push(`Token: None → ${tokenId} (unused, expires ${clockOf(token.expiresAt)})`)

  const event: FlowEvent = typed({
    ...base,
    action: kind === 'modify' ? 'Modified approval' : 'Approved action',
    description:
      kind === 'modify'
        ? `${actor.name} approved the recommendation to ${title.toLowerCase()} with a shorter duration, ${minutes} min instead of ${recommended}.`
        : `${actor.name} approved the recommendation to ${title.toLowerCase()}.`,
    changes,
    metadata: { ...metadata, 'Token ID': tokenId },
    record: recordOf(approval, personOf(actor), {
      decision: kind === 'modify' ? 'approved_with_changes' : 'approved',
      decision_reason: reason,
      params: approvedAction.params,
    }),
  })

  return {
    ok: true,
    state: {
      ...state,
      approvals: replaceApproval(state, record),
      tokens: [...state.tokens, token],
      events: [...state.events, event],
    },
  }
}

/*
  The executor starts: the guard checks the token (unused, this
  recommendation, exactly this action, unexpired, right role), then the
  token is marked used at once, before anything runs. A second attempt
  on the same token is refused by the guard and changes nothing.
*/
export async function beginExecution(state: FlowState, approvalId: string, policy?: ResponsePolicy): Promise<FlowResult> {
  const approval = state.approvals.find((item) => item.id === approvalId)
  const action = approval?.approvedAction

  if (!approval || approval.decision !== 'Approved' || !action) {
    return refused('not_ready', 'Only an approved request can run.')
  }

  if (action.name === 'suspend_user_session') {
    return refused('unsupported', 'Suspending a session is not run from this console.')
  }

  const { recommendation } = approval
  const startedAt = addSeconds(state.now, STEP_SECONDS)
  const verdict = await guard(
    {
      actionName: action.name,
      params: action.params,
      recommendationId: recommendation.id,
      tokenId: approval.tokenId,
      requestedBy: recommendation.requestedBy,
      riskScore: recommendation.riskScore,
      confidence: recommendation.confidence,
      assetClass: assetClassOf(recommendation.alertId),
      now: startedAt,
    },
    state.tokens,
    policy,
  )

  if (!verdict.allowed) {
    // A request that never started is marked refused; one that already ran is left as it is
    const started = Boolean(approval.executionId)

    return {
      ok: false,
      code: verdict.code,
      reason: verdict.reason,
      state: started ? undefined : { ...state, refusals: { ...state.refusals, [approval.id]: verdict.reason } },
    }
  }

  const runId = nextNumber('EXE', [...state.runs.map((run) => run.id), ...state.facts.map((item) => item.id)])
  const minutes = Number(action.params.duration_min)
  const facts: ExecutionFacts = {
    id: runId,
    approvalId: approval.id,
    startedAt,
    expiresAt: addMinutes(startedAt, minutes),
    action,
  }
  const event: FlowEvent = {
    at: startedAt,
    user: 'AthenaSec AI',
    role: 'System',
    sourceIp: '127.0.0.1',
    action: 'Used approval token',
    target: `${approval.tokenId} · ${approval.id}`,
    description: `The executor used up ${approval.tokenId} to run the approved action. A token runs one action once.`,
    changes: [`Token ${approval.tokenId}: Unused → Used`],
    metadata: {
      'Token ID': approval.tokenId ?? '',
      'Approval ID': approval.id,
      'Execution ID': runId,
      'Alert ID': recommendation.alertId,
    },
  }

  return {
    ok: true,
    state: {
      ...state,
      now: startedAt,
      tokens: consumeToken(state.tokens, approval.tokenId ?? '', startedAt),
      approvals: replaceApproval(state, { ...approval, executionId: runId }),
      facts: [...state.facts, facts],
      running: [...state.running, approval.id],
      // An armed failure applies to this one run, whose token is already used up
      failNext: false,
      failing: state.failNext ? [...state.failing, approval.id] : state.failing,
      events: [...state.events, event],
    },
  }
}

// What the executor reports back for a finished action, in the words of the Incident Response page
function buildRun(approval: ApprovalRecord, facts: ExecutionFacts, finishedAt: string): ExecutionRecord {
  const { recommendation, decidedBy } = approval
  const block = facts.action.name === 'block_ip'
  const target = String(block ? facts.action.params.ip : facts.action.params.host)
  const verbed = block ? 'blocked' : 'isolated'
  const approver = decidedBy?.name ?? 'a person'
  const approverRole = decidedBy ? APPROVER_LABELS[decidedBy.role] : 'person'
  const recommended = Number(recommendation.action.params.duration_min)
  const minutes = Number(facts.action.params.duration_min)

  return {
    id: facts.id,
    triggeringAlert: recommendation.alertId,
    approvalId: approval.id,
    policy: policyLabel(approval.policy),
    action: block ? 'Block IP' : 'Isolate Host',
    target,
    startTime: clockOf(facts.startedAt),
    endTime: clockOf(finishedAt),
    duration: '1 minute',
    result: 'Completed',
    rollbackStatus: `${block ? 'Block lifts' : 'Reconnects'} automatically at ${clockOf(facts.expiresAt)}`,
    failureReason: 'None',
    happened: `AthenaSec ${verbed} ${target} after ${approver} approved the recommendation.`,
    classified: `${recommendation.evidence.slice(0, 2).join('; ')}.`,
    responseReason: `${approvalActionTitle(approval)} was recommended at risk ${recommendation.riskScore} with confidence ${recommendation.confidence.toFixed(2)} under response policy version ${approval.policy.version}. ${approver} (${approverRole}) approved it${minutes !== recommended ? ` for ${minutes} min instead of ${recommended}` : ''}.`,
    evidence: [
      `Risk score ${recommendation.riskScore}`,
      ...recommendation.evidence.slice(0, 3),
      `Approved by ${approver} at ${clockOf(approval.decidedAt ?? facts.startedAt)}`,
    ],
    timeline: [
      { time: clockOf(recommendation.createdAt), event: `${approvalActionTitle(approval)} recommended` },
      { time: clockOf(approval.decidedAt ?? facts.startedAt), event: `Approved by ${approver} (${approverRole})` },
      { time: clockOf(facts.startedAt), event: 'Command sent, approval token used' },
      { time: clockOf(finishedAt), event: `${target} ${verbed} successfully` },
    ],
  }
}

// The same run when the target did not confirm (demo: an armed failure): nothing was blocked or isolated
function buildFailedRun(approval: ApprovalRecord, facts: ExecutionFacts, finishedAt: string): ExecutionRecord {
  const run = buildRun(approval, facts, finishedAt)
  const block = facts.action.name === 'block_ip'
  const approver = approval.decidedBy?.name ?? 'a person'

  return {
    ...run,
    result: 'Failed',
    rollbackStatus: 'Not applicable',
    failureReason: block
      ? 'The firewall did not acknowledge the block before the execution timeout.'
      : 'The endpoint agent did not acknowledge the isolation command before the execution timeout.',
    happened: `AthenaSec tried to ${block ? 'block' : 'isolate'} ${run.target} after ${approver} approved it, but the ${block ? 'firewall' : 'endpoint'} did not confirm.`,
    timeline: [
      ...run.timeline.slice(0, 3),
      { time: clockOf(finishedAt), event: `${block ? 'Block' : 'Isolation'} command timed out` },
    ],
  }
}

// The executor finishes: the run is recorded as completed, or as failed when a failure was armed
export function finishExecution(state: FlowState, approvalId: string): FlowResult {
  const approval = state.approvals.find((item) => item.id === approvalId)
  const facts = state.facts.find((item) => item.approvalId === approvalId)

  if (!approval || !facts || !state.running.includes(approvalId)) {
    return refused('not_running', 'That request is not running.')
  }

  const finishedAt = addSeconds(facts.startedAt, RUN_SECONDS)
  const block = facts.action.name === 'block_ip'

  if (state.failing.includes(approvalId)) {
    const failed = buildFailedRun(approval, facts, finishedAt)
    const failure: FlowEvent = typed({
      at: finishedAt,
      user: 'AthenaSec AI',
      role: 'System',
      sourceIp: '127.0.0.1',
      action: 'Execution failed',
      target: failed.target,
      description: `${failed.failureReason} ${failed.target} was not ${block ? 'blocked' : 'isolated'}. The approval token stays used and is never reused: a new request needs a new approval.`,
      changes: [`${failed.target} not ${block ? 'blocked' : 'isolated'}`, `Token ${approval.tokenId} stays used`, 'Execution marked Failed'],
      metadata: {
        'Execution ID': failed.id,
        'Approval ID': approval.id,
        'Triggering Alert': failed.triggeringAlert,
        Policy: failed.policy,
        'Token ID': approval.tokenId ?? '',
      },
      result: 'Failed',
      record: recordOf(approval, AGENT, {
        decision: 'approved',
        params: facts.action.params,
        execution_result: 'failed',
      }),
    })

    return {
      ok: true,
      state: {
        ...state,
        now: finishedAt,
        runs: [...state.runs, failed],
        running: state.running.filter((id) => id !== approvalId),
        failing: state.failing.filter((id) => id !== approvalId),
        events: [...state.events, failure],
      },
    }
  }

  const run = buildRun(approval, facts, finishedAt)
  const event: FlowEvent = typed({
    at: finishedAt,
    user: 'AthenaSec AI',
    role: 'System',
    sourceIp: '127.0.0.1',
    action: block ? 'Executed block' : 'Executed host isolation',
    target: run.target,
    description: `AthenaSec AI ${block ? 'blocked' : 'isolated'} ${run.target} for ${facts.action.params.duration_min} minutes under response policy version ${approval.policy.version}, using the approval token issued to ${approval.decidedBy?.name ?? 'the approver'}.`,
    changes: [
      block ? `${run.target} blocked` : `${run.target} isolated`,
      `Reverses automatically at ${clockOf(facts.expiresAt)}`,
      'Execution marked Completed',
    ],
    metadata: {
      'Execution ID': run.id,
      'Approval ID': approval.id,
      'Triggering Alert': run.triggeringAlert,
      Policy: run.policy,
      'Approved By': `${approval.decidedBy?.name ?? ''} (${approval.decidedBy ? APPROVER_LABELS[approval.decidedBy.role] : ''})`,
    },
    record: recordOf(approval, AGENT, {
      decision: 'approved',
      params: facts.action.params,
      execution_result: 'success',
      expires_at: facts.expiresAt,
    }),
  })

  return {
    ok: true,
    state: {
      ...state,
      now: finishedAt,
      runs: [...state.runs, run],
      running: state.running.filter((id) => id !== approvalId),
      events: [...state.events, event],
    },
  }
}

// ===== Demo mode: time passing, an armed failure, asking again =====

// Demo time moves in these steps only, in minutes
export const ADVANCE_STEPS = [5, 15, 60] as const

// "5 minutes", "15 minutes", "1 hour"
export const stepLabel = (minutes: number) => (minutes === 60 ? '1 hour' : `${minutes} minutes`)

// "15:46:00" from "2026-08-03T15:46:00"
const clockWithSeconds = (time: string) => time.slice(11)

/*
  Moves the demo clock forward by a fixed step (never reads the real
  one) and settles what that decides: a request past its deadline
  becomes Timed out (nothing runs, the alert stays open, and the
  Administrator is told), and a block or isolation past its expiry is
  reversed. Using the control is a Demo event with old → new time.
*/
export function advanceTime(state: FlowState, minutes: number, actor: Actor): FlowResult {
  if (!ADVANCE_STEPS.some((step) => step === minutes)) {
    return refused('invalid_step', 'Demo time moves in steps of 5 minutes, 15 minutes or 1 hour.')
  }

  const before = state.now
  const after = addMinutes(before, minutes)
  const events: FlowEvent[] = [
    {
      at: after,
      user: actor.name,
      role: appRole(actor),
      sourceIp: actor.sourceIp,
      action: 'Advanced demo time',
      target: 'Demo clock',
      description: `${actor.name} moved the demo clock forward ${stepLabel(minutes)}. Deadlines and expiries are measured from it, not from the real clock.`,
      changes: [`Demo time: ${clockWithSeconds(before)} → ${clockWithSeconds(after)}`],
      metadata: { 'Step (min)': String(minutes) },
      demo: true,
    },
  ]

  const approvals = state.approvals.map((approval) => {
    if (approval.decision !== 'Pending' || parseTime(approval.recommendation.approvalDeadline) >= parseTime(after)) {
      return approval
    }

    const title = approvalActionTitle(approval)
    const needsLead = approval.requiredRole === 'soc_lead'

    events.push(typed({
      at: after,
      user: 'AthenaSec AI',
      role: 'System',
      sourceIp: '127.0.0.1',
      action: 'Approval timed out',
      target: `${approval.id} · ${title}`,
      description: `Nobody decided before the deadline (${clockOf(approval.recommendation.approvalDeadline)}). Nothing ran and ${approval.recommendation.alertId} stays open. ${
        needsLead ? 'A second notice went to all Administrators.' : 'The request was escalated to the Administrator.'
      }`,
      changes: ['Decision: Pending → Timed out'],
      metadata: {
        'Approval ID': approval.id,
        'Recommendation ID': approval.recommendation.id,
        'Alert ID': approval.recommendation.alertId,
        Deadline: clockOf(approval.recommendation.approvalDeadline),
      },
      record: recordOf(approval, AGENT, { decision: 'timed_out', execution_result: 'not_executed' }),
    }))

    return { ...approval, decision: 'Timed out' as const }
  })

  const runs = state.runs.map((run) => {
    const facts = state.facts.find((item) => item.id === run.id)

    if (run.result !== 'Completed' || run.reversedAt || !facts || parseTime(facts.expiresAt) > parseTime(after)) {
      return run
    }

    const block = run.action === 'Block IP'

    const expiredApproval = state.approvals.find((item) => item.id === run.approvalId)

    events.push(typed({
      at: after,
      user: 'AthenaSec AI',
      role: 'System',
      sourceIp: '127.0.0.1',
      action: 'Action expired',
      target: run.target,
      description: `The ${block ? 'block' : 'isolation'} of ${run.target} ran its approved time and was reversed automatically.`,
      changes: [`${block ? 'Block of' : 'Isolation of'} ${run.target}: Active → Reversed`, `Reversed at ${clockOf(facts.expiresAt)}`],
      metadata: { 'Execution ID': run.id, 'Approval ID': run.approvalId, 'Triggering Alert': run.triggeringAlert },
      record: expiredApproval
        ? recordOf(expiredApproval, AGENT, {
            decision: 'approved',
            params: facts.action.params,
            execution_result: 'success',
            expires_at: facts.expiresAt,
          })
        : undefined,
    }))

    return {
      ...run,
      reversedAt: facts.expiresAt,
      rollbackStatus: `${block ? 'Block lifted' : 'Reconnected'} at ${clockOf(facts.expiresAt)}`,
    }
  })

  return { ok: true, state: { ...state, now: after, approvals, runs, events: [...state.events, ...events] } }
}

export const ATTEMPT_LABELS: Record<AttemptDecision['decision'], string> = {
  allowed: 'Allowed',
  needs_approval: 'Needs approval',
  refused: 'Refused',
}

/*
  Demo mode "Simulate an attempt": asks the policy guard what it would do
  with an action and writes it to the audit log as a Demo event. It runs
  nothing and changes nothing else: no request, token, run or clock. A
  refusal also writes the "Policy violation blocked" event (result Denied)
  that the policy's enforcement layer 3 describes.
*/
export function simulateAttempt(
  state: FlowState,
  request: AttemptRequest,
  actor: Actor,
  policy?: ResponsePolicy,
): { state: FlowState; decision: AttemptDecision } {
  const decision = attemptDecision(request, policy)
  const label = ATTEMPT_LABELS[decision.decision]
  const parameters = Object.entries(request.params)
    .map(([key, value]) => `${key}=${value}`)
    .join(', ')
  const detail = {
    Rule: decision.rule,
    Code: decision.code,
    ...(parameters ? { Parameters: parameters } : {}),
    Executed: 'No',
  }

  const events: FlowEvent[] = [
    {
      at: state.now,
      user: actor.name,
      role: appRole(actor),
      sourceIp: actor.sourceIp,
      action: 'Simulated an attempt',
      target: request.actionName,
      description: `${actor.name} simulated an attempt to run ${request.actionName}. The policy guard answered “${label}”: ${decision.reason} Nothing was executed.`,
      changes: [`Attempt: ${request.actionName} → ${label}`],
      metadata: detail,
      demo: true,
    },
  ]

  if (decision.decision === 'refused') {
    events.push(typed({
      at: state.now,
      user: 'AthenaSec AI',
      role: 'System',
      sourceIp: '127.0.0.1',
      action: 'Policy violation blocked',
      target: request.actionName,
      description: `The policy guard refused ${request.actionName}: ${decision.reason} Nothing was executed.`,
      changes: [`${request.actionName}: Requested → Blocked`],
      metadata: detail,
      demo: true,
      result: 'Denied',
      record: {
        actor: AGENT.id,
        actor_role: AGENT.role,
        tier: catalogueRowFor(request.actionName)?.tier,
        action: request.actionName,
        params: request.params,
        risk_score: request.riskScore,
        confidence: request.confidence,
        execution_result: 'not_executed',
      },
    }))
  }

  return { state: { ...state, events: [...state.events, ...events] }, decision }
}

// Demo mode: the next execution will fail after using its token
export function armFailure(state: FlowState, actor: Actor): FlowResult {
  if (state.failNext) {
    return refused('already_armed', 'A failure is already armed for the next execution.')
  }

  const event: FlowEvent = {
    at: state.now,
    user: actor.name,
    role: appRole(actor),
    sourceIp: actor.sourceIp,
    action: 'Armed a failed execution',
    target: 'Executor',
    description: `${actor.name} armed the next execution to fail. Its approval token is still used up, and a new request needs a new approval.`,
    changes: ['Next execution: Will succeed → Will fail'],
    metadata: {},
    demo: true,
  }

  return { ok: true, state: { ...state, failNext: true, events: [...state.events, event] } }
}

/*
  A run can be asked for again when it failed or its block or isolation
  lapsed, the alert is still open, nothing for that alert is waiting,
  and no later run for it is active. Returns why not, or null.
*/
export function requestAgainRefusal(
  state: FlowState,
  run: ExecutionRecord,
  alertOpen: boolean,
  policy?: ResponsePolicy,
): string | null {
  if (run.result !== 'Failed' && !run.reversedAt) {
    return 'Only a run that failed or has lapsed can be asked for again.'
  }

  // A new request is checked against the policy as it stands now
  const earlier = state.approvals.find((item) => item.id === run.approvalId)
  const lapsed = earlier && requestPolicyRefusal(earlier.recommendation, assetClassOf(earlier.recommendation.alertId), policy)

  if (lapsed) {
    return `The response policy no longer allows this: ${lapsed.reason}`
  }

  if (!alertOpen) {
    return `${run.triggeringAlert} is closed, so there is nothing to ask for.`
  }

  if (state.approvals.some((item) => item.decision === 'Pending' && item.recommendation.alertId === run.triggeringAlert)) {
    return 'A request for this alert is already waiting for a decision.'
  }

  const index = state.runs.findIndex((item) => item.id === run.id)

  if (state.runs.slice(index + 1).some((item) => item.triggeringAlert === run.triggeringAlert && item.result === 'Completed' && !item.reversedAt)) {
    return 'A later run for this alert is still active.'
  }

  return null
}

/*
  Asks for the same action again after a failed or lapsed run: a new
  recommendation and approval (new ids), asked by this person, so they
  cannot decide on it. The earlier approval and its token are left as
  they were and are never reused.
*/
export function requestAgain(
  state: FlowState,
  runId: string,
  actor: Actor,
  alertOpen: boolean,
  policy: ResponsePolicy = DEFAULT_POLICY,
): FlowResult {
  const run = state.runs.find((item) => item.id === runId)
  const earlier = run && state.approvals.find((item) => item.id === run.approvalId)

  if (!run || !earlier) {
    return refused('unknown_run', 'There is no such run.')
  }

  const reason = requestAgainRefusal(state, run, alertOpen, policy)

  if (reason) {
    return refused('not_allowed', reason)
  }

  // The new request carries the action's rule as the policy has it now
  const rule = policySnapshot(policy, earlier.recommendation.action.name)
  const recommendation = {
    ...earlier.recommendation,
    id: nextNumber('REC', state.approvals.map((item) => item.recommendation.id)),
    requestedBy: actor.id,
    createdAt: state.now,
    approvalDeadline: addMinutes(state.now, rule.windowMinutes),
  }
  const approval: ApprovalRecord = {
    id: nextNumber('APR', state.approvals.map((item) => item.id)),
    recommendation,
    requiredRole: rule.approver,
    policy: rule,
    decision: 'Pending',
  }
  const title = approvalActionTitle(approval)
  const event: FlowEvent = typed({
    at: state.now,
    user: actor.name,
    role: appRole(actor),
    sourceIp: actor.sourceIp,
    action: 'Requested approval',
    target: `${approval.id} · ${title}`,
    description: `${actor.name} asked for ${title.toLowerCase()} again after ${run.id} ${run.reversedAt ? 'lapsed' : 'failed'}. The earlier approval and its token are not reused; this request needs a new decision and a new token.`,
    changes: [`Request: None → ${approval.id} (pending)`, `Requested by: None → ${actor.name}`],
    metadata: {
      'Approval ID': approval.id,
      'Recommendation ID': recommendation.id,
      'Alert ID': recommendation.alertId,
      'Earlier run': run.id,
      'Earlier approval': earlier.id,
      'Earlier token': earlier.tokenId ?? '',
    },
    record: recordOf(approval, personOf(actor)),
  })

  return { ok: true, state: { ...state, approvals: [...state.approvals, approval], events: [...state.events, event] } }
}
