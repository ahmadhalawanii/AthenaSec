import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { DEMO_NOW } from '../data/agentPolicyData'
import {
  advanceTime,
  approvalActionTitle,
  armFailure,
  ATTEMPT_LABELS,
  beginExecution,
  decide as decideRequest,
  decisionRefusal,
  finishExecution,
  requestAgain,
  requestAgainRefusal,
  simulateAttempt,
  STEP_HOLD_MS,
  stepLabel,
} from '../data/approvalFlow'
import { buildSeedTokens, seedApprovalRecords, seedExecutionFacts } from '../data/approvalData'
import { auditTimestamp, takeAuditId } from '../data/auditLogsData'
import { executionRecords } from '../data/incidentResponseData'
import { initialUsers } from '../data/userManagementData'
import { ResponseContext } from '../hooks/responseContext'
import { useResponsePolicy } from '../hooks/useResponsePolicy'
import type { Actor, FlowEvent, FlowState } from '../types/approvalTypes'
import type { AuthenticatedUser } from '../types/appTypes'
import type { AuditLogRecord } from '../types/auditLogsTypes'
import type { AttemptRequest } from '../types/policyTypes'
import type { AttemptOutcome, DecisionOutcome, DecisionRequest, ResponseState } from '../types/responseStateTypes'

type ResponseStateProviderProps = {
  user: AuthenticatedUser | null
  children: ReactNode
}

// Where each demo account signs in from, as the seed audit log records it
const SOURCE_IPS = { Analyst: '10.0.2.25', Administrator: '10.0.1.10' } as const

function actorFor(user: AuthenticatedUser | null): Actor | null {
  const record = user ? initialUsers.find((item) => item.email === user.email) : undefined

  if (!user || !record) {
    return null
  }

  return {
    id: record.id,
    name: record.name,
    role: user.role === 'Administrator' ? 'soc_lead' : 'soc_analyst',
    sourceIp: SOURCE_IPS[user.role],
  }
}

const initialFlow: FlowState = {
  now: DEMO_NOW,
  approvals: seedApprovalRecords,
  tokens: [],
  facts: seedExecutionFacts,
  runs: executionRecords,
  running: [],
  refusals: {},
  failNext: false,
  failing: [],
  events: [],
}

// An event from the flow as an audit record, numbered from the shared counter
function toAuditRecord(event: FlowEvent): AuditLogRecord {
  return {
    id: takeAuditId(),
    timestamp: auditTimestamp(event.at),
    user: event.user,
    role: event.role,
    category: 'Incident Response',
    action: event.action,
    target: event.target,
    result: event.result ?? 'Success',
    sourceIp: event.sourceIp,
    description: event.description,
    changes: event.changes,
    metadata: event.metadata,
    ...(event.demo ? { demo: true } : {}),
    ...(event.eventType ? { eventType: event.eventType } : {}),
    ...(event.record ? { record: event.record } : {}),
  }
}

// What the executor does next: finish what is running, else start the first approved request
function nextStep(flow: FlowState) {
  if (flow.running.length > 0) {
    return { kind: 'finish' as const, approvalId: flow.running[0] }
  }

  const waiting = flow.approvals.find(
    (approval) => approval.decision === 'Approved' && !approval.executionId && !flow.refusals[approval.id],
  )

  return waiting ? { kind: 'begin' as const, approvalId: waiting.id } : null
}

/*
  The approval flow for the whole session. It sits above the routes, so a
  request an analyst makes is still there when the Administrator signs in,
  and it resets when the page reloads. The flow functions (approvalFlow.ts)
  do the work; this holds their state, numbers their audit events, and
  drives the executor one visible step at a time with a timer that is
  cleared on every change, on sign-out and on unmount.
*/
function ResponseStateProvider({ user, children }: ResponseStateProviderProps) {
  const [flow, setFlow] = useState<FlowState>(initialFlow)
  const latest = useRef<FlowState>(initialFlow)
  const [ready, setReady] = useState(false)
  const [auditEvents, setAuditEvents] = useState<AuditLogRecord[]>([])
  const [announcement, setAnnouncement] = useState('')
  const deciding = useRef(false)

  const actor = useMemo(() => actorFor(user), [user])

  // The response policy as it stands now: every decision, run, attempt and new request is checked against it
  const { policy, policyRef, allowLeaving } = useResponsePolicy()

  // Records the next state, and numbers the audit events it added (newest first)
  const apply = useCallback((next: FlowState) => {
    const fresh = next.events.slice(latest.current.events.length)

    latest.current = next
    setFlow(next)

    if (fresh.length > 0) {
      const records = fresh.map(toAuditRecord).reverse()

      setAuditEvents((current) => [...records, ...current])
    }
  }, [])

  // The seed token carries a SHA-256 digest (Web Crypto), so it arrives a moment after load
  useEffect(() => {
    let cancelled = false

    buildSeedTokens().then((tokens) => {
      if (cancelled) {
        return
      }

      const next = { ...latest.current, tokens }

      latest.current = next
      setFlow(next)
      setReady(true)
    })

    return () => {
      cancelled = true
    }
  }, [])

  // The executor: one step at a time, each held on screen, only while someone is signed in.
  // The timer is cleared when the state changes, on sign-out and on unmount, and a step that
  // was already running when that happened is dropped before it changes anything.
  useEffect(() => {
    if (!actor || !ready) {
      return undefined
    }

    const step = nextStep(flow)

    if (!step) {
      return undefined
    }

    let cancelled = false

    const timer = window.setTimeout(async () => {
      if (step.kind === 'finish') {
        const result = finishExecution(latest.current, step.approvalId)

        if (!cancelled && result.ok) {
          const title = approvalActionTitle(result.state.approvals.find((item) => item.id === step.approvalId)!)

          apply(result.state)
          setAnnouncement(`Done: ${title}. The run finished and the token stays used.`)
        }

        return
      }

      const result = await beginExecution(latest.current, step.approvalId, policyRef.current)

      if (cancelled) {
        return
      }

      if (result.ok) {
        const title = approvalActionTitle(result.state.approvals.find((item) => item.id === step.approvalId)!)

        apply(result.state)
        setAnnouncement(`Executing: ${title}. The approval token was used up.`)
      } else if (result.state) {
        apply(result.state)
        setAnnouncement(`The action did not run: ${result.reason}`)
      }
    }, STEP_HOLD_MS)

    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [flow, actor, ready, apply, policyRef])

  const decide = useCallback(
    async (request: DecisionRequest): Promise<DecisionOutcome> => {
      if (!actor || !ready) {
        return { ok: false, reason: 'Sign in to decide on a request.' }
      }

      if (deciding.current) {
        return { ok: false, reason: 'Another decision is being recorded. Try again in a moment.' }
      }

      deciding.current = true

      try {
        const result = await decideRequest(latest.current, { ...request, actor }, policyRef.current)

        if (!result.ok) {
          setAnnouncement(result.reason)

          return { ok: false, reason: result.reason }
        }

        const approval = result.state.approvals.find((item) => item.id === request.approvalId)!
        const title = approvalActionTitle(approval)

        apply(result.state)
        setAnnouncement(
          request.kind === 'reject'
            ? `${approval.id} rejected: ${title}. Nothing will run.`
            : `${approval.id} approved: ${title}. A single-use token was issued and the executor runs it next.`,
        )

        return { ok: true }
      } finally {
        deciding.current = false
      }
    },
    [actor, ready, apply, policyRef],
  )

  // Demo mode: each control writes its own Demo audit event and never reads the real clock
  const advance = useCallback(
    (minutes: number): DecisionOutcome => {
      if (!actor || !ready) {
        return { ok: false, reason: 'Sign in to use Demo mode.' }
      }

      const result = advanceTime(latest.current, minutes, actor)

      if (!result.ok) {
        setAnnouncement(result.reason)

        return { ok: false, reason: result.reason }
      }

      const settled = result.state.events.length - latest.current.events.length - 1

      apply(result.state)
      setAnnouncement(
        `Demo time moved forward ${stepLabel(minutes)} to ${result.state.now.slice(11)}.${
          settled > 0 ? ` ${settled} request or action settled.` : ''
        }`,
      )

      return { ok: true }
    },
    [actor, ready, apply],
  )

  const armFailureNow = useCallback((): DecisionOutcome => {
    if (!actor || !ready) {
      return { ok: false, reason: 'Sign in to use Demo mode.' }
    }

    const result = armFailure(latest.current, actor)

    if (!result.ok) {
      setAnnouncement(result.reason)

      return { ok: false, reason: result.reason }
    }

    apply(result.state)
    setAnnouncement('The next execution is armed to fail.')

    return { ok: true }
  }, [actor, ready, apply])

  const askAgain = useCallback(
    (runId: string, alertOpen: boolean): DecisionOutcome => {
      if (!actor || !ready) {
        return { ok: false, reason: 'Sign in to ask again.' }
      }

      const result = requestAgain(latest.current, runId, actor, alertOpen, policyRef.current)

      if (!result.ok) {
        setAnnouncement(result.reason)

        return { ok: false, reason: result.reason }
      }

      const added = result.state.approvals[result.state.approvals.length - 1]

      apply(result.state)
      setAnnouncement(`${added.id} asked for ${approvalActionTitle(added)} again. It needs a new decision.`)

      return { ok: true }
    },
    [actor, ready, apply, policyRef],
  )

  const simulate = useCallback(
    (request: AttemptRequest): AttemptOutcome => {
      if (!actor || !ready) {
        return { ok: false, reason: 'Sign in to use Demo mode.' }
      }

      const { state, decision } = simulateAttempt(latest.current, request, actor, policyRef.current)

      apply(state)
      setAnnouncement(
        `${ATTEMPT_LABELS[decision.decision]}: ${request.actionName}. ${decision.reason} Nothing was executed.`,
      )

      return { ok: true, decision }
    },
    [actor, ready, apply, policyRef],
  )

  const value = useMemo<ResponseState>(
    () => ({
      ready,
      now: flow.now,
      actor,
      approvals: flow.approvals,
      tokens: flow.tokens,
      facts: flow.facts,
      runs: flow.runs,
      running: flow.running,
      refusals: flow.refusals,
      failNext: flow.failNext,
      auditEvents,
      announcement,
      refusalFor(approval) {
        if (!actor) {
          return 'Sign in to decide on a request.'
        }

        return decisionRefusal(approval, actor, flow.now, policy)?.reason ?? null
      },
      requestAgainRefusal: (run, alertOpen) => requestAgainRefusal(flow, run, alertOpen, policy),
      decide,
      advance,
      armFailure: armFailureNow,
      requestAgain: askAgain,
      simulateAttempt: simulate,
      // Everything back to the seed: the simplest reset that cannot miss a provider
      // (the person has just confirmed it, so the browser's "leave this page?" prompt for an unsaved
      // Permissions draft is skipped: the reset ends the draft on purpose)
      resetDemo: () => {
        allowLeaving()
        window.location.reload()
      },
    }),
    [ready, flow, actor, policy, auditEvents, announcement, decide, advance, armFailureNow, askAgain, simulate, allowLeaving],
  )

  return <ResponseContext.Provider value={value}>{children}</ResponseContext.Provider>
}

export default ResponseStateProvider
