import { APPROVER_LABELS } from '../data/agentPolicyData'
import { clockOf, parseTime, tokenState, windowState } from '../data/policyEngine'
import { approvalActionTitle, requesterName } from '../data/approvalFlow'
import { useDemoNow } from '../hooks/useDemoNow'
import type { ApprovalRecord, ExecutionFacts } from '../types/approvalTypes'
import type { ApprovalToken } from '../types/policyTypes'

type ApprovalDetailsProps = {
  approval: ApprovalRecord
  // Tokens are hashed with Web Crypto, so this is undefined for a moment after load
  token?: ApprovalToken
  facts?: ExecutionFacts
  // The run failed, so there is no action window
  failed?: boolean
}


/*
  One approval, in plain words: what was asked, who decides, what they
  decided, the policy version it was checked against, the single-use
  token bound to the exact action, and when the action reverses.
  Deadlines and expiries are measured from the demo clock.
*/
function ApprovalDetails({ approval, token, facts, failed }: ApprovalDetailsProps) {
  const now = useDemoNow()
  const { recommendation, decidedBy, policy } = approval
  const minutes = recommendation.action.params.duration_min
  const timeLeft = windowState(recommendation.approvalDeadline, now)

  let decision: string

  if (approval.decision === 'Pending') {
    decision = `Waiting for a ${APPROVER_LABELS[approval.requiredRole]} (${timeLeft.label}, by ${clockOf(recommendation.approvalDeadline)})`
  } else if (decidedBy && approval.decidedAt) {
    decision = `${approval.decision} by ${decidedBy.name} (${APPROVER_LABELS[decidedBy.role]}) at ${clockOf(approval.decidedAt)}`
  } else if (approval.decision === 'Timed out') {
    decision = `Timed out: nobody decided by ${clockOf(recommendation.approvalDeadline)}, so nothing ran`
  } else {
    decision = approval.decision
  }

  let tokenText: string | null = null

  if (approval.tokenId) {
    tokenText = token
      ? `${token.id}, ${tokenState(token, now).toLowerCase()}${token.usedAt ? ` at ${clockOf(token.usedAt)}` : ''}`
      : `${approval.tokenId}, checking`
  }

  return (
    <dl className="facts approval-facts" data-approval-id={approval.id}>
      <div>
        <dt>Request</dt>
        <dd data-field="request">
          <span className="mono">{approval.id}</span> · {approvalActionTitle(approval)} for {minutes} min
        </dd>
      </div>
      {approval.approvedAction && Number(approval.approvedAction.params.duration_min) !== Number(minutes) && (
        <div>
          <dt>Approved as</dt>
          <dd data-field="approvedAs">
            {approvalActionTitle(approval)} for {approval.approvedAction.params.duration_min} min (shortened from{' '}
            {minutes})
          </dd>
        </div>
      )}
      <div>
        <dt>Asked by</dt>
        <dd data-field="requestedBy">
          {requesterName(recommendation.requestedBy)} at {clockOf(recommendation.createdAt)}
        </dd>
      </div>
      <div>
        <dt>Decision</dt>
        <dd data-field="decision">{decision}</dd>
      </div>
      {approval.reason && (
        <div>
          <dt>Reason</dt>
          <dd data-field="reason">{approval.reason}</dd>
        </div>
      )}
      <div>
        <dt>Policy</dt>
        <dd data-field="policy">
          Response policy version {policy.version}, {policy.action}: {APPROVER_LABELS[policy.approver]} approves,
          minimum risk {policy.minRisk}
        </dd>
      </div>
      {tokenText && (
        <div>
          <dt>Approval token</dt>
          <dd data-field="token">
            {tokenText}
            {token && (
              <span className="mono approval-digest" title={token.paramsDigest}>
                {' '}
                bound to sha256 {token.paramsDigest.slice(0, 12)}…
              </span>
            )}
          </dd>
        </div>
      )}
      {facts && (
        <div>
          <dt>Action window</dt>
          <dd data-field="window">
            {failed
              ? 'None: the execution failed'
              : parseTime(now) < parseTime(facts.expiresAt)
                ? `Active until ${clockOf(facts.expiresAt)}`
                : `Reversed at ${clockOf(facts.expiresAt)}`}
          </dd>
        </div>
      )}
    </dl>
  )
}

export default ApprovalDetails
