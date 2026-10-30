import {
  ACTION_CATALOGUE,
  APPROVER_LABELS,
  formatMinutes,
  tierWords,
  type Assumption,
  type CatalogueRow,
} from '../data/agentPolicyData'

import { standingLabel } from '../data/policyEngine'
import type { ApprovalLimits } from '../types/responsePoliciesTypes'
import { useAdminState } from '../hooks/useAdminState'
import { statusTone } from '../utils/statusTone'

import TableScroll from './TableScroll'

// "30 min default · 24 h longest · SOC analyst · minimum risk 70", or nothing when the action has no limits
function limitsText(limits: ApprovalLimits | undefined) {
  if (!limits) {
    return ''
  }

  return [
    limits.defaultMinutes !== undefined ? `${formatMinutes(limits.defaultMinutes)} default` : '',
    limits.maxMinutes !== undefined ? `${formatMinutes(limits.maxMinutes)} longest` : '',
    APPROVER_LABELS[limits.approver],
    `${limits.windowMinutes} min to decide`,
    `minimum risk ${limits.minRisk}`,
  ]
    .filter(Boolean)
    .join(' · ')
}

const TIER_TONE = { 1: 'ok', 2: 'warn', 3: 'danger' } as const

// A value the PDF does not give: tagged, with its note in plain sight
function Assumed({ note }: { note: Assumption }) {
  return (
    <span className="assumption" data-assumption={note.field}>
      <span className="assumption-tag">Assumption</span> {note.note}
    </span>
  )
}

const noteFor = (row: CatalogueRow, field: Assumption['field']) => row.assumed.find((item) => item.field === field)

// A dash for "not applicable", with the words for a screen reader
function NotApplicable() {
  return (
    <>
      <span aria-hidden="true">{'—'}</span> <span className="visually-hidden">Not applicable</span>
    </>
  )
}

/*
  The Agent Action Catalogue as one table: every action the agent has,
  its tier in words, what the policy PDF says about it, and where each
  value comes from. Built from ACTION_CATALOGUE, the same rows the
  policy guard, the form's refusals and "Simulate an attempt" read.
*/
function ActionCatalogue() {
  // The policy's current standing for each action (listed, mode, limits)
  const { responsePolicy } = useAdminState()

  return (
    <div className="card catalogue" data-catalogue>
      <div className="catalogue-head">
        <h2>Action catalogue</h2>
        <p className="sub">
          Every action the agent has, from the Agent Action Catalogue and Approval Policy. Tier 1 runs on its own, Tier 2 only
          after a named person approves it, and Tier 3 never runs. Values the policy does not give are tagged as
          assumptions.
        </p>
      </div>

      <TableScroll label="Action catalogue">
        <table>
          <caption className="visually-hidden">
            The 21 actions of the agent action catalogue, grouped by tier, with where each stands in the response policy
          </caption>
          <thead>
            <tr>
              <th scope="col">Action</th>
              <th scope="col">Tier</th>
              <th scope="col">When the agent uses it</th>
              <th scope="col">Default</th>
              <th scope="col">Maximum</th>
              <th scope="col">Approver and window</th>
              <th scope="col">Reversible</th>
              <th scope="col">Response policy</th>
              <th scope="col">Source</th>
            </tr>
          </thead>
          <tbody>
            {ACTION_CATALOGUE.map((row) => {
              const does = noteFor(row, 'does')
              const reversible = noteFor(row, 'reversible')

              return (
                <tr key={row.key} data-catalogue-row={row.key} data-tier={row.tier}>
                  <td data-field="action">
                    <span className={row.tier === 3 ? 'catalogue-action' : 'mono catalogue-action'}>{row.action}</span>
                    {row.does && <span className="catalogue-does">{row.does}</span>}
                    {does && <Assumed note={does} />}
                  </td>
                  <td data-field="tier">
                    <span className={`pill ${TIER_TONE[row.tier]}`}>Tier {row.tier}</span>{' '}
                    <span className="catalogue-tier-words">{tierWords(row)}</span>
                  </td>
                  <td data-field="when">
                    {row.whenUsed}
                    {row.why && <span className="catalogue-does">Why: {row.why}</span>}
                    {row.tier === 2 && row.riskFloor !== undefined && row.confidenceFloor !== undefined && (
                      <span className="catalogue-does" data-field="floor">
                        Floor: risk {row.riskFloor} and confidence {row.confidenceFloor.toFixed(2)}
                      </span>
                    )}
                  </td>
                  <td data-field="default">
                    {row.defaultMinutes !== undefined ? formatMinutes(row.defaultMinutes) : <NotApplicable />}
                  </td>
                  <td data-field="maximum">
                    {row.maxMinutes !== undefined ? formatMinutes(row.maxMinutes) : <NotApplicable />}
                  </td>
                  <td data-field="approver">
                    {row.approver && row.approvalWindowMinutes !== undefined ? (
                      <>
                        {APPROVER_LABELS[row.approver]}{' '}
                        <span className="catalogue-does">{row.approvalWindowMinutes} min window</span>
                      </>
                    ) : (
                      <NotApplicable />
                    )}
                  </td>
                  <td data-field="reversible">
                    {row.reversible}
                    {reversible && <Assumed note={reversible} />}
                  </td>
                  <td data-field="policy">
                    <span className={`pill ${statusTone(standingLabel(responsePolicy, row.key))}`}>
                      {standingLabel(responsePolicy, row.key)}
                    </span>
                    {limitsText(responsePolicy.whitelist.find((entry) => entry.action === row.key)?.limits) && (
                      <span className="catalogue-does" data-field="policyLimits">
                        {limitsText(responsePolicy.whitelist.find((entry) => entry.action === row.key)?.limits)}
                      </span>
                    )}
                  </td>
                  <td data-field="source">
                    <span className="mono">{row.source}</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </TableScroll>
    </div>
  )
}

export default ActionCatalogue
