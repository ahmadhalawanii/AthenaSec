import type { Assessment } from '../types/policyTypes'

import { OUTCOME_LABELS, RISK_WEIGHTS } from '../data/agentPolicyData'
import { displayedParts, displayedPartsTotal } from '../data/policyEngine'

type RiskAssessmentProps = {
  assessment: Assessment
}

const percent = (weight: number) => `${Math.round(weight * 100)}%`

/*
  Why an alert has the risk, confidence and outcome it has: each input
  with its normalised value, weight and the points it adds, the total,
  the outcome the agent chose, and every other outcome with the reason
  it was not chosen.
*/
function RiskAssessment({ assessment }: RiskAssessmentProps) {
  const higher = assessment.alternativesConsidered.filter((item) => item.direction === 'higher')
  const lower = assessment.alternativesConsidered.filter((item) => item.direction === 'lower')
  const shownParts = displayedParts(assessment.breakdown.parts)

  return (
    <section className="assessment" aria-labelledby={`assessmentTitle-${assessment.alertId}`} data-assessment-for={assessment.alertId}>
      <h3 className="workspace-subhead" id={`assessmentTitle-${assessment.alertId}`}>
        Risk assessment
      </h3>

      <p className="assessment-outcome">
        <strong data-field="outcome">{OUTCOME_LABELS[assessment.outcome]}</strong>
        <span className="assessment-line" data-field="confidence">
          Confidence {assessment.confidence.toFixed(2)} ({assessment.confidenceBand.toLowerCase()})
        </span>
      </p>

      <table className="score-table">
        <caption className="visually-hidden">
          How the risk score of {assessment.risk} out of 100 is made up
        </caption>
        <thead>
          <tr>
            <th scope="col">Input</th>
            <th scope="col">Value × weight</th>
            <th scope="col">Points</th>
          </tr>
        </thead>
        <tbody>
          {assessment.breakdown.parts.map((part) => (
            <tr key={part.key} data-input={part.key}>
              <th scope="row">
                <span className="score-key">{part.key}</span> {part.label}
                <span className="score-raw">{part.rawLabel}</span>
              </th>
              <td className="mono">
                {part.normalised.toFixed(2)} × {percent(part.weight)}
              </td>
              <td className="mono">{shownParts[assessment.breakdown.parts.indexOf(part)]}</td>
            </tr>
          ))}
        </tbody>
        <tfoot>
          <tr>
            <th scope="row" colSpan={2}>
              Sum of the parts
            </th>
            <td className="mono" data-field="riskSum">
              {displayedPartsTotal(assessment.breakdown.parts)}
            </td>
          </tr>
          <tr>
            <th scope="row" colSpan={2}>
              Risk score (rounded)
            </th>
            <td className="mono" data-field="riskTotal">
              {assessment.risk} / 100
            </td>
          </tr>
        </tfoot>
      </table>

      <p className="assessment-formula mono">
        risk = 100 × ({RISK_WEIGHTS.S} S + {RISK_WEIGHTS.E} E + {RISK_WEIGHTS.R} R + {RISK_WEIGHTS.A} A)
      </p>

      {assessment.escalation && (
        <p className="policy-note" data-field="escalation">
          {assessment.escalation}
        </p>
      )}

      <h4 className="assessment-sub">Alternatives considered</h4>
      <ul className="alternatives" data-field="alternatives">
        {[...higher, ...lower].map((item) => (
          <li key={item.outcome} data-direction={item.direction}>
            <strong>{OUTCOME_LABELS[item.outcome]}</strong>
            <span>{item.reason}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

export default RiskAssessment
