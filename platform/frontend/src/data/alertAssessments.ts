import type { RiskBand } from '../types/alertsTypes'
import type { Assessment } from '../types/policyTypes'
import type { ResponsePolicy } from '../types/responsePoliciesTypes'

import { assessmentInputs } from './agentPolicyData'
import { assess, scoreRisk } from './policyEngine'

/*
  Alert risk comes from the policy's formula, not from typed-in data.
  The score depends only on the alert's inputs; the outcome also
  depends on the response policy as it stands now.
*/

// The bands the Alerts risk filter uses: Low 0-39, Medium 40-69, High 70-89, Critical 90-100
export function riskBandFor(risk: number): RiskBand {
  if (risk >= 90) {
    return 'critical'
  }

  if (risk >= 70) {
    return 'high'
  }

  return risk >= 40 ? 'medium' : 'low'
}

// The alert's risk score (0-100) from the formula
export function riskFor(alertId: string) {
  const input = assessmentInputs.find((item) => item.alertId === alertId)

  if (!input) {
    throw new Error(`No assessment inputs for ${alertId}`)
  }

  return scoreRisk(input).risk
}

// Every alert's full assessment against the given response policy
export function assessAlerts(policy: ResponsePolicy): Record<string, Assessment> {
  return Object.fromEntries(assessmentInputs.map((input) => [input.alertId, assess(input, policy)]))
}
