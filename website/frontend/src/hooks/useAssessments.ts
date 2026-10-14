import { useMemo } from 'react'

import { assessAlerts } from '../data/alertAssessments'
import { useAdminState } from './useAdminState'

/*
  Every alert's assessment (risk, confidence, outcome, score breakdown,
  alternatives considered) against the response policy as it stands
  now, so changing a minimum risk or a list changes the outcome here too.
*/
export function useAssessments() {
  const { responsePolicy } = useAdminState()

  return useMemo(() => assessAlerts(responsePolicy), [responsePolicy])
}
