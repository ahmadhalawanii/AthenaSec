import type { AlertRecord, AlertResponseState } from './alertsTypes'
import type { StatusTone } from '../utils/statusTone'

// One cell of the posture strip under the attack map
export type PostureItem = {
  value: number
  label: string
  note: string
  tone?: StatusTone
}

// A row in "Needs a decision"
export type DecisionItem = {
  alert: AlertRecord
  state: AlertResponseState
  detail: string
}

// A row in the automated response log
export type ResponseLogItem = {
  id: string
  time: string
  action: string
  by: string
  result: 'Done' | 'Failed'
}
