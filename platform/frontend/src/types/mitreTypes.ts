import type { AlertResponseState } from './alertsTypes'

export type MitreTechnique = {
  id: string
  name: string
}

export type MitreTactic = {
  name: string
  techniques: MitreTechnique[]
}

/*
  What the ATT&CK activity grid shows for a technique, worst first:
  failed (a containment failed), waiting (a recommendation waits for a
  person), open (an alert is open with nothing waiting), handled (every
  alert for it is contained, blocked or closed), quiet (no alert uses it).
*/
export type ActivityState = 'failed' | 'waiting' | 'open' | 'handled' | 'quiet'

// An alert that used the technique, and what the agent did about it
export type ActivityAlert = {
  id: string
  title: string
  risk: number
  // The agent's outcome for it ("Recommend IP block")
  outcome: string
  response: AlertResponseState
  // The request waiting for a person, when there is one
  approvalId?: string
}

export type ActivityCell = MitreTechnique & {
  state: ActivityState
  alerts: ActivityAlert[]
}

export type ActivityColumn = {
  tactic: string
  cells: ActivityCell[]
  // Techniques in this tactic that an alert used
  seenCount: number
}
