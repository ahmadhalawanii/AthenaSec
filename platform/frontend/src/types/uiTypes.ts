import type { AlertRecord } from './alertsTypes'

export type Severity = AlertRecord['severity']

export type TimelineStepState = 'done' | 'fail' | 'active'

export type TimelineStep = {
  time: string
  label: string
  state: TimelineStepState
}

export type SegmentedOption<T extends string> = {
  value: T
  label: string
  // Optional count shown after the label, e.g. "Needs decision 3"
  count?: number
}
