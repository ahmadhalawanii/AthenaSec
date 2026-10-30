import type { DemoAccount } from '../types/appTypes'
import type { LoginStat, RadarBlip } from '../types/loginTypes'
import { statusTone } from '../utils/statusTone'

import { initialAlerts } from './alertsData'
import { executionRecords } from './incidentResponseData'
import { initialServices } from './systemHealthData'

export const DEMO_ACCOUNTS: DemoAccount[] = [
  {
    email: 'analyst@athenasec.com',
    password: 'analyst123',
    role: 'Analyst',
    name: 'Analyst A',
  },
  {
    email: 'admin@athenasec.com',
    password: 'admin123',
    role: 'Administrator',
    name: 'System Administrator',
  },
]

// The demo MFA code: MfaPage checks against it and the Demo mode note shows it.
export const DEMO_MFA_CODE = '123456'

function minutesBetween(start: string, end: string) {
  const toMinutes = (time: string) => {
    const [hours, minutes] = time.split(':').map(Number)
    return hours * 60 + minutes
  }

  return toMinutes(end) - toMinutes(start)
}

const completedIsolations = executionRecords
  .filter((run) => run.action === 'Isolate Host' && run.result === 'Completed')
  .map((run) => minutesBetween(run.startTime, run.endTime))

const completedRuns = executionRecords.filter(
  (run) => run.result === 'Completed',
).length

// Login brand panel figures, all derived from the app's data.
export const LOGIN_STATS: LoginStat[] = [
  {
    value:
      completedIsolations.length > 0
        ? `${Math.min(...completedIsolations)} min`
        : 'n/a',
    label: 'from exploit detected to host isolated',
  },
  {
    value: `${completedRuns} of ${executionRecords.length}`,
    label: 'responses completed',
  },
  {
    value: String(initialServices.length),
    label: 'services monitored in one console',
  },
]

// Fixed blip positions on the 400x400 radar, one per alert in order.
const RADAR_POSITIONS: Array<[number, number]> = [
  [300, 110],
  [120, 140],
  [250, 290],
  [105, 265],
  [330, 240],
  [160, 320],
  [280, 170],
]

export const RADAR_BLIPS: RadarBlip[] = initialAlerts
  .slice(0, RADAR_POSITIONS.length)
  .map((alert, index) => ({
    id: alert.id,
    x: RADAR_POSITIONS[index][0],
    y: RADAR_POSITIONS[index][1],
    tone: statusTone(alert.severity),
    open: alert.status === 'Open',
  }))

const openDetections = initialAlerts.filter(
  (alert) => alert.status === 'Open',
).length

export const RADAR_LABEL = `Threat radar showing ${initialAlerts.length} detections today, ${openDetections} open`
