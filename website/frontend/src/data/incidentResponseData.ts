import type { ExecutionRecord } from '../types/incidentResponseTypes'

import { riskFor } from './alertAssessments'

/*
  What has run today. Nothing runs without a person's approval, so a
  run exists only after its approval record (approvalData.ts). Only the
  isolation of endpoint-12 has been approved and carried out; ALT-001's
  block is still waiting for an analyst. The score in the evidence
  comes from the policy formula, like every other score.
*/
export const executionRecords: ExecutionRecord[] = [
  {
    id: 'EXE-001',
    triggeringAlert: 'ALT-006',
    approvalId: 'APR-001',
    policy: 'Response policy v2: isolate_host',
    action: 'Isolate Host',
    target: 'endpoint-12',
    startTime: '15:44',
    endTime: '15:45',
    duration: '1 minute',
    result: 'Completed',
    rollbackStatus: 'Reconnects automatically at 17:44',
    failureReason: 'None',
    happened:
      'AthenaSec isolated endpoint-12 after the System Administrator approved the recommendation.',
    classified:
      'EDR flagged the web service injecting code into a system process, the host beaconed every 60 seconds to a command-and-control address listed by MISP, and a persistence service was created.',
    responseReason:
      'Isolation stops the beaconing and any lateral movement while the host keeps its telemetry for investigation. The host is a Business asset, so isolation was allowed, and a SOC lead approved it.',
    evidence: [
      `Risk score ${riskFor('ALT-006')}`,
      'Code injection into a system process',
      'Beaconing to 203.0.113.9 every 60 seconds',
      'Approved by the System Administrator at 15:43',
    ],
    timeline: [
      {
        time: '15:41',
        event: 'Code injection and beaconing detected',
      },
      {
        time: '15:42',
        event: 'Isolation recommended for endpoint-12',
      },
      {
        time: '15:43',
        event: 'Approved by the System Administrator (SOC lead)',
      },
      {
        time: '15:44',
        event: 'Isolation command sent, approval token used',
      },
      {
        time: '15:45',
        event: 'endpoint-12 isolated successfully',
      },
    ],
  },
]
