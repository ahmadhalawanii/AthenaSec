import type { AlertEvidence } from '../types/alertsTypes'

/*
  Tagged evidence per alert. The wording follows the case and
  execution records (casesData.ts, incidentResponseData.ts), which win
  over the design files where they differ.
*/
export const alertEvidence: Record<string, AlertEvidence[]> = {
  'ALT-001': [
    { source: 'Auth', text: '148 failed SSH logins in five minutes' },
    { source: 'Auth', text: 'Multiple privileged usernames targeted' },
    { source: 'Intel', text: 'Source matched earlier scanning activity' },
    { source: 'Auth', text: 'No confirmed successful login' },
    { source: 'Policy', text: 'Block recommended under response policy v3 (risk 77), waiting for a SOC analyst to approve' },
  ],
  'ALT-002': [
    { source: 'Endpoint', text: 'Unexpected sudo from a standard user session' },
    { source: 'Endpoint', text: 'Elevation outside the maintenance window' },
    { source: 'Policy', text: 'Risk 50 is below the 70 needed to recommend containment' },
  ],
  'ALT-003': [
    { source: 'Auth', text: 'Login attempts spread across many VPN accounts' },
    { source: 'Network', text: 'All attempts from 203.0.113.88' },
    { source: 'Policy', text: 'Risk 54 is below the 70 needed to recommend a block' },
  ],
  'ALT-004': [
    { source: 'Endpoint', text: 'Kernel exploit signature matched endpoint telemetry' },
    { source: 'Policy', text: 'Risk 52 is below the 85 needed to recommend isolation' },
    { source: 'Response', text: 'Nothing isolated, no lateral movement seen' },
  ],
  'ALT-005': [
    { source: 'Network', text: 'One connection attempt to port 22, no follow-up' },
  ],
  'ALT-006': [
    { source: 'Endpoint', text: 'EDR flagged the web service injecting code into a system process' },
    { source: 'Network', text: 'Outbound beaconing every 60 seconds to 203.0.113.9' },
    { source: 'Intel', text: 'Destination 203.0.113.9 is on a MISP command-and-control feed' },
    { source: 'Endpoint', text: 'A new systemd service was created for persistence' },
    { source: 'Endpoint', text: 'A shell was spawned by the application service account' },
    { source: 'Response', text: 'endpoint-12 isolated at 15:44 after SOC lead approval, until 17:44' },
  ],
}

// Recommended next steps per alert (Alerts page, Response tab)
export const alertNextSteps: Record<string, string[]> = {
  'ALT-001': [
    'Approve or reject the block of 203.0.113.45 (a SOC analyst decides)',
    'Confirm no session was opened from 203.0.113.45',
    'Reset credentials for the targeted privileged accounts',
    'Close the alert and CASE-006',
  ],
  'ALT-002': [
    'Review the sudo session and command history',
    'Confirm whether the activity was authorized',
    'Lock the account that ran sudo if it was not',
  ],
  'ALT-003': [
    'Check whether any targeted VPN account logged in successfully',
    'Close the alert',
  ],
  'ALT-004': [
    'Image endpoint-09 for forensics',
    'Rebuild before reconnecting',
  ],
  'ALT-005': ['No action needed'],
  'ALT-006': [
    'Image endpoint-12 for forensics before it reconnects at 17:44',
    'Check other hosts for beaconing to 203.0.113.9',
    'Rebuild or clean endpoint-12 before it reconnects',
  ],
}
