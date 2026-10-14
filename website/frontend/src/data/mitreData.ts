import type { MitreTactic } from '../types/mitreTypes'

/*
  MITRE ATT&CK tactics shown on the admin dashboard, in kill-chain order,
  with the techniques AthenaSec tracks for each. Technique ids match the
  MITRE mappings on the alerts (T1548 for the privilege escalation
  alert, as in its data); the grid shows which of them an alert used
  and what the agent did about it. A technique no alert uses is "not seen".
*/
export const mitreTactics: MitreTactic[] = [
  { name: 'Reconnaissance', techniques: [] },
  {
    name: 'Initial access',
    techniques: [{ id: 'T1133', name: 'External remote services' }],
  },
  { name: 'Execution', techniques: [] },
  { name: 'Persistence', techniques: [] },
  {
    name: 'Privilege escalation',
    techniques: [
      { id: 'T1068', name: 'Exploitation for privilege escalation' },
      { id: 'T1548', name: 'Abuse elevation control mechanism' },
    ],
  },
  { name: 'Defense evasion', techniques: [] },
  {
    name: 'Credential access',
    techniques: [
      { id: 'T1110', name: 'Brute force' },
      { id: 'T1110.003', name: 'Password spraying' },
    ],
  },
  {
    name: 'Discovery',
    techniques: [{ id: 'T1046', name: 'Network service discovery' }],
  },
  {
    name: 'Lateral movement',
    techniques: [{ id: 'T1021', name: 'Remote services' }],
  },
  {
    name: 'Command and control',
    techniques: [{ id: 'T1071', name: 'Application layer protocol' }],
  },
  { name: 'Impact', techniques: [] },
]

// "T1110 - Brute Force" -> "T1110"
export function mitreId(mapping: string) {
  return mapping.trim().split(/\s+/)[0] ?? ''
}
