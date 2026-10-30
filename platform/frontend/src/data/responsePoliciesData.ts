import type { ResponsePolicy } from '../types/responsePoliciesTypes'

import {
  PROTECTED_BLOCK_SEEDS,
  PROTECTED_ISOLATE_SEEDS,
  THRESHOLDS,
  tier1Actions,
  tier3Actions,
} from './agentPolicyData'

/*
  The response policy the demo starts with (design/athenasec-redesign/screens/
  response-policy-lists.png): the ten Tier 1 actions whitelisted Automatic,
  block_ip and isolate_host whitelisted Needs approval, the six prohibited
  actions blacklisted, and suspend_user_session, kill_process,
  quarantine_file and reset_password on neither list (so denied).
  Version 3: the first two versions are the audited changes AUD-203 and AUD-206.

  The limits are what the old policies enforced: block_ip 30 min by default
  and 24 h at most, isolate_host 2 h and 4 h, 15 min to decide, and
  Minimum risk 70 and 90 (the PDF's floor for isolation is 85; the administrator raised it).
*/

export const SEED_POLICY_VERSION = 3

export const initialResponsePolicy: ResponsePolicy = {
  version: SEED_POLICY_VERSION,
  whitelist: [
    ...tier1Actions.map((action) => ({ action: action.name.split('(')[0], mode: 'Automatic' as const })),
    {
      action: 'block_ip',
      mode: 'Needs approval',
      limits: { defaultMinutes: 30, maxMinutes: 24 * 60, approver: 'soc_analyst', windowMinutes: 15, minRisk: THRESHOLDS.block.risk },
    },
    {
      action: 'isolate_host',
      mode: 'Needs approval',
      limits: { defaultMinutes: 120, maxMinutes: 240, approver: 'soc_lead', windowMinutes: 15, minRisk: 90 },
    },
  ],
  blacklist: tier3Actions.map((action) => ({ action: action.requestName, required: true })),
  neverBlock: PROTECTED_BLOCK_SEEDS.map((target) => ({ ...target, required: true })),
  neverIsolate: PROTECTED_ISOLATE_SEEDS.map((target) => ({ ...target, required: true })),
}
