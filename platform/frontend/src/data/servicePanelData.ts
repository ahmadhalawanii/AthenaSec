import type { ServicePanelState } from '../types/servicePanelTypes'

import { vmChecks } from './serviceInventory'
import { initialServices } from './systemHealthData'

/*
  Demo data for the Service Panel. The live checks run in the desktop
  Service Panel on the Ubuntu VM; this page only shows a fixed snapshot,
  so there is no jitter: every figure is the same on every load.

  The snapshot matches the design: the Wazuh Manager and Indexer are
  running and the Dashboard is still starting, so Wazuh reads
  "Partially running — 2/3". MISP answers on its login page, Cortex on
  /api/status, and Docker Engine has been up for 2 days 4 hours 12 minutes.
*/

export const initialServicePanel: ServicePanelState = {
  // The six checks are the VM group of the service inventory (src/data/systemHealthData.ts):
  // the component uptimes there are assumed, since the design only shows that the Wazuh group has none
  results: vmChecks(initialServices),
  usage: {
    cpuPercent: 38.4,
    // 71.2 % of 8 GiB, which reads "5.7 / 8.0 GiB" (set in bytes so both figures display exactly)
    memoryUsedBytes: 6116033430,
    memoryTotalBytes: 8589934592,
  },
}
