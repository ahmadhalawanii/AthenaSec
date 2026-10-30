#!/usr/bin/env node
/*
  Self-test for the Service Panel logic (src/data/servicePanel.ts) and its
  demo seed (src/data/servicePanelData.ts), ported from the desktop
  Service Panel v3.

  Compiles the two files with the project's own TypeScript into a
  temporary folder (nothing is written to the project), then checks them
  in Node. The summarize cases mirror the desktop panel's own tests in
  tests/test_overview_and_sites.py, with the same expected titles. No
  install needed.

  Usage:
    npm run verify:panel

  Exit code: 0 when every check passes, 1 on any failure, 2 if the code
  does not compile.
*/

import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const root = resolve('.')
const outDir = mkdtempSync(join(tmpdir(), 'athenasec-panel-'))

function compile() {
  const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc')
  const result = spawnSync(
    process.execPath,
    [
      tsc,
      'src/data/servicePanel.ts',
      'src/data/servicePanelData.ts',
      'src/utils/statusTone.ts',
      '--ignoreConfig',
      '--outDir', outDir,
      '--rootDir', 'src',
      '--module', 'commonjs',
      '--moduleResolution', 'node10',
      '--ignoreDeprecations', '6.0',
      '--target', 'es2022',
      '--lib', 'es2022,dom',
      '--strict',
      '--skipLibCheck',
    ],
    { cwd: root, encoding: 'utf8' },
  )

  if (result.status !== 0) {
    console.error('verify:panel: the code did not compile:')
    console.error(result.stdout || result.stderr)
    rmSync(outDir, { recursive: true, force: true })
    process.exit(2)
  }
}

compile()

const require = createRequire(import.meta.url)
const panel = require(join(outDir, 'data', 'servicePanel.js'))
const { initialServicePanel: seed } = require(join(outDir, 'data', 'servicePanelData.js'))

const results = []

function check(area, name, run) {
  try {
    const outcome = run()
    const pass = outcome === true || (outcome && outcome.pass === true)
    results.push({ area, name, pass, detail: pass ? '' : outcome?.detail ?? String(outcome) })
  } catch (error) {
    results.push({ area, name, pass: false, detail: `threw: ${error.message}` })
  }
}

const is = (actual, expected) =>
  actual === expected || { pass: false, detail: `got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}` }

// The desktop panel's helper: three Wazuh checks with the given states and uptimes
const wazuhChecks = (states, uptimes = [null, null, null]) =>
  ['manager', 'indexer', 'dashboard'].map((key, index) => ({ key, state: states[index], detail: '', uptime: uptimes[index], displayStatus: '' }))

/*
  Five states, not six, as in tests/test_overview_and_sites.py
  (itertools.product of these five, repeat=3, so 125 combinations).
  "partial" is left out on purpose: it is only ever the summary of the
  three Wazuh checks, never a state one check reports.
*/
const STATES5 = ['running', 'stopped', 'starting', 'unhealthy', 'unknown']
const combos = STATES5.flatMap((a) => STATES5.flatMap((b) => STATES5.map((c) => [a, b, c])))

// ---------- summarize: every case of test_overview_and_sites.py ----------
check('summarize', `all ${combos.length} combinations of five states across three checks: running only when all three run, unknown when any is unknown, else partial when some run`, () => {
  const bad = []
  for (const states of combos) {
    const wazuh = panel.summarizeWazuh(wazuhChecks(states))[0]
    const allRunning = states.every((s) => s === 'running')
    if ((wazuh.state === 'running') !== allRunning) bad.push(`${states} running?`)
    if (states.includes('unknown') && wazuh.state !== 'unknown') bad.push(`${states} unknown?`)
    else if (!states.includes('unknown') && states.filter((s) => s === 'running').length > 0 && !allRunning && wazuh.state !== 'partial') bad.push(`${states} partial?`)
  }
  return bad.length === 0 || { pass: false, detail: bad.slice(0, 5).join('; ') }
})
check('summarize', 'the title for each combination follows the precedence (running, unknown, partial, stopped, unhealthy, starting, else unknown)', () => {
  const expectedTitle = (states) => {
    const count = states.filter((s) => s === 'running').length
    if (count === 3) return 'Running — 3/3'
    if (states.includes('unknown')) return `Unverified — ${count}/3 running`
    if (count > 0) return `Partially running — ${count}/3`
    if (states.every((s) => s === 'stopped')) return 'Stopped — 0/3'
    if (states.includes('unhealthy')) return 'Unhealthy — 0/3 running'
    if (states.includes('starting')) return 'Starting — 0/3 running'
    return 'Unverified — 0/3 running'
  }
  const bad = combos.filter((states) => panel.summarizeWazuh(wazuhChecks(states))[0].displayStatus !== expectedTitle(states))
  return bad.length === 0 || { pass: false, detail: bad.slice(0, 5).join('; ') }
})
check('summarize', 'each title, spelled out: Running — 3/3, Unverified — 1/3 running, Partially running — 2/3, Stopped — 0/3, Unhealthy — 0/3 running, Starting — 0/3 running, Unverified — 0/3 running', () => {
  const title = (states) => panel.summarizeWazuh(wazuhChecks(states))[0].displayStatus
  const got = [
    title(['running', 'running', 'running']),
    title(['running', 'unknown', 'stopped']),
    title(['running', 'stopped', 'running']),
    title(['stopped', 'stopped', 'stopped']),
    title(['stopped', 'unhealthy', 'stopped']),
    title(['starting', 'stopped', 'starting']),
    title(['partial', 'partial', 'partial']),
  ]
  const want = ['Running — 3/3', 'Unverified — 1/3 running', 'Partially running — 2/3', 'Stopped — 0/3', 'Unhealthy — 0/3 running', 'Starting — 0/3 running', 'Unverified — 0/3 running']
  return JSON.stringify(got) === JSON.stringify(want) || { pass: false, detail: JSON.stringify(got) }
})
check('summarize', 'partial card names the failed component: "Partially running — 2/3", detail has "Indexer: Stopped", no uptime', () => {
  const card = panel.summarizeWazuh(wazuhChecks(['running', 'stopped', 'running']))[0]
  return card.displayStatus === 'Partially running — 2/3' && card.detail.includes('Indexer: Stopped') && card.uptime === null || { pass: false, detail: JSON.stringify(card) }
})
check('summarize', 'the detail is three lines, "Manager: Running", "Indexer: Stopped", "Dashboard: Starting"', () =>
  is(panel.summarizeWazuh(wazuhChecks(['running', 'stopped', 'starting']))[0].detail, 'Manager: Running\nIndexer: Stopped\nDashboard: Starting'))
check('summarize', 'all stopped and a zero-running failure are distinct: stopped, then unhealthy', () =>
  panel.summarizeWazuh(wazuhChecks(['stopped', 'stopped', 'stopped']))[0].state === 'stopped' && panel.summarizeWazuh(wazuhChecks(['stopped', 'unhealthy', 'stopped']))[0].state === 'unhealthy')
check('summarize', 'a missing result is unknown ("Unverified — 1/3 running" when only the Manager reported)', () => {
  const wazuh = panel.summarizeWazuh([{ key: 'manager', state: 'running', detail: '', uptime: null, displayStatus: '' }])[0]
  return wazuh.state === 'unknown' && wazuh.displayStatus === 'Unverified — 1/3 running' || { pass: false, detail: JSON.stringify(wazuh) }
})
check('summarize', 'group uptime is the time since the last component became active (600, 300, 400 gives 300)', () =>
  is(panel.summarizeWazuh(wazuhChecks(['running', 'running', 'running'], [600, 300, 400]))[0].uptime, 300))
check('summarize', 'no group uptime when a component has none (600, null, 400)', () =>
  is(panel.summarizeWazuh(wazuhChecks(['running', 'running', 'running'], [600, null, 400]))[0].uptime, null))
check('summarize', 'four logical services keep independent results: keys wazuh, misp, cortex, docker; 3 running; MISP detail "HTTP 503" kept', () => {
  const rows = [
    ...wazuhChecks(['running', 'running', 'running']),
    { key: 'misp', state: 'unhealthy', detail: 'HTTP 503', uptime: null, displayStatus: '' },
    { key: 'cortex', state: 'running', detail: 'Available', uptime: null, displayStatus: '' },
    { key: 'docker', state: 'running', detail: 'Active', uptime: null, displayStatus: '' },
  ]
  const cards = panel.summarizeWazuh(rows)
  return cards.map((c) => c.key).join() === 'wazuh,misp,cortex,docker' && cards.filter((c) => c.state === 'running').length === 3 && cards[1].detail === 'HTTP 503' || { pass: false, detail: JSON.stringify(cards) }
})
check('summarize', 'a missing MISP, Cortex or Docker result is unknown, not dropped', () => {
  const cards = panel.summarizeWazuh(wazuhChecks(['running', 'running', 'running']))
  return cards.length === 4 && cards.slice(1).every((c) => c.state === 'unknown' && c.detail === 'No result') || { pass: false, detail: JSON.stringify(cards) }
})

// ---------- Catalogue (the structural facts of test_services.py) ----------
check('catalogue', 'six checks in the desktop panel\'s order, each with its unit or port and path', () => {
  const rows = panel.SERVICE_CHECKS.map((c) => `${c.key}:${c.unit ?? ''}${c.port ? `${c.port}${c.path}` : ''}`).join()
  return is(rows, 'manager:wazuh-manager,indexer:wazuh-indexer,dashboard:wazuh-dashboard,misp:9445/users/heartbeat,cortex:9444/api/status,docker:docker')
})
check('catalogue', 'six states in order and four groups: wazuh, misp, cortex, docker', () =>
  panel.SERVICE_STATES.join() === 'running,partial,stopped,starting,unhealthy,unknown' && panel.OVERVIEW_GROUPS.map((g) => g.key).join() === 'wazuh,misp,cortex,docker' && panel.GROUP_COUNT === 4)
check('catalogue', 'the three console origins are the fixed ones, in one constant', () =>
  JSON.stringify(Object.entries(panel.CONSOLES).map(([k, v]) => [k, v.origin])) === JSON.stringify([['wazuh', 'https://192.168.1.164'], ['cortex', 'https://192.168.1.164:9444'], ['misp', 'https://192.168.1.164:9445']]))
check('catalogue', 'Docker Engine has no console; Wazuh, Cortex and MISP do', () => !('docker' in panel.CONSOLES) && Object.keys(panel.CONSOLES).length === 3)

// ---------- Uptime wording ----------
check('uptime', 'boundaries: 59 s is "0m", 60 s "1m", 3599 s "59m", 1 h "1h 0m", 1 d "1d 0h 0m"', () => {
  const got = [59, 60, 3599, 3600, 86399, 86400].map(panel.formatUptime)
  return got.join('|') === '0m|1m|59m|1h 0m|23h 59m|1d 0h 0m' || { pass: false, detail: got.join('|') }
})
check('uptime', '0 s is "0m"; fractions truncate (59.9 s is "0m"); 2d 4h 12m is exact', () =>
  panel.formatUptime(0) === '0m' && panel.formatUptime(59.9) === '0m' && panel.formatUptime(2 * 86400 + 4 * 3600 + 12 * 60) === '2d 4h 12m')
check('uptime', 'the card lines: Wazuh "All active for:", Docker "Uptime:", MISP and Cortex "Endpoint check, no uptime"', () =>
  panel.uptimeLine('wazuh', null) === 'All active for: —' && panel.uptimeLine('wazuh', 300) === 'All active for: 5m' && panel.uptimeLine('docker', 187920) === 'Uptime: 2d 4h 12m' && panel.uptimeLine('misp', null) === 'Endpoint check, no uptime' && panel.uptimeLine('cortex', 9) === 'Endpoint check, no uptime')

// ---------- Issue count ----------
const groupsWith = (running, otherState = 'stopped') =>
  ['wazuh', 'misp', 'cortex', 'docker'].map((key, index) => ({ key, state: index < running ? 'running' : otherState, detail: '', uptime: null, displayStatus: '' }))
check('issues', 'issues are 4 minus the running groups, for 0 to 4 running', () => {
  const got = [0, 1, 2, 3, 4].map((n) => panel.issueCount(groupsWith(n)))
  return got.join() === '4,3,2,1,0' || { pass: false, detail: got.join() }
})
check('issues', 'partial, starting, stopped, unhealthy and unknown all count as issues; only running does not', () =>
  ['partial', 'starting', 'stopped', 'unhealthy', 'unknown'].every((state) => panel.issueCount(groupsWith(3, state)) === 1) && panel.runningCount(groupsWith(3)) === 3)
check('issues', 'the seed has 3 running and 1 issue', () => {
  const groups = panel.summarizeWazuh(seed.results)
  return panel.runningCount(groups) === 3 && panel.issueCount(groups) === 1 || { pass: false, detail: groups.map((g) => g.state).join() }
})

// ---------- Sentences ----------
check('words', 'header sentence for the seed: "3 of 4 service groups running; Wazuh Dashboard is still starting."', () =>
  is(panel.statusSentence(seed.results), 'The AthenaSec stack on the Ubuntu VM. 3 of 4 service groups running; Wazuh Dashboard is still starting.'))
check('words', 'header sentence when everything runs, and when MISP is down and Cortex is unverified', () => {
  const allUp = ['manager', 'indexer', 'dashboard', 'misp', 'cortex', 'docker'].map((key) => ({ key, state: 'running', detail: '', uptime: null, displayStatus: '' }))
  const two = allUp.map((r) => (r.key === 'misp' ? { ...r, state: 'unhealthy' } : r.key === 'cortex' ? { ...r, state: 'unknown' } : r))
  return panel.statusSentence(allUp) === 'The AthenaSec stack on the Ubuntu VM. All 4 service groups running.' && panel.statusSentence(two) === 'The AthenaSec stack on the Ubuntu VM. 2 of 4 service groups running; MISP is unhealthy; Cortex could not be verified.' || { pass: false, detail: panel.statusSentence(two) }
})
check('words', 'Wazuh detail for the seed: "Manager and Indexer are active. Dashboard is still starting, so the Wazuh console may not load yet."', () =>
  is(panel.wazuhDetail(seed.results), 'Manager and Indexer are active. Dashboard is still starting, so the Wazuh console may not load yet.'))
check('words', 'Wazuh detail when all run, and when only the Indexer is stopped (no console warning)', () => {
  const rows = (states) => wazuhChecks(states)
  return panel.wazuhDetail(rows(['running', 'running', 'running'])) === 'Manager, Indexer and Dashboard are active.' && panel.wazuhDetail(rows(['running', 'stopped', 'running'])) === 'Manager and Dashboard are active. Indexer is stopped.' || { pass: false, detail: panel.wazuhDetail(rows(['running', 'stopped', 'running'])) }
})
check('words', 'state tones: running green, partial and starting amber, unhealthy red, stopped and unknown neutral', () => {
  const got = panel.SERVICE_STATES.map((s) => `${s}:${panel.stateTone(s)}`).join()
  return got === 'running:ok,partial:caution,stopped:neutral,starting:caution,unhealthy:danger,unknown:neutral' || { pass: false, detail: got }
})

// ---------- The demo seed matches the design ----------
check('seed', 'six results, one per check, in the desktop panel\'s order', () => is(seed.results.map((r) => r.key).join(), 'manager,indexer,dashboard,misp,cortex,docker'))
check('seed', 'Manager and Indexer running, Dashboard starting: Wazuh is "Partially running — 2/3" with no group uptime', () => {
  const wazuh = panel.summarizeWazuh(seed.results)[0]
  return wazuh.state === 'partial' && wazuh.displayStatus === 'Partially running — 2/3' && wazuh.uptime === null || { pass: false, detail: JSON.stringify(wazuh) }
})
check('seed', 'MISP is "Available" (state running) with "MISP login page responded; web availability only"', () => {
  const misp = panel.summarizeWazuh(seed.results)[1]
  return misp.state === 'running' && misp.displayStatus === 'Available' && misp.detail === 'MISP login page responded; web availability only' || { pass: false, detail: JSON.stringify(misp) }
})
check('seed', 'Cortex is running; Docker Engine is running with uptime 2d 4h 12m', () => {
  const [, , cortex, docker] = panel.summarizeWazuh(seed.results)
  return cortex.state === 'running' && docker.state === 'running' && panel.formatUptime(docker.uptime) === '2d 4h 12m' || { pass: false, detail: JSON.stringify([cortex, docker]) }
})
check('seed', 'CPU 38.4 %, RAM 71.2 % and "5.7 / 8.0 GiB" all display exactly (no rounding surprise)', () => {
  const { cpuPercent, memoryUsedBytes, memoryTotalBytes } = seed.usage
  const ram = panel.percentText(panel.memoryPercent(memoryUsedBytes, memoryTotalBytes))
  return panel.percentText(cpuPercent) === '38.4' && ram === '71.2' && panel.memoryDetail(memoryUsedBytes, memoryTotalBytes) === '5.7 / 8.0 GiB' || { pass: false, detail: `${ram} ${panel.memoryDetail(memoryUsedBytes, memoryTotalBytes)}` }
})
check('seed', 'the percentage helper rounds like the desktop panel for ordinary values', () =>
  panel.percentText(0) === '0.0' && panel.percentText(100) === '100.0' && panel.percentText(41.7) === '41.7')

// ---------- One vocabulary (the Panel's states through the shared service words) ----------
const inventory = require(join(outDir, 'data', 'serviceInventory.js'))
const { initialServices } = require(join(outDir, 'data', 'systemHealthData.js'))
const { statusTone } = require(join(outDir, 'utils', 'statusTone.js'))

check('words', 'a failed VM service never displays as Degraded: every VM service set to Failed reads Failed (the Panel\'s "unhealthy"), is Failed in the top bar, and the Wazuh title keeps "Unhealthy — 0/3 running" while the page shows "Failed — 0/3 running"', () => {
  const bad = []
  for (const service of initialServices.filter((s) => s.group === 'vm')) {
    const failed = initialServices.map((s) => (s.id === service.id ? { ...s, status: 'Failed' } : s))
    const word = inventory.serviceStatus(failed.find((s) => s.id === service.id))
    const status = inventory.systemStatus(failed)
    const check = inventory.vmChecks(failed).find((c) => c.key === service.check.key)
    if (word !== 'Failed') bad.push(`${service.name} reads ${word}`)
    if (check.state !== 'unhealthy' || inventory.STATE_WORDS[check.state] !== 'Failed') bad.push(`${service.name} panel word`)
    if (!status.text.toLowerCase().includes('failed') && !status.text.includes('need attention')) bad.push(`${service.name} top bar "${status.text}"`)
    if (status.level !== 'danger' || status.affected[0] !== service.name) bad.push(`${service.name} not named first as an outage`)
  }
  const allDown = initialServices.map((s) => (['SVC-001', 'SVC-008', 'SVC-009'].includes(s.id) ? { ...s, status: 'Failed' } : s))
  const title = panel.summarizeWazuh(inventory.vmChecks(allDown))[0].displayStatus
  if (title !== 'Unhealthy — 0/3 running' || inventory.inDisplayWords(title) !== 'Failed — 0/3 running') bad.push(`title ${title}`)
  return bad.length === 0 || { pass: false, detail: bad.join('; ') }
})
check('words', 'Failed and Degraded stay distinct: different words, different tones, and Failed counts as needing attention and sorts before Degraded', () => {
  const failed = initialServices.map((s) => (s.id === 'SVC-007' ? { ...s, status: 'Failed' } : s))
  const order = inventory.attentionServices(failed).map((s) => inventory.serviceStatus(s))
  return statusTone('Failed') !== statusTone('Degraded') && order.join() === 'Failed,Degraded,Starting' || { pass: false, detail: order.join() }
})

// ---------- Report ----------
rmSync(outDir, { recursive: true, force: true })

const byArea = {}
for (const r of results) {
  byArea[r.area] ??= { pass: 0, total: 0 }
  byArea[r.area].total += 1
  if (r.pass) byArea[r.area].pass += 1
}

for (const [area, { pass, total }] of Object.entries(byArea)) {
  console.log(`  ${pass === total ? 'ok  ' : 'FAIL'}  ${area.padEnd(10)} ${pass}/${total}`)
}

const failed = results.filter((r) => !r.pass)

if (failed.length) {
  console.log('Failed checks:')
  for (const f of failed) console.log(`  [${f.area}] ${f.name}\n      ${f.detail}`)
}

console.log(`${results.length - failed.length}/${results.length} panel checks passed.`)
process.exit(failed.length ? 1 : 0)
