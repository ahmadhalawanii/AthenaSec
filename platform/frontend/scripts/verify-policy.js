#!/usr/bin/env node
/*
  Self-test for the Agent Action Catalogue and Approval Policy engine
  (src/data/policyEngine.ts, src/data/agentPolicyData.ts).

  Compiles the engine with the project's own TypeScript into a temporary
  folder (nothing is written to the project), then checks the policy in
  Node: the risk formula, every threshold edge of the decision ladder,
  the allow-list, durations, approval tokens, the policy guard, approval
  records (src/data/approvalData.ts) and the audit hash chain (Web
  Crypto). No install needed.

  Usage:
    npm run verify:policy

  Exit code: 0 when every check passes, 1 on any failure, 2 if the
  engine does not compile.
*/

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const root = resolve('.')
const outDir = mkdtempSync(join(tmpdir(), 'athenasec-policy-'))

function compile() {
  const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc')
  const result = spawnSync(
    process.execPath,
    [
      tsc,
      'src/data/policyEngine.ts',
      'src/data/approvalData.ts',
      'src/data/approvalFlow.ts',
      'src/data/incidentResponseData.ts',
      'src/data/auditLogsData.ts',
      'src/data/auditChain.ts',
      'src/data/auditEventTypes.ts',
      'src/data/auditDemoEvents.ts',
      'src/data/notificationsData.ts',
      'src/data/statusSummary.ts',
      'src/data/alertAssessments.ts',
      'src/data/userManagementData.ts',
      'src/data/systemHealthData.ts',
      'src/data/configurationData.ts',
      'src/data/loginData.ts',
      'src/data/serviceInventory.ts',
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
    console.error('verify:policy: the engine did not compile:')
    console.error(result.stdout || result.stderr)
    rmSync(outDir, { recursive: true, force: true })
    process.exit(2)
  }
}

compile()

const require = createRequire(import.meta.url)
const engineRaw = require(join(outDir, 'data', 'policyEngine.js'))
const data = require(join(outDir, 'data', 'agentPolicyData.js'))
const approvals = require(join(outDir, 'data', 'approvalData.js'))
const flow = require(join(outDir, 'data', 'approvalFlow.js'))
const incident = require(join(outDir, 'data', 'incidentResponseData.js'))
const policies = require(join(outDir, 'data', 'responsePoliciesData.js'))

/*
  R3a: the engine takes a response policy (default: the seed). The checks written
  against the PDF's own numbers (the decision ladder, the floors, the caps, the guard
  and the attempt) run unchanged against PDF_POLICY: every Tier 2 action whitelisted at the
  PDF's own limits, every Tier 1 action Automatic, the six prohibited actions blacklisted.
  The seed policy (isolate_host minimum risk 90, suspend_user_session and the three
  assumption actions on neither list) has its own checks in the "R3a" area, which
  call engineRaw with it.
*/
const PDF_POLICY = {
  version: 1,
  whitelist: [
    ...data.tier1Actions.map((a) => ({ action: a.name.split('(')[0], mode: 'Automatic' })),
    ...data.tier2Actions.map((a) => ({
      action: a.name,
      mode: 'Needs approval',
      limits: { defaultMinutes: a.defaultMinutes, maxMinutes: a.maxMinutes, approver: a.approver, windowMinutes: a.approvalWindowMinutes, minRisk: a.floor.risk },
    })),
  ],
  blacklist: policies.initialResponsePolicy.blacklist,
  neverBlock: policies.initialResponsePolicy.neverBlock,
  neverIsolate: policies.initialResponsePolicy.neverIsolate,
}
// A copy of a policy with one change applied by `change(copy)`
const policyWith = (change, base = PDF_POLICY) => {
  const copy = structuredClone(base)
  change(copy)
  return copy
}
const limitsOf = (policy, action) => policy.whitelist.find((entry) => entry.action === action).limits
// A wrapper keeps the function's own declared length (attemptDecision takes one request)
const withPdfPolicy = (fn, index) => {
  const wrapped = (...args) => {
    while (args.length < index) args.push(undefined)
    args[index] ??= PDF_POLICY
    return fn(...args)
  }
  Object.defineProperty(wrapped, 'length', { value: fn.length })
  return wrapped
}
const engine = {
  ...engineRaw,
  assess: withPdfPolicy(engineRaw.assess, 1),
  attemptDecision: withPdfPolicy(engineRaw.attemptDecision, 1),
  guard: withPdfPolicy(engineRaw.guard, 2),
  tier2Spec: withPdfPolicy(engineRaw.tier2Spec, 1),
  approvalRefusal: withPdfPolicy(engineRaw.approvalRefusal, 3),
}
const audit =require(join(outDir, 'data', 'auditLogsData.js'))
const chainModule = require(join(outDir, 'data', 'auditChain.js'))
const eventTypes = require(join(outDir, 'data', 'auditEventTypes.js'))
const notifications = require(join(outDir, 'data', 'notificationsData.js'))
const demoEvents = require(join(outDir, 'data', 'auditDemoEvents.js'))
const summary = require(join(outDir, 'data', 'statusSummary.js'))
const alertData = require(join(outDir, 'data', 'alertsData.js'))
const assessmentData = require(join(outDir, 'data', 'alertAssessments.js'))
const userData = require(join(outDir, 'data', 'userManagementData.js'))
const healthData = require(join(outDir, 'data', 'systemHealthData.js'))
const configData = require(join(outDir, 'data', 'configurationData.js'))
const loginData = require(join(outDir, 'data', 'loginData.js'))
const inventory = require(join(outDir, 'data', 'serviceInventory.js'))
const panelLogic = require(join(outDir, 'data', 'servicePanel.js'))
const panelData = require(join(outDir, 'data', 'servicePanelData.js'))
const toneModule = require(join(outDir, 'utils', 'statusTone.js'))

const results = []

async function check(area, name, run) {
  try {
    const outcome = await run()
    const pass = outcome === true || (outcome && outcome.pass === true)
    results.push({ area, name, pass, detail: pass ? '' : outcome?.detail ?? String(outcome) })
  } catch (error) {
    results.push({ area, name, pass: false, detail: `threw: ${error.message}` })
  }
}

const is = (actual, expected) =>
  actual === expected || { pass: false, detail: `got ${JSON.stringify(actual)}, wanted ${JSON.stringify(expected)}` }

// A baseline input; each test changes only what it is about
function input(overrides = {}) {
  return {
    alertId: 'ALT-T',
    ruleLevel: 15,
    signals: ['a', 'b', 'c', 'd', 'e'],
    reputation: 0,
    reputationSource: 'test',
    sourceIp: '203.0.113.45',
    asset: 'endpoint-01',
    assetClass: 'Standard',
    confidence: 0.9,
    hostExploitEvidence: false,
    ...overrides,
  }
}

// Risk = 35 + 25 + 4.5 (Standard) + 25 x reputation when the first two are maxed
const burst = { count: 12, accounts: 3, windowMin: 5 }
const riskOf = (overrides) => engine.assess(input(overrides)).risk

// ---------- Scoring ----------
await check('scoring', 'S is the Wazuh level over 15, E signals over 5 (capped), R as given, A 1.0 / 0.6 / 0.3', () => {
  const { parts } = engine.scoreRisk(input({ ruleLevel: 15, signals: ['a', 'b'], reputation: 0.5, assetClass: 'Business' }))
  const n = Object.fromEntries(parts.map((p) => [p.key, p.normalised]))
  return n.S === 1 && n.E === 0.4 && n.R === 0.5 && n.A === 0.6 || { pass: false, detail: JSON.stringify(n) }
})
await check('scoring', 'weights are 0.35 / 0.25 / 0.25 / 0.15 and the points add up to the risk', () => {
  const b = engine.scoreRisk(input({ ruleLevel: 15, signals: ['a'], reputation: 1, assetClass: 'Critical' }))
  return b.parts.map((p) => p.weight).join() === '0.35,0.25,0.25,0.15' && b.risk === Math.round(b.parts.reduce((s, p) => s + p.points, 0)) || { pass: false, detail: JSON.stringify(b) }
})
await check('scoring', 'more than 5 signals count as 5', () => is(engine.scoreRisk(input({ signals: Array(9).fill('x') })).parts[1].normalised, 1))
await check('scoring', 'risk is 0 for nothing and 100 for everything', () => {
  const low = engine.scoreRisk(input({ ruleLevel: 0, signals: [], reputation: 0, assetClass: 'Standard' })).risk
  const high = engine.scoreRisk(input({ ruleLevel: 15, signals: Array(5).fill('x'), reputation: 1, assetClass: 'Critical' })).risk
  return low === 5 && high === 100 || { pass: false, detail: `${low} / ${high}` }
})
await check('scoring', 'severity bands: 6 Low, 7 Medium, 9 Medium, 10 High, 12 High, 13 Critical', () =>
  ['6:Low', '7:Medium', '9:Medium', '10:High', '12:High', '13:Critical'].every((s) => engine.severityBand(Number(s.split(':')[0])) === s.split(':')[1]))
await check('scoring', 'confidence bands: 0.49 Low, 0.50 Medium, 0.79 Medium, 0.80 High', () =>
  [[0.49, 'Low'], [0.5, 'Medium'], [0.79, 'Medium'], [0.8, 'High']].every(([c, b]) => engine.confidenceBand(c) === b))

// ---------- The score table adds up on screen ----------
// What the table prints, as integer cents
const shownCents = (parts) => engine.displayedParts(parts).map((text) => Math.round(Number(text) * 100))
for (const seed of data.seedAssessmentInputs) {
  await check('scoring', `${seed.alertId}: the parts shown add up to the sum shown (to the cent), and that sum rounds to the risk shown`, () => {
    const b = engine.scoreRisk(seed)
    const sum = shownCents(b.parts).reduce((a, c) => a + c, 0)
    return Math.round(Number(engine.displayedPartsTotal(b.parts)) * 100) === sum && Math.round(sum / 100) === b.risk && engine.displayedParts(b.parts).every((t) => /^\d+\.\d{2}$/.test(t)) || { pass: false, detail: `${engine.displayedParts(b.parts).join('+')} = ${engine.displayedPartsTotal(b.parts)}, risk ${b.risk}` }
  })
}
await check('scoring', 'ALT-006 reads 32.67 + 25.00 + 23.75 + 9.00 = 90.42, shown as 90 (so R is no longer rounded to 23.8)', () => {
  const b = engine.scoreRisk(data.seedAssessmentInputs.find((s) => s.alertId === 'ALT-006'))
  return engine.displayedParts(b.parts).join(' + ') === '32.67 + 25.00 + 23.75 + 9.00' && engine.displayedPartsTotal(b.parts) === '90.42' && b.risk === 90
})
await check('scoring', 'for every input combination (16 rule levels × 6 signal counts × 21 reputations × 3 asset classes) the displayed parts add up to the displayed sum and it rounds to the risk', () => {
  const bad = []
  for (let level = 0; level <= 15; level++) for (let n = 0; n <= 5; n++) for (let r = 0; r <= 20; r++) for (const assetClass of ['Critical', 'Business', 'Standard']) {
    const b = engine.scoreRisk(input({ ruleLevel: level, signals: Array(n).fill('x'), reputation: r / 20, assetClass }))
    const sum = shownCents(b.parts).reduce((a, c) => a + c, 0)
    if (Math.round(Number(engine.displayedPartsTotal(b.parts)) * 100) !== sum || Math.round(sum / 100 + 1e-9) !== b.risk) bad.push(`${level}/${n}/${r}/${assetClass}: ${engine.displayedPartsTotal(b.parts)} vs ${b.risk}`)
  }
  return bad.length === 0 || { pass: false, detail: `${bad.length} mismatches, e.g. ${bad.slice(0, 3).join('; ')}` }
})

// ---------- The five alerts, from their own evidence (nothing tuned) ----------
const expectedSeeds = { 'ALT-001': [77, 'recommend_block_ip'], 'ALT-002': [50, 'investigate_further'], 'ALT-003': [54, 'investigate_further'], 'ALT-004': [52, 'investigate_further'], 'ALT-005': [34, 'monitor'], 'ALT-006': [90, 'recommend_host_isolation'] }
for (const seed of data.seedAssessmentInputs) {
  await check('alerts', `${seed.alertId}: risk ${expectedSeeds[seed.alertId][0]}, outcome ${expectedSeeds[seed.alertId][1]}`, () => {
    const result = engine.assess(seed)
    return result.risk === expectedSeeds[seed.alertId][0] && result.outcome === expectedSeeds[seed.alertId][1] || { pass: false, detail: `${result.risk} / ${result.outcome}` }
  })
}
await check('alerts', 'ALT-001 is a block recommendation for 203.0.113.45, 30 min, under the seed response policy (block_ip minimum risk 70, set at version 3)', () => {
  const result = engineRaw.assess(data.seedAssessmentInputs.find((s) => s.alertId === 'ALT-001'))
  return result.outcome === 'recommend_block_ip' && JSON.stringify(result.proposal) === JSON.stringify({ name: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 } }) || { pass: false, detail: JSON.stringify(result.proposal) }
})
await check('alerts', 'with block_ip\'s minimum risk at 90 (as before the audited change), or block_ip off the whitelist or on the blacklist, ALT-001 is only a ticket, and the reason names the policy', () => {
  const seed = data.assessmentInputs.find((s) => s.alertId === 'ALT-001')
  const old = engineRaw.assess(seed, policyWith((p) => { limitsOf(p, 'block_ip').minRisk = 90 }, policies.initialResponsePolicy))
  const off = engineRaw.assess(seed, policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip') }, policies.initialResponsePolicy))
  const black = engineRaw.assess(seed, policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false }) }, policies.initialResponsePolicy))
  const why = (r) => r.alternativesConsidered.find((a) => a.outcome === 'recommend_block_ip').reason
  return [old, off, black].every((r) => r.outcome === 'create_alert_and_ticket') && why(old).includes("risk 77 is below the policy's minimum of 90") && why(off).includes('block_ip is not on the whitelist') && why(black).includes('block_ip is on the blacklist') || { pass: false, detail: [old, off, black].map((r) => `${r.outcome}: ${why(r)}`).join(' | ') }
})
await check('alerts', 'ALT-006 (exploit evidence, beaconing to a known-bad IP, EDR, Business asset) is an isolation recommendation: endpoint-12, 120 min', () => {
  const result = engine.assess(data.seedAssessmentInputs.find((s) => s.alertId === 'ALT-006'))
  return result.proposal.name === 'isolate_host' && result.proposal.params.host === 'endpoint-12' && result.proposal.params.duration_min === 120 && result.confidenceBand === 'High' || { pass: false, detail: JSON.stringify(result.proposal) }
})
await check('alerts', 'ALT-006 needs isolate_host\'s minimum risk to be met: the seed policy\'s 90 isolates it (risk 90), a minimum of 91 does not', () => {
  const seed = data.assessmentInputs.find((s) => s.alertId === 'ALT-006')
  const seeded = engineRaw.assess(seed)
  const result = engineRaw.assess(seed, policyWith((p) => { limitsOf(p, 'isolate_host').minRisk = 91 }, policies.initialResponsePolicy))
  return seeded.outcome === 'recommend_host_isolation' && result.outcome !== 'recommend_host_isolation' && result.alternativesConsidered.find((a) => a.outcome === 'recommend_host_isolation').reason.includes("risk 90 is below the policy's minimum of 91") || { pass: false, detail: `${seeded.outcome} / ${result.outcome}` }
})
await check('alerts', 'only ALT-006 reaches host isolation', () =>
  data.seedAssessmentInputs.filter((s) => engine.assess(s).outcome === 'recommend_host_isolation').map((s) => s.alertId).join() === 'ALT-006')
await check('alerts', 'OPEN ISSUE: with no reputation (an internal-only alert) the score tops out at 75, below the isolation floor of 85', () => {
  const best = engine.scoreRisk(input({ ruleLevel: 15, signals: Array(5).fill('x'), reputation: 0, assetClass: 'Critical' })).risk
  return best === 75 || { pass: false, detail: String(best) }
})

// ---------- The ladder: every edge ----------
await check('ladder', 'block: risk 70 and confidence 0.80 recommend a block', () => {
  const r = engine.assess(input({ reputation: 0.22, confidence: 0.8, failedLogins: burst }))
  return r.risk === 70 && r.outcome === 'recommend_block_ip' || { pass: false, detail: `${r.risk} ${r.outcome}` }
})
await check('ladder', 'block: risk 69 falls through to alert + ticket', () => {
  const r = engine.assess(input({ reputation: 0.18, confidence: 0.9, failedLogins: burst }))
  return r.risk === 69 && r.outcome === 'create_alert_and_ticket' || { pass: false, detail: `${r.risk} ${r.outcome}` }
})
await check('ladder', 'block: confidence 0.79 falls through to alert + ticket (fall-through above 69 is right)', () => {
  const r = engine.assess(input({ reputation: 0.22, confidence: 0.79, failedLogins: burst }))
  return r.outcome === 'create_alert_and_ticket' || { pass: false, detail: r.outcome }
})
await check('ladder', 'block needs reputation 0.70 OR a burst: neither gives a ticket', () => {
  const r = engine.assess(input({ reputation: 0.22, confidence: 0.9 }))
  return r.risk === 70 && r.outcome === 'create_alert_and_ticket' || { pass: false, detail: `${r.risk} ${r.outcome}` }
})
await check('ladder', 'reputation 0.70 alone is enough, without a burst', () => engine.assess(input({ reputation: 0.7, confidence: 0.9 })).outcome === 'recommend_block_ip')
await check('ladder', 'a burst of 9 failed logins, or on 2 accounts, or over 6 minutes, is not enough', () =>
  [{ count: 9, accounts: 3, windowMin: 5 }, { count: 12, accounts: 2, windowMin: 5 }, { count: 12, accounts: 3, windowMin: 6 }]
    .every((b) => engine.assess(input({ reputation: 0.22, confidence: 0.9, failedLogins: b })).outcome === 'create_alert_and_ticket'))
await check('ladder', 'block needs block_ip on the whitelist, and risk at or above its minimum risk', () => {
  const none = engine.assess(input({ reputation: 0.9 }), policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip') })).outcome
  const high = engine.assess(input({ reputation: 0.9 }), policyWith((p) => { limitsOf(p, 'block_ip').minRisk = 95 })).outcome
  return none === 'create_alert_and_ticket' && high === 'create_alert_and_ticket' || { pass: false, detail: `${none} / ${high}` }
})
await check('ladder', 'isolation: risk 85, confidence 0.85 and exploit evidence recommend isolation', () => {
  const r = engine.assess(input({ ruleLevel: 15, signals: Array(5).fill('x'), reputation: 0.64, assetClass: 'Business', confidence: 0.85, hostExploitEvidence: true, sourceIp: '10.0.7.51' }))
  return r.risk === 85 && r.outcome === 'recommend_host_isolation' && r.proposal.name === 'isolate_host' && r.proposal.params.duration_min === 120 || { pass: false, detail: `${r.risk} ${r.outcome}` }
})
await check('ladder', 'isolation: risk 84 drops to a block when the source is blockable, else to a ticket', () => {
  const internal = engine.assess(input({ reputation: 0.6, assetClass: 'Business', confidence: 0.9, hostExploitEvidence: true, sourceIp: '10.0.7.51' }))
  return internal.risk === 84 && internal.outcome === 'create_alert_and_ticket' || { pass: false, detail: `${internal.risk} ${internal.outcome}` }
})
await check('ladder', 'isolation: confidence 0.84 does not isolate', () =>
  engine.assess(input({ reputation: 0.64, assetClass: 'Business', confidence: 0.84, hostExploitEvidence: true, sourceIp: '10.0.7.51' })).outcome !== 'recommend_host_isolation')
await check('ladder', 'isolation: no exploit evidence, no isolation', () =>
  engine.assess(input({ reputation: 0.64, assetClass: 'Business', confidence: 0.9, hostExploitEvidence: false, sourceIp: '10.0.7.51' })).outcome !== 'recommend_host_isolation')
await check('ladder', 'a Critical asset is never isolated: ticket plus escalation, recorded as such', () => {
  const r = engine.assess(input({ reputation: 0.4, assetClass: 'Critical', confidence: 0.9, hostExploitEvidence: true, sourceIp: '10.0.7.51' }))
  const iso = r.alternativesConsidered.find((a) => a.outcome === 'recommend_host_isolation')
  return r.outcome === 'create_alert_and_ticket' && /ticket and escalates/.test(r.escalation ?? '') && /Critical asset/.test(iso.reason) || { pass: false, detail: `${r.outcome} ${r.escalation}` }
})
await check('ladder', 'isolation outranks block when both qualify', () =>
  engine.assess(input({ reputation: 0.9, assetClass: 'Business', confidence: 0.95, hostExploitEvidence: true })).outcome === 'recommend_host_isolation')
await check('ladder', 'low confidence (0.45) sends even risk 100 to investigate further', () => {
  const r = engine.assess(input({ reputation: 1, assetClass: 'Critical', confidence: 0.45 }))
  return r.risk === 100 && r.outcome === 'investigate_further' || { pass: false, detail: `${r.risk} ${r.outcome}` }
})
await check('ladder', 'confidence exactly 0.50 is not "low": risk 69 stays a ticket, while 0.49 investigates', () => {
  const base = { ruleLevel: 15, signals: Array(5).fill('x'), reputation: 0.18, assetClass: 'Standard', sourceIp: '10.0.0.1' }
  const half = engine.assess(input({ ...base, confidence: 0.5 }))
  const under = engine.assess(input({ ...base, confidence: 0.49 }))
  return half.risk === 69 && half.outcome === 'create_alert_and_ticket' && under.outcome === 'investigate_further' || { pass: false, detail: `${half.risk} ${half.outcome} / ${under.outcome}` }
})
await check('ladder', 'exact edges: 39 monitors, 40 investigates, 59 investigates, 60 is a ticket', () => {
  // Rule level, signals, reputation chosen to land exactly on each risk with a Standard asset (4.5 points)
  const edge = (risk) => {
    for (let level = 0; level <= 15; level += 1) {
      for (let signals = 0; signals <= 5; signals += 1) {
        for (let rep = 0; rep <= 100; rep += 1) {
          const probe = input({ ruleLevel: level, signals: Array(signals).fill('x'), reputation: rep / 100, confidence: 0.6, sourceIp: '10.0.0.1' })
          if (engine.scoreRisk(probe).risk === risk) return engine.assess(probe).outcome
        }
      }
    }
    return null
  }
  const got = [edge(39), edge(40), edge(59), edge(60)]
  return got.join() === 'monitor,investigate_further,investigate_further,create_alert_and_ticket' || { pass: false, detail: got.join() }
})
await check('ladder', 'a source on the internal range or allow-list is never proposed for a block, with the reason recorded', () => {
  const r = engine.assess(input({ reputation: 0.95, sourceIp: '192.168.1.45', confidence: 0.95 }))
  const block = r.alternativesConsidered.find((a) => a.outcome === 'recommend_block_ip')
  return r.outcome === 'create_alert_and_ticket' && /internal or on the allow-list/.test(block.reason) || { pass: false, detail: `${r.outcome} ${block.reason}` }
})
await check('ladder', 'alternatives_considered lists the other four outcomes, higher ones with their reasons', () => {
  const r = engine.assess(input({ reputation: 0.9, confidence: 0.9 }))
  return r.alternativesConsidered.length === 4 && r.alternativesConsidered.filter((a) => a.direction === 'higher').length === 1 && r.alternativesConsidered.filter((a) => a.direction === 'lower').length === 3 || { pass: false, detail: JSON.stringify(r.alternativesConsidered.map((a) => a.outcome + ':' + a.direction)) }
})

// ---------- Allow-list ----------
await check('allow-list', 'internal ranges, partner, cloud and SIEM addresses are never blockable', () =>
  ['10.0.1.15', '172.20.1.1', '192.168.1.45', '127.0.0.1', '192.0.2.10', '192.0.2.200'].every((ip) => engine.isAllowListed(ip) && !engine.isBlockableIp(ip)))
await check('allow-list', 'documentation IPs outside the list are blockable (203.0.113.45, 198.51.100.77)', () =>
  ['203.0.113.45', '198.51.100.77'].every((ip) => engine.isBlockableIp(ip)))
await check('allow-list', 'range edges: 172.15.x and 172.32.x are external, 192.0.2.127 is external, 192.0.2.128 is cloud', () =>
  engine.isBlockableIp('172.15.0.1') && engine.isBlockableIp('172.32.0.1') && engine.isBlockableIp('192.0.2.127') && !engine.isBlockableIp('192.0.2.128'))
await check('allow-list', 'junk and missing values are not blockable', () => ['', 'abc', '999.1.1.1', '1.2.3'].every((ip) => !engine.isBlockableIp(ip)) && !engine.isBlockableIp(undefined))

// ---------- Durations ----------
await check('duration', 'an approver may shorten (30 to 20) but never extend (30 to 31) or pass the maximum', () => {
  const ok = engine.checkDurationChange('block_ip', 30, 20)
  const longer = engine.checkDurationChange('block_ip', 30, 31)
  const zero = engine.checkDurationChange('block_ip', 30, 0)
  const half = engine.checkDurationChange('block_ip', 30, 1.5)
  const same = engine.checkDurationChange('isolate_host', 120, 120)
  const over = engine.checkDurationChange('isolate_host', 300, 300)
  return ok.ok && ok.minutes === 20 && !longer.ok && !zero.ok && !half.ok && same.ok && !over.ok || { pass: false, detail: JSON.stringify({ ok, longer, zero, half, same, over }) }
})
await check('duration', 'catalogue limits: block 30 min default / 24 h max, isolate 2 h / 4 h, suspend 30 / 60 min; the three assumption rows (a SOC lead, 15 min) have no duration', () => {
  const m = Object.fromEntries(data.tier2Actions.map((a) => [a.name, [a.defaultMinutes, a.maxMinutes, a.approver, a.approvalWindowMinutes]]))
  return JSON.stringify(m) === JSON.stringify({ block_ip: [30, 1440, 'soc_analyst', 15], isolate_host: [120, 240, 'soc_lead', 15], suspend_user_session: [30, 60, 'soc_analyst', 15], kill_process: [null, null, 'soc_lead', 15], quarantine_file: [null, null, 'soc_lead', 15], reset_password: [null, null, 'soc_lead', 15] }) || { pass: false, detail: JSON.stringify(m) }
})

// ---------- Approval and self-approval ----------
const rec = (overrides = {}) => ({ id: 'REC-T-1', alertId: 'ALT-T', outcome: 'recommend_block_ip', action: { name: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 } }, tier: 2, evidence: [], riskScore: 82, confidence: 0.88, alternativesConsidered: [], rationale: '', requestedBy: 'agent', createdAt: '2026-08-03T15:41:00', approvalDeadline: '2026-08-03T15:56:00', ...overrides })
const isolateRec = rec({ id: 'REC-T-2', outcome: 'recommend_host_isolation', action: { name: 'isolate_host', params: { host: 'endpoint-09', path: 'edr_network_isolation', duration_min: 120 } }, riskScore: 90, confidence: 0.9 })

await check('approval', 'the requester cannot approve their own request', () => engine.approvalRefusal(rec({ requestedBy: 'USR-002' }), 'USR-002', 'soc_analyst') !== null)
await check('approval', 'an analyst cannot approve isolation; a lead can; a lead can also approve a block', () =>
  engine.approvalRefusal(isolateRec, 'USR-002', 'soc_analyst') !== null && engine.approvalRefusal(isolateRec, 'USR-001', 'soc_lead') === null && engine.approvalRefusal(rec(), 'USR-001', 'soc_lead') === null && engine.approvalRefusal(rec(), 'USR-002', 'soc_analyst') === null)

// ---------- Tokens and the guard ----------
const NOW = '2026-08-03T15:45:00'
const issue = (recommendation, approvedAction, id = 'USR-002', role = 'soc_analyst', now = NOW) =>
  engine.issueToken({ recommendation, approvedAction, approverId: id, approverRole: role, now })
const request = (overrides = {}) => ({ actionName: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 }, recommendationId: 'REC-T-1', requestedBy: 'agent', riskScore: 82, confidence: 0.88, now: NOW, ...overrides })

const token = await issue(rec(), rec().action)
await check('guard', 'a valid approved block passes', async () => (await engine.guard(request({ tokenId: token.id }), [token])).allowed)
await check('guard', 'a token is single-use: after it is consumed the same request is refused (token_reused)', async () => {
  const used = engine.consumeToken([token], token.id, NOW)
  const r = await engine.guard(request({ tokenId: token.id }), used)
  return r.code === 'token_reused' || { pass: false, detail: r.code }
})
await check('guard', 'consuming a token twice keeps the first time', () => {
  const once = engine.consumeToken([token], token.id, '2026-08-03T15:45:00')
  const twice = engine.consumeToken(once, token.id, '2026-08-03T15:50:00')
  return twice[0].usedAt === '2026-08-03T15:45:00'
})
await check('guard', 'changed parameters are refused: a longer duration, another IP', async () => {
  const longer = await engine.guard(request({ tokenId: token.id, params: { ip: '203.0.113.45', duration_min: 60 } }), [token])
  const other = await engine.guard(request({ tokenId: token.id, params: { ip: '203.0.113.99', duration_min: 30 } }), [token])
  return longer.code === 'params_changed' && other.code === 'params_changed' || { pass: false, detail: `${longer.code} ${other.code}` }
})
await check('guard', 'the digest ignores key order, so the same action in another order still passes', async () =>
  (await engine.guard(request({ tokenId: token.id, params: { duration_min: 30, ip: '203.0.113.45' } }), [token])).allowed)
await check('guard', 'a token for another recommendation is refused (wrong_recommendation)', async () => {
  const r = await engine.guard(request({ tokenId: token.id, recommendationId: 'REC-T-9' }), [token])
  return r.code === 'wrong_recommendation' || { pass: false, detail: r.code }
})
await check('guard', 'an expired token is refused (token_expired), one minute inside the limit is fine', async () => {
  const late = await engine.guard(request({ tokenId: token.id, now: '2026-08-03T15:51:00' }), [token])
  const edge = await engine.guard(request({ tokenId: token.id, now: '2026-08-03T15:50:00' }), [token])
  return late.code === 'token_expired' && edge.allowed || { pass: false, detail: `${late.code} ${edge.code}` }
})
await check('guard', 'no token, or an unknown token id, is refused (no_token)', async () =>
  (await engine.guard(request(), [token])).code === 'no_token' && (await engine.guard(request({ tokenId: 'nope' }), [token])).code === 'no_token')
await check('guard', 'an analyst token cannot run isolation (wrong_role); a lead token can', async () => {
  const analystToken = await issue(isolateRec, isolateRec.action, 'USR-002', 'soc_analyst')
  const leadToken = await issue(isolateRec, isolateRec.action, 'USR-001', 'soc_lead')
  const isolation = (t) => engine.guard({ actionName: 'isolate_host', params: isolateRec.action.params, recommendationId: 'REC-T-2', tokenId: t.id, requestedBy: 'agent', riskScore: 90, confidence: 0.9, assetClass: 'Business', now: NOW }, [t])
  const a = await isolation(analystToken)
  const l = await isolation(leadToken)
  return a.code === 'wrong_role' && l.allowed || { pass: false, detail: `${a.code} ${l.code}` }
})
await check('guard', 'self-approval is refused at the guard (self_approval)', async () => {
  const mine = await issue(rec({ requestedBy: 'USR-002' }), rec().action, 'USR-002', 'soc_analyst')
  const r = await engine.guard(request({ tokenId: mine.id, requestedBy: 'USR-002' }), [mine])
  return r.code === 'self_approval' || { pass: false, detail: r.code }
})
await check('guard', 'approve with changes: a token for 20 min runs only the 20 min action', async () => {
  const shorter = { name: 'block_ip', params: { ip: '203.0.113.45', duration_min: 20 } }
  const t = await issue(rec(), shorter)
  const as20 = await engine.guard(request({ tokenId: t.id, params: shorter.params }), [t])
  const as30 = await engine.guard(request({ tokenId: t.id }), [t])
  return as20.allowed && as30.code === 'params_changed' || { pass: false, detail: `${as20.code} ${as30.code}` }
})
await check('guard', 'a block longer than 24 h is refused even with a matching token (duration_over_max)', async () => {
  const long = { name: 'block_ip', params: { ip: '203.0.113.45', duration_min: 1500 } }
  const t = await issue(rec(), long)
  const r = await engine.guard(request({ tokenId: t.id, params: long.params }), [t])
  return r.code === 'duration_over_max' || { pass: false, detail: r.code }
})
await check('guard', 'blocking an internal or allow-listed address is refused even with a matching token', async () => {
  const codes = []
  for (const ip of ['192.168.1.45', '10.0.1.15', '192.0.2.10', '192.0.2.200']) {
    const a = { name: 'block_ip', params: { ip, duration_min: 30 } }
    const t = await issue(rec(), a)
    codes.push((await engine.guard(request({ tokenId: t.id, params: a.params }), [t])).code)
  }
  return codes.join() === 'internal_ip,internal_ip,allow_listed,allow_listed' || { pass: false, detail: codes.join() }
})
await check('guard', 'risk or confidence under the action\'s floor is refused (below_threshold)', async () => {
  const low = await engine.guard(request({ tokenId: token.id, riskScore: 60 }), [token])
  const unsure = await engine.guard(request({ tokenId: token.id, confidence: 0.7 }), [token])
  return low.code === 'below_threshold' && unsure.code === 'below_threshold' || { pass: false, detail: `${low.code} ${unsure.code}` }
})
await check('guard', 'isolating a Critical asset is refused (critical_asset)', async () => {
  const t = await issue(isolateRec, isolateRec.action, 'USR-001', 'soc_lead')
  const r = await engine.guard({ actionName: 'isolate_host', params: isolateRec.action.params, recommendationId: 'REC-T-2', tokenId: t.id, requestedBy: 'agent', riskScore: 90, confidence: 0.9, assetClass: 'Critical', now: NOW }, [t])
  return r.code === 'critical_asset' || { pass: false, detail: r.code }
})
await check('guard', 'every prohibited action is refused with no token (prohibited), whatever else is sent', async () => {
  const codes = []
  for (const item of data.tier3Actions) codes.push((await engine.guard({ actionName: item.requestName, params: {}, tokenId: token.id, now: NOW }, [token])).code)
  return codes.length === 6 && codes.every((c) => c === 'prohibited') || { pass: false, detail: codes.join() }
})
await check('guard', 'unknown functions are refused (not_in_catalogue); Tier 1 functions pass without a token', async () => {
  const unknown = await engine.guard({ actionName: 'format_disk', params: {}, now: NOW }, [])
  const tier1 = await Promise.all(data.tier1Actions.map((a) => engine.guard({ actionName: a.name.split('(')[0], params: {}, now: NOW }, [])))
  return unknown.code === 'not_in_catalogue' && tier1.length === 9 && tier1.every((r) => r.allowed) || { pass: false, detail: `${unknown.code} ${tier1.map((r) => r.code).join()}` }
})
await check('guard', 'the catalogue has 9 Tier 1, 6 Tier 2 (the PDF\'s three and three assumption rows) and 6 Tier 3 entries', () =>
  data.tier1Actions.length === 9 && data.tier2Actions.length === 6 && data.tier3Actions.length === 6)

// ---------- Hashing and the audit chain ----------
await check('hash', 'SHA-256 of "abc" is the standard test vector', async () => is(await engine.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'))
await check('hash', 'canonical JSON does not depend on key order', () => engine.canonicalJson({ a: 1, b: { d: 2, c: [3, { z: 1, y: 2 }] } }) === engine.canonicalJson({ b: { c: [3, { y: 2, z: 1 }], d: 2 }, a: 1 }))
await check('time', 'addMinutes crosses the hour and parses without a timezone', () => is(engine.addMinutes('2026-08-03T15:45:00', 15), '2026-08-03T16:00:00'))

const bodies = [
  { id: 'AUD-1', event_type: 'recommendation_created', actor: 'agent' },
  { id: 'AUD-2', event_type: 'decision_recorded', actor: 'USR-002', decision: 'approved' },
  { id: 'AUD-3', event_type: 'action_executed', actor: 'agent' },
]
const chain = await engine.buildChain(bodies)
await check('chain', 'a built chain verifies, the first record links to the genesis hash, each links to the one before', async () => {
  const v = await engine.verifyChain(chain)
  return v.ok && v.count === 3 && chain[0].prev_hash === engine.GENESIS_HASH && chain[1].prev_hash === chain[0].hash && chain[2].prev_hash === chain[1].hash || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'the same records always give the same hashes', async () => is((await engine.buildChain(bodies)).map((r) => r.hash).join(), chain.map((r) => r.hash).join()))
await check('chain', 'changing one field of one record is detected at that record', async () => {
  const tampered = chain.map((r, i) => (i === 1 ? { ...r, body: { ...r.body, decision: 'rejected' } } : r))
  const v = await engine.verifyChain(tampered)
  return !v.ok && v.brokenAt === 1 || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'removing a record, reordering records or editing a prev_hash is detected', async () => {
  const removed = await engine.verifyChain([chain[0], chain[2]])
  const swapped = await engine.verifyChain([chain[1], chain[0], chain[2]])
  const relinked = await engine.verifyChain(chain.map((r, i) => (i === 2 ? { ...r, prev_hash: engine.GENESIS_HASH } : r)))
  return !removed.ok && removed.brokenAt === 1 && !swapped.ok && swapped.brokenAt === 0 && !relinked.ok && relinked.brokenAt === 2 || { pass: false, detail: JSON.stringify({ removed, swapped, relinked }) }
})
await check('chain', 'an edited hash is detected, and an empty chain is intact', async () => {
  const forged = await engine.verifyChain(chain.map((r, i) => (i === 0 ? { ...r, hash: 'f'.repeat(64) } : r)))
  const empty = await engine.verifyChain([])
  return !forged.ok && forged.brokenAt === 0 && empty.ok && empty.count === 0 || { pass: false, detail: JSON.stringify({ forged, empty }) }
})

// ---------- Approval records ----------
const seed = await approvals.buildSeedApprovals()
const [apr1, apr2] = seed.records
const [tkn1] = seed.tokens
const [exe1] = seed.executions
const copy = (value) => structuredClone(value)
const verdict = (record, token, executions) => engine.validateApprovalRecord(record, token, executions)

// Expects the first broken rule to be `code`
async function expectCode(name, record, token, executions, code) {
  await check('approval', name, async () => {
    const result = await verdict(record, token, executions)
    return result.code === code || { pass: false, detail: `${result.code}: ${result.reason}` }
  })
}

// The approved isolation (APR-001) with changes applied to the record, token and execution
function approved(change = () => {}) {
  const record = copy(apr1)
  const token = copy(tkn1)
  const run = copy(exe1)
  change(record, token, run)
  return [record, token, [run]]
}

await check('approval', 'the seed has two records: APR-001 approved (ALT-006) and APR-002 pending (ALT-001), one token and one execution', () =>
  apr1.id === 'APR-001' && apr1.decision === 'Approved' && apr1.recommendation.alertId === 'ALT-006' &&
  apr2.id === 'APR-002' && apr2.decision === 'Pending' && apr2.recommendation.alertId === 'ALT-001' &&
  seed.records.length === 2 && seed.tokens.length === 1 && seed.executions.length === 1 || { pass: false, detail: JSON.stringify(seed.records.map((r) => [r.id, r.decision])) })
await check('approval', 'both seed records follow the policy (APR-001 with its token and execution, APR-002 with none)', async () => {
  const a = await verdict(apr1, tkn1, [exe1])
  const b = await verdict(apr2, undefined, [])
  return a.ok && b.ok || { pass: false, detail: `${a.code} / ${b.code}` }
})
await check('approval', 'each recommendation is the engine\'s own assessment of its alert: ALT-006 isolate endpoint-12 (risk 90, 0.92, 120 min), ALT-001 block 203.0.113.45 (risk 77, 0.88, 30 min)', () => {
  const one = apr1.recommendation
  const two = apr2.recommendation
  return one.riskScore === 90 && one.confidence === 0.92 && one.action.name === 'isolate_host' && one.action.params.host === 'endpoint-12' && one.action.params.duration_min === 120 &&
    two.riskScore === 77 && two.confidence === 0.88 && two.action.name === 'block_ip' && two.action.params.ip === '203.0.113.45' && two.action.params.duration_min === 30 &&
    one.requestedBy === 'agent' && two.requestedBy === 'agent' && one.alternativesConsidered.length === 4 || { pass: false, detail: JSON.stringify([one.riskScore, two.riskScore]) }
})
await check('approval', 'the day runs in order: policy version 2 (AUD-203) 15:10:42, REC-001 15:42:00, approval 15:43:10, execution 15:44:00, policy version 3 (AUD-206) 15:44:07, REC-002 15:44:30', () => {
  const t = (time) => engine.parseTime(`2026-08-03T${time}`)
  return t('15:10:42') < t(apr1.recommendation.createdAt.slice(11)) && apr1.recommendation.createdAt === '2026-08-03T15:42:00' &&
    apr1.decidedAt === '2026-08-03T15:43:10' && tkn1.issuedAt === apr1.decidedAt && tkn1.usedAt === exe1.startedAt && exe1.startedAt === '2026-08-03T15:44:00' &&
    t('15:44:07') < engine.parseTime(apr2.recommendation.createdAt) && apr2.recommendation.createdAt === '2026-08-03T15:44:30' || { pass: false, detail: JSON.stringify([apr1.decidedAt, exe1.startedAt]) }
})
await check('approval', 'the isolation lasts exactly the approved duration: started 15:44:00, 120 min, reverses 17:44:00; the token expires 15:48:10', () =>
  exe1.expiresAt === '2026-08-03T17:44:00' && tkn1.expiresAt === '2026-08-03T15:48:10' && apr1.approvedAction.params.duration_min === 120 || { pass: false, detail: `${exe1.expiresAt} / ${tkn1.expiresAt}` })
await check('approval', 'the approval deadline is 15 min after the request: REC-001 15:57:00, REC-002 15:59:30', () =>
  apr1.recommendation.approvalDeadline === '2026-08-03T15:57:00' && apr2.recommendation.approvalDeadline === '2026-08-03T15:59:30' || { pass: false, detail: `${apr1.recommendation.approvalDeadline} / ${apr2.recommendation.approvalDeadline}` })
await check('approval', 'each record keeps the action\'s rule at the version it was checked against: APR-001 isolate_host v2 (SOC lead, minimum risk 90, 240 min, 15 min to decide), APR-002 block_ip v3 (SOC analyst, minimum risk 70, 1440 min, 15 min), matching the seed policy', () => {
  const now = (name) => engineRaw.policySnapshot(policies.initialResponsePolicy, name)
  return JSON.stringify(apr1.policy) === JSON.stringify({ version: 2, action: 'isolate_host', approver: 'soc_lead', minRisk: 90, maxMinutes: 240, windowMinutes: 15 }) && JSON.stringify({ ...apr1.policy, version: 3 }) === JSON.stringify(now('isolate_host')) &&
    JSON.stringify(apr2.policy) === JSON.stringify({ version: 3, action: 'block_ip', approver: 'soc_analyst', minRisk: 70, maxMinutes: 1440, windowMinutes: 15 }) && JSON.stringify(apr2.policy) === JSON.stringify(now('block_ip')) || { pass: false, detail: JSON.stringify([apr1.policy, apr2.policy]) }
})
await check('approval', 'the token is bound to the exact action: its digest is the SHA-256 of the approved action and changes with a shorter duration', async () => {
  const same = await engine.actionDigest(apr1.approvedAction)
  const shorter = await engine.actionDigest({ ...apr1.approvedAction, params: { ...apr1.approvedAction.params, duration_min: 60 } })
  return tkn1.paramsDigest === same && same !== shorter && /^[0-9a-f]{64}$/.test(same) || { pass: false, detail: tkn1.paramsDigest }
})

await expectCode('self-approval is refused: the requester cannot decide', ...approved((r) => { r.recommendation.requestedBy = 'USR-001' }), 'self_approval')
await expectCode('an analyst cannot approve an isolation', ...approved((r, t) => { r.decidedBy.role = 'soc_analyst'; t.approverRole = 'soc_analyst' }), 'wrong_role')
await expectCode('a decision after the approval window is refused', ...approved((r, t) => { r.decidedAt = '2026-08-03T15:58:00'; t.issuedAt = r.decidedAt; t.expiresAt = '2026-08-03T16:03:00' }), 'after_deadline')
await expectCode('a decision earlier than the request is refused', ...approved((r, t) => { r.decidedAt = '2026-08-03T15:41:00'; t.issuedAt = r.decidedAt }), 'before_request')
await expectCode('an approval with a different token id is refused', ...approved((r) => { r.tokenId = 'TKN-999' }), 'no_token')
await expectCode('a token for another recommendation is refused', ...approved((r, t) => { t.recommendationId = 'REC-002' }), 'token_mismatch')
await expectCode('a token issued to someone else is refused', ...approved((r, t) => { t.approverId = 'USR-002' }), 'token_mismatch')
await expectCode('a token bound to a different action (changed target) is refused', ...approved((r, t) => { t.paramsDigest = 'a'.repeat(64) }), 'digest_mismatch')
await expectCode('an approved action that changes the host is refused', ...approved((r) => { r.approvedAction = { ...r.approvedAction, params: { ...r.approvedAction.params, host: 'dc-01' } } }), 'action_changed')
await expectCode('an approved duration longer than recommended is refused', ...approved((r) => { r.approvedAction = { ...r.approvedAction, params: { ...r.approvedAction.params, duration_min: 180 } } }), 'duration_not_shorter')
await expectCode('an approved duration over the catalogue maximum (isolation 240 min) is refused', ...approved((r) => { r.approvedAction = { ...r.approvedAction, params: { ...r.approvedAction.params, duration_min: 300 } } }), 'duration_over_max')
await expectCode('a shortened duration without a reason is refused', ...approved((r) => { r.reason = ''; r.approvedAction = { ...r.approvedAction, params: { ...r.approvedAction.params, duration_min: 60 } } }), 'reason_required')
await expectCode('an approval without a reason is refused', ...approved((r) => { delete r.reason }), 'reason_required')
await check('approval', 'a shortened duration with a reason, a matching token and a matching execution passes (approve with changes: 60 min, reverses 16:44:00)', async () => {
  const short = { ...apr1.approvedAction, params: { ...apr1.approvedAction.params, duration_min: 60 } }
  const [r, t, e] = approved((rec, tok, run) => {
    rec.approvedAction = short
    rec.reason = 'Isolate for one hour while the host is imaged'
    tok.paramsDigest = ''
    run.action = short
    run.expiresAt = '2026-08-03T16:44:00'
  })
  t.paramsDigest = await engine.actionDigest(short)
  const result = await verdict(r, t, e)
  return result.ok || { pass: false, detail: `${result.code}: ${result.reason}` }
})
await expectCode('a token used with no execution recorded is refused', ...(([r, t]) => [r, t, []])(approved()), 'token_used_without_execution')
await expectCode('two executions on one token are refused (single use)', ...(([r, t, [e]]) => [r, t, [e, { ...e, id: 'EXE-002' }]])(approved()), 'multiple_executions')
await expectCode('an execution that did not use up the token is refused', ...approved((r, t) => { delete t.usedAt }), 'execution_without_token')
await expectCode('an execution before the decision is refused', ...approved((r, t, e) => { e.startedAt = '2026-08-03T15:43:00'; t.usedAt = e.startedAt; e.expiresAt = '2026-08-03T17:43:00' }), 'execution_outside_token')
await expectCode('an execution after the token expired is refused', ...approved((r, t, e) => { e.startedAt = '2026-08-03T15:49:00'; t.usedAt = e.startedAt; e.expiresAt = '2026-08-03T17:49:00' }), 'execution_outside_token')
await expectCode('an execution that ran a different action than approved is refused', ...approved((r, t, e) => { e.action = { ...e.action, params: { ...e.action.params, host: 'dc-01' } } }), 'execution_changed')
await expectCode('an execution recorded against another approval is refused', ...approved((r, t, e) => { e.approvalId = 'APR-002' }), 'execution_changed')
await expectCode('an action that reverses at the wrong time is refused', ...approved((r, t, e) => { e.expiresAt = '2026-08-03T18:44:00' }), 'wrong_expiry')
await expectCode('an isolation under a policy that lets a SOC analyst approve it is refused', ...approved((r) => { r.policy.approver = 'soc_analyst'; r.requiredRole = 'soc_analyst' }), 'mode_not_allowed')
await expectCode('a record whose required role differs from its policy snapshot\'s approver is refused', ...approved((r) => { r.policy.approver = 'soc_analyst' }), 'role_mismatch')
await expectCode('a record whose required role differs from the catalogue is refused', ...approved((r) => { r.requiredRole = 'soc_analyst' }), 'role_mismatch')
await expectCode('a pending request that already carries a token is refused', copy(apr2), copy(tkn1), [], 'unexpected_fields')
await expectCode('a timed-out request with a decider is refused', { ...copy(apr2), decision: 'Timed out', decidedBy: apr1.decidedBy }, undefined, [], 'unexpected_fields')
await check('approval', 'a timed-out request with nothing else passes', async () => (await verdict({ ...copy(apr2), decision: 'Timed out' }, undefined, [])).ok)

const rejected = (change = {}) => {
  const record = copy(apr2)
  Object.assign(record, { decision: 'Rejected', decidedBy: { id: 'USR-002', name: 'Analyst A', role: 'soc_analyst' }, decidedAt: '2026-08-03T15:50:00', reason: 'Scanner traffic from a partner test' })
  change(record)
  return record
}
await check('approval', 'a rejection with a reason, no token and no execution passes', async () => (await verdict(rejected(() => {}), undefined, [])).ok)
await expectCode('a rejection without a reason is refused', rejected((r) => { r.reason = '  ' }), undefined, [], 'reason_required')
await expectCode('a rejection that issued a token is refused', rejected(() => {}), copy(tkn1), [], 'unexpected_fields')
await check('approval', 'a SOC lead may decide on an analyst-level request (APR-002 approved by the System Administrator passes with a matching token)', async () => {
  const record = copy(apr2)
  Object.assign(record, { decision: 'Approved', decidedBy: apr1.decidedBy, decidedAt: '2026-08-03T15:50:00', reason: 'Approved by the lead.', approvedAction: record.recommendation.action })
  const token = { id: 'TKN-T', recommendationId: record.recommendation.id, paramsDigest: await engine.actionDigest(record.recommendation.action), approverId: 'USR-001', approverRole: 'soc_lead', issuedAt: record.decidedAt, expiresAt: '2026-08-03T15:55:00' }
  record.tokenId = token.id
  const result = await verdict(record, token, [])
  return result.ok || { pass: false, detail: `${result.code}: ${result.reason}` }
})

// ---------- R3a: the response policy (whitelist, blacklist, protected targets) ----------
// Replaces the four IF/THEN policies POL-001 to POL-004 and the checks that named them (listed in the R3a summary).
{ // (a block of its own: the services further down have a SEED too)
const SEED = policies.initialResponsePolicy
const standings = () => Object.fromEntries(data.ACTION_CATALOGUE.map((row) => [row.key, engineRaw.standingLabel(SEED, row.key)]))
const attemptSeed = (name, params = {}, extra = {}) => engineRaw.attemptDecision({ actionName: name, params, ...extra }, SEED)

await check('R3a model', 'the seed is version 3: the nine Tier 1 actions Automatic, block_ip and isolate_host Needs approval, the six prohibited actions Blacklisted, and suspend_user_session, kill_process, quarantine_file and reset_password Not listed', () => {
  const s = standings()
  const tier = (n) => data.ACTION_CATALOGUE.filter((r) => r.tier === n).map((r) => r.key)
  return SEED.version === 3 && tier(1).length === 9 && tier(1).every((k) => s[k] === 'Automatic') && s.block_ip === 'Needs approval' && s.isolate_host === 'Needs approval' &&
    tier(3).length === 6 && tier(3).every((k) => s[k] === 'Blacklisted') && SEED.blacklist.every((e) => e.required) &&
    ['suspend_user_session', 'kill_process', 'quarantine_file', 'reset_password'].every((k) => s[k] === 'Not listed') || { pass: false, detail: JSON.stringify(s) }
})
await check('R3a model', 'the seed limits reproduce the old numbers: block_ip 30 min by default, 24 h at most, a SOC analyst, 15 min to decide, minimum risk 70; isolate_host 2 h, 4 h, a SOC lead, 15 min, minimum risk 90', () =>
  JSON.stringify(limitsOf(SEED, 'block_ip')) === JSON.stringify({ defaultMinutes: 30, maxMinutes: 1440, approver: 'soc_analyst', windowMinutes: 15, minRisk: 70 }) &&
  JSON.stringify(limitsOf(SEED, 'isolate_host')) === JSON.stringify({ defaultMinutes: 120, maxMinutes: 240, approver: 'soc_lead', windowMinutes: 15, minRisk: 90 }))
await check('R3a model', 'the seed policy, and the PDF-limits policy the older checks use, are both accepted by policyRefusal', () =>
  engineRaw.policyRefusal(SEED) === null && engineRaw.policyRefusal(PDF_POLICY) === null || { pass: false, detail: `${engineRaw.policyRefusal(SEED)} / ${engineRaw.policyRefusal(PDF_POLICY)}` })
await check('R3a model', 'the catalogue has 21 actions: nine Tier 1, six Tier 2 (the PDF\'s three and the three assumption rows) and six Tier 3', () =>
  data.ACTION_CATALOGUE.length === 21 && [1, 2, 3].map((n) => data.ACTION_CATALOGUE.filter((r) => r.tier === n).length).join() === '9,6,6' && data.tier2Actions.map((a) => a.name).join() === 'block_ip,isolate_host,suspend_user_session,kill_process,quarantine_file,reset_password')
await check('R3a model', 'kill_process, quarantine_file and reset_password are assumption rows: a SOC lead approves, 15 min to decide, no duration, and each carries an Assumption tag', () =>
  ['kill_process', 'quarantine_file', 'reset_password'].every((name) => {
    const a = data.tier2Actions.find((x) => x.name === name)
    return a.approver === 'soc_lead' && a.approvalWindowMinutes === 15 && a.defaultMinutes === undefined && a.maxMinutes === undefined && a.assumed.length === 2 && a.source === 'PDF p.4'
  }))
await check('R3a model', 'the agent never recommends the four unlisted actions: no seed assessment proposes anything but block_ip or isolate_host, even with all six Tier 2 actions whitelisted', () => {
  const all = policyWith((p) => { for (const a of data.tier2Actions) if (!p.whitelist.some((e) => e.action === a.name)) p.whitelist.push({ action: a.name, mode: 'Needs approval', limits: { defaultMinutes: a.defaultMinutes, maxMinutes: a.maxMinutes, approver: a.approver, windowMinutes: a.approvalWindowMinutes, minRisk: a.floor.risk } }) }, SEED)
  return data.seedAssessmentInputs.every((s) => { const r = engineRaw.assess(s, all); return !r.proposal || ['block_ip', 'isolate_host'].includes(r.proposal.name) })
})
await check('R3a model', 'the seed approvals cite their rule: APR-001 isolate_host at version 2 (the isolation ran before AUD-206), APR-002 block_ip at version 3; the audit seed events AUD-203 and AUD-206 are the policy\'s version 2 and 3', () => {
  const byId = Object.fromEntries(audit.auditLogs.map((l) => [l.id, l]))
  return byId['AUD-203'].target === 'Response policy' && byId['AUD-203'].metadata['Policy Version'] === '2' && byId['AUD-203'].changes.join() === 'isolate_host: Automatic → Needs approval' &&
    byId['AUD-206'].target === 'Response policy' && byId['AUD-206'].metadata['Policy Version'] === '3' && byId['AUD-206'].changes.join() === 'block_ip: Automatic → Needs approval,block_ip minimum risk: 90 → 70' &&
    byId['AUD-206'].metadata['Policy Version'] === String(SEED.version) || { pass: false, detail: JSON.stringify([byId['AUD-203'].changes, byId['AUD-206'].changes]) }
})

// Limits: each one capped by the PDF, with the PDF's own number in the reason
const lim = (action, change) => ({ ...limitsOf(PDF_POLICY, action), ...change })
const refusalOf = (action, change) => engineRaw.limitRefusal(action, lim(action, change))
await check('R3a limits', 'longest allowed: block_ip 24 h (1441 min refused), isolate_host 4 h (241 refused), suspend_user_session 60 min (61 refused); the cap itself is accepted', () =>
  refusalOf('block_ip', { maxMinutes: 1441 })?.includes('24 h') && refusalOf('isolate_host', { maxMinutes: 241 })?.includes('4 h') && refusalOf('suspend_user_session', { maxMinutes: 61, defaultMinutes: 30, approver: 'soc_analyst', minRisk: 75 })?.includes('60 min') &&
  refusalOf('block_ip', { maxMinutes: 1440 }) === null && refusalOf('isolate_host', { maxMinutes: 240, defaultMinutes: 120 }) === null || { pass: false, detail: [refusalOf('block_ip', { maxMinutes: 1441 }), refusalOf('isolate_host', { maxMinutes: 241 })].join(' | ') })
await check('R3a limits', 'time to decide: 15 min is accepted, 16 is refused with "15 min"; 0 and 1.5 are refused as not whole minutes', () =>
  refusalOf('block_ip', { windowMinutes: 15 }) === null && refusalOf('block_ip', { windowMinutes: 16 })?.includes('15 min') && refusalOf('block_ip', { windowMinutes: 10 }) === null &&
  typeof refusalOf('block_ip', { windowMinutes: 0 }) === 'string' && typeof refusalOf('block_ip', { windowMinutes: 1.5 }) === 'string')
await check('R3a limits', 'who approves: a policy can only ask for the PDF\'s role or higher (isolate_host cannot go down to a SOC analyst; block_ip can go up to a SOC lead)', () =>
  refusalOf('isolate_host', { approver: 'soc_analyst' })?.includes('SOC lead') && refusalOf('block_ip', { approver: 'soc_lead' }) === null && refusalOf('block_ip', { approver: 'soc_analyst' }) === null)
await check('R3a limits', 'Minimum risk: at least the PDF\'s floor (block_ip 70, isolate_host 85, suspend_user_session 75) and a higher value is allowed, up to 100', () =>
  refusalOf('block_ip', { minRisk: 69 })?.includes('70') && refusalOf('block_ip', { minRisk: 70 }) === null && refusalOf('block_ip', { minRisk: 95 }) === null &&
  refusalOf('isolate_host', { minRisk: 84 })?.includes('85') && refusalOf('isolate_host', { minRisk: 85 }) === null && refusalOf('isolate_host', { minRisk: 90 }) === null &&
  typeof refusalOf('block_ip', { minRisk: 101 }) === 'string')
await check('R3a limits', 'the default duration is whole minutes and cannot be longer than the longest allowed', () =>
  refusalOf('block_ip', { defaultMinutes: 31, maxMinutes: 30 })?.includes('default') && refusalOf('block_ip', { defaultMinutes: 0 }) !== null && refusalOf('block_ip', { defaultMinutes: 30, maxMinutes: 30 }) === null)
await check('R3a limits', 'an action with no duration (kill_process, quarantine_file, reset_password) takes no default or longest time; its approver, time to decide and minimum risk are still capped', () =>
  ['kill_process', 'quarantine_file', 'reset_password'].every((name) => {
    const ok = { approver: 'soc_lead', windowMinutes: 15, minRisk: 75 }
    return engineRaw.limitRefusal(name, ok) === null && engineRaw.limitRefusal(name, { ...ok, maxMinutes: 60 }) !== null && engineRaw.limitRefusal(name, { ...ok, approver: 'soc_analyst' }) !== null && engineRaw.limitRefusal(name, { ...ok, minRisk: 74 }) !== null
  }))
await check('R3a limits', 'policyRefusal catches a limit past a cap inside a whole policy, and a Tier 2 action set to Automatic (never allowed)', () => {
  const longer = policyWith((p) => { limitsOf(p, 'isolate_host').maxMinutes = 300 }, SEED)
  const auto = policyWith((p) => { p.whitelist.find((e) => e.action === 'block_ip').mode = 'Automatic' }, SEED)
  return engineRaw.policyRefusal(longer)?.includes('4 h') && engineRaw.policyRefusal(auto)?.includes('always needs a person') || { pass: false, detail: `${engineRaw.policyRefusal(longer)} / ${engineRaw.policyRefusal(auto)}` }
})
await check('R3a limits', 'the engine reads the limits from the policy: a longest allowed of 60 min makes a 90 min block_ip attempt duration_over_max, a 45 min one passes, and the approval window follows the policy', () => {
  const stricter = policyWith((p) => { Object.assign(limitsOf(p, 'block_ip'), { maxMinutes: 60, windowMinutes: 10, approver: 'soc_lead' }) }, SEED)
  const run = (m) => engineRaw.attemptDecision({ actionName: 'block_ip', params: { ip: '203.0.113.45', duration_min: m }, riskScore: 90, confidence: 0.9 }, stricter)
  return run(90).code === 'duration_over_max' && run(45).decision === 'needs_approval' && run(45).approver === 'soc_lead' && run(45).approvalWindowMinutes === 10 || { pass: false, detail: JSON.stringify([run(90), run(45)]) }
})

// Lists: unlisted means denied; a blacklisted action is never run; both lists agree between the guard and the attempt
await check('R3a lists', 'under the seed policy: Tier 1 actions are allowed, block_ip and isolate_host need approval from their approver within 15 min, and the four unlisted actions are refused (not_listed)', () => {
  const kinds = {
    get_logs: attemptSeed('get_logs'),
    block_ip: attemptSeed('block_ip', { ip: '203.0.113.45', duration_min: 30 }, { riskScore: 80, confidence: 0.9 }),
    isolate_host: attemptSeed('isolate_host', { host: 'endpoint-09', duration_min: 120 }, { riskScore: 90, confidence: 0.9, assetClass: 'Business' }),
    suspend_user_session: attemptSeed('suspend_user_session', { user: 'j.smith', duration_min: 30 }, { riskScore: 90, confidence: 0.9 }),
    kill_process: attemptSeed('kill_process', { host: 'endpoint-09' }, { riskScore: 90, confidence: 0.9 }),
    quarantine_file: attemptSeed('quarantine_file', { host: 'endpoint-09' }, { riskScore: 90, confidence: 0.9 }),
    reset_password: attemptSeed('reset_password', { user: 'j.smith' }, { riskScore: 90, confidence: 0.9 }),
  }
  return kinds.get_logs.decision === 'allowed' && kinds.block_ip.decision === 'needs_approval' && kinds.block_ip.approver === 'soc_analyst' && kinds.isolate_host.decision === 'needs_approval' && kinds.isolate_host.approver === 'soc_lead' && kinds.isolate_host.approvalWindowMinutes === 15 &&
    ['suspend_user_session', 'kill_process', 'quarantine_file', 'reset_password'].every((k) => kinds[k].decision === 'refused' && kinds[k].code === 'not_listed' && kinds[k].reason.includes('not on the response policy') && kinds[k].executed === false) || { pass: false, detail: JSON.stringify(kinds) }
})
await check('R3a lists', 'the seed minimum risk applies: isolate_host at risk 89 is refused (below_threshold), at 90 it needs approval; block_ip at 69 is refused, at 70 it needs approval', () => {
  const iso = (r) => attemptSeed('isolate_host', { host: 'endpoint-09', duration_min: 120 }, { riskScore: r, confidence: 0.9, assetClass: 'Business' })
  const blk = (r) => attemptSeed('block_ip', { ip: '203.0.113.45', duration_min: 30 }, { riskScore: r, confidence: 0.9 })
  return iso(89).code === 'below_threshold' && iso(90).decision === 'needs_approval' && blk(69).code === 'below_threshold' && blk(70).decision === 'needs_approval'
})
await check('R3a lists', 'whitelisting an unlisted Tier 2 action only makes it available: it becomes needs_approval (never allowed or Automatic), and policyRefusal rejects setting it to Automatic', () => {
  const open = policyWith((p) => p.whitelist.push({ action: 'kill_process', mode: 'Needs approval', limits: { approver: 'soc_lead', windowMinutes: 15, minRisk: 75 } }), SEED)
  const d = engineRaw.attemptDecision({ actionName: 'kill_process', params: { host: 'endpoint-09' }, riskScore: 80, confidence: 0.9, assetClass: 'Business' }, open)
  const auto = policyWith((p) => { p.whitelist.find((e) => e.action === 'kill_process').mode = 'Automatic' }, open)
  return engineRaw.policyRefusal(open) === null && d.decision === 'needs_approval' && d.approver === 'soc_lead' && d.approvalWindowMinutes === 15 && engineRaw.policyRefusal(auto) !== null || { pass: false, detail: JSON.stringify(d) }
})
await check('R3a lists', 'the assumption actions follow the PDF\'s rules for critical hosts and privileged accounts: kill_process on a Critical host (critical_asset) and reset_password on a privileged account (privileged_account) are refused; no duration is needed', () => {
  const open = policyWith((p) => { for (const k of ['kill_process', 'reset_password']) p.whitelist.push({ action: k, mode: 'Needs approval', limits: { approver: 'soc_lead', windowMinutes: 15, minRisk: 75 } }) }, SEED)
  const at = (name, params, extra) => engineRaw.attemptDecision({ actionName: name, params, riskScore: 90, confidence: 0.9, ...extra }, open)
  return at('kill_process', { host: 'dc-01' }, { assetClass: 'Critical' }).code === 'critical_asset' && at('kill_process', { host: 'endpoint-09' }, { assetClass: 'Business' }).decision === 'needs_approval' &&
    at('reset_password', { user: 'admin' }, { privilegedAccount: true }).code === 'privileged_account' && at('reset_password', { user: 'j.smith' }, { privilegedAccount: false }).decision === 'needs_approval'
})
await check('R3a lists', 'blacklisting a Tier 1 action refuses it (blacklisted) and a blacklisted Tier 2 action too; the six Tier 3 actions keep their prohibited code first', () => {
  const black = policyWith((p) => { p.whitelist = p.whitelist.filter((e) => !['get_logs', 'block_ip'].includes(e.action)); p.blacklist.push({ action: 'get_logs', required: false }, { action: 'block_ip', required: false }) }, SEED)
  const a = (name, params = {}) => engineRaw.attemptDecision({ actionName: name, params, riskScore: 90, confidence: 0.9 }, black)
  return a('get_logs').code === 'blacklisted' && a('block_ip', { ip: '203.0.113.45', duration_min: 30 }).code === 'blacklisted' && a('delete_logs').code === 'prohibited' && a('get_logs').reason.includes('blacklist')
})
await check('R3a lists', 'the guard (with a valid token) and the attempt give the same code and reason for the new refusals (not_listed, blacklisted, protected_target)', async () => {
  const black = policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false }) }, SEED)
  const noted = policyWith((p) => p.neverBlock.push({ value: '198.51.100.0/24', label: 'Test range', required: false }), SEED)
  const cases = [['kill_process', { host: 'x' }, SEED], ['block_ip', { ip: '203.0.113.45', duration_min: 30 }, black], ['block_ip', { ip: '198.51.100.9', duration_min: 30 }, noted]]
  const bad = []
  for (const [name, params, policy] of cases) {
    const recommendation = rec({ id: 'REC-G2', action: { name: 'block_ip', params } })
    const t = await engineRaw.issueToken({ recommendation, approvedAction: { name, params }, approverId: 'USR-001', approverRole: 'soc_lead', now: NOW })
    const a = engineRaw.attemptDecision({ actionName: name, params, riskScore: 90, confidence: 0.9 }, policy)
    const g = await engineRaw.guard({ actionName: name, params, recommendationId: 'REC-G2', tokenId: t.id, requestedBy: 'agent', riskScore: 90, confidence: 0.9, now: NOW }, [t], policy)
    if (a.code !== g.code || a.reason !== g.reason || g.allowed) bad.push(`${name}: ${a.code}/${g.code}`)
  }
  return bad.length === 0 || { pass: false, detail: bad.join('; ') }
})
await check('R3a lists', 'a Tier 1 action set to Needs approval (the engine keeps a mode per entry; the page locks Tier 1 to Automatic for now) is answered needs_approval and the guard will not run it; policyRefusal says "Needs approval: available later"', async () => {
  const held = policyWith((p) => { p.whitelist.find((e) => e.action === 'get_logs').mode = 'Needs approval' }, SEED)
  const a = engineRaw.attemptDecision({ actionName: 'get_logs', params: {} }, held)
  const g = await engineRaw.guard({ actionName: 'get_logs', params: {}, now: NOW }, [], held)
  return a.decision === 'needs_approval' && !g.allowed && engineRaw.policyRefusal(held)?.startsWith('Needs approval: available later') || { pass: false, detail: JSON.stringify([a.decision, g.code, engineRaw.policyRefusal(held)]) }
})
await check('R3a lists', 'the Tier 3 actions cannot be taken off the blacklist or onto the whitelist, and an action cannot sit on both lists', () => {
  const off = policyWith((p) => { p.blacklist = p.blacklist.filter((e) => e.action !== 'delete_logs') }, SEED)
  const on = policyWith((p) => p.whitelist.push({ action: 'delete_logs', mode: 'Needs approval' }), SEED)
  const both = policyWith((p) => p.blacklist.push({ action: 'get_logs', required: false }), SEED)
  return engineRaw.policyRefusal(off)?.includes('prohibited') && engineRaw.policyRefusal(on)?.includes('prohibited') && engineRaw.policyRefusal(both)?.includes('both lists') || { pass: false, detail: [off, on, both].map(engineRaw.policyRefusal).join(' | ') }
})

// Protected targets: the PDF's entries are Required and cannot be removed; the administrator's own can be
await check('R3a protected', 'the seed lists are the PDF\'s: Never block holds the four internal ranges, the partner address, the cloud range and the SIEM address; Never isolate holds dc-01, db-prod-01 and siem-01; all Required', () =>
  SEED.neverBlock.map((t) => t.value).join() === '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,192.0.2.10/32,192.0.2.128/25,10.0.1.15/32' && SEED.neverIsolate.map((t) => t.value).join() === 'dc-01,db-prod-01,siem-01' &&
  [...SEED.neverBlock, ...SEED.neverIsolate].every((t) => t.required && t.label))
await check('R3a protected', 'a Required entry cannot be removed (policyRefusal), an administrator\'s own entry can; an address or range must be valid', () => {
  const noInternal = policyWith((p) => { p.neverBlock = p.neverBlock.filter((t) => t.value !== '10.0.0.0/8') }, SEED)
  const noHost = policyWith((p) => { p.neverIsolate = p.neverIsolate.filter((t) => t.value !== 'dc-01') }, SEED)
  const own = policyWith((p) => p.neverBlock.push({ value: '198.51.100.0/24', label: 'Test range', required: false }), SEED)
  const badIp = policyWith((p) => p.neverBlock.push({ value: '300.1.1.1', label: 'x', required: false }), SEED)
  return engineRaw.policyRefusal(noInternal)?.includes('Never block') && engineRaw.policyRefusal(noHost)?.includes('Never isolate') && engineRaw.policyRefusal(own) === null && engineRaw.policyRefusal(badIp)?.includes('300.1.1.1')
})
await check('R3a protected', 'the engine refuses a whitelisted action against an administrator\'s protected target: block_ip on a Never block range and isolate_host on a Never isolate host (host names ignore case), with the list and its label in the reason', () => {
  const mine = policyWith((p) => { p.neverBlock.push({ value: '198.51.100.0/24', label: 'Test range', required: false }); p.neverIsolate.push({ value: 'SIEM-02', label: 'Second SIEM', required: false }) }, SEED)
  const blk = engineRaw.attemptDecision({ actionName: 'block_ip', params: { ip: '198.51.100.9', duration_min: 30 }, riskScore: 90, confidence: 0.9 }, mine)
  const iso = engineRaw.attemptDecision({ actionName: 'isolate_host', params: { host: 'siem-02', duration_min: 120 }, riskScore: 95, confidence: 0.95, assetClass: 'Business' }, mine)
  const fine = engineRaw.attemptDecision({ actionName: 'isolate_host', params: { host: 'endpoint-09', duration_min: 120 }, riskScore: 95, confidence: 0.95, assetClass: 'Business' }, mine)
  return blk.code === 'protected_target' && blk.reason.includes('Never block') && blk.reason.includes('Test range') && iso.code === 'protected_target' && iso.reason.includes('Never isolate') && fine.decision === 'needs_approval' || { pass: false, detail: JSON.stringify([blk, iso, fine]) }
})
await check('R3a protected', 'the PDF\'s own protections keep their codes: an internal IP is internal_ip, an allow-listed one allow_listed, a Critical asset critical_asset (they come before the policy\'s own lists)', () =>
  attemptSeed('block_ip', { ip: '10.0.1.15', duration_min: 30 }, { riskScore: 90, confidence: 0.9 }).code === 'internal_ip' && attemptSeed('block_ip', { ip: '192.0.2.200', duration_min: 30 }, { riskScore: 90, confidence: 0.9 }).code === 'allow_listed' &&
  attemptSeed('isolate_host', { host: 'dc-01', duration_min: 120 }, { riskScore: 95, confidence: 0.95, assetClass: 'Critical' }).code === 'critical_asset' && attemptSeed('isolate_host', { host: 'DC-01', duration_min: 120 }, { riskScore: 95, confidence: 0.95, assetClass: 'Business' }).code === 'protected_target')
await check('R3a protected', 'the agent\'s assessment respects the lists: an alert whose source IP is on an administrator\'s Never block range is not recommended for a block, and the reason names the list', () => {
  const mine = policyWith((p) => p.neverBlock.push({ value: '203.0.113.0/24', label: 'Test range', required: false }), SEED)
  const r = engineRaw.assess(data.assessmentInputs.find((s) => s.alertId === 'ALT-001'), mine)
  return r.outcome !== 'recommend_block_ip' && r.alternativesConsidered.find((a) => a.outcome === 'recommend_block_ip').reason.includes('203.0.113.45 is on the Never block list') || { pass: false, detail: r.outcome }
})

// Changes: old → new lines for the audit event, and no line when nothing changed
await check('R3a changes', 'listChanges writes the old → new lines: "block_ip: Needs approval → Blacklisted", "isolate_host longest allowed: 4 h → 2 h", "Never isolate: added SIEM-02", and the other limits and lists', () => {
  const next = policyWith((p) => {
    p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false })
    Object.assign(limitsOf(p, 'isolate_host'), { maxMinutes: 120, windowMinutes: 10, minRisk: 92, defaultMinutes: 90 })
    p.neverIsolate.push({ value: 'SIEM-02', label: 'Second SIEM', required: false }); p.neverBlock = p.neverBlock.filter((t) => t.required)
    p.whitelist.push({ action: 'reset_password', mode: 'Needs approval', limits: { approver: 'soc_lead', windowMinutes: 15, minRisk: 75 } })
    p.whitelist = p.whitelist.filter((e) => e.action !== 'get_logs')
  }, SEED)
  const lines = engineRaw.listChanges(SEED, next)
  const want = ['block_ip: Needs approval → Blacklisted', 'isolate_host longest allowed: 4 h → 2 h', 'isolate_host default duration: 2 h → 90 min', 'isolate_host time to decide: 15 min → 10 min', 'isolate_host minimum risk: 90 → 92', 'Never isolate: added SIEM-02', 'reset_password: Not listed → Needs approval', 'get_logs: Automatic → Not listed']
  return want.every((l) => lines.includes(l)) && lines.length === want.length || { pass: false, detail: JSON.stringify(lines) }
})
await check('R3a changes', 'an unchanged policy has no changes (so a save writes nothing and keeps the version), and a removed own target reads "Never block: removed …"', () => {
  const own = policyWith((p) => p.neverBlock.push({ value: '198.51.100.0/24', label: 'x', required: false }), SEED)
  return engineRaw.listChanges(SEED, structuredClone(SEED)).length === 0 && engineRaw.listChanges(own, SEED).join() === 'Never block: removed 198.51.100.0/24' && engineRaw.listChanges(SEED, own).join() === 'Never block: added 198.51.100.0/24'
})
await check('R3a changes', 'policySnapshot keeps the action\'s rule and policyLabel reads "Response policy v3: isolate_host"; checkDurationChange honours the snapshot\'s longest time', () => {
  const snap = engineRaw.policySnapshot(SEED, 'isolate_host')
  return JSON.stringify(snap) === JSON.stringify({ version: 3, action: 'isolate_host', approver: 'soc_lead', minRisk: 90, maxMinutes: 240, windowMinutes: 15 }) && engineRaw.policyLabel(snap) === 'Response policy v3: isolate_host' &&
    engineRaw.checkDurationChange('isolate_host', 120, 100, 90).ok === false && engineRaw.checkDurationChange('isolate_host', 120, 90, 90).ok === true
})

// The refusal texts (these replace C5a's tier-rules, threshold-floor and policy-mode checks)
// The per-policy tier rules, the threshold floor and the approval modes went with the IF/THEN policies; the
// caps they enforced are the limit checks above, with the same PDF numbers.
await check('R3a limits', 'the refusals name the PDF\'s number: minimum risk "block_ip needs a minimum risk of 70 or more (Agent Action Policy), so the minimum cannot be lower."; Automatic on a Tier 2 action "always needs a person"', () => {
  const lowRisk = refusalOf('block_ip', { minRisk: 60 })
  const auto = engineRaw.policyRefusal(policyWith((p) => { p.whitelist.find((e) => e.action === 'isolate_host').mode = 'Automatic' }, SEED))
  return is(lowRisk, 'block_ip needs a minimum risk of 70 or more (Agent Action Policy), so the minimum cannot be lower.') === true &&
    is(auto, 'isolate_host always needs a person to approve it, so it cannot run automatically (Agent Action Policy).') === true
})
await check('R3a limits', 'the caps are the catalogue\'s own rows: POLICY_CAPS holds, for each Tier 2 action, its longest time, time to decide, approver and risk floor', () =>
  data.tier2Actions.every((a) => { const c = data.POLICY_CAPS[a.name]; return c.maxMinutes === a.maxMinutes && c.windowMinutes === a.approvalWindowMinutes && c.approver === a.approver && c.minRisk === a.floor.risk }) &&
  Object.keys(data.POLICY_CAPS).length === 6)

// What a save may do (this replaces C5b's "turning a policy off is never blocked by the floor")
// There is no policy to switch off any more: an action leaves the whitelist instead, which a save always allows.
await check('R3a changes', 'taking an action off the whitelist is never blocked by a cap: block_ip off the whitelist (or blacklisted) is accepted by policyRefusal, as is any limit set stricter than the PDF\'s', () => {
  const off = policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'block_ip') }, SEED)
  const black = policyWith((p) => { p.whitelist = p.whitelist.filter((e) => e.action !== 'isolate_host'); p.blacklist.push({ action: 'isolate_host', required: false }) }, SEED)
  const strict = policyWith((p) => Object.assign(limitsOf(p, 'isolate_host'), { maxMinutes: 30, defaultMinutes: 15, windowMinutes: 5, minRisk: 99 }), SEED)
  return [off, black, strict].every((p) => engineRaw.policyRefusal(p) === null)
})
}

// ---------- The approval flow (decide, start, finish) ----------
const analystA = { id: 'USR-002', name: 'Analyst A', role: 'soc_analyst', sourceIp: '10.0.2.25' }
const lead = { id: 'USR-001', name: 'System Administrator', role: 'soc_lead', sourceIp: '10.0.1.10' }
const FLOW_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/
const flowSeed = async (now = data.DEMO_NOW) => ({
  now,
  approvals: copy(seed.records),
  tokens: copy(seed.tokens),
  facts: copy(seed.executions),
  runs: copy(incident.executionRecords),
  running: [],
  refusals: {},
  failNext: false,
  failing: [],
  events: [],
})
// A pending isolation (as a person's "request again" would make it), asked by the analyst
const pendingIsolation = () => {
  const rec = { ...copy(apr1.recommendation), id: 'REC-003', requestedBy: 'USR-002', createdAt: '2026-08-03T15:46:00', approvalDeadline: '2026-08-03T16:01:00' }
  return { id: 'APR-003', recommendation: rec, requiredRole: 'soc_lead', policy: copy(apr1.policy), decision: 'Pending' }
}
const refusedWith = async (name, promise, code, reasonPattern) => check('flow', name, async () => {
  const r = await promise
  return !r.ok && r.code === code && (!reasonPattern || reasonPattern.test(r.reason)) || { pass: false, detail: JSON.stringify(r.ok ? 'ok' : [r.code, r.reason]) }
})

await check('flow', 'decisionRefusal: an analyst may decide the pending block (APR-002); the order of refusals is not pending, self-approval, wrong role, window closed', async () => {
  const s = await flowSeed()
  const can = flow.decisionRefusal(s.approvals[1], analystA, s.now)
  const done = flow.decisionRefusal(s.approvals[0], lead, s.now)
  const own = flow.decisionRefusal({ ...s.approvals[1], recommendation: { ...s.approvals[1].recommendation, requestedBy: 'USR-002' } }, analystA, s.now)
  const ownIso = flow.decisionRefusal(pendingIsolation(), analystA, s.now)
  const role = flow.decisionRefusal({ ...pendingIsolation(), recommendation: { ...pendingIsolation().recommendation, requestedBy: 'agent' } }, analystA, s.now)
  const late = flow.decisionRefusal(s.approvals[1], lead, '2026-08-03T16:00:00')
  return can === null && done.code === 'not_pending' && own.code === 'self_approval' && ownIso.code === 'self_approval' && role.code === 'wrong_role' && late.code === 'window_closed' || { pass: false, detail: JSON.stringify({ can, done, own, ownIso, role, late }) }
})
await check('flow', 'decisionRefusal: the reasons read in words ("Only a SOC lead can decide this request.", "The approval window closed at 15:59.")', async () => {
  const s = await flowSeed()
  const role = flow.decisionRefusal({ ...pendingIsolation(), recommendation: { ...pendingIsolation().recommendation, requestedBy: 'agent' } }, analystA, s.now)
  const late = flow.decisionRefusal(s.approvals[1], lead, '2026-08-03T16:00:00')
  const self = flow.decisionRefusal(pendingIsolation(), analystA, s.now)
  return role.reason === 'Only a SOC lead can decide this request.' && late.reason === 'The approval window closed at 15:59.' && self.reason === 'You requested this action, so you cannot decide on it.' || { pass: false, detail: [role.reason, late.reason, self.reason].join(' | ') }
})
await check('flow', 'a request can be decided up to its deadline itself, and not one second after (15:59:30)', async () => {
  const s = await flowSeed()
  return flow.decisionRefusal(s.approvals[1], analystA, '2026-08-03T15:59:30') === null && flow.decisionRefusal(s.approvals[1], analystA, '2026-08-03T15:59:31').code === 'window_closed'
})
await refusedWith('approve without a reason is refused', flowSeed().then((s) => flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: '   ' })), 'reason_required', /reason to approve/)
await refusedWith('reject without a reason is refused', flowSeed().then((s) => flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'reject', reason: '' })), 'reason_required', /reason to reject/)
await refusedWith('modify without a reason is refused', flowSeed().then((s) => flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: '', minutes: 10 })), 'reason_required')
await refusedWith('a decision on a request nobody asked for is refused', flowSeed().then((s) => flow.decide(s, { approvalId: 'APR-999', actor: analystA, kind: 'approve', reason: 'x' })), 'unknown_request')
await refusedWith('a decision after the deadline is refused and issues no token', flowSeed('2026-08-03T16:00:00').then((s) => flow.decide(s, { approvalId: 'APR-002', actor: lead, kind: 'approve', reason: 'late' })), 'window_closed', /closed at 15:59/)
await refusedWith('an analyst cannot approve an isolation', (async () => { const s = await flowSeed(); s.approvals.push({ ...pendingIsolation(), recommendation: { ...pendingIsolation().recommendation, requestedBy: 'agent' } }); return flow.decide(s, { approvalId: 'APR-003', actor: analystA, kind: 'approve', reason: 'x' }) })(), 'wrong_role', /SOC lead/)
await refusedWith('self-approval through decide() is refused (the requester asked, so cannot decide)', (async () => { const s = await flowSeed(); s.approvals.push(pendingIsolation()); return flow.decide(s, { approvalId: 'APR-003', actor: analystA, kind: 'reject', reason: 'x' }) })(), 'self_approval')
await check('flow', 'approve: APR-002 becomes Approved by Analyst A at the demo time, TKN-002 is issued bound to the exact action (SHA-256), expires 5 min later, and the record passes the policy rules', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'Confirmed brute force from a scanner.' })
  if (!r.ok) return { pass: false, detail: r.reason }
  const rec = r.state.approvals[1]
  const tok = r.state.tokens.find((t) => t.id === 'TKN-002')
  const verdict = await engine.validateApprovalRecord(rec, tok, [])
  return rec.decision === 'Approved' && rec.decidedAt === data.DEMO_NOW && rec.decidedBy.name === 'Analyst A' && rec.tokenId === 'TKN-002' && tok.paramsDigest === await engine.actionDigest(rec.approvedAction) && tok.expiresAt === '2026-08-03T15:51:00' && !tok.usedAt && verdict.ok && r.state.tokens.length === 2 || { pass: false, detail: JSON.stringify([rec.decision, rec.tokenId, tok, verdict]) }
})
await check('flow', 'approve writes one audit event "Approved action" with old → new: "Decision: Pending → Approved" and "Token: None → TKN-002 (unused, expires 15:51)"', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })
  const e = r.state.events
  return e.length === 1 && e[0].action === 'Approved action' && e[0].user === 'Analyst A' && e[0].role === 'Analyst' && e[0].target === 'APR-002 · Block 203.0.113.45' && e[0].changes.join('|') === 'Decision: Pending → Approved|Token: None → TKN-002 (unused, expires 15:51)' && e[0].metadata['Token ID'] === 'TKN-002' || { pass: false, detail: JSON.stringify(e) }
})
await check('flow', 'the System Administrator (a SOC lead) may approve an analyst-level request', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: lead, kind: 'approve', reason: 'Approved by the lead.' })
  return r.ok && r.state.approvals[1].decidedBy.role === 'soc_lead' && r.state.events[0].role === 'Administrator' || { pass: false, detail: r.ok ? '' : r.reason }
})
await check('flow', 'modify: a shorter duration (30 → 10 min) is approved, the token is bound to the shortened action, and the event says "Duration: 30 → 10 min"', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: 'Ten minutes is enough for the review.', minutes: 10 })
  if (!r.ok) return { pass: false, detail: r.reason }
  const rec = r.state.approvals[1]
  const tok = r.state.tokens[1]
  return rec.approvedAction.params.duration_min === 10 && rec.recommendation.action.params.duration_min === 30 && tok.paramsDigest === await engine.actionDigest(rec.approvedAction) && tok.paramsDigest !== await engine.actionDigest(rec.recommendation.action) && r.state.events[0].action === 'Modified approval' && r.state.events[0].changes.includes('Duration: 30 → 10 min') || { pass: false, detail: JSON.stringify(r.state.events[0]) }
})
for (const [name, minutes] of [['extend (40 > 30)', 40], ['keep the same (30)', 30], ['zero', 0], ['a fraction (7.5)', 7.5], ['go negative', -5]]) {
  await refusedWith(`modify that tries to ${name} is refused`, flowSeed().then((s) => flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: 'x', minutes })), 'duration_not_shorter')
}
await check('flow', 'modify cannot change the action or the target: the approved action equals the recommendation except its duration', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: 'shorter', minutes: 5 })
  const rec = r.state.approvals[1]
  const strip = (a) => JSON.stringify({ name: a.name, ip: a.params.ip })
  return strip(rec.approvedAction) === strip(rec.recommendation.action) && Object.keys(rec.approvedAction.params).join() === Object.keys(rec.recommendation.action.params).join()
})
await check('flow', 'reject: Rejected with the reason, no token, event "Rejected action" ("Decision: Pending → Rejected"); the request cannot be decided again', async () => {
  const s = await flowSeed()
  const r = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'reject', reason: 'A partner scan, not an attack.' })
  const again = await flow.decide(r.state, { approvalId: 'APR-002', actor: lead, kind: 'approve', reason: 'second thoughts' })
  const rec = r.state.approvals[1]
  return rec.decision === 'Rejected' && rec.reason === 'A partner scan, not an attack.' && !rec.tokenId && r.state.tokens.length === 1 && r.state.events[0].action === 'Rejected action' && r.state.events[0].changes.join() === 'Decision: Pending → Rejected' && !again.ok && again.code === 'not_pending' || { pass: false, detail: JSON.stringify([rec, again]) }
})
await check('flow', 'a refused decision changes nothing: no event, no token, the request stays Pending', async () => {
  const s = await flowSeed()
  const before = JSON.stringify(s)
  const results = await Promise.all([
    flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: '' }),
    flow.decide(s, { approvalId: 'APR-001', actor: lead, kind: 'reject', reason: 'x' }),
    flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: 'x', minutes: 99 }),
  ])
  return results.every((x) => !x.ok) && JSON.stringify(s) === before && s.events.length === 0
})
await check('flow', 'start: the guard passes, TKN-002 is used up at once (15:46:10), the request is running, the action window is 30 min from the start, and "Used approval token" is recorded', async () => {
  let s = await flowSeed()
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
  const r = await flow.beginExecution(s, 'APR-002')
  if (!r.ok) return { pass: false, detail: r.reason }
  const tok = r.state.tokens.find((t) => t.id === 'TKN-002')
  const fact = r.state.facts.find((f) => f.approvalId === 'APR-002')
  const ev = r.state.events[r.state.events.length - 1]
  return tok.usedAt === '2026-08-03T15:46:10' && fact.id === 'EXE-002' && fact.startedAt === '2026-08-03T15:46:10' && fact.expiresAt === '2026-08-03T16:16:10' && r.state.running.join() === 'APR-002' && r.state.now === '2026-08-03T15:46:10' && r.state.runs.length === 1 && ev.action === 'Used approval token' && ev.changes[0] === 'Token TKN-002: Unused → Used' || { pass: false, detail: JSON.stringify([tok, fact, r.state.running]) }
})
await check('flow', 'single use through the flow: a second start on the same token is refused ("already used") and changes nothing, before and after the run finishes', async () => {
  let s = await flowSeed()
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
  s = (await flow.beginExecution(s, 'APR-002')).state
  const during = await flow.beginExecution(s, 'APR-002')
  s = flow.finishExecution(s, 'APR-002').state
  const after = await flow.beginExecution(s, 'APR-002')
  return !during.ok && during.code === 'token_reused' && /already used/.test(during.reason) && during.state === undefined && !after.ok && after.code === 'token_reused' && s.runs.length === 2 && s.events.length === 3 || { pass: false, detail: JSON.stringify([during, after, s.events.length]) }
})
await refusedWith('a request that is not approved cannot start (pending, rejected)', flowSeed().then((s) => flow.beginExecution(s, 'APR-002')), 'not_ready')
await check('flow', 'a start whose token was tampered with is refused by the guard and the request is marked refused (nothing runs)', async () => {
  let s = await flowSeed()
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
  s = { ...s, tokens: s.tokens.map((t) => (t.id === 'TKN-002' ? { ...t, paramsDigest: 'a'.repeat(64) } : t)) }
  const r = await flow.beginExecution(s, 'APR-002')
  return !r.ok && r.code === 'params_changed' && r.state.refusals['APR-002'] === r.reason && r.state.runs.length === 1 && r.state.running.length === 0 || { pass: false, detail: JSON.stringify(r.ok ? 'ok' : [r.code, r.reason]) }
})
await check('flow', 'finish: EXE-002 is recorded for ALT-001, Block IP 203.0.113.45, Completed, 15:46 to 15:47, "1 minute", rolls back at 16:16, with the approver named; "Executed block" is the last event', async () => {
  let s = await flowSeed()
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
  s = (await flow.beginExecution(s, 'APR-002')).state
  const r = flow.finishExecution(s, 'APR-002')
  const run = r.state.runs[1]
  const ev = r.state.events[r.state.events.length - 1]
  return run.id === 'EXE-002' && run.triggeringAlert === 'ALT-001' && run.approvalId === 'APR-002' && run.action === 'Block IP' && run.target === '203.0.113.45' && run.result === 'Completed' && run.startTime === '15:46' && run.endTime === '15:47' && run.duration === '1 minute' && run.rollbackStatus === 'Block lifts automatically at 16:16' && /Analyst A/.test(run.happened) && run.evidence[0] === 'Risk score 77' && r.state.running.length === 0 && r.state.now === '2026-08-03T15:47:10' && ev.action === 'Executed block' && ev.user === 'AthenaSec AI' || { pass: false, detail: JSON.stringify(run) }
})
await check('flow', 'a run always lasts exactly one minute, whatever second it starts on: start and end differ by 1 minute for starts at :00, :20, :50 and across an hour', async () => {
  const outcomes = []
  for (const now of ['2026-08-03T15:46:00', '2026-08-03T15:46:20', '2026-08-03T15:46:50', '2026-08-03T15:50:00']) {
    let s = await flowSeed(now)
    s.approvals[1].recommendation.approvalDeadline = '2026-08-03T16:30:00'
    s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
    s = (await flow.beginExecution(s, 'APR-002')).state
    const run = flow.finishExecution(s, 'APR-002').state.runs[1]
    const [sh, sm] = run.startTime.split(':').map(Number)
    const [eh, em] = run.endTime.split(':').map(Number)
    outcomes.push((eh * 60 + em) - (sh * 60 + sm))
  }
  return outcomes.every((m) => m === 1) || { pass: false, detail: outcomes.join() }
})
await check('flow', 'a finish for a request that is not running is refused', async () => {
  const s = await flowSeed()
  const r = flow.finishExecution(s, 'APR-002')
  return !r.ok && r.code === 'not_running'
})
await check('flow', 'a modified approval runs for the shortened time: window 10 min from the start, and the run says "for 10 min instead of 30"', async () => {
  let s = await flowSeed()
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'modify', reason: 'shorter', minutes: 10 })).state
  s = (await flow.beginExecution(s, 'APR-002')).state
  const r = flow.finishExecution(s, 'APR-002')
  const fact = r.state.facts.find((f) => f.approvalId === 'APR-002')
  return fact.expiresAt === '2026-08-03T15:56:10' && /for 10 min instead of 30/.test(r.state.runs[1].responseReason) && r.state.runs[1].rollbackStatus === 'Block lifts automatically at 15:56' || { pass: false, detail: JSON.stringify([fact, r.state.runs[1].responseReason]) }
})
await check('flow', 'the SOC lead approves an isolation (asked by an analyst) and it runs: Isolate Host endpoint-12, rolls back by reconnecting at the end of the window, the asset class is checked by the guard', async () => {
  let s = await flowSeed()
  s.approvals.push(pendingIsolation())
  s = (await flow.decide(s, { approvalId: 'APR-003', actor: lead, kind: 'approve', reason: 'Approved by the SOC lead.' })).state
  s = (await flow.beginExecution(s, 'APR-003')).state
  const r = flow.finishExecution(s, 'APR-003')
  const run = r.state.runs[r.state.runs.length - 1]
  return run.action === 'Isolate Host' && run.target === 'endpoint-12' && /^Reconnects automatically at 17:46$/.test(run.rollbackStatus) && r.state.events.map((e) => e.action).join() === 'Approved action,Used approval token,Executed host isolation' || { pass: false, detail: JSON.stringify([run.rollbackStatus, r.state.events.map((e) => e.action)]) }
})
await check('flow', 'ids follow on: TKN-002 after TKN-001, EXE-002 after EXE-001, and a second approval gets TKN-003', async () => {
  let s = await flowSeed()
  s.approvals.push(pendingIsolation())
  s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'one' })).state
  s = (await flow.decide(s, { approvalId: 'APR-003', actor: lead, kind: 'approve', reason: 'two' })).state
  return s.tokens.map((t) => t.id).join() === 'TKN-001,TKN-002,TKN-003' && flow.nextNumber('EXE', ['EXE-001']) === 'EXE-002' && flow.nextNumber('TKN', []) === 'TKN-001'
})
await check('flow', 'every time the flow writes is a local YYYY-MM-DDTHH:MM:SS string, and the flow never reads the real clock (Date.now throws while it runs)', async () => {
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    let s = await flowSeed()
    s = (await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' })).state
    s = (await flow.beginExecution(s, 'APR-002')).state
    s = flow.finishExecution(s, 'APR-002').state
    const times = [s.now, ...s.events.map((e) => e.at), ...s.tokens.flatMap((t) => [t.issuedAt, t.expiresAt, t.usedAt].filter(Boolean)), ...s.facts.flatMap((f) => [f.startedAt, f.expiresAt]), ...s.approvals.flatMap((a) => [a.decidedAt].filter(Boolean))]
    const bad = times.filter((t) => !FLOW_TIME.test(t))
    return bad.length === 0 || { pass: false, detail: bad.join() }
  } finally {
    Date.now = real
  }
})

// ---------- Demo mode: time passing, an armed failure, asking again ----------
const runApproved = async (s, id, actor, reason = 'ok') => {
  let t = (await flow.decide(s, { approvalId: id, actor, kind: 'approve', reason })).state
  t = (await flow.beginExecution(t, id)).state
  return flow.finishExecution(t, id).state
}

for (const step of [0, 10, 30, -5, 7.5, 120]) {
  await check('demo', `demo time moves only in steps of 5 minutes, 15 minutes or 1 hour: ${step} is refused and changes nothing`, async () => {
    const s = await flowSeed()
    const r = flow.advanceTime(s, step, analystA)
    return !r.ok && r.code === 'invalid_step' && /5 minutes, 15 minutes or 1 hour/.test(r.reason) && s.events.length === 0 && s.now === data.DEMO_NOW
  })
}
await check('demo', 'advance +1 h: the clock moves 15:46:00 → 16:46:00 in one Demo event ("Demo time: 15:46:00 → 16:46:00", "forward 1 hour", step 60), the same format as the other steps', async () => {
  const s = await flowSeed()
  const r = flow.advanceTime(s, 60, lead)
  const e = r.state.events[0]
  return r.ok && r.state.now === '2026-08-03T16:46:00' && e.action === 'Advanced demo time' && e.demo === true && e.role === 'Administrator' && e.changes.join() === 'Demo time: 15:46:00 → 16:46:00' && /forward 1 hour\./.test(e.description) && e.metadata['Step (min)'] === '60' && e.target === 'Demo clock' || { pass: false, detail: JSON.stringify(r.state?.events[0]) }
})
await check('demo', 'two +1 h steps reach 17:46:00 and do what eight +15 min steps did: APR-002 timed out, the isolation reversed ("Reconnected at 17:44"), 2 Demo events', async () => {
  let s = await flowSeed()
  s = flow.advanceTime(s, 60, analystA).state
  s = flow.advanceTime(s, 60, analystA).state
  return s.now === '2026-08-03T17:46:00' && s.approvals[1].decision === 'Timed out' && s.runs[0].reversedAt === '2026-08-03T17:44:00' && s.runs[0].rollbackStatus === 'Reconnected at 17:44' && s.events.filter((e) => e.demo).length === 2 && s.events.filter((e) => e.action === 'Approval timed out').length === 1 && s.events.filter((e) => e.action === 'Action expired').length === 1
})
await check('demo', 'advance +5: the clock moves 15:46:00 → 15:51:00 and the use is a Demo audit event with old → new time ("Demo time: 15:46:00 → 15:51:00")', async () => {
  const s = await flowSeed()
  const r = flow.advanceTime(s, 5, analystA)
  const e = r.state.events[0]
  return r.ok && r.state.now === '2026-08-03T15:51:00' && r.state.events.length === 1 && e.action === 'Advanced demo time' && e.demo === true && e.user === 'Analyst A' && e.role === 'Analyst' && e.changes.join() === 'Demo time: 15:46:00 → 15:51:00' && e.metadata['Step (min)'] === '5' || { pass: false, detail: JSON.stringify(r.state?.events) }
})
await check('demo', 'advance +15 then +5: the old → new times chain (15:46:00 → 16:01:00, then 16:01:00 → 16:06:00)', async () => {
  let s = await flowSeed()
  s = flow.advanceTime(s, 15, lead).state
  s = flow.advanceTime(s, 5, lead).state
  const demos = s.events.filter((e) => e.demo)
  return s.now === '2026-08-03T16:06:00' && demos.map((e) => e.changes[0]).join('|') === 'Demo time: 15:46:00 → 16:01:00|Demo time: 16:01:00 → 16:06:00' && demos[0].role === 'Administrator'
})
await check('demo', 'timeout: +15 passes APR-002\'s deadline (15:59:30): it becomes Timed out with no token, "Approval timed out" says nothing ran, ALT-001 stays open and the Administrator was told', async () => {
  const s = await flowSeed()
  const r = flow.advanceTime(s, 15, analystA)
  const rec = r.state.approvals[1]
  const e = r.state.events.find((x) => x.action === 'Approval timed out')
  return rec.decision === 'Timed out' && !rec.tokenId && !rec.decidedBy && r.state.tokens.length === 1 && e.user === 'AthenaSec AI' && e.role === 'System' && e.changes.join() === 'Decision: Pending → Timed out' && /Nothing ran and ALT-001 stays open/.test(e.description) && /escalated to the Administrator/.test(e.description) && !e.demo && r.state.events.map((x) => x.action).join() === 'Advanced demo time,Approval timed out' || { pass: false, detail: JSON.stringify([rec, e]) }
})
await check('demo', 'timeout of an isolation request (needs a SOC lead) says a second notice went to all Administrators', async () => {
  const s = await flowSeed()
  s.approvals.push({ ...pendingIsolation(), recommendation: { ...pendingIsolation().recommendation, requestedBy: 'agent', approvalDeadline: '2026-08-03T15:59:00' } })
  const r = flow.advanceTime(s, 15, analystA)
  const e = r.state.events.find((x) => x.target.startsWith('APR-003'))
  return e.action === 'Approval timed out' && /second notice went to all Administrators/.test(e.description) && !/escalated/.test(e.description) || { pass: false, detail: JSON.stringify(e) }
})
await check('demo', 'the deadline itself is still open: from 15:44:30, +15 reaches 15:59:30 and APR-002 stays Pending; +5 more times it out', async () => {
  const s = await flowSeed('2026-08-03T15:44:30')
  const a = flow.advanceTime(s, 15, analystA)
  const b = flow.advanceTime(a.state, 5, analystA)
  return a.state.approvals[1].decision === 'Pending' && b.state.approvals[1].decision === 'Timed out'
})
await check('demo', 'a timed-out request cannot be decided or run, and deciding it refuses "already timed out"', async () => {
  const s = flow.advanceTime(await flowSeed(), 15, analystA).state
  const decide = await flow.decide(s, { approvalId: 'APR-002', actor: lead, kind: 'approve', reason: 'late' })
  const begin = await flow.beginExecution(s, 'APR-002')
  return !decide.ok && decide.code === 'not_pending' && /already timed out/.test(decide.reason) && !begin.ok && begin.code === 'not_ready'
})
await check('demo', 'timing out twice does nothing more: a second advance writes only its own Demo event', async () => {
  let s = flow.advanceTime(await flowSeed(), 15, analystA).state
  const before = s.events.filter((e) => e.action === 'Approval timed out').length
  s = flow.advanceTime(s, 5, analystA).state
  return before === 1 && s.events.filter((e) => e.action === 'Approval timed out').length === 1 && s.events.filter((e) => e.demo).length === 2
})
await check('demo', 'expiry: past 17:44:00 the isolation of endpoint-12 is reversed ("Reconnected at 17:44"), with an "Action expired" event; from 17:39:00 +5 lands exactly on 17:44:00 and reverses it', async () => {
  const early = flow.advanceTime(await flowSeed('2026-08-03T17:30:00'), 5, lead)
  const exact = flow.advanceTime(await flowSeed('2026-08-03T17:39:00'), 5, lead)
  const run = exact.state.runs[0]
  const e = exact.state.events.find((x) => x.action === 'Action expired')
  return !early.state.runs[0].reversedAt && run.reversedAt === '2026-08-03T17:44:00' && run.rollbackStatus === 'Reconnected at 17:44' && e.target === 'endpoint-12' && e.changes.join('|') === 'Isolation of endpoint-12: Active → Reversed|Reversed at 17:44' && e.role === 'System' && !e.demo || { pass: false, detail: JSON.stringify([run.reversedAt, e]) }
})
await check('demo', 'a reversed run is not reversed again, and a failed run is never "reversed"', async () => {
  let s = await flowSeed('2026-08-03T17:39:00')
  s = flow.advanceTime(s, 5, lead).state
  s = flow.advanceTime(s, 15, lead).state
  return s.events.filter((e) => e.action === 'Action expired').length === 1
})
await check('demo', 'expiry of a block: a block approved for 30 min lapses 30 minutes after it started and says "Block lifted at 16:16"', async () => {
  let s = await runApproved(await flowSeed(), 'APR-002', analystA)
  s = flow.advanceTime(s, 15, analystA).state
  const mid = s.runs[1].reversedAt
  s = flow.advanceTime(s, 15, analystA).state
  return mid === undefined && s.runs[1].reversedAt === '2026-08-03T16:16:10' && s.runs[1].rollbackStatus === 'Block lifted at 16:16' && s.events.filter((e) => e.action === 'Action expired' && e.target === '203.0.113.45').length === 1 || { pass: false, detail: JSON.stringify([mid, s.runs[1].reversedAt]) }
})
await check('demo', 'arm a failure: a Demo event "Next execution: Will succeed → Will fail"; arming twice is refused', async () => {
  const s = await flowSeed()
  const a = flow.armFailure(s, analystA)
  const b = flow.armFailure(a.state, analystA)
  const e = a.state.events[0]
  return a.ok && a.state.failNext && e.action === 'Armed a failed execution' && e.demo === true && e.changes.join() === 'Next execution: Will succeed → Will fail' && !b.ok && b.code === 'already_armed'
})
await check('demo', 'an armed failure fails the next run only: token used up, run Failed ("Not applicable", the reason), "Execution failed" event with result Failed, and the run after it succeeds', async () => {
  let s = (await flow.armFailure(await flowSeed(), analystA)).state
  s = await runApproved(s, 'APR-002', analystA)
  const failed = s.runs[1]
  const ev = s.events[s.events.length - 1]
  const tok = s.tokens.find((t) => t.id === 'TKN-002')
  s.approvals.push({ ...pendingIsolation(), recommendation: { ...pendingIsolation().recommendation, requestedBy: 'agent' } })
  s = await runApproved(s, 'APR-003', lead)
  return failed.result === 'Failed' && failed.rollbackStatus === 'Not applicable' && /firewall did not acknowledge/.test(failed.failureReason) && ev.action === 'Execution failed' && ev.result === 'Failed' && tok.usedAt === '2026-08-03T15:46:10' && s.runs[2].result === 'Completed' && !s.failNext && s.failing.length === 0 || { pass: false, detail: JSON.stringify([failed.result, ev, s.runs.map((r) => r.result)]) }
})
await check('demo', 'a failed run\'s step marks the failure at its end time (so the timeline marks it), and its token is never reused: starting it again is refused', async () => {
  let s = (await flow.armFailure(await flowSeed(), analystA)).state
  s = await runApproved(s, 'APR-002', analystA)
  const failed = s.runs[1]
  const again = await flow.beginExecution(s, 'APR-002')
  return failed.timeline[failed.timeline.length - 1].time === failed.endTime && /timed out/.test(failed.timeline[failed.timeline.length - 1].event) && !again.ok && again.code === 'token_reused'
})
await check('demo', 'request again after a failure: a new request with new ids (APR-003, REC-003), asked by the analyst, Pending, same role and policy; the old approval and token are untouched; an "Requested approval" event', async () => {
  let s = (await flow.armFailure(await flowSeed(), analystA)).state
  s = await runApproved(s, 'APR-002', analystA)
  const oldToken = JSON.stringify(s.tokens.find((t) => t.id === 'TKN-002'))
  const oldApproval = JSON.stringify(s.approvals[1])
  const r = flow.requestAgain(s, 'EXE-002', analystA, true)
  if (!r.ok) return { pass: false, detail: r.reason }
  const added = r.state.approvals[2]
  const e = r.state.events[r.state.events.length - 1]
  return added.id === 'APR-003' && added.recommendation.id === 'REC-003' && added.recommendation.requestedBy === 'USR-002' && added.decision === 'Pending' && !added.tokenId && added.requiredRole === 'soc_analyst' && added.policy.action === 'block_ip' && added.policy.version === 3 && added.recommendation.createdAt === r.state.now && added.recommendation.approvalDeadline === '2026-08-03T16:02:10' && JSON.stringify(r.state.tokens.find((t) => t.id === 'TKN-002')) === oldToken && JSON.stringify(r.state.approvals[1]) === oldApproval && e.action === 'Requested approval' && e.changes.join('|') === 'Request: None → APR-003 (pending)|Requested by: None → Analyst A' && e.metadata['Earlier token'] === 'TKN-002' || { pass: false, detail: JSON.stringify([added, e]) }
})
await check('demo', 'the requester cannot decide on their own request; the Administrator can, gets a new token (TKN-003, not TKN-002), and the run succeeds', async () => {
  let s = (await flow.armFailure(await flowSeed(), analystA)).state
  s = await runApproved(s, 'APR-002', analystA)
  s = flow.requestAgain(s, 'EXE-002', analystA, true).state
  const own = await flow.decide(s, { approvalId: 'APR-003', actor: analystA, kind: 'approve', reason: 'mine' })
  const before = JSON.stringify(s)
  s = await runApproved(s, 'APR-003', lead, 'The lead approves the second request.')
  return !own.ok && own.code === 'self_approval' && JSON.stringify(own) !== before && s.tokens.map((t) => t.id).join() === 'TKN-001,TKN-002,TKN-003' && s.tokens[1].usedAt === '2026-08-03T15:46:10' && s.approvals[2].tokenId === 'TKN-003' && s.runs[2].id === 'EXE-003' && s.runs[2].result === 'Completed' && s.runs[2].approvalId === 'APR-003' || { pass: false, detail: JSON.stringify([own, s.tokens.map((t) => t.id), s.runs.map((r) => r.id)]) }
})
await check('demo', 'request again after an isolation lapsed: the analyst asks, cannot decide (self-approval) and could not anyway (needs a SOC lead); the Administrator approves and it runs again', async () => {
  let s = flow.advanceTime(await flowSeed('2026-08-03T17:35:00'), 15, analystA).state
  const r = flow.requestAgain(s, 'EXE-001', analystA, true)
  if (!r.ok) return { pass: false, detail: r.reason }
  s = r.state
  const added = s.approvals[2]
  const own = flow.decisionRefusal(added, analystA, s.now)
  const analystOther = flow.decisionRefusal({ ...added, recommendation: { ...added.recommendation, requestedBy: 'USR-009' } }, analystA, s.now)
  s = await runApproved(s, 'APR-003', lead)
  const run = s.runs[s.runs.length - 1]
  return added.requiredRole === 'soc_lead' && added.policy.action === 'isolate_host' && added.policy.version === 3 && own.code === 'self_approval' && analystOther.code === 'wrong_role' && run.action === 'Isolate Host' && run.target === 'endpoint-12' && run.id === 'EXE-002' && run.result === 'Completed' && !run.reversedAt || { pass: false, detail: JSON.stringify([added.requiredRole, own, analystOther, run?.id]) }
})
await check('demo', 'asking again is refused when it makes no sense: a run that is active, a closed alert, a request already waiting, and a later run that is active', async () => {
  const s = await flowSeed()
  const active = flow.requestAgain(s, 'EXE-001', analystA, true)
  const lapsed = flow.advanceTime(await flowSeed('2026-08-03T17:35:00'), 15, analystA).state
  const closed = flow.requestAgain(lapsed, 'EXE-001', analystA, false)
  const first = flow.requestAgain(lapsed, 'EXE-001', analystA, true)
  const waiting = flow.requestAgain(first.state, 'EXE-001', analystA, true)
  const reasons = [active, closed, waiting].map((r) => r.reason)
  const later = await runApproved(first.state, 'APR-003', lead)
  const laterAgain = flow.requestAgain(later, 'EXE-001', analystA, true)
  return reasons.every((x) => x) && /failed or has lapsed/.test(active.reason) && /is closed/.test(closed.reason) && /already waiting/.test(waiting.reason) && !laterAgain.ok && /still active/.test(laterAgain.reason)
})
await check('demo', 'requesterName shows a person by name, not by id (USR-002 → Analyst A, USR-001 → System Administrator), the agent as AthenaSec AI, and an unknown id as it is', () =>
  flow.requesterName('USR-002') === 'Analyst A' && flow.requesterName('USR-001') === 'System Administrator' && flow.requesterName('agent') === 'AthenaSec AI' && flow.requesterName('USR-999') === 'USR-999')
await check('demo', 'a request that is not a run cannot be asked for again', async () => {
  const s = await flowSeed()
  const r = flow.requestAgain(s, 'EXE-999', analystA, true)
  return !r.ok && r.code === 'unknown_run'
})
await check('demo', 'the demo controls never read the real clock and write only local YYYY-MM-DDTHH:MM:SS times', async () => {
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    let s = (await flow.armFailure(await flowSeed(), analystA)).state
    s = flow.advanceTime(s, 5, analystA).state
    s = await runApproved(s, 'APR-002', analystA)
    s = flow.advanceTime(s, 15, analystA).state
    s = flow.requestAgain(s, 'EXE-002', analystA, true).state
    const times = [s.now, ...s.events.map((e) => e.at), ...s.runs.flatMap((r) => [r.reversedAt].filter(Boolean)), ...s.approvals.flatMap((a) => [a.recommendation.createdAt, a.recommendation.approvalDeadline])]
    const bad = times.filter((t) => !FLOW_TIME.test(t))
    return bad.length === 0 || { pass: false, detail: bad.join() }
  } finally {
    Date.now = real
  }
})

// ---------- The demo clock ----------
const LOCAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/
const seedTimes = () => [
  ['DEMO_NOW', data.DEMO_NOW],
  ...seed.records.flatMap((r) => [
    [`${r.id} createdAt`, r.recommendation.createdAt],
    [`${r.id} approvalDeadline`, r.recommendation.approvalDeadline],
    ...(r.decidedAt ? [[`${r.id} decidedAt`, r.decidedAt]] : []),
  ]),
  ...seed.tokens.flatMap((t) => [
    [`${t.id} issuedAt`, t.issuedAt],
    [`${t.id} expiresAt`, t.expiresAt],
    ...(t.usedAt ? [[`${t.id} usedAt`, t.usedAt]] : []),
  ]),
  ...seed.executions.flatMap((e) => [
    [`${e.id} startedAt`, e.startedAt],
    [`${e.id} expiresAt`, e.expiresAt],
  ]),
]
await check('clock', 'DEMO_NOW and every seed timestamp use one local format, YYYY-MM-DDTHH:MM:SS, with no trailing Z or UTC offset', () => {
  const bad = seedTimes().filter(([, value]) => !LOCAL_TIME.test(value)).map(([name, value]) => `${name}=${value}`)
  return bad.length === 0 && seedTimes().length === 11 || { pass: false, detail: bad.join('; ') || `${seedTimes().length} timestamps` }
})
await check('clock', 'DEMO_NOW is 15:46:00: after the isolation finished (15:45:00) and before ALT-001\'s deadline (15:59:30); the isolation is still active (reverses 17:44:00)', () => {
  const t = engine.parseTime
  return data.DEMO_NOW === '2026-08-03T15:46:00' && t(data.DEMO_NOW) > t('2026-08-03T15:45:00') && t(data.DEMO_NOW) < t(apr2.recommendation.approvalDeadline) && t(data.DEMO_NOW) < t(exe1.expiresAt) || { pass: false, detail: data.DEMO_NOW }
})
await check('clock', 'deadline arithmetic gives the same answer in UTC, UTC+4 and UTC-7 (the machine\'s time zone never shifts it)', () => {
  const saved = process.env.TZ
  const answers = []
  try {
    for (const zone of ['UTC', 'Asia/Dubai', 'America/Los_Angeles']) {
      process.env.TZ = zone
      answers.push([
        engine.addMinutes('2026-08-03T15:59:00', 2),
        engine.parseTime(apr2.recommendation.approvalDeadline) - engine.parseTime(data.DEMO_NOW),
        engine.windowState(apr2.recommendation.approvalDeadline, data.DEMO_NOW).label,
        engine.addMinutes(apr1.decidedAt, 5) === tkn1.expiresAt,
      ].join('|'))
    }
  } finally {
    if (saved === undefined) delete process.env.TZ
    else process.env.TZ = saved
  }
  return answers.every((a) => a === '2026-08-03T16:01:00|810000|13 min left|true') || { pass: false, detail: answers.join(' ; ') }
})
await check('clock', 'windowState: "13 min left" now, "40 s left" near the end, open at the deadline itself, "Overdue" one second after', () => {
  const d = apr2.recommendation.approvalDeadline
  const states = [
    engine.windowState(d, data.DEMO_NOW),
    engine.windowState(d, '2026-08-03T15:58:50'),
    engine.windowState(d, d),
    engine.windowState(d, '2026-08-03T15:59:31'),
  ]
  return states.map((s) => `${s.open}:${s.label}`).join() === 'true:13 min left,true:40 s left,true:0 s left,false:Overdue' || { pass: false, detail: states.map((s) => `${s.open}:${s.label}`).join() }
})
await check('clock', 'tokenState: TKN-001 stays Used; an unused token is Unused until its expiry, then Expired', () => {
  const unused = { ...tkn1, usedAt: undefined }
  return engine.tokenState(tkn1, data.DEMO_NOW) === 'Used' && engine.tokenState(tkn1, '2030-01-01T00:00:00') === 'Used' &&
    engine.tokenState(unused, tkn1.expiresAt) === 'Unused' && engine.tokenState(unused, '2026-08-03T15:48:11') === 'Expired'
})
await check('clock', 'the validators, guard and clock helpers never read the real clock (Date.now throws while they run)', async () => {
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    const [r, t, e] = approved()
    const a = await verdict(r, t, e)
    const g = await engine.guard({ actionName: 'block_ip', params: {}, now: data.DEMO_NOW }, [])
    engine.windowState(apr2.recommendation.approvalDeadline, data.DEMO_NOW)
    engine.tokenState(tkn1, data.DEMO_NOW)
    return a.ok && !g.allowed || { pass: false, detail: `${a.code} / ${g.code}` }
  } finally {
    Date.now = real
  }
})
await check('clock', 'no source file under src/ reads the real clock (Date.now, performance.now, new Date()), except the Service Panel\'s display-only "last refreshed" label', () => {
  const allowed = new Set(['src/pages/ServicePanelPage.tsx'])
  const hits = []
  for (const entry of readdirSync(join(root, 'src'), { recursive: true })) {
    const file = `src/${String(entry).replaceAll('\\', '/')}`
    if (!/\.(ts|tsx)$/.test(file) || allowed.has(file)) continue
    const text = readFileSync(join(root, file), 'utf8')
    for (const pattern of [/Date\.now\s*\(/, /performance\.now\s*\(/, /new Date\(\s*\)/]) {
      if (pattern.test(text)) hits.push(`${file}: ${pattern.source}`)
    }
  }
  return hits.length === 0 || { pass: false, detail: hits.join('; ') }
})
await check('clock', 'the only exception is the Service Panel\'s label, which is not used to compare anything; auditTimestamp takes the demo clock\'s time and has no default that reads the real one', () => {
  const stamp = readFileSync(join(root, 'src/data/auditLogsData.ts'), 'utf8')
  const panel = readFileSync(join(root, 'src/pages/ServicePanelPage.tsx'), 'utf8')
  return /export function auditTimestamp\(demoTime: string\)/.test(stamp) && /function clockTime\(\)/.test(panel) && !/parseTime|windowState|tokenState/.test(panel) || { pass: false, detail: 'an exception changed' }
})

// ---------- C5a: the action catalogue (every value from design/agent-action-policy.pdf) ----------
const catalogue = data.ACTION_CATALOGUE
const rowOf = (key) => catalogue.find((row) => row.key === key)
const PDF_TIER1 = [
  'get_logs(source, time_range)', 'analyse_alert(alert_id)', 'check_ip_reputation(ip)', 'get_asset_context(host)', 'monitor(entity, duration)',
  'create_alert(alert)', 'create_ticket(case)', 'recommend_response(rec)', 'notify_analyst(channel, message)',
]
// PDF page 5, with "Tier 1 critical" worded as the app words asset classes (Critical)
const PDF_TIER3 = [
  ['Permanent blocking, or any block longer than 24 h', 'Irreversible lockouts of legitimate users and partners'],
  ['Deleting or modifying logs, alerts, cases or evidence', 'Destroys the audit trail and forensic value'],
  ['Disabling or reconfiguring security controls (Wazuh agents, rules, firewall, EDR)', 'Blinds the SOC; a common attacker goal'],
  ['Creating, changing or disabling privileged accounts, credentials or group memberships', 'Highest-impact change; must stay with identity administrators'],
  ['Isolating a Critical system without authorised approval', 'Can take the business offline; a person decides and acts'],
  ['Changing its own policies, thresholds or allow-list', 'The agent cannot widen its own permissions'],
]
const PDF_TIER2 = {
  block_ip: { defaultMinutes: 30, maxMinutes: 1440, approver: 'soc_analyst', window: 15, risk: 70, confidence: 0.8 },
  isolate_host: { defaultMinutes: 120, maxMinutes: 240, approver: 'soc_lead', window: 15, risk: 85, confidence: 0.85 },
  suspend_user_session: { defaultMinutes: 30, maxMinutes: 60, approver: 'soc_analyst', window: 15, risk: 75, confidence: 0.8 },
}

await check('catalogue', 'the catalogue holds 21 rows: 9 Tier 1, 6 Tier 2, 6 Tier 3, each action once', () => {
  const tiers = [1, 2, 3].map((t) => catalogue.filter((row) => row.tier === t).length)
  return tiers.join() === '9,6,6' && new Set(catalogue.map((row) => row.key)).size === 21 || { pass: false, detail: `${tiers.join()} / ${new Set(catalogue.map((row) => row.key)).size} keys` }
})
await check('catalogue', 'the catalogue is built from the three tier lists (same rows, same order)', () =>
  catalogue.map((row) => row.action).join('|') === [...data.tier1Actions.map((a) => a.name), ...data.tier2Actions.map((a) => a.signature), ...data.tier3Actions.map((a) => a.action)].join('|'))
await check('catalogue', 'Tier 1 holds the PDF\'s nine actions, in its order, all from page 3', () =>
  catalogue.filter((row) => row.tier === 1).map((row) => row.action).join('|') === PDF_TIER1.join('|') && catalogue.filter((row) => row.tier === 1).every((row) => row.source === 'PDF p.3'))
await check('catalogue', 'Tier 1 limits: only monitor has a duration (24 h max); the rest have none', () => {
  const withMinutes = catalogue.filter((row) => row.tier === 1 && row.maxMinutes !== undefined).map((row) => `${row.key}:${row.maxMinutes}`)
  return withMinutes.join() === 'monitor:1440' || { pass: false, detail: withMinutes.join() }
})
await check('catalogue', 'Tier 1 "when used" follows page 3 for monitor (risk under 40, or 40-59 with low confidence), create_ticket and recommend_response', () =>
  rowOf('monitor').whenUsed === 'Risk below 40, or risk 40-59 with low confidence' && rowOf('create_ticket').whenUsed === 'Risk 60 or more, or any Tier 2 recommendation' && rowOf('recommend_response').whenUsed === 'Risk 70 or more and a matching policy')
for (const [name, want] of Object.entries(PDF_TIER2)) {
  await check('catalogue', `${name}: default ${want.defaultMinutes} min, max ${want.maxMinutes} min, ${want.approver}, ${want.window} min window, risk ${want.risk}+, confidence ${want.confidence.toFixed(2)}+, all from page 4`, () => {
    const row = rowOf(name)
    const got = { defaultMinutes: row.defaultMinutes, maxMinutes: row.maxMinutes, approver: row.approver, window: row.approvalWindowMinutes, risk: row.riskFloor, confidence: row.confidenceFloor }
    return JSON.stringify(got) === JSON.stringify(want) && row.tier === 2 && row.source === 'PDF p.4' || { pass: false, detail: JSON.stringify(got) }
  })
}
await check('catalogue', 'Tier 3 holds the PDF\'s six prohibited actions with their reasons, all from page 5, with no duration or approver', () => {
  const rows = catalogue.filter((row) => row.tier === 3)
  return rows.map((row) => `${row.action}|${row.why}`).join('\n') === PDF_TIER3.map((p) => p.join('|')).join('\n') &&
    rows.every((row) => row.source === 'PDF p.5' && row.defaultMinutes === undefined && row.maxMinutes === undefined && row.approver === undefined) || { pass: false, detail: rows.map((r) => r.action).join(' / ') }
})
await check('catalogue', 'every row says whether it reverses; Tier 3 rows carry a reason and no other row does', () =>
  catalogue.every((row) => row.reversible.length > 0 && (row.tier === 3) === (typeof row.why === 'string' && row.why.length > 0)))
await check('catalogue', 'reversible: block "auto-unblock on expiry" (PDF), monitor "expires after at most 24 h", create_alert and create_ticket "no change to systems", Tier 3 "never runs"', () =>
  rowOf('block_ip').reversible === 'Yes: auto-unblock on expiry' && rowOf('monitor').reversible === 'Expires after at most 24 h' && rowOf('create_alert').reversible === 'No change to systems' && rowOf('create_ticket').reversible === 'No change to systems' &&
  catalogue.filter((row) => row.tier === 3).every((row) => row.reversible === 'Not applicable: never runs'))
await check('catalogue', 'assumptions: exactly ten, each naming a known field and carrying a note of real length (the PDF gives no description for its three Tier 2 actions, and none for isolation\'s reversal; the three added rows are assumptions in what they do and in not reversing)', () => {
  const all = catalogue.flatMap((row) => row.assumed.map((a) => ({ key: row.key, ...a })))
  const listed = all.map((a) => `${a.key}.${a.field}`).sort().join()
  const wanted = ['block_ip.does', 'isolate_host.does', 'isolate_host.reversible', 'suspend_user_session.does', 'kill_process.does', 'kill_process.reversible', 'quarantine_file.does', 'quarantine_file.reversible', 'reset_password.does', 'reset_password.reversible'].sort().join()
  return listed === wanted && all.every((a) => ['does', 'reversible'].includes(a.field) && a.note.length >= 40) || { pass: false, detail: listed }
})
await check('catalogue', 'no Tier 1 or Tier 3 row (every value stated by the PDF) is marked as an assumption', () =>
  catalogue.filter((row) => row.tier !== 2).every((row) => row.assumed.length === 0))
await check('catalogue', 'the tier in words: Runs automatically / Needs a SOC analyst\'s approval / Needs a SOC lead\'s approval / Never allowed', () =>
  [data.tierWords(rowOf('get_logs')), data.tierWords(rowOf('block_ip')), data.tierWords(rowOf('isolate_host')), data.tierWords(rowOf('delete_logs'))].join('|') ===
  'Runs automatically|Needs a SOC analyst’s approval|Needs a SOC lead’s approval|Never allowed')
await check('catalogue', 'durations read as the PDF writes them: 30 min, 60 min, 2 h, 4 h, 24 h', () =>
  [30, 60, 120, 240, 1440].map(data.formatMinutes).join() === '30 min,60 min,2 h,4 h,24 h')
await check('catalogue', 'the guard\'s own lists are the catalogue\'s: every Tier 3 request name is a row, every Tier 2 name is a row', () =>
  data.tier3Actions.every((a) => rowOf(a.requestName)?.tier === 3) && data.tier2Actions.every((a) => rowOf(a.name)?.tier === 2))

// (C5a's tier-rules, threshold-floor and policy-mode checks were here; the R3a limits checks replace them.)

// ---------- C5a: "Simulate an attempt" (attemptDecision) ----------
const attempt = (name, params = {}, extra = {}) => engine.attemptDecision({ actionName: name, params, ...extra })
const tier2Base = {
  block_ip: { params: { ip: '203.0.113.45', duration_min: 30 }, riskScore: 82, confidence: 0.88, assetClass: 'Business' },
  isolate_host: { params: { host: 'endpoint-09', path: 'edr_network_isolation', duration_min: 120 }, riskScore: 90, confidence: 0.9, assetClass: 'Business' },
  suspend_user_session: { params: { user: 'j.smith', duration_min: 30 }, riskScore: 80, confidence: 0.9, assetClass: 'Standard' },
}
const tier2Try = (name, change = {}) => {
  const base = tier2Base[name]
  return attempt(name, { ...base.params, ...(change.params ?? {}) }, { riskScore: base.riskScore, confidence: base.confidence, assetClass: base.assetClass, ...Object.fromEntries(Object.entries(change).filter(([k]) => k !== 'params')) })
}

for (const row of catalogue.filter((r) => r.tier === 1)) {
  await check('attempt', `${row.key} (Tier 1): allowed, with its rule and "executed: false"`, () => {
    const d = attempt(row.key)
    return d.decision === 'allowed' && d.code === 'ok' && d.executed === false && d.rule === `Tier 1 · ${row.action} · PDF p.3` || { pass: false, detail: JSON.stringify(d) }
  })
}
for (const row of catalogue.filter((r) => r.tier === 3)) {
  await check('attempt', `${row.key} (Tier 3): refused as prohibited, whatever it carries, with its rule and the page`, () => {
    const d = attempt(row.key, { duration_min: 1 }, { riskScore: 100, confidence: 1, assetClass: 'Standard' })
    return d.decision === 'refused' && d.code === 'prohibited' && d.executed === false && d.rule === `Tier 3 · ${row.action} · PDF p.5` && d.reason.includes(row.key) || { pass: false, detail: JSON.stringify(d) }
  })
}
await check('attempt', 'a name outside the catalogue is refused (not_in_catalogue), with the layer-2 rule', () => {
  const d = attempt('format_disk')
  return d.decision === 'refused' && d.code === 'not_in_catalogue' && d.rule === 'Anything outside the catalogue is refused · PDF p.5' && d.executed === false || { pass: false, detail: JSON.stringify(d) }
})
for (const [name, want] of Object.entries(PDF_TIER2)) {
  await check('attempt', `${name} with every check passing needs approval from a ${want.approver === 'soc_lead' ? 'SOC lead' : 'SOC analyst'} within ${want.window} min (rule: its page 4 row)`, () => {
    const d = tier2Try(name)
    return d.decision === 'needs_approval' && d.code === 'needs_approval' && d.approver === want.approver && d.approvalWindowMinutes === want.window && d.executed === false && d.rule === `Tier 2 · ${rowOf(name).action} · PDF p.4` || { pass: false, detail: JSON.stringify(d) }
  })
  await check('attempt', `${name}: a duration of ${want.maxMinutes} min passes, ${want.maxMinutes + 1} min is refused (duration_over_max)`, () => {
    const ok = tier2Try(name, { params: { duration_min: want.maxMinutes } })
    const over = tier2Try(name, { params: { duration_min: want.maxMinutes + 1 } })
    return ok.decision === 'needs_approval' && over.code === 'duration_over_max' && over.decision === 'refused' || { pass: false, detail: `${ok.code} ${over.code}` }
  })
  await check('attempt', `${name}: risk ${want.risk} and confidence ${want.confidence.toFixed(2)} pass; one step below either is refused (below_threshold)`, () => {
    const at = tier2Try(name, { riskScore: want.risk, confidence: want.confidence })
    const lowRisk = tier2Try(name, { riskScore: want.risk - 1 })
    const lowConfidence = tier2Try(name, { confidence: Math.round((want.confidence - 0.01) * 100) / 100 })
    return at.decision === 'needs_approval' && lowRisk.code === 'below_threshold' && lowConfidence.code === 'below_threshold' || { pass: false, detail: `${at.code} ${lowRisk.code} ${lowConfidence.code}` }
  })
}
await check('attempt', 'block_ip: an internal address is refused (internal_ip) and an allow-listed or invalid one (allow_listed)', () => {
  const codes = ['192.168.1.45', '10.0.1.15', '192.0.2.10', '192.0.2.200', 'not-an-ip'].map((ip) => tier2Try('block_ip', { params: { ip, duration_min: 30 } }).code)
  return codes.join() === 'internal_ip,internal_ip,allow_listed,allow_listed,allow_listed' || { pass: false, detail: codes.join() }
})
await check('attempt', 'isolate_host: a Critical asset is refused (critical_asset); Business and Standard need approval', () =>
  tier2Try('isolate_host', { assetClass: 'Critical' }).code === 'critical_asset' && tier2Try('isolate_host', { assetClass: 'Business' }).decision === 'needs_approval' && tier2Try('isolate_host', { assetClass: 'Standard' }).decision === 'needs_approval')
await check('attempt', 'suspend_user_session: a privileged account is refused (privileged_account); the flag changes nothing for the other two Tier 2 actions', () =>
  tier2Try('suspend_user_session', { privilegedAccount: true }).code === 'privileged_account' && tier2Try('suspend_user_session', { privilegedAccount: false }).decision === 'needs_approval' &&
  tier2Try('block_ip', { privilegedAccount: true }).decision === 'needs_approval' && tier2Try('isolate_host', { privilegedAccount: true }).decision === 'needs_approval')
await check('attempt', 'a Tier 2 attempt with no risk or confidence given skips those checks, as the guard does', () =>
  attempt('block_ip', tier2Base.block_ip.params).decision === 'needs_approval')

// The guard and the attempt share their checks: same code, same reason on every refusal
const guardVsAttempt = async (name, change = {}) => {
  const base = tier2Base[name]
  const params = { ...base.params, ...(change.params ?? {}) }
  const extra = { riskScore: base.riskScore, confidence: base.confidence, assetClass: base.assetClass, ...Object.fromEntries(Object.entries(change).filter(([k]) => k !== 'params')) }
  const recommendation = rec({ id: 'REC-G', action: { name, params: base.params } })
  const t = await issue(recommendation, { name, params }, 'USR-001', 'soc_lead')
  const g = await engine.guard({ actionName: name, params, recommendationId: 'REC-G', tokenId: t.id, requestedBy: 'agent', now: NOW, ...extra }, [t])
  const bare = await engine.guard({ actionName: name, params, recommendationId: 'REC-G', requestedBy: 'agent', now: NOW, ...extra }, [])
  return { g, bare, a: engine.attemptDecision({ actionName: name, params, ...extra }) }
}
const scenarios = [
  ['block_ip', 'passing', {}], ['block_ip', 'over the maximum', { params: { duration_min: 1441 } }], ['block_ip', 'risk below', { riskScore: 69 }], ['block_ip', 'confidence below', { confidence: 0.79 }],
  ['block_ip', 'internal IP', { params: { ip: '10.0.1.15', duration_min: 30 } }], ['block_ip', 'allow-listed IP', { params: { ip: '192.0.2.10', duration_min: 30 } }],
  ['isolate_host', 'passing', {}], ['isolate_host', 'over the maximum', { params: { duration_min: 241 } }], ['isolate_host', 'risk below', { riskScore: 84 }], ['isolate_host', 'confidence below', { confidence: 0.84 }], ['isolate_host', 'Critical asset', { assetClass: 'Critical' }],
  ['suspend_user_session', 'passing', {}], ['suspend_user_session', 'over the maximum', { params: { duration_min: 61 } }], ['suspend_user_session', 'risk below', { riskScore: 74 }], ['suspend_user_session', 'confidence below', { confidence: 0.79 }], ['suspend_user_session', 'privileged account', { privilegedAccount: true }],
]
for (const [name, label, change] of scenarios) {
  await check('attempt vs guard', `${name}, ${label}: the guard (with a valid token) and the attempt give the same code and reason; only a missing token differs`, async () => {
    const { g, bare, a } = await guardVsAttempt(name, change)
    if (a.decision === 'refused') {
      return !g.allowed && g.code === a.code && g.reason === a.reason && !bare.allowed && bare.code === 'no_token' || { pass: false, detail: `guard ${g.code} "${g.reason}" / attempt ${a.code} "${a.reason}" / bare ${bare.code}` }
    }
    return g.allowed && a.decision === 'needs_approval' && bare.code === 'no_token' || { pass: false, detail: `guard ${g.code} / attempt ${a.code} / bare ${bare.code}` }
  })
}
await check('attempt vs guard', 'Tier 1, Tier 3 and unknown names: the guard and the attempt give the same code and reason', async () => {
  const names = [...catalogue.filter((r) => r.tier !== 2).map((r) => r.key), 'format_disk']
  const bad = []
  for (const name of names) {
    const g = await engine.guard({ actionName: name, params: {}, now: NOW }, [])
    const a = attempt(name)
    if (g.code !== a.code || g.reason !== a.reason) bad.push(`${name}: ${g.code}/${a.code}`)
  }
  return bad.length === 0 || { pass: false, detail: bad.join('; ') }
})
await check('attempt', 'an attempt changes nothing: the request is untouched, the result is the same twice, and it never reads the real clock', () => {
  const requestObject = { actionName: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 }, riskScore: 82, confidence: 0.88, assetClass: 'Business' }
  const before = JSON.stringify(requestObject)
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    const one = engine.attemptDecision(requestObject)
    const two = engine.attemptDecision(requestObject)
    return JSON.stringify(one) === JSON.stringify(two) && JSON.stringify(requestObject) === before && one.executed === false
  } finally {
    Date.now = real
  }
})
await check('attempt', 'attemptDecision takes no token list and no clock, so it cannot touch a token or the demo time (its signature is one request)', () =>
  engine.attemptDecision.length === 1)

// ---------- C5b: simulateAttempt (the flow's Demo event for an attempt) ----------
const strip = (s) => JSON.stringify({ ...s, events: undefined })
await check('attempt flow', 'an allowed or needs-approval attempt adds exactly one Demo event "Simulated an attempt" and changes nothing else (requests, tokens, runs, clock, failure flag)', async () => {
  const s = await flowSeed()
  const a = flow.simulateAttempt(s, { actionName: 'get_logs', params: {} }, lead)
  const b = flow.simulateAttempt(s, { actionName: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 }, riskScore: 90, confidence: 0.9 }, lead)
  const ev = (r) => r.state.events.slice(s.events.length)
  return [a, b].every((r) => ev(r).length === 1 && ev(r)[0].action === 'Simulated an attempt' && ev(r)[0].demo === true && ev(r)[0].result === undefined && strip(r.state) === strip(s) && r.decision.executed === false) &&
    a.decision.decision === 'allowed' && b.decision.decision === 'needs_approval' && ev(b)[0].changes[0] === 'Attempt: block_ip → Needs approval' || { pass: false, detail: JSON.stringify([ev(a), ev(b)]) }
})
await check('attempt flow', 'a refused attempt adds two Demo events: "Simulated an attempt" (Success) then "Policy violation blocked" (Denied, by AthenaSec AI), both carrying the rule, the code and "Executed: No"; still nothing else changes', async () => {
  const s = await flowSeed()
  const r = flow.simulateAttempt(s, { actionName: 'delete_logs', params: { target: 'audit' } }, analystA)
  const [one, two] = r.state.events.slice(s.events.length)
  return r.state.events.length === s.events.length + 2 && one.action === 'Simulated an attempt' && one.changes[0] === 'Attempt: delete_logs → Refused' && two.action === 'Policy violation blocked' && two.result === 'Denied' && two.user === 'AthenaSec AI' && two.role === 'System' && two.demo === true &&
    two.changes[0] === 'delete_logs: Requested → Blocked' && [one, two].every((e) => e.metadata.Executed === 'No' && e.metadata.Code === 'prohibited' && /^Tier 3 · Deleting or modifying logs, alerts, cases or evidence · PDF p\.5$/.test(e.metadata.Rule)) && strip(r.state) === strip(s) || { pass: false, detail: JSON.stringify([one, two]) }
})
await check('attempt flow', 'an attempt is stamped with the demo clock and never reads the real one (Date.now throws while it runs); the event is attributed to whoever is signed in (analyst or lead)', async () => {
  const s = await flowSeed('2026-08-03T16:20:00')
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    const a = flow.simulateAttempt(s, { actionName: 'format_disk', params: {} }, analystA)
    const l = flow.simulateAttempt(s, { actionName: 'format_disk', params: {} }, lead)
    const [first] = a.state.events.slice(s.events.length)
    const [second] = l.state.events.slice(s.events.length)
    return first.at === '2026-08-03T16:20:00' && first.user === 'Analyst A' && first.role === 'Analyst' && second.user === 'System Administrator' && second.role === 'Administrator' || { pass: false, detail: JSON.stringify([first, second]) }
  } finally {
    Date.now = real
  }
})

// (C5b's "turning a policy off is never blocked by the floor" was here; see "R3a changes".)

// ---------- C6a: audit ids, event types, the demo-clock stamp ----------
const seedLogs = audit.auditLogs
const numOf = (log) => Number(log.id.replace('AUD-', ''))
const seedAsc = [...seedLogs].sort((a, b) => numOf(a) - numOf(b))

await check('audit ids', 'the seed holds AUD-196 to AUD-206 once each, listed newest first (id order is the list order)', () =>
  seedLogs.map((l) => l.id).join() === ['AUD-206', 'AUD-205', 'AUD-204', 'AUD-203', 'AUD-202', 'AUD-201', 'AUD-200', 'AUD-199', 'AUD-198', 'AUD-197', 'AUD-196'].join() || { pass: false, detail: seedLogs.map((l) => l.id).join() })
await check('audit ids', 'ids are strictly increasing in time order: every later id has a strictly later timestamp (and the list, newest first, is in time order too)', () => {
  const bad = []
  for (let i = 1; i < seedAsc.length; i += 1) if (!(seedAsc[i].timestamp > seedAsc[i - 1].timestamp)) bad.push(`${seedAsc[i - 1].id} ${seedAsc[i - 1].timestamp} / ${seedAsc[i].id} ${seedAsc[i].timestamp}`)
  const byTimeDesc = [...seedLogs].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1)).map((l) => l.id).join()
  return bad.length === 0 && byTimeDesc === seedLogs.map((l) => l.id).join() || { pass: false, detail: bad.join('; ') || byTimeDesc }
})
await check('audit ids', 'the renumbering: AUD-200 the OpenSearch check SVC-002 (was an integration sync before Integrations was removed), AUD-201 USR-003, AUD-202 took ownership of ALT-001, AUD-203 the response policy (version 2), AUD-204 the saved configuration (was RULE-001 before Detection Rules was removed), AUD-205 the host isolation, AUD-206 the response policy (version 3)', () => {
  const targets = Object.fromEntries(seedLogs.map((l) => [l.id, l.target.split(' ')[0]]))
  const got = ['AUD-200', 'AUD-201', 'AUD-202', 'AUD-203', 'AUD-204', 'AUD-205', 'AUD-206'].map((id) => targets[id]).join()
  return got === 'SVC-002,USR-003,ALT-001,Response,Workspace,endpoint-12,Response' || { pass: false, detail: got }
})
await check('audit ids', 'every AUD id mentioned anywhere under src/ (approvals, policies, notifications, search, cases, pages, comments) exists in the audit data, and none is a session id (AUD-207 and up)', () => {
  const known = new Set(seedLogs.map((l) => l.id))
  const hits = []
  for (const entry of readdirSync(join(root, 'src'), { recursive: true })) {
    const file = `src/${String(entry).replaceAll('\\', '/')}`
    if (!/\.(ts|tsx)$/.test(file)) continue
    const text = readFileSync(join(root, file), 'utf8')
    for (const m of text.matchAll(/(?<![A-Z]-)\bAUD-\d+\b/g)) if (!known.has(m[0])) hits.push(`${file}: ${m[0]}`)
  }
  return hits.length === 0 || { pass: false, detail: hits.join('; ') }
})
await check('audit ids', 'the data the app holds at start names only existing AUD ids: the seed approvals, the response policy, the fixed notifications', () => {
  const known = new Set(seedLogs.map((l) => l.id))
  const text = JSON.stringify([seed.records, policies.initialResponsePolicy, notifications.notifications])
  const unknown = [...text.matchAll(/(?<![A-Z]-)\bAUD-\d+\b/g)].map((m) => m[0]).filter((id) => !known.has(id))
  return unknown.length === 0 || { pass: false, detail: unknown.join() }
})
await check('audit ids', 'the session counter starts after the seed (the first session event is AUD-207) and rises by one', () => {
  const first = audit.takeAuditId()
  const second = audit.takeAuditId()
  return first === 'AUD-207' && second === 'AUD-208' && numOf({ id: first }) > Math.max(...seedLogs.map(numOf)) || { pass: false, detail: `${first} ${second}` }
})
await check('audit ids', 'a session event is stamped from the demo clock: auditTimestamp(DEMO_NOW) is "2026-08-03 15:46:00", later than every seed event, and a later demo time gives a later stamp', () => {
  const stamp = audit.auditTimestamp(data.DEMO_NOW)
  const lastSeed = [...seedLogs].map((l) => l.timestamp).sort().pop()
  return stamp === '2026-08-03 15:46:00' && stamp > lastSeed && audit.auditTimestamp('2026-08-03T16:46:00') > stamp && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(stamp) || { pass: false, detail: `${stamp} / ${lastSeed}` }
})
await check('audit ids', 'auditTimestamp reads no clock: it gives the same answer with Date.now throwing, and takes its time as a required argument', () => {
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    return audit.auditTimestamp('2026-08-03T15:50:30') === '2026-08-03 15:50:30' && audit.auditTimestamp.length === 1
  } finally {
    Date.now = real
  }
})

await check('event types', 'the event types are the PDF\'s seven, in its order, each with a readable name', () =>
  eventTypes.AUDIT_EVENT_TYPES.join() === 'recommendation_created,decision_recorded,action_executed,action_failed,action_expired,approval_timed_out,policy_violation_blocked' && eventTypes.AUDIT_EVENT_TYPES.every((t) => eventTypes.AUDIT_EVENT_TYPE_NAMES[t].length > 3))

// A scripted flow that writes every kind of event, in one continuous state so the demo clock only moves forward
const scriptedEvents = async () => {
  let s = await flowSeed()
  const step = (r) => { if (!r.ok) throw new Error(`${r.code}: ${r.reason}`); s = r.state }
  step(flow.armFailure(s, analystA))
  step(await flow.decide(s, { approvalId: 'APR-002', actor: lead, kind: 'approve', reason: 'Confirmed.' }))
  step(await flow.beginExecution(s, 'APR-002'))
  step(flow.finishExecution(s, 'APR-002'))
  step(flow.requestAgain(s, 'EXE-002', analystA, true))
  step(await flow.decide(s, { approvalId: 'APR-003', actor: lead, kind: 'modify', reason: 'Shorter.', minutes: 20 }))
  step(await flow.beginExecution(s, 'APR-003'))
  step(flow.finishExecution(s, 'APR-003'))
  step(flow.advanceTime(s, 60, lead))
  step(flow.requestAgain(s, 'EXE-003', analystA, true))
  step(flow.advanceTime(s, 15, lead))
  step(flow.advanceTime(s, 5, lead))
  step(flow.requestAgain(s, 'EXE-003', analystA, true))
  step(await flow.decide(s, { approvalId: 'APR-005', actor: lead, kind: 'reject', reason: 'Not needed.' }))
  step(flow.advanceTime(s, 60, lead))
  step(flow.advanceTime(s, 60, lead))
  const allowed = flow.simulateAttempt(s, { actionName: 'get_logs', params: {} }, lead)
  const refused = flow.simulateAttempt(allowed.state, { actionName: 'delete_logs', params: { target: 'audit' }, riskScore: 99, confidence: 0.99 }, lead)
  s = refused.state
  // The isolation path, in its own state (a pending isolation asked for by the analyst)
  let t = await flowSeed()
  t = { ...t, approvals: [...t.approvals, pendingIsolation()] }
  const approvedIso = await flow.decide(t, { approvalId: 'APR-003', actor: lead, kind: 'approve', reason: 'Isolate.' })
  const begunIso = await flow.beginExecution(approvedIso.state, 'APR-003')
  const doneIso = flow.finishExecution(begunIso.state, 'APR-003')
  return { events: s.events, isolationEvents: doneIso.state.events, final: s }
}
const scripted = await scriptedEvents().catch((error) => ({ error: error.message }))

await check('event types', 'the scripted flow ran end to end (request, approve, fail, ask again, modify, execute, expire, time out, reject, simulate, refuse)', () => !scripted.error || { pass: false, detail: scripted.error })
const allFlowEvents = scripted.error ? [] : [...scripted.events, ...scripted.isolationEvents]

await check('event types', 'every action the flow writes is in the mapping and carries exactly the type the mapping gives (none for the supporting events), and every mapped action was written', () => {
  const table = eventTypes.FLOW_ACTION_EVENT_TYPE
  const written = new Set(allFlowEvents.map((e) => e.action))
  const unmapped = [...written].filter((a) => !(a in table))
  const wrongType = allFlowEvents.filter((e) => (table[e.action] ?? undefined) !== e.eventType).map((e) => `${e.action}:${e.eventType}`)
  const neverWritten = Object.keys(table).filter((a) => !written.has(a))
  return unmapped.length === 0 && wrongType.length === 0 && neverWritten.length === 0 || { pass: false, detail: JSON.stringify({ unmapped, wrongType, neverWritten }) }
})
await check('event types', 'the mapping: Requested approval is recommendation_created; Approved action, Modified approval and Rejected action are decision_recorded; Executed block and Executed host isolation are action_executed; Execution failed, Action expired, Approval timed out and Policy violation blocked have their own types; token use, Demo time, an armed failure and a simulated attempt have none', () => {
  const t = eventTypes.FLOW_ACTION_EVENT_TYPE
  return t['Requested approval'] === 'recommendation_created' && ['Approved action', 'Modified approval', 'Rejected action'].every((a) => t[a] === 'decision_recorded') && ['Executed block', 'Executed host isolation'].every((a) => t[a] === 'action_executed') &&
    t['Execution failed'] === 'action_failed' && t['Action expired'] === 'action_expired' && t['Approval timed out'] === 'approval_timed_out' && t['Policy violation blocked'] === 'policy_violation_blocked' &&
    ['Used approval token', 'Advanced demo time', 'Armed a failed execution', 'Simulated an attempt'].every((a) => t[a] === null) || { pass: false, detail: JSON.stringify(t) }
})
const byAction = (action) => allFlowEvents.filter((e) => e.action === action)
await check('event types', 'record fields follow the event: a rejection is decision rejected with its reason and not_executed; an approval approved with its reason; a modified approval approved_with_changes with the shorter params; a timeout timed_out and not_executed', () => {
  const [rej] = byAction('Rejected action'), [app] = byAction('Approved action'), [mod] = byAction('Modified approval'), [out] = byAction('Approval timed out')
  return rej.record.decision === 'rejected' && rej.record.decision_reason === 'Not needed.' && rej.record.execution_result === 'not_executed' && rej.record.actor === 'USR-001' && rej.record.actor_role === 'soc_lead' &&
    app.record.decision === 'approved' && app.record.decision_reason === 'Confirmed.' && mod.record.decision === 'approved_with_changes' && mod.record.params.duration_min === 20 &&
    out.record.decision === 'timed_out' && out.record.execution_result === 'not_executed' && out.record.actor === 'agent' && out.record.actor_role === 'agent' || { pass: false, detail: JSON.stringify([rej.record, app.record, mod.record, out.record]) }
})
await check('event types', 'record fields follow the event: execution success with expires_at, failure with failed, an expiry with the expiry time, a request with its asker; all carry recommendation, alert and policy ids, tier 2, risk and confidence', () => {
  const [exe] = byAction('Executed block'), [iso] = byAction('Executed host isolation'), [fail] = byAction('Execution failed'), [exp] = byAction('Action expired'), [req] = byAction('Requested approval')
  const all = [exe, iso, fail, exp, req, ...byAction('Approved action'), ...byAction('Rejected action')]
  return exe.record.execution_result === 'success' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(exe.record.expires_at) && iso.record.params.host === 'endpoint-12' && fail.record.execution_result === 'failed' && !fail.record.expires_at &&
    typeof exp.record.expires_at === 'string' && req.record.actor === 'USR-002' && req.record.actor_role === 'soc_analyst' && req.record.decision === undefined &&
    all.every((e) => e.record.recommendation_id && e.record.alert_id && e.record.policy_id && e.record.tier === 2 && typeof e.record.risk_score === 'number' && typeof e.record.confidence === 'number' && e.record.evidence.length > 0) || { pass: false, detail: JSON.stringify([exe.record, fail.record, exp.record, req.record]) }
})
await check('event types', 'a refused attempt\'s record: actor agent, the tier of the action (3 for delete_logs), its params, risk and confidence, not_executed; an allowed attempt has no type and no record', () => {
  const [v] = byAction('Policy violation blocked'), [sim] = byAction('Simulated an attempt')
  return v.record.actor === 'agent' && v.record.tier === 3 && v.record.action === 'delete_logs' && v.record.params.target === 'audit' && v.record.risk_score === 99 && v.record.execution_result === 'not_executed' && sim.eventType === undefined && sim.record === undefined || { pass: false, detail: JSON.stringify([v.record, sim]) }
})
await check('event types', 'the seeded isolation (AUD-205) is action_executed with its record matching the seed request and run: REC-001, ALT-006, response-policy-v2, endpoint-12, expires at the seed run\'s expiry; no other seed event has a type', () => {
  const e = seedLogs.find((l) => l.id === 'AUD-205')
  const fact = approvals.seedExecutionFacts.find((f) => f.id === 'EXE-001')
  const rec1 = seed.records[0].recommendation
  return e.eventType === 'action_executed' && e.record.recommendation_id === rec1.id && e.record.alert_id === rec1.alertId && e.record.policy_id === 'response-policy-v2' && e.record.params.host === 'endpoint-12' && e.record.expires_at === fact.expiresAt && e.record.execution_result === 'success' &&
    seedLogs.filter((l) => l.id !== 'AUD-205').every((l) => l.eventType === undefined && l.record === undefined) || { pass: false, detail: JSON.stringify([e.record, fact?.expiresAt]) }
})
await check('event types', 'the flow\'s demo-clock times only move forward: the events\' times never go back in the order they were written, and every one is later than the seed\'s last event once stamped', () => {
  const stamps = scripted.final.events.map((e) => e.at)
  const sorted = [...stamps].sort()
  const lastSeed = [...seedLogs].map((l) => l.timestamp).sort().pop()
  return stamps.join() === sorted.join() && stamps.every((at) => audit.auditTimestamp(at) > lastSeed) || { pass: false, detail: stamps.join() }
})

// ---------- C6a: the audit hash chain ----------
const asRecord = (e, n) => ({
  id: `AUD-${207 + n}`, timestamp: audit.auditTimestamp(e.at), user: e.user, role: e.role, category: 'Incident Response', action: e.action, target: e.target,
  result: e.result ?? 'Success', sourceIp: e.sourceIp, description: e.description, changes: e.changes, metadata: e.metadata,
  ...(e.demo ? { demo: true } : {}), ...(e.eventType ? { eventType: e.eventType } : {}), ...(e.record ? { record: e.record } : {}),
})
const sessionRecords = scripted.error ? [] : scripted.events.map(asRecord)
const everyLog = [...seedLogs, ...[...sessionRecords].reverse()]
const linksOf = async (logs) => chainModule.extendLinks({}, logs)
const seedLinks = await linksOf(seedLogs)
const allLinks = await linksOf(everyLog)

await check('chain', 'the seed chain verifies: 11 records, each hashed onto the one before it, the first onto the genesis hash of 64 zeros', async () => {
  const v = await chainModule.verifyAuditLogs(seedLinks, seedLogs)
  return v.status === 'intact' && v.count === 11 && seedLinks['AUD-196'].prev_hash === '0'.repeat(64) && seedAsc.every((l, i) => i === 0 || seedLinks[l.id].prev_hash === seedLinks[seedAsc[i - 1].id].hash) || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'the chain with a whole scripted session on top of the seed verifies (every event type, Demo events included)', async () => {
  const v = await chainModule.verifyAuditLogs(allLinks, everyLog)
  return v.status === 'intact' && v.count === everyLog.length && everyLog.length > 25 || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'every hash is 64 hex characters and every record has a different one', () => {
  const hashes = Object.values(allLinks).map((l) => l.hash)
  return hashes.every((h) => /^[0-9a-f]{64}$/.test(h)) && new Set(hashes).size === hashes.length
})
await check('chain', 'it is the same chain the engine builds: the hashes equal buildChain over the records\' content in id order', async () => {
  const ordered = [...everyLog].sort((a, b) => numOf(a) - numOf(b))
  const built = await engine.buildChain(ordered.map(chainModule.auditBody))
  return built.every((c, i) => c.hash === allLinks[ordered[i].id].hash && c.prev_hash === allLinks[ordered[i].id].prev_hash) || { pass: false, detail: 'differs' }
})
await check('chain', 'the order is the id order, not the array order: the same records in any order give the same chain', async () => {
  const shuffled = [...everyLog].sort((a, b) => (numOf(a) % 5) - (numOf(b) % 5) || numOf(b) - numOf(a))
  const again = await linksOf(shuffled)
  return JSON.stringify(Object.entries(again).sort()) === JSON.stringify(Object.entries(allLinks).sort())
})
await check('chain', 'a new record appended later keeps the chain intact and leaves every earlier hash as it was', async () => {
  const extra = { ...seedLogs[0], id: 'AUD-299', timestamp: '2026-08-03 16:00:00', description: 'later' }
  const links = await chainModule.extendLinks(seedLinks, [extra, ...seedLogs])
  const v = await chainModule.verifyAuditLogs(links, [extra, ...seedLogs])
  return v.status === 'intact' && v.count === 12 && seedAsc.every((l) => links[l.id].hash === seedLinks[l.id].hash) && links['AUD-299'].prev_hash === seedLinks['AUD-206'].hash || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'extendLinks returns the same links object when nothing is new', async () => (await chainModule.extendLinks(seedLinks, seedLogs)) === seedLinks)

// Altering any one field of any record breaks the chain at that record
const alterField = {
  id: (l) => ({ ...l, id: `AUD-1${numOf(l)}` }),
  timestamp: (l) => ({ ...l, timestamp: `${l.timestamp}1` }),
  user: (l) => ({ ...l, user: `${l.user}x` }),
  role: (l) => ({ ...l, role: l.role === 'Analyst' ? 'Administrator' : 'Analyst' }),
  category: (l) => ({ ...l, category: l.category === 'System' ? 'Integration' : 'System' }),
  action: (l) => ({ ...l, action: `${l.action}x` }),
  target: (l) => ({ ...l, target: `${l.target}x` }),
  result: (l) => ({ ...l, result: l.result === 'Success' ? 'Failed' : 'Success' }),
  sourceIp: (l) => ({ ...l, sourceIp: `${l.sourceIp}9` }),
  description: (l) => ({ ...l, description: `${l.description}x` }),
  changes: (l) => ({ ...l, changes: [...l.changes, 'extra'] }),
  metadata: (l) => ({ ...l, metadata: { ...l.metadata, Extra: 'x' } }),
  demo: (l) => ({ ...l, demo: l.demo ? undefined : true }),
  eventType: (l) => ({ ...l, eventType: l.eventType === 'action_failed' ? undefined : 'action_failed' }),
  record: (l) => ({ ...l, record: l.record ? { ...l.record, actor: `${l.record.actor}x` } : { actor: 'x', actor_role: 'agent' } }),
}
for (const [field, alter] of Object.entries(alterField)) {
  await check('chain', `altering "${field}" of any one record (all ${everyLog.length}) breaks the chain at exactly that record`, async () => {
    const bad = []
    for (const log of everyLog) {
      const changed = alter(log)
      const v = await chainModule.verifyAuditLogs(allLinks, everyLog.map((l) => (l === log ? changed : l)))
      const expected = field === 'id' ? changed.id : log.id
      if (v.status !== 'broken' || v.brokenId !== expected) bad.push(`${log.id}: ${JSON.stringify(v)}`)
    }
    return bad.length === 0 || { pass: false, detail: bad.slice(0, 3).join('; ') }
  })
}
await check('chain', 'deleting any one record breaks the chain and names it (the newest one too, which the hashes alone could not show)', async () => {
  const bad = []
  for (const log of everyLog) {
    const v = await chainModule.verifyAuditLogs(allLinks, everyLog.filter((l) => l !== log))
    if (v.status !== 'broken' || v.brokenId !== log.id) bad.push(`${log.id}: ${JSON.stringify(v)}`)
  }
  return bad.length === 0 || { pass: false, detail: bad.slice(0, 3).join('; ') }
})
await check('chain', 'a record slipped in without its hashes breaks the chain at that record', async () => {
  const sneaky = { ...seedLogs[3], id: 'AUD-250', description: 'inserted' }
  const v = await chainModule.verifyAuditLogs(allLinks, [sneaky, ...everyLog])
  return v.status === 'broken' && v.brokenId === 'AUD-250' || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'swapping two neighbouring records (their ids) breaks the chain at the first of them, for every neighbouring pair', async () => {
  const ordered = [...everyLog].sort((a, b) => numOf(a) - numOf(b))
  const bad = []
  for (let i = 0; i + 1 < ordered.length; i += 1) {
    const swapped = ordered.map((l, k) => (k === i ? { ...ordered[i + 1], id: ordered[i].id } : k === i + 1 ? { ...ordered[i], id: ordered[i + 1].id } : l))
    const v = await chainModule.verifyAuditLogs(allLinks, swapped)
    if (v.status !== 'broken' || v.brokenId !== ordered[i].id) bad.push(`${ordered[i].id}: ${JSON.stringify(v)}`)
  }
  return bad.length === 0 || { pass: false, detail: bad.slice(0, 3).join('; ') }
})
await check('chain', 'the Demo tamper (tamperLog) changes only a record\'s description, and the chain then fails at that record with every later record also unverifiable from it', async () => {
  const target = seedLogs[4]
  const altered = chainModule.tamperLog(target)
  const v = await chainModule.verifyAuditLogs(seedLinks, seedLogs.map((l) => (l === target ? altered : l)))
  const { description: _a, ...rest } = altered
  const { description: _b, ...orig } = target
  return v.status === 'broken' && v.brokenId === target.id && altered.description !== target.description && JSON.stringify(rest) === JSON.stringify(orig) || { pass: false, detail: JSON.stringify(v) }
})
await check('chain', 'building and verifying the chain never read the real clock (Date.now throws while they run)', async () => {
  const real = Date.now
  Date.now = () => { throw new Error('read the real clock') }
  try {
    const links = await chainModule.extendLinks({}, seedLogs)
    const v = await chainModule.verifyAuditLogs(links, seedLogs)
    return v.status === 'intact'
  } finally {
    Date.now = real
  }
})

// ---------- C6a: the violation notice ----------
const violationLogs = sessionRecords.filter((r) => r.eventType === 'policy_violation_blocked')
await check('notices', 'a Policy violation blocked event gives the Administrator one high-severity notice (Demo-labelled when simulated) that opens Audit Logs; the analyst gets none', () => {
  const adminItems = notifications.notificationsFor('Administrator', [], data.DEMO_NOW, '', sessionRecords).filter((n) => n.title === 'Policy violation blocked')
  const analystItems = notifications.notificationsFor('Analyst', [], data.DEMO_NOW, '', sessionRecords).filter((n) => n.title === 'Policy violation blocked')
  return violationLogs.length === 1 && adminItems.length === 1 && analystItems.length === 0 && adminItems[0].page === 'audit-logs' && adminItems[0].id === `NTF-${violationLogs[0].id}` &&
    /^Demo, high severity: delete_logs was refused and nothing ran\. Tier 3 · /.test(adminItems[0].detail) || { pass: false, detail: JSON.stringify([adminItems, violationLogs.length]) }
})
await check('notices', 'other events give no such notice, nothing is added without audit records, and the fixed notices are unchanged (2 for the Administrator, 2 for the analyst)', () => {
  const noViolation = sessionRecords.filter((r) => r.eventType !== 'policy_violation_blocked')
  const withOther = notifications.notificationsFor('Administrator', [], data.DEMO_NOW, '', noViolation)
  const none = notifications.notificationsFor('Administrator')
  const analyst = notifications.notificationsFor('Analyst')
  return withOther.length === none.length && none.length === 2 && analyst.length === 2 && new Set(notifications.notificationsFor('Administrator', [], data.DEMO_NOW, '', [...sessionRecords, ...sessionRecords.map((r) => ({ ...r, id: `${r.id}b` }))]).map((n) => n.id)).size === 4 || { pass: false, detail: `${withOther.length} ${none.length} ${analyst.length}` }
})

// ---------- C6b: the tamper control's events, and Restore re-verifying the hashes ----------
const stampOf = '2026-08-03 15:46:00'
const asSession = (kind, targetId, id) => ({ id, timestamp: stampOf, user: 'System Administrator', role: 'Administrator', result: 'Success', sourceIp: '10.0.1.10', ...demoEvents.demoAuditEvent(kind, targetId) })

await check('tamper', 'the Alter and Restore events are Demo events with no PDF event type, in the System category, naming the record and the change (Original → Altered, Altered → Original)', () => {
  const a = demoEvents.demoAuditEvent('tamper', 'AUD-200')
  const r = demoEvents.demoAuditEvent('restore', 'AUD-200')
  return a.demo === true && r.demo === true && a.eventType === undefined && r.eventType === undefined && a.record === undefined && a.category === 'System' && r.category === 'System' &&
    a.action === 'Tampered with a record' && r.action === 'Restored a record' && a.target === 'AUD-200' && a.changes.join() === 'AUD-200: Original → Altered' && r.changes.join() === 'AUD-200: Altered → Original' || { pass: false, detail: JSON.stringify([a, r]) }
})
await check('tamper', 'the whole cycle on real hashes: Alter breaks the chain at that record; Restore, which only puts the content back, makes verifyChain pass again after the hashes are recomputed from the restored data; both Demo events stay in the trail and in the chain', async () => {
  const target = seedLogs.find((l) => l.id === 'AUD-200')
  const alterEvent = asSession('tamper', 'AUD-200', 'AUD-207')
  const restoreEvent = asSession('restore', 'AUD-200', 'AUD-208')
  // Alter: the event is recorded (hashed) first, then the stored content changes
  const logsAfterAlterEvent = [alterEvent, ...seedLogs]
  const linksA = await chainModule.extendLinks(seedLinks, logsAfterAlterEvent)
  const altered = logsAfterAlterEvent.map((l) => (l.id === target.id ? chainModule.tamperLog(l) : l))
  const broken = await chainModule.verifyAuditLogs(linksA, altered)
  // Restore: the Demo event is recorded, the content goes back, and the chain is checked again from scratch
  const logsAfterRestore = [restoreEvent, ...logsAfterAlterEvent]
  const linksR = await chainModule.extendLinks(linksA, logsAfterRestore)
  const stillBroken = await chainModule.verifyAuditLogs(linksR, [restoreEvent, ...altered])
  const restored = await chainModule.verifyAuditLogs(linksR, logsAfterRestore)
  const recomputed = await engine.verifyChain(await engine.buildChain([...logsAfterRestore].sort((a, b) => numOf(a) - numOf(b)).map(chainModule.auditBody)))
  const ids = logsAfterRestore.map((l) => l.id)
  return broken.status === 'broken' && broken.brokenId === 'AUD-200' && stillBroken.status === 'broken' && stillBroken.brokenId === 'AUD-200' &&
    restored.status === 'intact' && restored.count === 13 && recomputed.ok === true && ids.includes('AUD-207') && ids.includes('AUD-208') &&
    logsAfterRestore.filter((l) => l.demo).map((l) => l.action).join() === 'Restored a record,Tampered with a record' &&
    Object.keys(seedLinks).every((id) => linksR[id].hash === seedLinks[id].hash) || { pass: false, detail: JSON.stringify({ broken, stillBroken, restored, recomputed }) }
})
await check('tamper', 'Restore is not a flag being cleared: with the hashes recorded for the record changed instead of its content, putting the content back does not make the chain pass', async () => {
  const forged = { ...seedLinks, 'AUD-200': { ...seedLinks['AUD-200'], hash: '0'.repeat(64) } }
  const v = await chainModule.verifyAuditLogs(forged, seedLogs)
  return v.status === 'broken' && v.brokenId === 'AUD-200' || { pass: false, detail: JSON.stringify(v) }
})
await check('tamper', 'every record has recorded hashes once extendLinks has run over the shown records (the screen reads them for the record panel), and each previous hash is the older record\'s hash', async () => {
  const links = await chainModule.extendLinks({}, everyLog)
  const ordered = [...everyLog].sort((a, b) => numOf(a) - numOf(b))
  return ordered.every((l, i) => links[l.id] && (i === 0 ? links[l.id].prev_hash === '0'.repeat(64) : links[l.id].prev_hash === links[ordered[i - 1].id].hash)) || { pass: false, detail: 'a link is missing or does not follow' }
})
await check('notices', 'a violation notice carries its audit event id so the bell can open Audit Logs on it; no other notice carries one', () => {
  const items = notifications.notificationsFor('Administrator', [], data.DEMO_NOW, '', sessionRecords)
  const withLight = items.filter((n) => n.highlight)
  return withLight.length === 1 && withLight[0].highlight === violationLogs[0].id && withLight[0].page === 'audit-logs' || { pass: false, detail: JSON.stringify(items.map((n) => [n.id, n.highlight])) }
})

// ---------- R1a: Detection Rules is gone; the dashboard's ATT&CK activity replaces rule coverage ----------
const seedAssessments = assessmentData.assessAlerts(policies.initialResponsePolicy)
const activity = (alerts = alertData.initialAlerts, runs = incident.executionRecords, approvalsNow = seed.records, assessments = seedAssessments) => summary.attackActivity(alerts, runs, approvalsNow, assessments)
const cellOf = (columns, id) => columns.flatMap((c) => c.cells).find((c) => c.id === id)

await check('R1a', 'no source file refers to Detection Rules any more: no import of its page, data or types, no "detection-rules" route, slug or link, no "Detection Rule" audit category', () => {
  const hits = []
  for (const entry of readdirSync(join(root, 'src'), { recursive: true })) {
    const file = `src/${String(entry).replaceAll('\\', '/')}`
    if (!/\.(ts|tsx)$/.test(file)) continue
    const text = readFileSync(join(root, file), 'utf8')
    for (const pattern of [/detectionRules(Data|Types)/, /DetectionRulesPage/, /detection-rules/, /'Detection Rule'/, /\bDetectionRule\b/]) {
      if (pattern.test(text)) hits.push(`${file}: ${pattern.source}`)
    }
  }
  return hits.length === 0 || { pass: false, detail: hits.join('; ') }
})
await check('R1a', 'the audit data has no rule or integration events: no seed event is in a Detection Rule or Integration category or targets a RULE- or INT- id, and the categories are the five that remain', () =>
  seedLogs.every((l) => l.category !== 'Detection Rule' && l.category !== 'Integration' && !/RULE-|INT-/.test(l.target)) && audit.AUDIT_CATEGORIES.join() === 'Authentication,Response Policy,User Management,Incident Response,System' || { pass: false, detail: audit.AUDIT_CATEGORIES.join() })
await check('R1a', 'ATT&CK activity from the seed: T1110 waiting (ALT-001 awaits approval, ALT-005 closed), T1548 and T1110.003 open, T1068 and T1071 handled, T1133, T1046 and T1021 quiet', () => {
  const cols = activity()
  const got = ['T1133', 'T1068', 'T1548', 'T1110', 'T1110.003', 'T1046', 'T1021', 'T1071'].map((id) => `${id}:${cellOf(cols, id).state}:${cellOf(cols, id).alerts.length}`).join()
  return got === 'T1133:quiet:0,T1068:handled:1,T1548:open:1,T1110:waiting:2,T1110.003:open:1,T1046:quiet:0,T1021:quiet:0,T1071:handled:1' || { pass: false, detail: got }
})
await check('R1a', 'each activity alert carries the live facts: its risk and outcome from the agent\'s assessment, where it stands, and the waiting request (APR-002 for ALT-001, none for the others)', () => {
  const t1110 = cellOf(activity(), 'T1110').alerts
  const a1 = t1110.find((a) => a.id === 'ALT-001')
  const a5 = t1110.find((a) => a.id === 'ALT-005')
  return a1.risk === 77 && a1.outcome === 'Recommend IP block' && a1.response === 'Awaiting approval' && a1.approvalId === 'APR-002' && a1.title === 'Brute Force SSH' &&
    a5.risk === 34 && a5.outcome === 'Monitor' && a5.response === 'Closed' && a5.approvalId === undefined || { pass: false, detail: JSON.stringify([a1, a5]) }
})
await check('R1a', 'a technique shows its worst alert: a failed containment outranks a waiting request, which outranks open, which outranks handled; a request decided or timed out no longer counts as waiting', () => {
  const failedRuns = incident.executionRecords.map((r) => (r.triggeringAlert === 'ALT-006' ? { ...r, result: 'Failed' } : r))
  const failed = cellOf(activity(undefined, failedRuns), 'T1071')
  const decided = seed.records.map((r) => ({ ...r, decision: 'Timed out' }))
  const noLongerWaiting = cellOf(activity(undefined, undefined, decided), 'T1110')
  const bothWorst = cellOf(activity([{ ...alertData.initialAlerts[0], mitre: 'T1068 - x' }, ...alertData.initialAlerts.filter((a) => a.id === 'ALT-004')]), 'T1068')
  return failed.state === 'failed' && noLongerWaiting.state === 'open' && bothWorst.state === 'waiting' || { pass: false, detail: `${failed.state} ${noLongerWaiting.state} ${bothWorst.state}` }
})
await check('R1a', 'the grid lists 11 tactics with Command and control added (for T1071, ALT-006\'s technique), and every technique an alert uses is a tracked one', () => {
  const cols = activity()
  const tracked = new Set(cols.flatMap((c) => c.cells).map((c) => c.id))
  return cols.length === 11 && cols[9].tactic === 'Command and control' && cols[9].cells.map((c) => c.id).join() === 'T1071' && alertData.initialAlerts.every((a) => tracked.has(a.mitre.split(/\s+/)[0])) || { pass: false, detail: cols.map((c) => c.tactic).join() }
})
await check('R1a', 'the activity needs no rule data: attackActivity takes only alerts, runs, requests and assessments, and the admin task list no longer names a rule or a missing policy', () => {
  const tasks = summary.needsAdministrator({ integrations: [], users: [], services: [] })
  return summary.attackActivity.length === 4 && tasks.length === 0 && !('mitreCoverage' in summary) && !('coverageDetail' in summary)
})

// ---------- R1b: Integrations is gone; services replace it on the dashboard and the login panel ----------
await check('R1b', 'no source file refers to Integrations any more: no import of its page, pipeline, data or types, no "integrations" route, slug, link or icon, no stylesheet for it, no IntegrationRecord type', () => {
  const hits = []
  for (const entry of readdirSync(join(root, 'src'), { recursive: true })) {
    const file = `src/${String(entry).replaceAll('\\', '/')}`
    if (!/\.(ts|tsx|css)$/.test(file)) continue
    const text = readFileSync(join(root, file), 'utf8')
    for (const pattern of [/integrations(Data|Types)/, /IntegrationsPage/, /IntegrationPipeline/, /'integrations'/, /\/integrations\b/, /integrations-table-fix/, /\bIntegrationRecord\b/, /\bPipelineHealth\b/]) {
      if (pattern.test(text)) hits.push(`${file}: ${pattern.source}`)
    }
  }
  return hits.length === 0 || { pass: false, detail: hits.join('; ') }
})
await check('R1b', 'the dashboard\'s first posture item is Services healthy, counted from the services (8 of 10 in the seed, "Ollama Runtime and Wazuh Dashboard need attention", warn), and the strip has four items: services, policies, MFA, audit', () => {
  const posture = summary.adminPosture({ responsePolicy: policies.initialResponsePolicy, users: userData.initialUsers, services: healthData.initialServices, configuration: configData.initialConfiguration })
  const first = posture[0]
  return posture.length === 4 && first.page === 'service-panel' && first.view === 'health' && first.value === '8' && first.total === '/10' && first.label === 'Services healthy' && first.note === 'Ollama Runtime and Wazuh Dashboard need attention' && first.tone === 'warn' || { pass: false, detail: JSON.stringify(first) }
})
await check('R1b', 'the posture follows the services: all running reads 10 of 10, "All healthy" and no tone; one stopped reads danger and names it', () => {
  const running = healthData.initialServices.map((s) => ({ ...s, status: 'Running', latency: s.latency === null ? null : 100 }))
  const stopped = running.map((s, i) => (i === 0 ? { ...s, status: 'Stopped' } : s))
  const args = (services) => ({ responsePolicy: policies.initialResponsePolicy, users: userData.initialUsers, services, configuration: configData.initialConfiguration })
  const a = summary.adminPosture(args(running))[0]
  const b = summary.adminPosture(args(stopped))[0]
  return a.value === '10' && a.note === 'All healthy' && a.tone === undefined && b.value === '9' && b.tone === 'danger' && b.note === `${healthData.initialServices[0].name} stopped` || { pass: false, detail: JSON.stringify([a, b]) }
})
await check('R1b', 'the admin task list names only people and services now (MFA, latency and a service still starting in the seed); a disconnected integration is no longer a thing', () => {
  const tasks = summary.needsAdministrator({ users: userData.initialUsers, services: healthData.initialServices })
  return tasks.map((t) => t.id).join() === 'user-USR-004,service-SVC-005,service-SVC-009' && tasks[2].text === 'Wazuh Dashboard is still starting.' || { pass: false, detail: tasks.map((t) => t.id).join() }
})
await check('R1b', 'the login panel counts the monitored services (10) instead of connected tools: "services monitored in one console"', () => {
  const stat = loginData.LOGIN_STATS[2]
  return stat.value === String(healthData.initialServices.length) && stat.value === '10' && stat.label === 'services monitored in one console' || { pass: false, detail: JSON.stringify(stat) }
})

// ---------- R2a: one service inventory, one vocabulary ----------
const SEED = healthData.initialServices
const withStatus = (id, status, latency) => SEED.map((s) => (s.id === id ? { ...s, status, ...(latency === undefined ? {} : { latency }) } : s))
const everyRunning = SEED.map((s) => ({ ...s, status: 'Running', latency: s.latency === null ? null : 100 }))

await check('R2a', 'the inventory has 10 services in two groups, none listed twice (by id or by name): 4 in the pipeline, 6 on the VM', () => {
  const ids = SEED.map((s) => s.id)
  const names = SEED.map((s) => s.name)
  const pipeline = SEED.filter((s) => s.group === 'pipeline').map((s) => s.name).join()
  const vm = SEED.filter((s) => s.group === 'vm').map((s) => s.name).join()
  return SEED.length === 10 && new Set(ids).size === 10 && new Set(names).size === 10 && pipeline === 'OpenSearch,Suricata Sensor,LangGraph Workflow,Ollama Runtime' && vm === 'Wazuh Manager,Wazuh Indexer,Wazuh Dashboard,MISP,Cortex,Docker Engine' || { pass: false, detail: `${ids.join()} | ${pipeline} | ${vm}` }
})
await check('R2a', 'only the six words are used: Running, Starting, Degraded, Failed, Stopped, Unverified (no Online, Offline, Unhealthy or Unknown anywhere in the inventory)', () => {
  const words = new Set(SEED.map((s) => inventory.serviceStatus(s)))
  const allowed = ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified']
  return [...words].every((w) => allowed.includes(w)) || { pass: false, detail: [...words].join() }
})
await check('R2a', 'healthy means Running and, with a response time, at or under 400 ms: 8 of 10 in the seed, with Ollama Runtime (486 ms) and Wazuh Dashboard (Starting) needing attention', () => {
  const healthy = SEED.filter(inventory.isHealthy).length
  const attention = inventory.attentionServices(SEED).map((s) => `${s.name}:${inventory.serviceStatus(s)}`).join()
  return healthy === 8 && attention === 'Ollama Runtime:Degraded,Wazuh Dashboard:Starting' || { pass: false, detail: `${healthy} ${attention}` }
})
await check('R2a', 'a Running service slower than 400 ms reads Degraded whatever was stored; exactly 400 ms is healthy; 401 ms is not', () => {
  const at = (latency) => inventory.serviceStatus({ ...SEED[0], status: 'Running', latency })
  return at(400) === 'Running' && at(401) === 'Degraded' && inventory.isHealthy({ ...SEED[0], status: 'Running', latency: 400 }) && !inventory.isHealthy({ ...SEED[0], status: 'Running', latency: 401 }) || { pass: false, detail: `${at(400)} ${at(401)}` }
})
await check('R2a', 'a Failed service is never Degraded: a failed VM service reads Failed, needs attention, and outranks a Degraded one', () => {
  const failed = withStatus('SVC-006', 'Failed')
  const word = inventory.serviceStatus(failed.find((s) => s.id === 'SVC-006'))
  const order = inventory.attentionServices(failed).map((s) => `${s.name}:${inventory.serviceStatus(s)}`)
  return word === 'Failed' && order[0] === 'MISP:Failed' && order[1] === 'Ollama Runtime:Degraded' || { pass: false, detail: `${word} ${order.join()}` }
})
await check('R2a', 'the top bar text: none affected reads All Systems Operational; one reads "<name> <state>"; two or more read "N services need attention"; phones read "1 degraded" and "N need attention"', () => {
  const none = inventory.systemStatus(everyRunning)
  const one = inventory.systemStatus(withStatus('SVC-005', 'Degraded', 486).map((s) => (s.id === 'SVC-009' ? { ...s, status: 'Running' } : s)))
  const two = inventory.systemStatus(SEED)
  return none.text === 'All Systems Operational' && none.level === 'ok' && one.text === 'Ollama Runtime degraded' && one.short === '1 degraded' && two.text === '2 services need attention' && two.short === '2 need attention' || { pass: false, detail: JSON.stringify([none.text, one.text, one.short, two.text, two.short]) }
})
await check('R2a', 'the top bar level: warn for Degraded or Starting only, danger once anything is Stopped or Failed; Failed is named before Degraded', () => {
  const warn = inventory.systemStatus(SEED).level
  const stopped = inventory.systemStatus(withStatus('SVC-003', 'Stopped')).level
  const failed = inventory.systemStatus(withStatus('SVC-007', 'Failed'))
  return warn === 'warn' && stopped === 'danger' && failed.level === 'danger' && failed.affected[0] === 'Cortex' && failed.title === 'Service Outage' || { pass: false, detail: JSON.stringify([warn, stopped, failed]) }
})
await check('R2a', 'one affected service stopped reads "<name> stopped" and "1 stopped" on a phone (the word follows the state)', () => {
  const one = inventory.systemStatus(everyRunning.map((s) => (s.id === 'SVC-004' ? { ...s, status: 'Stopped' } : s)))
  return one.text === 'LangGraph Workflow stopped' && one.short === '1 stopped' || { pass: false, detail: JSON.stringify(one) }
})
await check('R2a', 'the sidebar badge is the number needing attention (2 in the seed, 0 when all run), and equals the dashboard\'s unhealthy count and the top bar\'s affected count', () => {
  const badge = inventory.servicesNeedingAttention(SEED)
  const posture = summary.adminPosture({ responsePolicy: policies.initialResponsePolicy, users: userData.initialUsers, services: SEED, configuration: configData.initialConfiguration })[0]
  return badge === 2 && inventory.servicesNeedingAttention(everyRunning) === 0 && Number(posture.total.slice(1)) - Number(posture.value) === badge && inventory.systemStatus(SEED).affected.length === badge || { pass: false, detail: `${badge} ${JSON.stringify(posture)}` }
})
await check('R2a', 'the health summary, the dashboard, the login stat and the gauge agree: "8 of 10 services healthy", 8/10, 10 monitored, 80% running', () => {
  const sentence = inventory.healthSummary(SEED)
  const posture = summary.adminPosture({ responsePolicy: policies.initialResponsePolicy, users: userData.initialUsers, services: SEED, configuration: configData.initialConfiguration })[0]
  const gauge = healthData.initialMetrics.find((m) => m.id === 'services')
  return sentence.startsWith('8 of 10 services healthy.') && sentence.includes('Ollama Runtime is responding slowly') && sentence.includes('Wazuh Dashboard is still starting') && posture.value === '8' && posture.total === '/10' && loginData.LOGIN_STATS[2].value === '10' && gauge.value === 80 || { pass: false, detail: sentence }
})
await check('R2a', 'per-group counts: 3 of 4 healthy in the pipeline, 5 of 6 on the VM', () => {
  const a = inventory.groupCount(SEED, 'pipeline')
  const b = inventory.groupCount(SEED, 'vm')
  return a.healthy === 3 && a.total === 4 && b.healthy === 5 && b.total === 6 || { pass: false, detail: JSON.stringify([a, b]) }
})
await check('R2a', 'a probe moves only the pipeline: a VM service comes back unchanged (the same object); a pipeline service gets a new latency and the matching word (over 600 ms Stopped, over 400 Degraded, else Running)', () => {
  const vm = SEED.find((s) => s.group === 'vm')
  const pipe = SEED.find((s) => s.id === 'SVC-002')
  const slow = inventory.probe({ ...pipe, latency: 590 }, 20)
  const mid = inventory.probe({ ...pipe, latency: 410 }, 20)
  const fast = inventory.probe({ ...pipe, latency: 100 }, 20)
  return inventory.probe(vm, 50) === vm && slow.status === 'Stopped' && mid.status === 'Degraded' && fast.status === 'Running' && fast.latency === 120 && fast.lastCheck === 'Just now' || { pass: false, detail: JSON.stringify([slow.status, mid.status, fast.status]) }
})
await check('R2a', 'checking every service changes only the pipeline records: the six VM records are untouched', () => {
  const after = SEED.map((s) => inventory.probe(s, 17))
  const vmSame = SEED.filter((s) => s.group === 'vm').every((s) => after.find((a) => a.id === s.id) === s)
  const pipelineMoved = SEED.filter((s) => s.group === 'pipeline').every((s) => after.find((a) => a.id === s.id) !== s)
  return vmSame && pipelineMoved
})
await check('R2a', 'the Service Panel\'s six checks are the VM records: same keys in the desktop panel\'s order, and the seed results equal them', () => {
  const checks = inventory.vmChecks(SEED)
  return checks.map((c) => c.key).join() === 'manager,indexer,dashboard,misp,cortex,docker' && JSON.stringify(checks) === JSON.stringify(panelData.initialServicePanel.results) || { pass: false, detail: JSON.stringify(checks) }
})
await check('R2a', 'a VM service changing state reaches the Panel: Failed becomes the Panel\'s "unhealthy", and the Panel\'s words show it as Failed (the pure titles keep "Unhealthy")', () => {
  const checks = inventory.vmChecks(withStatus('SVC-006', 'Failed'))
  const misp = panelLogic.summarizeWazuh(checks)[1]
  const wazuhDown = panelLogic.summarizeWazuh(inventory.vmChecks(SEED.map((s) => (['SVC-001', 'SVC-008', 'SVC-009'].includes(s.id) ? { ...s, status: 'Failed' } : s))))[0]
  return misp.state === 'unhealthy' && inventory.STATE_WORDS[misp.state] === 'Failed' && wazuhDown.displayStatus === 'Unhealthy — 0/3 running' && inventory.inDisplayWords(wazuhDown.displayStatus) === 'Failed — 0/3 running' || { pass: false, detail: JSON.stringify([misp, wazuhDown]) }
})
await check('R2a', 'the Panel\'s state words: running Running, stopped Stopped, starting Starting, unhealthy Failed, unknown Unverified; "unhealthy" in a sentence reads "failed"', () => {
  const words = ['running', 'stopped', 'starting', 'unhealthy', 'unknown'].map((s) => inventory.STATE_WORDS[s]).join()
  return words === 'Running,Stopped,Starting,Failed,Unverified' && inventory.inDisplayWords('MISP is unhealthy') === 'MISP is failed' || { pass: false, detail: words }
})
await check('R2a', 'Degraded and Failed keep their own colours: Degraded warn, Failed danger, Starting caution, Running ok, Stopped and Unverified neutral (now from statusTone)', () => {
  const tones = ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified'].map((w) => toneModule.statusTone(w)).join()
  return tones === 'ok,caution,warn,danger,neutral,neutral' || { pass: false, detail: tones }
})
await check('R2a', 'the CPU and memory gauges come from the VM usage (38.4 % and 71.2 %), the same figures as the Service Panel meters', () => {
  const { cpuPercent, memoryUsedBytes, memoryTotalBytes } = panelData.initialServicePanel.usage
  const cpu = healthData.initialMetrics.find((m) => m.id === 'cpu').value
  const memory = healthData.initialMetrics.find((m) => m.id === 'memory').value
  return cpu === cpuPercent && memory === Number(panelLogic.percentText(panelLogic.memoryPercent(memoryUsedBytes, memoryTotalBytes))) || { pass: false, detail: `${cpu} ${memory}` }
})
await check('R2a', 'a service task per service needing attention, worst first: Failed and Stopped danger ("has failed", "is stopped"), Starting and Degraded warn', () => {
  const state = { users: [], services: SEED.map((s) => (s.id === 'SVC-006' ? { ...s, status: 'Failed' } : s.id === 'SVC-003' ? { ...s, status: 'Stopped' } : s)) }
  const tasks = summary.needsAdministrator(state)
  return tasks.map((t) => `${t.id}:${t.tone}`).join() === 'service-SVC-006:danger,service-SVC-003:danger,service-SVC-005:warn,service-SVC-009:warn' && tasks[0].text === 'MISP has failed.' && tasks[1].text === 'Suricata Sensor is stopped.' || { pass: false, detail: tasks.map((t) => `${t.id}:${t.tone}:${t.text}`).join(' | ') }
})
await check('R2a', 'the audit seed says 10 monitored services (target and metadata), matching the inventory', () => {
  const row = audit.auditLogs.find((log) => log.id === 'AUD-197')
  return row.target === '10 monitored services' && row.metadata.Services === String(SEED.length) || { pass: false, detail: JSON.stringify(row) }
})

// ---------- R2b: System health is a Service Panel tab; one colour per status word ----------
await check('R2b', 'the sidebar badge follows a service stopping and recovering: 2 in the seed, 3 once OpenSearch goes over 600 ms (Stopped), back to 2 after a fast probe', () => {
  const pipe = SEED.find((s) => s.id === 'SVC-002')
  const swap = (record) => SEED.map((s) => (s.id === record.id ? record : s))
  const stopped = inventory.probe({ ...pipe, latency: 650 }, 0)
  const recovered = inventory.probe(stopped, -600)
  return inventory.servicesNeedingAttention(SEED) === 2 && stopped.status === 'Stopped' && inventory.servicesNeedingAttention(swap(stopped)) === 3 && recovered.status === 'Running' && inventory.servicesNeedingAttention(swap(recovered)) === 2 || { pass: false, detail: `${stopped.status} ${recovered.status} ${recovered.latency}` }
})
await check('R2b', 'every service word has one colour in statusTone and none shares a word with another meaning: the executor step is "Executing" (info) and "Running" is only the service state (ok)', () => {
  const words = ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified']
  const tones = words.map((w) => toneModule.statusTone(w))
  return tones.join() === 'ok,caution,warn,danger,neutral,neutral' && toneModule.statusTone('Executing') === 'info' && toneModule.statusTone('Approved') === 'ok' && toneModule.statusTone('Done') === 'ok' || { pass: false, detail: tones.join() }
})
await check('R2b', 'the Approvals step and the service state no longer share a word: no source file uses "Running" for the executor step', () => {
  const hits = []
  for (const file of ['src/components/ApprovalStepper.tsx', 'src/pages/ApprovalsPage.tsx', 'src/components/ResponseStateProvider.tsx']) {
    const text = readFileSync(join(root, file), 'utf8')
    if (/'Running'|`Running:/.test(text)) hits.push(file)
  }
  return hits.length === 0 || { pass: false, detail: hits.join() }
})
await check('R2b', 'the health links open the tab: the dashboard tile, its service tasks and the System Warning notice all name page service-panel with view health; no link names system-health', () => {
  const posture = summary.adminPosture({ responsePolicy: policies.initialResponsePolicy, users: userData.initialUsers, services: SEED, configuration: configData.initialConfiguration })[0]
  const tasks = summary.needsAdministrator({ users: [], services: SEED })
  const ntf = notifications.notifications.find((n) => n.id === 'NTF-004')
  const bad = [posture, ...tasks, ntf].filter((x) => x.page !== 'service-panel' || x.view !== 'health')
  return bad.length === 0 && tasks.length === 2 || { pass: false, detail: JSON.stringify(bad) }
})
await check('R2b', 'no source file links to the removed System Health page: no "/app/system-health" except the redirect in App.tsx, no SystemHealthPage import, and the page file is gone', () => {
  const hits = []
  for (const entry of readdirSync(join(root, 'src'), { recursive: true })) {
    const file = `src/${String(entry).replaceAll('\\', '/')}`
    if (!/\.(ts|tsx)$/.test(file)) continue
    const text = readFileSync(join(root, file), 'utf8')
    if (/SystemHealthPage/.test(text)) hits.push(`${file}: SystemHealthPage`)
    if (/system-health/.test(text) && file !== 'src/App.tsx') hits.push(`${file}: system-health`)
  }
  return hits.length === 0 && !existsSync(join(root, 'src/pages/SystemHealthPage.tsx')) || { pass: false, detail: hits.join('; ') }
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
  console.log(`  ${pass === total ? 'ok  ' : 'FAIL'}  ${area.padEnd(11)} ${pass}/${total}`)
}

const failed = results.filter((r) => !r.pass)

if (failed.length) {
  console.log('Failed checks:')
  for (const f of failed) console.log(`  [${f.area}] ${f.name}\n      ${f.detail}`)
}

// ---------- R3b: the live policy reaches the approval flow, and the model keeps enforcing the PDF ----------
{
  const P = policies.initialResponsePolicy
  const without = (p, action) => { p.whitelist = p.whitelist.filter((e) => e.action !== action) }
  const apr2 = (s) => s.approvals.find((a) => a.id === 'APR-002')
  const refusalFor = async (change) => {
    const s = await flowSeed()
    return flow.decisionRefusal(apr2(s), analystA, s.now, policyWith(change, P))
  }

  await check('R3b live', 'with the seed policy APR-002 (block 203.0.113.45, risk 77) can be decided by an analyst; with block_ip\'s minimum risk raised to 78, blacklisted, off the whitelist, or 203.0.113.45 on Never block, it is refused with the policy\'s reason', async () => {
    const s = await flowSeed()
    const seeded = flow.decisionRefusal(apr2(s), analystA, s.now, P)
    const raised = await refusalFor((p) => { limitsOf(p, 'block_ip').minRisk = 78 })
    const edge = await refusalFor((p) => { limitsOf(p, 'block_ip').minRisk = 77 })
    const black = await refusalFor((p) => { without(p, 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false }) })
    const off = await refusalFor((p) => without(p, 'block_ip'))
    const protectedIp = await refusalFor((p) => p.neverBlock.push({ value: '203.0.113.45', label: 'Test', required: false }))
    return seeded === null && edge === null && raised?.code === 'below_threshold' && /minimum risk/.test(raised.reason) && black?.code === 'blacklisted' && off?.code === 'not_listed' && protectedIp?.code === 'protected_target' &&
      [raised, black, off, protectedIp].every((r) => r.reason.startsWith('The response policy no longer allows this:')) || { pass: false, detail: JSON.stringify({ seeded, edge, raised, black, off, protectedIp }) }
  })
  await check('R3b live', 'decide() refuses the request under a policy that no longer allows it, and changes nothing (no token, no event, the request still Pending); the seed policy still approves it', async () => {
    const s = await flowSeed()
    const black = policyWith((p) => { without(p, 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false }) }, P)
    const refused = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' }, black)
    const fine = await flow.decide(s, { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' }, P)
    return !refused.ok && refused.code === 'blacklisted' && !refused.state && fine.ok && fine.state.tokens.length === s.tokens.length + 1 || { pass: false, detail: JSON.stringify([refused.code, refused.ok, fine.ok]) }
  })
  await check('R3b live', 'an approved request whose action the policy then blacklists is refused by the guard when the executor starts, and marked refused (no run, the token not used)', async () => {
    let s = (await flow.decide(await flowSeed(), { approvalId: 'APR-002', actor: analystA, kind: 'approve', reason: 'ok' }, P)).state
    const black = policyWith((p) => { without(p, 'block_ip'); p.blacklist.push({ action: 'block_ip', required: false }) }, P)
    const r = await flow.beginExecution(s, 'APR-002', black)
    const token = r.state.tokens.find((t) => t.id === 'TKN-002')
    return !r.ok && r.code === 'blacklisted' && /blacklist/.test(r.reason) && r.state.refusals['APR-002'] === r.reason && !token.usedAt && r.state.runs.length === s.runs.length || { pass: false, detail: JSON.stringify([r.ok, r.code, r.reason]) }
  })
  await check('R3b live', 'a new request ("request again") is checked against the live policy: refused when block_ip is off the whitelist, and the new request carries the live policy\'s rule (version, approver, window)', async () => {
    let s = (await flow.armFailure(await flowSeed(), analystA)).state
    s = await runApproved(s, 'APR-002', analystA)
    const off = policyWith((p) => without(p, 'block_ip'), P)
    const stricter = policyWith((p) => { Object.assign(limitsOf(p, 'block_ip'), { windowMinutes: 10, approver: 'soc_lead' }); p.version = 4 }, P)
    const refusedAgain = flow.requestAgain(s, 'EXE-002', analystA, true, off)
    const again = flow.requestAgain(s, 'EXE-002', analystA, true, stricter)
    return !refusedAgain.ok && /no longer allows/.test(refusedAgain.reason) && flow.requestAgainRefusal(s, s.runs[1], true, off)?.includes('no longer allows') && again.ok &&
      again.state.approvals[2].policy.version === 4 && again.state.approvals[2].requiredRole === 'soc_lead' && again.state.approvals[2].recommendation.approvalDeadline === '2026-08-03T15:56:10' || { pass: false, detail: JSON.stringify([refusedAgain.reason, again.ok && again.state.approvals[2].policy]) }
  })
  await check('R3b live', 'Simulate an attempt uses the live policy: with 203.0.113.45 on Never block it is refused as protected_target and writes the "Policy violation blocked" event; with the seed policy it needs approval', async () => {
    const s = await flowSeed()
    const mine = policyWith((p) => p.neverBlock.push({ value: '203.0.113.45', label: 'Test', required: false }), P)
    const request = { actionName: 'block_ip', params: { ip: '203.0.113.45', duration_min: 30 }, riskScore: 90, confidence: 0.9 }
    const a = flow.simulateAttempt(s, request, lead, mine)
    const b = flow.simulateAttempt(s, request, lead, P)
    const events = a.state.events.slice(s.events.length)
    return a.decision.code === 'protected_target' && /Response policy: Never block/.test(a.decision.rule) && events.length === 2 && events[1].action === 'Policy violation blocked' && b.decision.decision === 'needs_approval' || { pass: false, detail: JSON.stringify([a.decision, events.length]) }
  })

  // The model keeps enforcing the PDF whatever is saved
  const floors = { block_ip: 70, isolate_host: 85, suspend_user_session: 75 }
  for (const [name, floor] of Object.entries(floors)) {
    await check('R3b enforced', `${name}: a policy whose minimum risk is ${floor - 1} is refused by policyRefusal (the PDF's floor is ${floor}); ${floor} and ${floor + 1} are accepted`, () => {
      const make = (risk) => policyWith((p) => {
        if (!p.whitelist.some((e) => e.action === name)) p.whitelist.push({ action: name, mode: 'Needs approval', limits: { ...limitsOf(PDF_POLICY, name) } })
        limitsOf(p, name).minRisk = risk
      }, P)
      return typeof engineRaw.policyRefusal(make(floor - 1)) === 'string' && engineRaw.policyRefusal(make(floor)) === null && engineRaw.policyRefusal(make(floor + 1)) === null
    })
  }
  await check('R3b enforced', 'a Tier 2 action is never Automatic: every one of the six, set to Automatic in an otherwise valid policy, is refused', () =>
    data.tier2Actions.every((a) => {
      const p = policyWith((x) => {
        if (!x.whitelist.some((e) => e.action === a.name)) x.whitelist.push({ action: a.name, mode: 'Needs approval', limits: { ...limitsOf(PDF_POLICY, a.name) } })
        x.whitelist.find((e) => e.action === a.name).mode = 'Automatic'
      }, P)
      return engineRaw.policyRefusal(p)?.includes('always needs a person')
    }))
  await check('R3b enforced', 'a Tier 3 action is never whitelistable, and cannot leave the blacklist: all six, whitelisted either way, are refused', () =>
    data.tier3Actions.every((a) => {
      const onList = policyWith((x) => x.whitelist.push({ action: a.requestName, mode: 'Needs approval' }), P)
      const moved = policyWith((x) => { x.blacklist = x.blacklist.filter((e) => e.action !== a.requestName); x.whitelist.push({ action: a.requestName, mode: 'Automatic' }) }, P)
      return engineRaw.policyRefusal(onList) !== null && engineRaw.policyRefusal(moved) !== null
    }))
  await check('R3b enforced', 'protected targets are always refused: each Never block entry of the PDF refuses block_ip, each Never isolate host refuses isolate_host even when called a Business asset, and none can be removed', () => {
    const blocks = ['10.9.9.9', '172.16.5.5', '192.168.9.9', '127.0.0.9', '192.0.2.10', '192.0.2.200', '10.0.1.15']
    const refused = blocks.map((ip) => engineRaw.attemptDecision({ actionName: 'block_ip', params: { ip, duration_min: 30 }, riskScore: 99, confidence: 0.99 }, P))
    const hosts = ['dc-01', 'DB-PROD-01', 'Siem-01'].map((host) => engineRaw.attemptDecision({ actionName: 'isolate_host', params: { host, duration_min: 60 }, riskScore: 99, confidence: 0.99, assetClass: 'Business' }, P))
    const removable = [...P.neverBlock, ...P.neverIsolate].every((t) => engineRaw.policyRefusal(policyWith((x) => { x.neverBlock = x.neverBlock.filter((y) => y.value !== t.value); x.neverIsolate = x.neverIsolate.filter((y) => y.value !== t.value) }, P)) !== null)
    return refused.every((d) => d.decision === 'refused') && hosts.every((d) => d.code === 'protected_target') && removable || { pass: false, detail: JSON.stringify([refused.map((d) => d.code), hosts.map((d) => d.code), removable]) }
  })
  await check('R3b enforced', 'unlisted means denied: take any Tier 1 or Tier 2 action off the whitelist and an attempt is refused (not_listed) and so is the guard; nothing outside the lists is ever allowed', async () => {
    const bad = []
    for (const row of data.ACTION_CATALOGUE.filter((r) => r.tier !== 3)) {
      const p = policyWith((x) => without(x, row.key), PDF_POLICY)
      const a = engineRaw.attemptDecision({ actionName: row.key, params: { ip: '203.0.113.45', host: 'endpoint-09', duration_min: 30 }, riskScore: 99, confidence: 0.99, assetClass: 'Business' }, p)
      const g = await engineRaw.guard({ actionName: row.key, params: {}, now: NOW }, [], p)
      if (a.decision !== 'refused' || a.code !== 'not_listed' || g.allowed || g.code !== 'not_listed') bad.push(`${row.key}: ${a.code}/${g.code}`)
    }
    return bad.length === 0 || { pass: false, detail: bad.join('; ') }
  })
  await check('R3b enforced', 'a Tier 2 request is never allowed without its limits: a whitelisted Tier 2 entry with no limits is refused by policyRefusal', () => {
    const noLimits = policyWith((x) => { delete x.whitelist.find((e) => e.action === 'block_ip').limits }, P)
    return engineRaw.policyRefusal(noLimits)?.includes('approval limits') || { pass: false, detail: engineRaw.policyRefusal(noLimits) }
  })
}

console.log(`${results.length - failed.length}/${results.length} policy checks passed.`)
process.exit(failed.length ? 1 : 0)
