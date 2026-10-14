#!/usr/bin/env node
/*
  Motion audit, static part (Phase 6, part 1). Read-only: it reads the
  stylesheets in src/styles and prints every @keyframes, every animation
  and transition declaration, and whether it is gated by
  prefers-reduced-motion. It writes nothing but the report in
  verify-ui-output/motion-static.json.

  Usage:
    node scripts/audit-motion.js

  How a declaration is classed:
    gated      inside @media (prefers-reduced-motion: no-preference)
    reduced    its selector is switched off by an @media (prefers-reduced-motion: reduce) rule,
               or one reduce rule on * zeroes every animation and transition duration
    ungated    neither: it runs for everyone
  (An `animation: none` or `transition: none` is not motion, so it is not listed.)
*/

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const root = resolve('.')
const stylesDir = join(root, 'src', 'styles')
const outDir = resolve(process.env.VERIFY_UI_OUT_DIR ?? 'verify-ui-output')

const files = readdirSync(stylesDir).filter((name) => name.endsWith('.css'))

// Parses nested CSS into flat rules: { file, line, at: [prelude, ...], selector, decls: [[prop, value]] }
function parse(file, text) {
  const rules = []
  const stack = []
  let buffer = ''
  let line = 1
  let startLine = 1
  let inComment = false

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    const next = text[i + 1]

    if (ch === '\n') line += 1

    if (inComment) {
      if (ch === '*' && next === '/') { inComment = false; i += 1 }
      continue
    }

    if (ch === '/' && next === '*') { inComment = true; i += 1; continue }

    if (ch === '{') {
      stack.push({ prelude: buffer.trim(), line: startLine, body: '' })
      buffer = ''
      startLine = line
      continue
    }

    if (ch === '}') {
      const block = stack.pop()
      const body = block.body + buffer
      buffer = ''
      startLine = line
      if (!block) continue
      const prelude = block.prelude
      if (prelude.startsWith('@media') || prelude.startsWith('@supports') || prelude.startsWith('@layer')) {
        // children were already collected into rules with this prelude on the stack; nothing to add
      } else if (!prelude.startsWith('@keyframes') && !/^(from|to|\d+%)/.test(prelude) && !prelude.startsWith('@font-face')) {
        const decls = body
          .split(';')
          .map((d) => d.trim())
          .filter(Boolean)
          .map((d) => {
            const at = d.indexOf(':')
            return [d.slice(0, at).trim(), d.slice(at + 1).trim()]
          })
        rules.push({ file, line: block.line, at: stack.map((s) => s.prelude).filter((p) => p.startsWith('@')), selector: prelude, decls })
      } else if (prelude.startsWith('@keyframes')) {
        rules.push({ file, line: block.line, at: [], keyframes: prelude.replace('@keyframes', '').trim(), decls: [] })
      }
      if (stack.length) stack[stack.length - 1].body += ''
      continue
    }

    if (stack.length && ch !== undefined) {
      // declarations live in the innermost block's own text; collect them in buffer until { or }
    }
    buffer += ch
    if (buffer.trim() === '' ) startLine = line
  }

  return rules
}

const all = []
for (const file of files) {
  all.push(...parse(file, readFileSync(join(stylesDir, file), 'utf8')))
}

const keyframes = all.filter((r) => r.keyframes)
const rules = all.filter((r) => r.selector)

const motionProps = ['animation', 'animation-name', 'transition', 'transition-property']
const isReduce = (rule) => rule.at.some((a) => /prefers-reduced-motion:\s*reduce/.test(a))
const isGated = (rule) => rule.at.some((a) => /prefers-reduced-motion:\s*no-preference/.test(a))

// Selectors a reduce rule switches off (animation or transition none)
const switchedOff = new Set()
// One reduce rule for everything: a selector of * that zeroes the animation and transition durations
const globalReduce = rules.some(
  (rule) => isReduce(rule) && rule.selector.split(',').some((s) => s.trim() === '*') && rule.decls.some(([p, v]) => p === 'animation-duration' && /^0(\.0+)?m?s/.test(v)) && rule.decls.some(([p, v]) => p === 'transition-duration' && /^0(\.0+)?m?s/.test(v)),
)
for (const rule of rules.filter(isReduce)) {
  if (rule.decls.some(([p, v]) => (p === 'animation' || p === 'transition') && /^none/.test(v))) {
    for (const part of rule.selector.split(',')) switchedOff.add(part.trim())
  }
}

const found = []
for (const rule of rules) {
  if (isReduce(rule)) continue
  for (const [prop, value] of rule.decls) {
    if (!motionProps.includes(prop) || /^none\b/.test(value) || value === 'all 0s') continue
    const selectors = rule.selector.split(',').map((s) => s.trim())
    const reduced = selectors.every((s) => switchedOff.has(s))
    found.push({
      file: rule.file,
      line: rule.line,
      selector: rule.selector.replace(/\s+/g, ' '),
      prop: prop.startsWith('animation') ? 'animation' : 'transition',
      value: value.replace(/\s+/g, ' '),
      status: isGated(rule) ? 'gated' : reduced || globalReduce ? 'reduced' : 'ungated',
    })
  }
}

const scroll = rules.flatMap((r) => r.decls.filter(([p]) => p === 'scroll-behavior').map(([, v]) => ({ selector: r.selector, value: v, gated: isGated(r), reduced: isReduce(r) })))

const usedBy = Object.fromEntries(keyframes.map((k) => [k.keyframes, found.filter((f) => f.prop === 'animation' && new RegExp(`\\b${k.keyframes}\\b`).test(f.value)).map((f) => ({ selector: f.selector, status: f.status }))]))

const animations = found.filter((f) => f.prop === 'animation')
const transitions = found.filter((f) => f.prop === 'transition')

console.log(`Motion audit (static): ${keyframes.length} @keyframes, ${animations.length} animation declarations, ${transitions.length} transition declarations`)
console.log(`  animations:  ${['gated', 'reduced', 'ungated'].map((s) => `${animations.filter((a) => a.status === s).length} ${s}`).join(', ')}`)
console.log(`  transitions: ${['gated', 'reduced', 'ungated'].map((s) => `${transitions.filter((a) => a.status === s).length} ${s}`).join(', ')}`)
console.log(`  scroll-behavior: ${scroll.map((s) => `${s.selector} ${s.value}${s.gated ? ' (gated)' : ''}${s.reduced ? ' (reduce)' : ''}`).join('; ') || 'none'}`)
console.log('\n@keyframes and where each is used:')
for (const [name, uses] of Object.entries(usedBy)) {
  console.log(`  ${name.padEnd(14)} ${uses.length === 0 ? 'USED BY NO RULE' : uses.map((u) => `${u.selector} [${u.status}]`).join(' ; ')}`)
}
console.log('\nUngated animations (run for everyone):')
for (const a of animations.filter((x) => x.status === 'ungated')) console.log(`  ${a.file}:${a.line}  ${a.selector}  ->  ${a.value}`)
console.log('\nUngated transitions:')
for (const t of transitions.filter((x) => x.status === 'ungated')) console.log(`  ${t.file}:${t.line}  ${t.selector}  ->  ${t.value}`)
console.log('\nSwitched off under reduce by an existing rule:')
console.log(`  ${[...switchedOff].join(', ')}`)

mkdirSync(outDir, { recursive: true })
writeFileSync(join(outDir, 'motion-static.json'), JSON.stringify({ keyframes: keyframes.map((k) => k.keyframes), usedBy, animations, transitions, scroll, switchedOff: [...switchedOff] }, null, 2))

/*
  Runtime part: node scripts/audit-motion.js --runtime   (the dev server must be running)
  Walks the app twice, once under reduced motion and once without, and after each
  interaction (opening a menu, a dialog, a drawer, moving to a page, a search highlight, hovering
  a control) lists every CSS animation and transition the browser is running
  (document.getAnimations()). Writes verify-ui-output/motion-runtime.json and prints, per
  interaction, what ran under each setting. Read-only: it only reads and clicks, and signs in
  with the demo account.
*/
async function walk(page) {
  const base = '__BASE_URL__'
  const rows = []
  const sample = () =>
    page.evaluate(() =>
      document.getAnimations().map((a) => {
        const e = a.effect
        const t = e && e.getComputedTiming()
        const el = e && e.target
        const cls = el && typeof el.className === 'string' && el.className ? '.' + el.className.trim().split(/\s+/).slice(0, 3).join('.') : ''
        return {
          kind: a.constructor.name === 'CSSTransition' ? 'transition' : 'animation',
          name: a.animationName ?? a.transitionProperty,
          target: el ? el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + cls : null,
          ms: t ? t.duration : null,
          infinite: t ? t.iterations === Infinity : false,
        }
      }),
    )

  async function run(mode) {
    await page.emulateMedia({ reducedMotion: mode })
    const log = async (where, act, wait = 30) => {
      await act()
      await page.waitForTimeout(wait)
      rows.push({ mode, where, running: await sample() })
    }
    await page.setViewportSize({ width: 1440, height: 900 })

    await log('login page', async () => {
      await page.goto(base + '/login')
      await page.evaluate(() => localStorage.clear())
      await page.goto(base + '/login')
    }, 120)
    await page.click('.demo-account:has-text("admin@athenasec.com")')
    await page.click('.login-submit')
    await page.waitForURL('**/mfa')
    await log('MFA page', async () => { await page.waitForSelector('.mfa-account dd.mono') }, 120)
    const digits = page.locator('[data-mfa-digit]')
    for (let i = 0; i < 6; i += 1) await digits.nth(i).fill(String(i + 1))
    await page.click('button:has-text("Verify")')
    await page.waitForURL('**/app/dashboard')
    await page.waitForTimeout(500)

    for (const path of ['dashboard', 'configuration', 'response-policies', 'approvals', 'user-management', 'audit-logs', 'service-panel', 'settings', 'profile']) {
      await log(`page /app/${path} (just opened)`, () => page.goto(`${base}/app/${path}`), 40)
    }
    await page.goto(base + '/app/dashboard')
    await page.waitForTimeout(400)
    await log('bell menu opens', () => page.click('.icon-btn'), 30)
    await page.keyboard.press('Escape')
    await log('account menu opens', () => page.click('.user-avatar'), 30)
    await page.keyboard.press('Escape')
    await log('search results open', async () => { await page.fill('#globalSearch', 'siem') }, 30)
    await page.waitForSelector('#globalSearchResults [role="option"]')
    await log('search result chosen: the row is highlighted', async () => {
      await page.click('#globalSearchResults [role="option"]')
      await page.waitForSelector('.is-highlighted')
    }, 200)
    await page.goto(base + '/app/user-management')
    await page.waitForTimeout(400)
    await log('dialog opens (Add User)', () => page.click('button:has-text("+ Add User")'), 30)
    await log('dialog closes', () => page.keyboard.press('Escape'), 30)
    await page.goto(base + '/app/response-policies')
    await page.waitForTimeout(400)
    await log('hover a button (Blacklist icon)', () => page.hover('[data-list="whitelist"] li[data-action="get_logs"] .btn[data-tip]'), 30)
    await log('hover a card', () => page.hover('[data-list="history"]'), 30)
    await log('switch tab (Action catalogue)', () => page.click('[role="tab"]:has-text("Action catalogue")'), 30)
    await page.goto(base + '/app/approvals')
    await page.waitForTimeout(400)
    await log('select a request (APR-002)', () => page.click('.queue-item[data-record-id="APR-002"]'), 30)

    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto(base + '/app/dashboard')
    await page.waitForTimeout(400)
    await log('phone: menu drawer opens', () => page.click('.sidebar-toggle'), 30)
    await log('phone: menu drawer, 150 ms in', async () => {}, 120)
    await log('phone: menu drawer closes', () => page.keyboard.press('Escape'), 30)
  }

  await run('reduce')
  await run('no-preference')
  return JSON.stringify(rows)
}

if (process.argv.includes('--runtime')) {
  const { spawnSync } = await import('node:child_process')
  const { tmpdir } = await import('node:os')
  const { rmSync } = await import('node:fs')
  const baseUrl = (process.env.VERIFY_UI_BASE_URL ?? 'http://localhost:5173').replace(/\/$/, '')
  const useShell = process.platform === 'win32'
  const quote = (v) => (useShell ? `"${v}"` : v)
  const cli = (args) => spawnSync('playwright-cli', ['-s=audit-motion', ...args], { shell: useShell, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  const file = join(tmpdir(), `audit-motion-${process.pid}.js`)
  writeFileSync(file, `async page => (${walk.toString()})(page)`.replace("'__BASE_URL__'", JSON.stringify(baseUrl)))
  let raw = ''
  try {
    cli(['open', quote(baseUrl)])
    raw = cli(['--raw', 'run-code', `--filename=${quote(file)}`]).stdout.trim()
  } finally {
    cli(['close'])
    rmSync(file, { force: true })
  }
  let rows = JSON.parse(raw)
  if (typeof rows === 'string') rows = JSON.parse(rows)
  writeFileSync(join(outDir, 'motion-runtime.json'), JSON.stringify(rows, null, 2))
  const places = [...new Set(rows.map((r) => r.where))]
  const show = (items) => (items.length === 0 ? 'nothing' : [...new Set(items.map((i) => `${i.kind} ${i.name} on ${i.target} ${i.infinite ? '(infinite)' : `${i.ms} ms`}`))].join('; '))
  console.log('\nWhat the browser was animating after each interaction ("reduce" = reduced motion on)')
  for (const place of places) {
    const reduce = rows.find((r) => r.where === place && r.mode === 'reduce')?.running ?? []
    const normal = rows.find((r) => r.where === place && r.mode === 'no-preference')?.running ?? []
    console.log(`\n${place}\n  reduce:        ${show(reduce)}\n  no-preference: ${show(normal)}`)
  }
}
