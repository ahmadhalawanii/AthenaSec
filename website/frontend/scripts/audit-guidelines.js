#!/usr/bin/env node
/*
  Guidelines audit, automated part (Phase 6, part 2). Read-only: it signs in with the
  demo accounts, walks every page of both roles at 1440, 1280 and 390px (and the states
  a page opens: menus, dialogs, drawers, the Permissions drafts and refused saves, every
  Service Panel tab), and records findings. It changes no project file and writes only
  verify-ui-output/guidelines-raw.json.

  Usage (the dev server must be running):
    node scripts/audit-guidelines.js

  What it measures in each state:
    contrast        text against its effective background (4.5:1, 3:1 for large text);
                    input borders and placeholders
    overflow        page-level sideways scroll, and elements past the viewport
    touch targets   interactive elements under 24px (WCAG 2.5.8) and under the app's own 40px
    names           controls without an accessible name, icon-only controls, svg icons
                    not hidden from assistive technology, images without alt
    forms           autocomplete, name, placeholder style, spellcheck on codes and emails
    structure       one h1, heading levels, landmarks, lang, viewport, theme-color,
                    color-scheme, a skip link
    typography      "..." for an ellipsis, straight quotes, tabular numbers, heading wrap
    content         clipped text without a title or name
    focus           Tab order (backwards jumps), a visible focus indicator on every
                    stop, a focused element covered by something else
*/

import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const baseUrl = (process.env.VERIFY_UI_BASE_URL ?? 'http://localhost:5173').replace(/\/$/, '')
const outDir = resolve(process.env.VERIFY_UI_OUT_DIR ?? 'verify-ui-output')

async function walk(page) {
  const base = '__BASE_URL__'
  const findings = []
  const states = []

  // ---- what runs inside the page for one state ----
  const scanInPage = () => {
    const out = []
    const text = (el) => (el?.getAttribute?.('aria-label') || el?.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60)
    const sel = (el) => {
      if (!el || !el.tagName) return ''
      let s = el.tagName.toLowerCase()
      if (el.id) s += '#' + el.id
      const c = typeof el.className === 'string' ? el.className.trim().split(/\s+/).filter(Boolean).slice(0, 3) : []
      if (c.length) s += '.' + c.join('.')
      return s
    }
    const add = (check, el, evidence, extra = {}) => out.push({ check, selector: sel(el), text: text(el), evidence, ...extra })
    const rect = (el) => el.getBoundingClientRect()
    const shown = (el) => {
      const r = rect(el)
      if (r.width <= 1 || r.height <= 1) return false
      const cs = getComputedStyle(el)
      return cs.visibility !== 'hidden' && cs.display !== 'none'
    }
    const hiddenVisually = (el) => !!el.closest('.visually-hidden')

    // colours
    const parse = (s) => {
      if (!s || s === 'transparent') return [0, 0, 0, 0]
      const m = s.match(/[\d.]+(?:e-?\d+)?/g)
      if (!m) return null
      if (s.startsWith('color(')) return [Number(m[0]) * 255, Number(m[1]) * 255, Number(m[2]) * 255, m[3] === undefined ? 1 : Number(m[3])]
      return [Number(m[0]), Number(m[1]), Number(m[2]), m[3] === undefined ? 1 : Number(m[3])]
    }
    const over = (top, bottom) => {
      const a = top[3]
      return [top[0] * a + bottom[0] * (1 - a), top[1] * a + bottom[1] * (1 - a), top[2] * a + bottom[2] * (1 - a), 1]
    }
    const lum = ([r, g, b]) => {
      const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4 }
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
    }
    const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05) }
    const background = (el) => {
      const layers = []
      let approx = false
      for (let e = el; e; e = e.parentElement) {
        const cs = getComputedStyle(e)
        if (cs.backgroundImage !== 'none') approx = true
        const c = parse(cs.backgroundColor)
        if (c && c[3] > 0) { layers.push(c); if (c[3] === 1) break }
      }
      let base = [18, 6, 7, 1]
      if (layers.length && layers[layers.length - 1][3] === 1) base = layers.pop()
      for (let i = layers.length - 1; i >= 0; i -= 1) base = over(layers[i], base)
      return { color: base, approx }
    }
    const opacityOf = (el) => { let o = 1; for (let e = el; e; e = e.parentElement) o *= Number(getComputedStyle(e).opacity); return o }
    const hex = (c) => '#' + c.slice(0, 3).map((v) => Math.round(v).toString(16).padStart(2, '0')).join('')

    // 1. text contrast
    const seen = new Set()
    for (const el of document.querySelectorAll('body *')) {
      if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'OPTION', 'OPTGROUP', 'svg', 'path'].includes(el.tagName) || el.closest('svg')) continue
      const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())
      if (!own || !shown(el) || hiddenVisually(el)) continue
      const cs = getComputedStyle(el)
      if (cs.webkitTextFillColor === 'rgba(0, 0, 0, 0)' || el.closest('[disabled], [aria-disabled="true"]')) continue
      const fg0 = parse(cs.color)
      if (!fg0) continue
      const bg = background(el)
      const o = opacityOf(el)
      const fg = over([fg0[0], fg0[1], fg0[2], fg0[3] * o], bg.color)
      const size = parseFloat(cs.fontSize)
      const large = size >= 24 || (size >= 18.66 && Number(cs.fontWeight) >= 700)
      const r = ratio(fg, bg.color)
      const need = large ? 3 : 4.5
      if (r < need) {
        const key = sel(el) + r.toFixed(2)
        if (seen.has(key)) continue
        seen.add(key)
        add('contrast', el, `${r.toFixed(2)}:1 (needs ${need}) ${hex(fg)} on ${hex(bg.color)}${bg.approx ? ' (gradient behind, approximate)' : ''}, ${size}px ${cs.fontWeight}`)
      }
    }
    // placeholders and input borders
    for (const el of document.querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]), select, textarea')) {
      if (!shown(el)) continue
      const bg = background(el.parentElement ?? el)
      const own = background(el)
      if (el.placeholder) {
        const pc = parse(getComputedStyle(el, '::placeholder').color)
        if (pc) {
          const r = ratio(over(pc, own.color), own.color)
          if (r < 4.5) add('contrast', el, `placeholder ${r.toFixed(2)}:1 (needs 4.5) ${hex(over(pc, own.color))} on ${hex(own.color)}`)
        }
      }
      const cs = getComputedStyle(el)
      const bc = parse(cs.borderTopColor)
      if (bc && parseFloat(cs.borderTopWidth) > 0) {
        const r = ratio(over(bc, bg.color), bg.color)
        const fieldFill = ratio(own.color, bg.color)
        if (r < 3 && fieldFill < 3) add('non-text contrast', el, `field border ${r.toFixed(2)}:1 and fill ${fieldFill.toFixed(2)}:1 against its surroundings (needs 3:1 for one of them)`)
      }
    }

    // 2. overflow
    const de = document.documentElement
    if (de.scrollWidth > de.clientWidth + 1) add('overflow', de, `page scrolls sideways: scrollWidth ${de.scrollWidth} > clientWidth ${de.clientWidth}`)
    let n = 0
    for (const el of document.querySelectorAll('body *')) {
      if (n >= 6) break
      if (!shown(el) || hiddenVisually(el) || el.closest('svg') || el.closest('[role="dialog"]') && false) continue
      const r = rect(el)
      if (r.right > innerWidth + 1 || r.left < -1) {
        let clipped = false
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const o = getComputedStyle(p)
          if (['auto', 'scroll', 'hidden', 'clip'].includes(o.overflowX)) { clipped = true; break }
          if (o.position === 'fixed') { clipped = false; break }
        }
        if (!clipped && getComputedStyle(el).position !== 'fixed') { add('overflow', el, `extends past the viewport: left ${Math.round(r.left)}, right ${Math.round(r.right)} of ${innerWidth}`); n += 1 }
      }
    }

    // 3. touch targets
    const targets = 'a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="tab"], [role="menuitem"], [role="switch"], [role="option"], summary'
    for (const el of document.querySelectorAll(targets)) {
      if (!shown(el) || hiddenVisually(el)) continue
      let box = rect(el)
      if ((el.type === 'checkbox' || el.type === 'radio') && el.labels?.length) box = rect(el.labels[0])
      const cs = getComputedStyle(el)
      const inline = el.tagName === 'A' && cs.display === 'inline'
      const disabled = el.disabled || el.getAttribute('aria-disabled') === 'true'
      const w = Math.round(box.width)
      const h = Math.round(box.height)
      if (w < 24 || h < 24) add('touch target', el, `${w}x${h}px, under 24px (WCAG 2.5.8)${inline ? ', inline in text (exempt)' : ''}${disabled ? ', disabled' : ''}`, { level: inline ? 'exempt' : 'fail' })
      else if ((w < 40 || h < 40) && !inline) add('touch target', el, `${w}x${h}px, over 24px but under the app's 40px rule${disabled ? ', disabled' : ''}`, { level: 'below-40' })
    }

    // 4. names
    const nameOf = (el) => {
      const al = el.getAttribute('aria-label')
      if (al && al.trim()) return al.trim()
      const lb = el.getAttribute('aria-labelledby')
      if (lb) { const t = lb.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ').trim(); if (t) return t }
      if (el.labels && el.labels.length) { const t = [...el.labels].map((l) => l.textContent).join(' ').trim(); if (t) return t }
      const clone = el.cloneNode(true)
      clone.querySelectorAll('[aria-hidden="true"]').forEach((x) => x.remove())
      const t = clone.textContent.replace(/\s+/g, ' ').trim()
      if (t) return t
      const img = el.querySelector('img[alt]')
      if (img && img.alt) return img.alt
      if (el.tagName === 'INPUT' && ['submit', 'button'].includes(el.type) && el.value) return el.value
      return ''
    }
    for (const el of document.querySelectorAll(targets)) {
      if (!shown(el) || hiddenVisually(el)) continue
      const name = nameOf(el)
      if (!name) {
        if (el.getAttribute('title')) add('accessible name', el, `name comes from title only ("${el.getAttribute('title')}")`, { level: 'title-only' })
        else add('accessible name', el, 'no accessible name', { level: 'none' })
      }
    }
    for (const el of document.querySelectorAll('svg')) {
      if (!shown(el)) continue
      if (el.getAttribute('aria-hidden') === 'true' || el.getAttribute('role') === 'img' || el.getAttribute('aria-label') || el.querySelector('title')) continue
      if (el.closest('[aria-hidden="true"]')) continue
      add('decorative icon', el, 'svg is neither aria-hidden nor named')
    }
    for (const el of document.querySelectorAll('img')) {
      if (!el.hasAttribute('alt')) add('image alt', el, 'img has no alt')
      if (!el.getAttribute('width') || !el.getAttribute('height')) add('image size', el, 'img has no width and height')
    }

    // 5. forms
    for (const el of document.querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"]), textarea')) {
      if (!shown(el)) continue
      if (!el.hasAttribute('autocomplete')) add('form: autocomplete', el, `${el.tagName.toLowerCase()}[type=${el.type}] has no autocomplete attribute`)
      if (!el.getAttribute('name')) add('form: name', el, 'no name attribute')
      if (el.placeholder && !/(…|\.\.\.)$/.test(el.placeholder)) add('form: placeholder', el, `placeholder "${el.placeholder}" does not end with an ellipsis`)
      if ((el.type === 'email' || /code|digit|user|email|ip|host/i.test(el.id + el.name)) && el.spellcheck) add('form: spellcheck', el, 'spellcheck is on for a code, address or identifier')
    }

    // 6. structure
    const hs = [...document.querySelectorAll('h1, h2, h3, h4, h5, h6')].filter(shown)
    const h1s = hs.filter((h) => h.tagName === 'H1')
    if (h1s.length !== 1) add('headings', document.body, `${h1s.length} h1 elements (want one)`)
    let prev = 0
    for (const h of hs) {
      const level = Number(h.tagName[1])
      if (prev && level > prev + 1) add('headings', h, `heading level jumps from h${prev} to h${level}`)
      prev = level
    }
    if (!document.querySelector('main, [role="main"]')) add('landmarks', document.body, 'no main landmark')
    if (!document.querySelector('nav, [role="navigation"]') && !location.pathname.match(/login|mfa/)) add('landmarks', document.body, 'no nav landmark')
    if (!document.documentElement.lang) add('document', document.documentElement, 'html has no lang')
    const vp = document.querySelector('meta[name="viewport"]')?.content ?? ''
    if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1(\.0)?\b/.test(vp)) add('document', document.documentElement, `viewport blocks zoom: ${vp}`)
    if (!document.querySelector('meta[name="theme-color"]')) add('document', document.documentElement, 'no theme-color meta')
    if (getComputedStyle(document.documentElement).colorScheme.indexOf('dark') < 0) add('document', document.documentElement, `color-scheme is "${getComputedStyle(document.documentElement).colorScheme}", not dark (native scrollbars and form controls)`)
    const first = [...document.querySelectorAll('a[href], button, input, select, textarea, [tabindex="0"]')].find(shown)
    if (!(first && first.tagName === 'A' && /skip/i.test(first.textContent))) add('skip link', document.body, `no skip-to-content link before the first stop (${first ? sel(first) : 'none'})`)

    // 7. typography
    for (const el of document.querySelectorAll('body *')) {
      if (!shown(el) || el.closest('svg, code, pre, .mono, [data-field="metadata"]') && false) continue
      for (const nde of el.childNodes) {
        if (nde.nodeType !== 3) continue
        const t = nde.textContent
        if (/\.\.\./.test(t) && !el.closest('script, style')) add('typography: ellipsis', el, `"${t.trim().slice(0, 50)}" uses three dots`)
        if (/\w"\w|"\w[^"]*\w"/.test(t) && !el.closest('script, style')) add('typography: quotes', el, `"${t.trim().slice(0, 50)}" uses straight quotes`)
      }
    }
    const numeric = [...document.querySelectorAll('td, .stat strong, .response-summary strong, .metric span, .count')].filter((el) => shown(el) && /^[\d.,:%/ -]+$/.test(el.textContent.trim()) && el.textContent.trim().length > 0)
    const noTab = numeric.filter((el) => !/tabular-nums/.test(getComputedStyle(el).fontVariantNumeric))
    if (noTab.length) add('typography: tabular numbers', noTab[0], `${noTab.length} of ${numeric.length} numeric cells lack tabular-nums (first: "${noTab[0].textContent.trim()}")`)
    for (const h of hs.filter((x) => ['H1', 'H2'].includes(x.tagName))) {
      const tw = getComputedStyle(h).textWrap
      if (!/balance|pretty/.test(tw)) add('typography: heading wrap', h, `text-wrap is ${tw} (balance or pretty avoids widows)`)
    }

    // 8. clipped content
    n = 0
    for (const el of document.querySelectorAll('body *')) {
      if (n >= 8) break
      if (!shown(el) || hiddenVisually(el) || el.closest('svg')) continue
      const cs = getComputedStyle(el)
      if (!['hidden', 'clip'].includes(cs.overflowX) && cs.textOverflow !== 'ellipsis') continue
      if (el.scrollWidth > el.clientWidth + 1 && el.textContent.trim() && !el.getAttribute('title') && !el.getAttribute('aria-label')) {
        add('clipped text', el, `text is cut off (${el.scrollWidth}px of ${el.clientWidth}px) with no title`)
        n += 1
      }
    }

    // 9. interactive non-semantics and misc
    for (const el of document.querySelectorAll('div[onclick], span[onclick], [role="button"]:not(button):not(a), div[tabindex], span[tabindex]')) {
      if (shown(el)) add('semantics', el, 'non-button element used as a control')
    }
    const touch = getComputedStyle(document.querySelector('button') ?? document.body).touchAction
    if (touch !== 'manipulation') add('touch-action', document.body, `buttons have touch-action ${touch} (manipulation avoids the double-tap zoom delay)`)
    for (const el of document.querySelectorAll('[role="dialog"], .modal, .sidebar, .alert-drawer')) {
      if (shown(el) && !/contain|none/.test(getComputedStyle(el).overscrollBehaviorY)) add('overscroll', el, 'no overscroll-behavior: contain on a dialog, drawer or sheet')
    }
    const live = document.querySelectorAll('[aria-live], [role="status"], [role="alert"]').length
    out.push({ check: 'info', selector: 'document', text: '', evidence: `live regions: ${live}` })
    return out
  }

  // ---- Tab order for one state ----
  const tabScan = async (max = 45) => {
    await page.evaluate(() => {
      window.scrollTo(0, 0)
      const start = document.createElement('span')
      start.id = '__tabStart'
      start.tabIndex = 0
      document.body.prepend(start)
      start.focus()
    })
    const stops = []
    for (let i = 0; i < max; i += 1) {
      await page.keyboard.press('Tab')
      const s = await page.evaluate(() => {
        const el = document.activeElement
        if (!el || el === document.body || el.id === '__tabStart') return null
        const cs = getComputedStyle(el)
        const r = el.getBoundingClientRect()
        const cx = r.left + r.width / 2
        const cy = r.top + r.height / 2
        const hit = cx >= 0 && cy >= 0 && cx <= innerWidth && cy <= innerHeight ? document.elementFromPoint(cx, cy) : null
        const sel = (e) => (e ? e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (typeof e.className === 'string' && e.className ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.') : '') : '')
        return {
          selector: sel(el),
          name: (el.getAttribute('aria-label') || el.textContent || el.id || '').replace(/\s+/g, ' ').trim().slice(0, 40),
          top: r.top + scrollY, left: r.left, h: r.height,
          indicator: (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || cs.boxShadow !== 'none',
          covered: !!hit && hit !== el && !el.contains(hit) && !hit.contains(el) ? sel(hit) : '',
          offscreen: r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth,
        }
      })
      if (!s || stops.some((p) => p.selector === s.selector && p.top === s.top && p.left === s.left)) break
      stops.push(s)
    }
    await page.evaluate(() => document.getElementById('__tabStart')?.remove())
    return stops
  }

  const tabFindings = (stops) => {
    const out = []
    stops.forEach((s, i) => {
      if (!s.indicator) out.push({ check: 'focus indicator', selector: s.selector, text: s.name, evidence: 'no outline or glow when focused' })
      if (s.covered) out.push({ check: 'focus covered', selector: s.selector, text: s.name, evidence: `covered by ${s.covered} when focused` })
      if (i > 0) {
        const a = stops[i - 1]
        const ca = a.top + a.h / 2
        const cb = s.top + s.h / 2
        const sameRow = Math.abs(ca - cb) < 12
        if (sameRow ? s.left < a.left : cb < ca) out.push({ check: 'focus order', selector: s.selector, text: s.name, evidence: `after ${a.name || a.selector} the focus moves backwards on screen` })
      }
    })
    if (stops.length < 2) out.push({ check: 'focus order', selector: 'document', text: '', evidence: `only ${stops.length} focus stop(s) found` })
    return out
  }

  const record = async (role, label, width) => {
    try {
      const a = await page.evaluate(scanInPage)
      const stops = await tabScan()
      const rows = [...a, ...tabFindings(stops)]
      states.push({ role, label, width, stops: stops.length, findings: rows.filter((r) => r.check !== 'info').length })
      for (const r of rows) findings.push({ role, state: label, width, ...r })
    } catch (error) {
      findings.push({ role, state: label, width, check: 'audit error', selector: '', text: '', evidence: String(error.message ?? error).slice(0, 200) })
    }
  }

  const settle = (ms = 300) => page.waitForTimeout(ms)
  const signIn = async (email) => {
    await page.goto(base + '/login')
    await page.evaluate(() => localStorage.clear())
    await page.goto(base + '/login')
    await page.click(`.demo-account:has-text("${email}")`)
    await page.click('.login-submit')
    await page.waitForURL('**/mfa')
    await page.waitForSelector('.mfa-account dd.mono')
    const digits = page.locator('[data-mfa-digit]')
    for (let i = 0; i < 6; i += 1) await digits.nth(i).fill(String(i + 1))
    await page.click('button:has-text("Verify")')
    await page.waitForURL('**/app/dashboard')
    await page.waitForSelector('.sidebar .side-item', { state: 'attached' })
    await settle()
  }
  const go = async (path) => { await page.goto(base + path); await settle() }
  const attempt = async (fn) => { try { await fn() } catch (error) { findings.push({ role: '-', state: 'setup', width: '-', check: 'audit error', selector: '', text: '', evidence: String(error.message ?? error).slice(0, 200) }) } }

  await page.emulateMedia({ reducedMotion: 'reduce' })

  for (const [name, w, h] of [['1440', 1440, 900], ['1280', 1280, 800], ['390', 390, 844]]) {
    await page.setViewportSize({ width: w, height: h })
    const phone = w < 600

    // before sign-in
    await page.goto(base + '/login')
    await page.evaluate(() => localStorage.clear())
    await page.goto(base + '/login')
    await settle()
    await record('-', 'Login', name)
    await page.click('.demo-account:has-text("analyst@athenasec.com")')
    await page.click('.login-submit')
    await page.waitForURL('**/mfa')
    await page.waitForSelector('.mfa-account dd.mono')
    await settle()
    await record('-', 'MFA', name)

    // ----- analyst -----
    await signIn('analyst@athenasec.com')
    for (const [label, path] of [['Dashboard', '/app/dashboard'], ['Alerts', '/app/alerts'], ['Case Management', '/app/cases'], ['Incident Response', '/app/incident'], ['Approvals', '/app/approvals'], ['Profile', '/app/profile']]) {
      await go(path)
      await record('analyst', label, name)
    }
    await attempt(async () => { await go('/app/alerts'); await page.click('[data-record-id="ALT-001"]'); await settle(); await record('analyst', 'Alerts (ALT-001 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/cases'); await page.click('[data-record-id="CASE-007"]'); await settle(); await record('analyst', 'Cases (CASE-007 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/incident'); await page.click('[data-record-id="EXE-001"]'); await settle(); await record('analyst', 'Incident (EXE-001 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/approvals'); await page.click('.queue-item[data-record-id="APR-002"]'); await settle(); await record('analyst', 'Approvals (APR-002 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/dashboard'); await page.click('.icon-btn'); await settle(120); await record('analyst', 'Bell menu open', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/dashboard'); await page.click('.user-avatar'); await settle(120); await record('analyst', 'Account menu open', name); await page.keyboard.press('Escape') })
    if (phone) await attempt(async () => { await go('/app/dashboard'); await page.click('.sidebar-toggle'); await settle(); await record('analyst', 'Menu drawer open', name); await page.keyboard.press('Escape') })

    // ----- administrator -----
    await signIn('admin@athenasec.com')
    for (const [label, path] of [['Dashboard', '/app/dashboard'], ['Configuration', '/app/configuration'], ['Response Policies: Permissions', '/app/response-policies'], ['Response Policies: Action catalogue', '/app/response-policies?view=catalogue'], ['Approvals', '/app/approvals'], ['User Management', '/app/user-management'], ['Audit Logs', '/app/audit-logs'], ['Service Panel: Overview', '/app/service-panel'], ['Service Panel: Wazuh', '/app/service-panel?view=wazuh'], ['Service Panel: Cortex', '/app/service-panel?view=cortex'], ['Service Panel: MISP', '/app/service-panel?view=misp'], ['Service Panel: System health', '/app/service-panel?view=health'], ['Settings', '/app/settings'], ['Profile', '/app/profile']]) {
      await go(path)
      await record('admin', label, name)
    }
    // Permissions states
    await attempt(async () => {
      await go('/app/response-policies')
      await page.click('.perm button[aria-label="Approval limits for block_ip"]')
      await page.click('.perm button[aria-label="Approval limits for isolate_host"]')
      await settle(150)
      await record('admin', 'Permissions: limits open', name)
      await page.click('.perm button[aria-label="Move get_logs to the blacklist"]')
      await settle(150)
      await record('admin', 'Permissions: draft with a change', name)
      await page.fill('#limit-block_ip-maxMinutes', '1441')
      await page.fill('#limit-block_ip-minRisk', '60')
      await page.locator('.perm-bar .btn.primary').click()
      await settle(150)
      await record('admin', 'Permissions: refused save (reasons shown)', name)
      await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click()
      await page.click('.perm [data-targets="block"] button[aria-expanded]')
      await page.fill('#add-block-value', 'not-an-ip')
      await page.keyboard.press('Enter')
      await settle(150)
      await record('admin', 'Permissions: Add form with an error', name)
    })
    await attempt(async () => {
      await go('/app/response-policies?view=catalogue')
      await page.selectOption('#attemptAction', 'block_ip')
      await page.fill('#attemptTarget', '10.0.0.5')
      await page.locator('.attempt-form button[type="submit"]').click()
      await settle(150)
      await record('admin', 'Action catalogue: attempt result', name)
    })
    await attempt(async () => { await go('/app/approvals'); await page.click('.queue-item[data-record-id="APR-002"]'); await settle(); await record('admin', 'Approvals (APR-002 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/user-management'); await page.click('button:has-text("+ Add User")'); await settle(150); await record('admin', 'User Management: Add user dialog', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/audit-logs'); await page.click('.audit-pick[data-record-id="AUD-206"]'); await settle(); await record('admin', 'Audit Logs (AUD-206 open)', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/service-panel?view=health'); await page.locator('tbody tr[data-record-id] button', { hasText: 'View' }).first().click(); await settle(); await record('admin', 'System health: service details open', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/dashboard'); await page.click('.icon-btn'); await settle(120); await record('admin', 'Bell menu open', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/dashboard'); await page.click('.user-avatar'); await settle(120); await record('admin', 'Account menu open', name); await page.keyboard.press('Escape') })
    await attempt(async () => { await go('/app/dashboard'); await page.fill('#globalSearch', 'siem'); await settle(150); await record('admin', 'Search results open', name); await page.keyboard.press('Escape') })
    if (phone) await attempt(async () => { await go('/app/dashboard'); await page.click('.sidebar-toggle'); await settle(); await record('admin', 'Menu drawer open', name); await page.keyboard.press('Escape') })
  }
  return JSON.stringify({ states, findings })
}

const file = join(tmpdir(), `audit-guidelines-${process.pid}.js`)
writeFileSync(file, `async page => (${walk.toString()})(page)`.replace("'__BASE_URL__'", JSON.stringify(baseUrl)))
const useShell = process.platform === 'win32'
const quote = (v) => (useShell ? `"${v}"` : v)
const cli = (args) => spawnSync('playwright-cli', ['-s=audit-guidelines', ...args], { shell: useShell, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
let raw = ''
try {
  cli(['open', quote(baseUrl)])
  raw = cli(['--raw', 'run-code', `--filename=${quote(file)}`]).stdout.trim()
} finally {
  cli(['close'])
  rmSync(file, { force: true })
}
let result
try {
  result = JSON.parse(raw)
  if (typeof result === 'string') result = JSON.parse(result)
} catch {
  console.error(`audit-guidelines: no report came back:\n${raw.slice(0, 1500)}`)
  process.exit(1)
}
mkdirSync(outDir, { recursive: true })
writeFileSync(join(outDir, 'guidelines-raw.json'), JSON.stringify(result, null, 2))
const byCheck = {}
for (const f of result.findings) byCheck[f.check] = (byCheck[f.check] ?? 0) + 1
console.log(`${result.states.length} states scanned, ${result.findings.length} raw findings`)
console.log(Object.entries(byCheck).sort((a, b) => b[1] - a[1]).map(([k, v]) => `  ${k}: ${v}`).join('\n'))
console.log(`raw findings: ${join(outDir, 'guidelines-raw.json')}`)
