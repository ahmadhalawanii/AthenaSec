#!/usr/bin/env node
/*
  UI verification for the AthenaSec frontend.

  Drives the running dev server with playwright-cli and checks every
  page for both demo roles at 1440px, 1280px and 390px: Login and MFA
  (Demo mode, errors, pasted codes, reduced motion, reading order that
  follows the layout), navigation
  (exact spec menu items), the top bar (threat meter, status, bell,
  account, 44px controls), the single Ctrl+K and "/" search shortcut
  handler, the sticky mobile header, status accuracy, tables, the User
  Management "⋯" row menu, dialogs (Escape, focus trap), labels, focus
  rings, global search, copy, colour tones, button variants, derived
  dashboard figures, the attack path map (keyboard, text alternative,
  list on phones), simulated analyst actions reaching every page, the
  self-hosted font and the
  horizontal-scroll cue.

  Usage (dev server must already be running):
    npm run dev          # in one terminal
    npm run verify:ui    # in another

  Requires the playwright-cli command on PATH
  (npm install -g @playwright/cli@latest).

  Environment:
    VERIFY_UI_BASE_URL  default http://localhost:5173
    VERIFY_UI_OUT_DIR   default ./verify-ui-output (screenshots + report.json + timings.json)
    VERIFY_UI_EXACT_WAITS=1   sit out every fixed wait for its full time (the pre-Phase-6 behaviour);
                              by default a short wait ends as soon as the page has been still for 80 ms

  Exit code: 0 when every check passes and the browser logged no
  errors or warnings; 1 on any failure; 2 if setup failed.

  How it works: runChecks() below is serialised and executed by
  "playwright-cli run-code", so it must stay self-contained (no
  imports, no references to anything outside the function). The two
  placeholders '__OUT_DIR__/' and '__BASE_URL__' are filled in before
  it runs. To add a check, call check(width, area, name, pass, detail)
  inside runChecks.
*/

import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const BASE_URL = (process.env.VERIFY_UI_BASE_URL ?? 'http://localhost:5173').replace(/\/$/, '')
const OUT_DIR = resolve(process.env.VERIFY_UI_OUT_DIR ?? 'verify-ui-output')
const SESSION = 'verify-ui'

async function runChecks(page) {
  const out = '__OUT_DIR__/';
  const base = '__BASE_URL__';
  const results = [];
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e));
  page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') errors.push(m.type() + ': ' + m.text()); });

  // Timing, for finding where the run spends its time (no effect on any check): each result carries the
  // milliseconds since the start (t) and the milliseconds spent in fixed waitForTimeout calls so far (s)
  const startedAt = Date.now();
  let slept = 0;
  const realWait = page.waitForTimeout.bind(page);
  const exactWaits = '__EXACT_WAITS__' === 'yes';
  // A short wait after an action is "wait until the page has stopped changing", with the old time as the
  // limit: the DOM must be quiet for QUIET ms (and the wait lasts at least that long). Waits over LONGEST,
  // which are timers the check really means to sit through, stay exact, and so does every wait when
  // VERIFY_UI_EXACT_WAITS=1 (the old behaviour, for finding out whether a failure is a timing one).
  const QUIET = 80;
  const LONGEST = 500;
  // Still also means no finite CSS transition or animation is running (they change no DOM, but a drawer
  // that is still sliding, or a button still fading to its hover colour, is not yet what a check measures)
  const settle = ms => page.evaluate(({ max, quiet }) => new Promise(resolve => {
    let timer;
    const finish = () => { observer.disconnect(); clearTimeout(timer); clearTimeout(cap); resolve(); };
    const running = () => document.getAnimations().filter(a => a.playState === 'running' && a.effect && a.effect.getComputedTiming().iterations !== Infinity);
    const quietNow = () => {
      const pending = running();
      if (pending.length === 0) { finish(); return; }
      Promise.all(pending.map(a => a.finished.catch(() => {}))).then(() => { timer = setTimeout(finish, 0); });
    };
    const observer = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(quietNow, quiet); });
    observer.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
    timer = setTimeout(quietNow, quiet);
    const cap = setTimeout(finish, max);
  }), { max: ms, quiet: QUIET });
  page.waitForTimeout = async ms => {
    const began = Date.now();
    if (exactWaits || ms > LONGEST || ms <= QUIET) {
      await realWait(ms);
    } else {
      // (a page that is mid-navigation cannot be asked: sit out the whole time instead)
      await settle(ms).catch(() => realWait(ms));
    }
    slept += Date.now() - began;
  };
  const check = (width, area, name, pass, detail = '') => results.push({ width, area, name, pass: !!pass, detail: String(detail), t: Date.now() - startedAt, s: slept });

  // Record every keydown listener the app keeps on document/window, so the
  // shortcut check can prove there is exactly one search-shortcut handler.
  await page.addInitScript(() => {
    const live = [];
    window.__keydownListeners = live;
    const add = EventTarget.prototype.addEventListener;
    const remove = EventTarget.prototype.removeEventListener;
    const watched = t => t === window || t === document;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      if (type === 'keydown' && fn && watched(this)) live.push({ target: this, fn });
      return add.call(this, type, fn, opts);
    };
    EventTarget.prototype.removeEventListener = function (type, fn, opts) {
      if (type === 'keydown' && watched(this)) {
        const i = live.findIndex(l => l.fn === fn && l.target === this);
        if (i >= 0) live.splice(i, 1);
      }
      return remove.call(this, type, fn, opts);
    };
  });
  // I3: every status word seen in a table or key/value pill -> the colours it was drawn in
  const pillColors = {};

  const roles = {
    analyst: { email: 'analyst@athenasec.com', pw: 'analyst123', pages: ['dashboard', 'alerts', 'cases', 'incident', 'approvals', 'profile'] },
    admin: { email: 'admin@athenasec.com', pw: 'admin123', pages: ['dashboard', 'configuration', 'response-policies', 'approvals', 'user-management', 'audit-logs', 'service-panel?view=health', 'service-panel', 'settings', 'profile'] },
  };

  /*
    Phase 6, F02 and F04: how clearly each matching field shows its edge (the border against the colour
    behind it, WCAG 1.4.11, 3:1) and its placeholder against the field's fill (WCAG 1.4.3, 4.5:1).
    Returns one entry per visible field: { id, border, placeholder }.
  */
  const fieldContrast = selector => page.evaluate(sel => {
    const parse = s => { const m = (s || '').match(/[\d.]+/g); return m ? [Number(m[0]), Number(m[1]), Number(m[2]), m[3] === undefined ? 1 : Number(m[3])] : [0, 0, 0, 0]; };
    const over = (t, b) => [t[0] * t[3] + b[0] * (1 - t[3]), t[1] * t[3] + b[1] * (1 - t[3]), t[2] * t[3] + b[2] * (1 - t[3]), 1];
    const lum = ([r, g, b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return Math.round(((x + 0.05) / (y + 0.05)) * 100) / 100; };
    const behind = el => { const layers = []; for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c[3] > 0) { layers.push(c); if (c[3] === 1) break; } } let base = [18, 6, 7, 1]; if (layers.length && layers[layers.length - 1][3] === 1) base = layers.pop(); for (let i = layers.length - 1; i >= 0; i--) base = over(layers[i], base); return base; };
    return [...document.querySelectorAll(sel)].filter(el => el.getBoundingClientRect().width > 1).map(el => {
      const cs = getComputedStyle(el);
      const outside = behind(el.parentElement);
      const fill = over(parse(cs.backgroundColor), outside);
      const border = over(parse(cs.borderTopColor), outside);
      const ph = el.placeholder ? parse(getComputedStyle(el, '::placeholder').color) : null;
      return { id: el.id || el.className.split(' ')[0], border: ratio(border, outside), placeholder: ph ? ratio(over(ph, fill), fill) : null };
    });
  }, selector);
  /*
    Phase 6, F15, F16, F17, F24: what each visible field declares. Returns one problem string per fault:
    a field without a name; a text-like field without autocomplete; an email field with spellcheck on;
    a placeholder that does not end with an ellipsis; a field that has focus without being asked.
  */
  const fieldFaults = scope => page.evaluate(root => {
    const faults = [];
    const label = el => el.id || el.name || el.getAttribute('aria-label') || el.tagName;
    const fields = [...document.querySelectorAll(`${root} input, ${root} select, ${root} textarea`)].filter(el => el.type !== 'hidden' && el.getClientRects().length > 0);
    for (const el of fields) {
      if (!el.getAttribute('name')) faults.push(`${label(el)}: no name`);
      const textLike = el.tagName === 'TEXTAREA' || (el.tagName === 'INPUT' && !['checkbox', 'radio', 'button', 'submit', 'range'].includes(el.type)) || el.tagName === 'SELECT';
      if (textLike && !el.getAttribute('autocomplete')) faults.push(`${label(el)}: no autocomplete`);
      if (el.type === 'email' && el.getAttribute('spellcheck') !== 'false') faults.push(`${label(el)}: spellcheck on`);
      if (el.placeholder && !el.placeholder.endsWith('…')) faults.push(`${label(el)}: placeholder "${el.placeholder}" does not end with an ellipsis`);
    }
    const active = document.activeElement;
    if (active && ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName) && !active.closest('[role="dialog"]')) faults.push(`${label(active)}: has focus without being asked`);
    return { count: fields.length, faults };
  }, scope);
  const fieldsClear = list =>list.length > 0 && list.every(f => f.border >= 3 && (f.placeholder === null || f.placeholder >= 4.5));

  // Signs in through the Demo mode panel and checks the role routing on the way.
  async function login(r, wname, rname) {
    await page.goto(base + '/login');
    await page.evaluate(() => localStorage.clear());
    await page.goto(base + '/login');
    const loginTitle = await page.title();
    await page.click(`.demo-account:has-text("${r.email}")`);
    const filled = await page.evaluate(() => ({ email: document.querySelector('#loginEmail').value, pw: document.querySelector('#loginPassword').value }));
    check(wname, 'C5 login', `${rname}: Demo mode button fills email and password`, filled.email === r.email && filled.pw === r.pw, filled.email);
    const loginFaults = await fieldFaults('body');
    check(wname, 'a11y forms', `${rname}: the sign-in fields and the Remember me box have names and autocomplete, the email field turns spellcheck off and placeholders end with "…" (no field has focus on load)`, loginFaults.count === 3 && loginFaults.faults.length === 0, JSON.stringify(loginFaults));
    if (rname === 'analyst') {
      const authFields = await fieldContrast('.auth-input');
      check(wname, 'a11y fields', 'the sign-in fields show their edge at 3:1 or more against the panel (WCAG 1.4.11) and their placeholders read at 4.5:1 or more', fieldsClear(authFields) && authFields.length === 2, JSON.stringify(authFields));
    }
    await page.click('.login-submit');
    await page.waitForURL('**/mfa');
    await page.waitForSelector('.mfa-account dd.mono');
    const account = await page.evaluate(() => document.querySelector('.mfa-account dd.mono')?.textContent.trim());
    check(wname, 'C6 MFA', `${rname}: MFA shows the account being verified`, account === r.email, account);
    check(wname, 'a11y titles', `${rname}: the sign-in and verification pages have their own titles`, (await page.title()) === 'Two-step verification · AthenaSec' && loginTitle === 'Sign in · AthenaSec', `${loginTitle} | ${await page.title()}`);
    if (rname === 'analyst') {
      const codeBoxes = await fieldContrast('.code');
      check(wname, 'a11y fields', 'the six MFA code boxes show their edge at 3:1 or more against the panel (WCAG 1.4.11)', fieldsClear(codeBoxes) && codeBoxes.length === 6, JSON.stringify(codeBoxes));
    }
    const digits = page.locator('[data-mfa-digit]');
    for (let i = 0; i < 6; i++) await digits.nth(i).fill(String(i + 1));
    await page.click('button:has-text("Verify")');
    await page.waitForURL('**/app/dashboard');
    await page.waitForSelector('.sidebar .side-item', { state: 'attached' });
    await page.waitForTimeout(300);
    const title = await page.evaluate(() => document.querySelector('.sidebar .side-title')?.textContent.trim());
    check(wname, 'C5 login', `${rname}: sign-in lands on the dashboard with the ${rname} menu`, page.url().endsWith('/app/dashboard') && title === (rname === 'admin' ? 'Security management' : 'Analyst'), `${page.url()} | ${title}`);

    // ---------- Phase 6 guidelines fixes F06, F07, F08: page titles, the skip link and the navigation landmark ----------
    const names = { dashboard: 'Dashboard', alerts: 'Alerts', cases: 'Case Management', incident: 'Incident Response', approvals: 'Approvals', configuration: 'Configuration', 'response-policies': 'Response Policies', 'user-management': 'User Management', 'audit-logs': 'Audit Logs', 'service-panel': 'Service Panel', settings: 'Settings', profile: 'Profile' };
    const routes = r.pages.map(p => [p, p.split('?')[0], p.includes('?view=health') ? 'System health' : null]);
    if (rname === 'admin') routes.push(['response-policies?view=catalogue', 'response-policies', 'Action catalogue'], ['service-panel?view=wazuh', 'service-panel', 'Wazuh'], ['service-panel?view=cortex', 'service-panel', 'Cortex'], ['service-panel?view=misp', 'service-panel', 'MISP']);
    const wrongTitles = [];
    for (const [path, base0, tab] of routes) {
      await page.goto(base + '/app/' + path);
      await page.waitForTimeout(200);
      const tabName = tab ?? (base0 === 'service-panel' ? 'Overview' : base0 === 'response-policies' ? 'Permissions' : null);
      const want = [tabName, names[base0], 'AthenaSec'].filter(Boolean).join(' · ');
      const got = await page.title();
      if (got !== want) wrongTitles.push(`${path}: "${got}" (want "${want}")`);
    }
    check(wname, 'a11y titles', `${rname}: every page sets its own title, "Page name · AthenaSec", with the tab in front on Service Panel and Response Policies (${routes.length} routes)`, wrongTitles.length === 0, wrongTitles.join(' ; ') || `${routes.length} routes`);
    if (rname === 'admin') {
      await page.goto(base + '/app/service-panel');
      await page.waitForTimeout(200);
      const seen = [await page.title()];
      for (const tabLabel of ['Wazuh', 'Cortex', 'MISP', 'System health', 'Overview']) {
        await page.click(`[role="tab"]:has-text("${tabLabel}")`);
        await page.waitForFunction(t => document.title.startsWith(t + ' ·'), tabLabel, { timeout: 3000 }).catch(() => {});
        seen.push(await page.title());
      }
      check(wname, 'a11y titles', 'admin: the title follows a tab change on Service Panel (Overview, Wazuh, Cortex, MISP, System health, Overview)', seen.join('|') === ['Overview', 'Wazuh', 'Cortex', 'MISP', 'System health', 'Overview'].map(t => `${t} · Service Panel · AthenaSec`).join('|'), seen.join(' | '));
    }

    await page.goto(base + '/app/dashboard');
    await page.waitForTimeout(300);
    await page.evaluate(() => { window.scrollTo(0, 0); const s = document.createElement('span'); s.id = '__t0'; s.tabIndex = 0; document.body.prepend(s); s.focus(); });
    const idleSkip = await page.evaluate(() => { const a = document.querySelector('a.skip-link'); const b = a.getBoundingClientRect(); return { text: a.textContent.trim(), bottom: Math.round(b.bottom) }; });
    await page.keyboard.press('Tab');
    const skipFocus = await page.evaluate(() => { const a = document.activeElement; const b = a.getBoundingClientRect(); const cs = getComputedStyle(a); return { isSkip: a.classList.contains('skip-link'), top: Math.round(b.top), left: Math.round(b.left), height: Math.round(b.height), outline: parseFloat(cs.outlineWidth), outlineStyle: cs.outlineStyle, vw: innerWidth }; });
    await page.keyboard.press('Enter');
    await page.waitForTimeout(100);
    const afterSkip = await page.evaluate(() => { document.getElementById('__t0')?.remove(); const a = document.activeElement; return { id: a.id, tag: a.tagName, hash: location.hash }; });
    check(wname, 'a11y skip link', `${rname}: the first Tab stop is a Skip to main content link, off screen until it has focus (bottom ${idleSkip.bottom}px before), then on screen at ${skipFocus.left},${skipFocus.top} and ${skipFocus.height}px tall with a visible focus ring`, idleSkip.text === 'Skip to main content' && idleSkip.bottom <= 0 && skipFocus.isSkip && skipFocus.top >= 0 && skipFocus.left >= 0 && skipFocus.height >= 40 && skipFocus.outline >= 2 && skipFocus.outlineStyle !== 'none', JSON.stringify({ idleSkip, skipFocus }));
    check(wname, 'a11y skip link', `${rname}: Enter on the skip link puts focus on main#main (tabindex -1) without changing the address`, afterSkip.id === 'main' && afterSkip.tag === 'MAIN' && afterSkip.hash === '', JSON.stringify(afterSkip));
    await page.keyboard.press('Tab');
    const afterMainTab = await page.evaluate(() => ({ inMain: !!document.activeElement.closest('main'), name: (document.activeElement.getAttribute('aria-label') || document.activeElement.textContent || '').trim().slice(0, 30) }));
    check(wname, 'a11y skip link', `${rname}: Tab after the skip link goes to the first control inside the page, not back to the header`, afterMainTab.inMain, JSON.stringify(afterMainTab));

    const navs = await page.evaluate(() => ({ all: [...document.querySelectorAll('nav')].map(n => n.getAttribute('aria-label')), main: document.querySelectorAll('nav[aria-label="Main"]').length, links: document.querySelectorAll('nav[aria-label="Main"] a.side-item').length, asides: [...document.querySelectorAll('aside')].filter(a => a.classList.contains('sidebar')).length, skipInsideNav: !!document.querySelector('nav .skip-link'), controls: document.querySelector('.sidebar-toggle')?.getAttribute('aria-controls'), target: document.querySelector('nav[aria-label="Main"]')?.id }));
    const navRole = await page.getByRole('navigation', { name: 'Main', includeHidden: true }).count();
    // F12: in one table or list no two buttons or links share an accessible name (the name carries the row identifier)
    const sameNames = [];
    const labelled = [];
    for (const [path] of routes) {
      await page.goto(base + '/app/' + path);
      await page.waitForTimeout(250);
      const found = await page.evaluate(() => {
        const nameOf = e => (e.getAttribute('aria-label') || e.innerText || e.textContent || '').replace(/\s+/g, ' ').trim();
        const dupes = [];
        let total = 0;
        for (const box of document.querySelectorAll('main table, main ul, main ol')) {
          const seen = new Map();
          for (const e of box.querySelectorAll('button, a[href]')) {
            if (e.getClientRects().length === 0 || e.closest('.visually-hidden')) continue;
            // A button in a labelled group (a row mode switch: "block_ip: how it runs") is named within its group
            const group = e.closest('[role="group"][aria-label]');
            const n = (group && box.contains(group) ? group.getAttribute('aria-label') + ' > ' : '') + nameOf(e);
            if (!nameOf(e)) continue;
            total++;
            seen.set(n, (seen.get(n) || 0) + 1);
          }
          for (const [n, c] of seen) if (c > 1) dupes.push(`${n} x${c}`);
        }
        // Label in name (WCAG 2.5.3): a visible label must still be inside an aria-label
        const lost = [...document.querySelectorAll('main td.actions-cell button, main .sp-card .btn, main .decision-actions .btn, main .task-link')].filter(e => e.getClientRects().length > 0 && e.getAttribute('aria-label') && e.innerText.trim() && !e.getAttribute('aria-label').toLowerCase().includes(e.innerText.trim().toLowerCase())).map(e => `${e.innerText.trim()} / ${e.getAttribute('aria-label')}`);
        return { dupes, total, lost };
      });
      if (found.dupes.length) sameNames.push(`${path}: ${found.dupes.slice(0, 6).join(', ')}`);
      if (found.lost.length) labelled.push(`${path}: ${found.lost.slice(0, 4).join(' ; ')}`);
    }
    check(wname, 'a11y names', `${rname}: in every table and list on its pages (${routes.length} routes) no two buttons or links share an accessible name`, sameNames.length === 0, sameNames.join(' | ') || 'all names unique');
    check(wname, 'a11y names', `${rname}: the row buttons, console buttons, decision buttons and task links named by F12 still contain their visible text (WCAG 2.5.3 Label in Name)`, labelled.length === 0, labelled.join(' | ') || 'all labels contain their text');
    if (rname === 'admin') {
      await page.goto(base + '/app/user-management');
      await page.waitForTimeout(250);
      const rowNames = await page.evaluate(() => { const row = [...document.querySelectorAll('main tbody tr')].find(r => !r.querySelector('[disabled]')); return row ? [...row.querySelectorAll('td.actions-cell button:not(.overflow-trigger)')].filter(b => b.getClientRects().length > 0).map(b => `${b.innerText.trim()} = ${b.getAttribute('aria-label')}`) : []; });
      await page.goto(base + '/app/service-panel?view=health');
      await page.waitForTimeout(250);
      const healthNames = await page.evaluate(() => [...document.querySelectorAll('main tbody tr')].slice(0, 1).flatMap(r => [...r.querySelectorAll('td.actions-cell button')].map(b => `${b.innerText.trim()} = ${b.getAttribute('aria-label')}`)));
      await page.goto(base + '/app/service-panel');
      await page.waitForTimeout(250);
      const consoleNames = await page.evaluate(() => [...document.querySelectorAll('.sp-card .btn')].map(b => b.getAttribute('aria-label')));
      check(wname, 'a11y names', 'admin: row buttons name their subject, visible text unchanged (User Management "View Name", "Edit user Name", "Reset Password for Name", "Delete user Name"; System health "View Service", "Check Service"; Service Panel "Open console for Service")', rowNames.length >= (wname === 'mobile' ? 1 : 2) && rowNames.every(n => / = (View|Edit user|Reset Password for|Suspend user|Activate user|Delete user) \S+/.test(n)) && healthNames.length >= 1 && healthNames.every(n => / = (View|Check) \S+/.test(n)) && consoleNames.length === 3 && consoleNames.every(n => /^Open console for \S+/.test(n)), JSON.stringify({ rowNames, healthNames, consoleNames }));
    }
    // F15, F16, F17, F24: every field on every page declares a name and autocomplete, email fields skip spellcheck,
    // placeholders end with an ellipsis, and no page-level field grabs focus when the page opens
    const fieldProblems = [];
    const typoProblems = [];
    let fieldTotal = 0;
    for (const [path] of routes) {
      await page.goto(base + '/app/' + path);
      await page.waitForTimeout(250);
      if (path === 'approvals') {
        await page.click('.queue-item >> nth=0');
        if (wname === 'mobile') await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
      }
      const found = await fieldFaults('body');
      fieldTotal += found.count;
      fieldProblems.push(...found.faults.map(f => `${path}: ${f}`));
      // F18 and F21: headings balance their lines; prose has curly quotes (code, ids and mono text are left alone)
      const typo = await page.evaluate(() => {
        const unbalanced = [...document.querySelectorAll('h1, h2, h3')].filter(h => h.getClientRects().length > 0 && !h.classList.contains('visually-hidden') && getComputedStyle(h).textWrap !== 'balance').map(h => h.textContent.trim().slice(0, 30));
        const straight = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          const el = n.parentElement;
          if (!el || el.closest('script, style, code, pre, .mono, textarea, input, [aria-hidden="true"], .visually-hidden') || el.getClientRects().length === 0) continue;
          if (/["']/.test(n.textContent.replace(/(\w)'(s|t|re|ve|ll|d|m)\b/gi, '$1').replace(/s'(?=\s|$|[.,;:])/gi, 's'))) straight.push(n.textContent.trim().slice(0, 60));
        }
        return { unbalanced, straight };
      });
      typoProblems.push(...typo.unbalanced.map(h => `${path}: heading "${h}" is not balanced`), ...typo.straight.slice(0, 3).map(s => `${path}: straight quote in "${s}"`));
    }
    check(wname, 'a11y forms', `${rname}: every field on its pages (${routes.length} routes, ${fieldTotal} fields) has a name and an autocomplete value, email fields turn spellcheck off, placeholders end with "…", and no page field has focus when the page opens`, fieldProblems.length === 0 && fieldTotal > 0, fieldProblems.slice(0, 8).join(' ; ') || `${fieldTotal} fields`);
    check(wname, 'a11y typography', `${rname}: on every page (${routes.length} routes) headings h1 to h3 balance their lines (text-wrap: balance) and the visible prose has no straight quotes or apostrophe-quotes (mono text, code and ids are not checked)`, typoProblems.length === 0, typoProblems.slice(0, 8).join(' ; ') || `${routes.length} routes`);
    // F19 and F20: the menu, dialogs and drawers contain overscroll and skip the double-tap delay; page controls are left alone
    await page.goto(base + '/app/dashboard');
    await page.waitForTimeout(250);
    const surfaces = await page.evaluate(() => {
      const css = (sel, prop) => { const e = document.querySelector(sel); return e ? getComputedStyle(e)[prop] : null; };
      return { sidebar: css('.sidebar', 'overscrollBehaviorY'), sidebarLink: css('.sidebar a.side-item', 'touchAction'), toggle: css('.sidebar-toggle', 'touchAction'), pageButton: css('main .btn, main button', 'touchAction') };
    });
    await page.click('.user-avatar');
    await page.click('.drop-item:has-text("Logout")');
    await page.waitForSelector('[role="dialog"]');
    const dialogCss = await page.evaluate(() => ({ modal: getComputedStyle(document.querySelector('[role="dialog"]')).overscrollBehaviorY, button: getComputedStyle(document.querySelector('[role="dialog"] button')).touchAction, backdrop: getComputedStyle(document.querySelector('.modal-backdrop')).touchAction }));
    await page.keyboard.press('Escape');
    check(wname, 'a11y typography', `${rname}: the menu and dialogs stop scrolling the page behind them (overscroll-behavior: contain) and their controls skip the double-tap zoom delay (touch-action: manipulation); buttons in the page itself are left as they were`, surfaces.sidebar === 'contain' && surfaces.sidebarLink === 'manipulation' && surfaces.toggle === 'manipulation' && surfaces.pageButton === 'auto' && dialogCss.modal === 'contain' && dialogCss.button === 'manipulation' && dialogCss.backdrop === 'manipulation', JSON.stringify({ surfaces, dialogCss }));
    await page.goto(base + '/app/profile');
    await page.waitForTimeout(250);
    const profileTokens = await page.evaluate(() => ['profileName', 'profileEmail', 'profileDepartment', 'profilePhone'].map(id => `${id}=${document.getElementById(id)?.getAttribute('autocomplete')}/${document.getElementById(id)?.getAttribute('spellcheck')}`).join(' '));
    check(wname, 'a11y forms', `${rname}: the Profile fields use the real autocomplete tokens (name, email, organization, tel) and the email field has spellcheck off`, profileTokens === 'profileName=name/null profileEmail=email/false profileDepartment=organization/null profilePhone=tel/null', profileTokens);

    // The walk after sign-in starts from the dashboard
    await page.goto(base + '/app/dashboard');
    await page.waitForTimeout(300);
    check(wname, 'a11y landmarks', `${rname}: the menu is one navigation landmark named Main (also on the phone, where it is the drawer), holding its links, and the menu button controls it`, navs.all.length === 1 && navs.main === 1 && navRole === 1 && navs.links >= 5 && navs.asides === 0 && navs.controls === navs.target, JSON.stringify({ ...navs, navRole }));
  }

  /*
    Tab through a page and check focus follows what's on screen: each
    stop is below the previous one, or on the same row and to its right.
    Also checks no CSS `order` reorders the auth layout.
  */
  async function readingOrder(wname, label) {
    // Start tabbing from the top of the document, not from whatever was last focused.
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      const start = document.createElement('span');
      start.id = '__tabStart';
      start.tabIndex = 0;
      document.body.prepend(start);
      start.focus();
    });
    const stops = [];
    for (let i = 0; i < 20; i++) {
      await page.keyboard.press('Tab');
      const s = await page.evaluate(() => {
        const el = document.activeElement;
        // Body, or wrapped back round to the start marker: the page is done
        if (!el || el === document.body || el.id === '__tabStart') return null;
        const r = el.getBoundingClientRect();
        return { name: (el.getAttribute('aria-label') || el.textContent || el.id || el.tagName).trim().slice(0, 30), top: r.top + window.scrollY, left: r.left, height: r.height };
      });
      if (!s || stops.some(p => p.name === s.name && p.top === s.top && p.left === s.left)) break;
      stops.push(s);
    }
    await page.evaluate(() => document.getElementById('__tabStart')?.remove());
    // Same row when vertical centres line up; otherwise the next stop must be lower.
    const backwards = [];
    for (let i = 1; i < stops.length; i++) {
      const a = stops[i - 1], b = stops[i];
      const ca = a.top + a.height / 2, cb = b.top + b.height / 2;
      const sameRow = Math.abs(ca - cb) < 12;
      if (sameRow ? b.left < a.left : cb < ca) backwards.push(`${a.name} -> ${b.name}`);
    }
    const reordered = await page.evaluate(() => [...document.querySelectorAll('.auth-split, .auth-split *')]
      .filter(el => getComputedStyle(el).order !== '0').map(el => el.className || el.tagName));
    const panels = await page.evaluate(() => {
      const [brand, panel] = [...document.querySelector('.auth-split').children].map(el => el.getBoundingClientRect());
      return { brandFirst: panel.left >= brand.right - 1 || panel.top >= brand.bottom - 1 };
    });
    check(wname, 'reading order', `${label}: keyboard focus follows the visual order`, stops.length >= 3 && backwards.length === 0, backwards.join(' ; ') || stops.map(s => s.name).join(' > '));
    check(wname, 'reading order', `${label}: brand panel comes first on screen and in the DOM, no CSS order`, panels.brandFirst && reordered.length === 0, JSON.stringify({ ...panels, reordered }));
  }

  const unlabeled = () => page.evaluate(() =>
    [...document.querySelectorAll('input, select, textarea, button')]
      .filter(el => el.getClientRects().length > 0)
      .filter(el => {
        if (el.tagName === 'BUTTON') return !el.textContent.trim() && !el.getAttribute('aria-label');
        return !el.labels?.length && !el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby');
      })
      .map(el => el.outerHTML.slice(0, 90)));

  const hOverflow = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

  // ---------- Approvals page helpers (policy phase C4a) ----------
  const APR_SCOPE = ':is([role="dialog"], .card.detail-panel)';
  const aprState = () => page.evaluate(() => {
    const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
    const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel');
    return {
      h1: t(document.querySelector('h1')),
      sub: t(document.querySelector('#approvalsSummary')),
      seg: [...document.querySelectorAll('.page.active .headline .segmented-option')].map(b => `${t(b)}:${b.getAttribute('aria-pressed')}`).join(' | '),
      rows: [...document.querySelectorAll('.approval-row')].map(li => ({
        id: li.querySelector('.queue-item')?.dataset.recordId, name: t(li.querySelector('.queue-name')), route: t(li.querySelector('.queue-route')),
        meta: t(li.querySelector('.queue-meta')), outcome: t(li.querySelector('[data-field="outcome"]')), state: t(li.querySelector('.queue-state')),
        link: li.querySelector('a')?.getAttribute('href') ?? null, linkText: t(li.querySelector('a')), pressed: li.querySelector('.queue-item')?.getAttribute('aria-pressed'),
      })),
      panel: scope && scope.querySelector('#approvalTitle') ? {
        id: scope.querySelector('[data-workspace-id]')?.dataset.workspaceId, title: t(scope.querySelector('#approvalTitle')),
        fields: Object.fromEntries(['request', 'requestedBy', 'decision', 'reason', 'policy', 'token', 'window', 'approvedAs'].map(n => [n, t(scope.querySelector(`.approval-facts [data-field="${n}"]`))])),
        form: !!scope.querySelector('[data-field="decisionForm"]'), radios: [...scope.querySelectorAll('.approval-choice')].map(t),
        refusal: t(scope.querySelector('[data-field="refusal"]')), message: t(scope.querySelector('[data-field="decisionMessage"]')),
        stage: scope.querySelector('.approval-steps')?.dataset.stage ?? null,
        steps: [...scope.querySelectorAll('.approval-step')].map(s => `${s.dataset.step}=${s.dataset.state}`).join(','),
        alternatives: scope.querySelectorAll('[data-field="alternatives"] li').length,
        links: [...scope.querySelectorAll('.workspace-actions a')].map(a => t(a)).join(' | '),
      } : null,
    };
  });
  // Watches the executor's steps after a decision: the stages seen in order, and the pulse on "Executing"
  const sampleStages = async (end = 'Done') => {
    const seen = [];
    let pulse = null;
    for (let i = 0; i < 100; i++) {
      const s = await page.evaluate(() => {
        const o = document.querySelector('.approval-steps');
        const dot = document.querySelector('.approval-step.current .approval-dot');
        return { stage: o?.dataset.stage ?? null, anim: dot ? getComputedStyle(dot).animationName : null };
      });
      if (s.stage && seen[seen.length - 1] !== s.stage) seen.push(s.stage);
      if (s.stage === 'Executing' && pulse === null) pulse = s.anim;
      if (s.stage === end) break;
      await page.waitForTimeout(40);
    }
    return { seen, pulse };
  };
  // Signs out through the account menu and the confirm dialog, then in again without a reload (a reload would reset the session)
  const signOutInApp = async () => {
    await page.click('.user-avatar');
    await page.click('.drop-item:has-text("Logout")');
    await page.waitForSelector('[role="dialog"]');
    // What the executor was doing at the moment of confirming: the step on screen, and the page's own busy / idle flag
    const atConfirm = await page.evaluate(() => ({ stage: document.querySelector('.approval-steps')?.dataset.stage ?? null, executor: document.querySelector('[data-page="approvals"]')?.dataset.executor ?? null }));
    await page.click('[role="dialog"] button:has-text("Sign Out")');
    await page.waitForURL('**/login');
    return atConfirm;
  };
  const signInInApp = async account => {
    await page.waitForSelector('#loginForm');
    await page.click(`.demo-account:has-text("${account.email}")`);
    await page.click('.login-submit');
    await page.waitForURL('**/mfa');
    await page.waitForSelector('.mfa-account dd.mono');
    const digits = page.locator('[data-mfa-digit]');
    for (let i = 0; i < 6; i++) await digits.nth(i).fill(String(i + 1));
    await page.click('button:has-text("Verify")');
    await page.waitForURL('**/app/dashboard');
    await page.waitForSelector('.sidebar .side-item', { state: 'attached' });
    await page.waitForTimeout(300);
  };
  const demoNow = () => page.evaluate(() => document.querySelector('[data-field="demoNow"]')?.textContent.trim() ?? null);
  const demoAdvance = async minutes => { await page.click(`[data-demo-panel] button:has-text("Advance ${minutes === 60 ? '1 h' : `${minutes} min`}")`); await page.waitForTimeout(120); };
  // In-app navigation through the sidebar (a reload would reset the session's approvals)
  const goSide = async (label, phone) => {
    if (phone) { await page.click('.sidebar-toggle'); await page.waitForTimeout(350); }
    await page.click(`.sidebar .side-item:has-text("${label}")`);
    await page.waitForTimeout(350);
  };
  const sideBadge = label => page.evaluate(text => [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === text)?.querySelector('.count')?.textContent ?? null, label);
  const bellLabel = () => page.evaluate(() => document.querySelector('.icon-btn')?.getAttribute('aria-label'));
  const sideBadgeApr = () => sideBadge('Approvals');

  // Click like a finger would: bring the element to mid-screen by scrolling the page only, then
  // click its centre. Playwright's locator.click() instead retries other scroll-into-view
  // alignments when the sticky mobile header covers the target, which also scrolls a pinned
  // cell's table sideways.
  async function tap(selector) {
    await page.evaluate(sel => {
      const el = document.querySelector(sel);
      window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 300, behavior: 'instant' });
    }, selector);
    await page.waitForTimeout(50);
    const box = await page.locator(selector).boundingBox();
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  }

  // Tab/Shift+Tab/Escape behaviour for whichever dialog is open.
  async function dialogKeyboard(width, label, openFn) {
    await openFn();
    await page.waitForSelector('[role="dialog"]');
    await page.waitForTimeout(150);
    const inside = () => page.evaluate(() => { const d = document.querySelector('[role="dialog"]'); return !!d && d.contains(document.activeElement); });
    check(width, 'C8 modal', `${label}: focus moves into dialog on open`, await inside());
    let escaped = 0;
    for (let i = 0; i < 25; i++) { await page.keyboard.press('Tab'); if (!(await inside())) escaped++; }
    check(width, 'C8 modal', `${label}: Tab x25 stays inside`, escaped === 0, `left dialog ${escaped} times`);
    let escapedBack = 0;
    for (let i = 0; i < 25; i++) { await page.keyboard.press('Shift+Tab'); if (!(await inside())) escapedBack++; }
    check(width, 'C8 modal', `${label}: Shift+Tab x25 stays inside`, escapedBack === 0, `left dialog ${escapedBack} times`);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
    const closed = await page.evaluate(() => !document.querySelector('[role="dialog"]'));
    check(width, 'C8 modal', `${label}: Escape closes`, closed);
    return closed;
  }

  // Attack path map: what each node should say (attack and status on sources, health on endpoints)
  const MAP_WORDS = {
    'src-203.0.113.45': ['Brute Force SSH', 'Awaiting approval'],
    'src-203.0.113.88': ['Password Spray', 'Open'],
    'src-198.51.100.77': ['SSH Probe', 'Closed'],
    'src-203.0.113.9': ['C2 Beaconing', 'Contained'],
    'src-10.0.2.18': ['Privilege Escalation', 'Open'],
    'src-10.0.7.51': ['Kernel Exploit Attempt', 'Closed'],
    'endpoint-01': ['At risk', null],
    'endpoint-03': ['At risk', null],
    'endpoint-09': ['Healthy', null],
    'endpoint-12': ['Isolated', null],
  };
  const mapWordsOk = ds => Object.entries(MAP_WORDS).every(([id, [caption, status]]) => {
    const node = ds.nodes.find(n => n.id === id);
    return node && node.caption === caption && (node.status ?? null) === status;
  });
  // Nodes that leave the canvas, and pairs of nodes that touch (isolated outline included)
  const mapLayout = () => page.evaluate(() => {
    const canvas = document.querySelector('.path-canvas').getBoundingClientRect();
    const nodes = [...document.querySelectorAll('.path-node')].map(n => {
      const r = n.getBoundingClientRect();
      const pad = n.classList.contains('isolated') ? 6 : 0;
      return { id: n.dataset.nodeId, left: r.left - pad, right: r.right + pad, top: r.top - pad, bottom: r.bottom + pad };
    });
    const hit = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
    return {
      spill: nodes.filter(r => r.left < canvas.left - 1 || r.right > canvas.right + 1 || r.top < canvas.top - 1 || r.bottom > canvas.bottom + 1).map(r => r.id),
      overlapping: nodes.flatMap((a, i) => nodes.slice(i + 1).filter(b => hit(a, b)).map(b => `${a.id}/${b.id}`)),
      canvasWidth: Math.round(canvas.width),
    };
  });

  /*
    List items on the list + detail pages (they replace the old tables, so
    these replace the pinned-column and clipping checks): every item is a
    button at least 40px tall, fully on screen and inside its list, with no
    text cut off, and exactly one is pressed.
  */
  const listGeometry = itemSel => page.evaluate(sel => {
    const vw = document.documentElement.clientWidth;
    const items = [...document.querySelectorAll(sel)].filter(el => el.getClientRects().length > 0);
    return {
      count: items.length,
      ids: items.map(el => el.dataset.recordId),
      notButtons: items.filter(el => el.tagName !== 'BUTTON').map(el => el.dataset.recordId),
      short: items.filter(el => el.getBoundingClientRect().height < 39.5).map(el => el.dataset.recordId),
      offscreen: items.filter(el => {
        const r = el.getBoundingClientRect();
        const box = el.closest('.card')?.getBoundingClientRect() ?? r;
        return r.left < -0.5 || r.right > vw + 0.5 || r.left < box.left - 0.5 || r.right > box.right + 0.5;
      }).map(el => el.dataset.recordId),
      // The item, or any text inside it, cut short
      // (text spilling out of the item, or cut by an inner overflow/ellipsis)
      // (Screen-reader-only text is clipped on purpose, so it is skipped.)
      clipped: items.filter(el => el.scrollWidth > el.clientWidth + 1 || [...el.querySelectorAll('span, p, strong')].some(t => !t.classList.contains('visually-hidden') && t.scrollWidth > t.clientWidth + 1 && getComputedStyle(t).overflowX !== 'visible')).map(el => el.dataset.recordId),
      pressed: items.filter(el => el.getAttribute('aria-pressed') === 'true').map(el => el.dataset.recordId),
      // Starts at its container's content edge (no stray list indent)
      indented: items.filter(el => {
        const holder = el.closest('ul')?.parentElement;
        if (!holder) return false;
        const cs = getComputedStyle(holder);
        const contentLeft = holder.getBoundingClientRect().left + parseFloat(cs.borderLeftWidth) + parseFloat(cs.paddingLeft);
        return el.getBoundingClientRect().left - contentLeft > 1;
      }).map(el => el.dataset.recordId),
    };
  }, itemSel);

  const listChecks = async (wname, area, itemSel, wantCount) => {
    const g = await listGeometry(itemSel);
    check(wname, area, `${wantCount} items, all buttons at least 40px tall`, g.count === wantCount && g.notButtons.length === 0 && g.short.length === 0, JSON.stringify(g));
    check(wname, area, 'every item fully on screen and inside its list, no text cut off', g.offscreen.length === 0 && g.clipped.length === 0, JSON.stringify({ offscreen: g.offscreen, clipped: g.clipped }));
    check(wname, area, 'exactly one item is pressed', g.pressed.length === 1, g.pressed.join(', ') || 'none');
    check(wname, area, 'items start at their list\'s edge (no stray indent)', g.indented.length === 0, g.indented.join(', '));
    return g;
  };

  // Dialogs fail the run if anything still uses window.alert/confirm.
  /*
    Everything runs with prefers-reduced-motion emulated, so a running
    animation can never keep an element "unstable" for Playwright's
    click (a rare 30s timeout on the dashboard's posture links). The
    dedicated "motion" checks switch to no-preference to read the
    animations, then go back to reduce.
  */
  await page.emulateMedia({ reducedMotion: 'reduce' });

  const nativeDialogs = [];
  page.on('dialog', async d => { nativeDialogs.push(d.message()); await d.dismiss(); });

  // ---------- One screen: Login and MFA fit common laptop sizes without scrolling ----------
  const scrollState = () => page.evaluate(() => {
    const doc = document.documentElement;
    const clipped = [doc, document.body, document.getElementById('root'), ...document.querySelectorAll('.auth-split, .auth-split > *')]
      .filter(Boolean)
      .filter(el => /hidden|clip/.test(getComputedStyle(el).overflowY) || /hidden|clip/.test(getComputedStyle(el).overflowX))
      .map(el => el.id || el.className || el.tagName);
    const panels = [...document.querySelectorAll('.auth-split > *')].map(el => Math.round(el.getBoundingClientRect().height));
    return { scrollHeight: doc.scrollHeight, viewport: window.innerHeight, clipped, panels };
  });
  for (const [vw, vh] of [[1280, 720], [1366, 768], [1440, 900]]) {
    const size = `${vw}x${vh}`;
    await page.setViewportSize({ width: vw, height: vh });
    await page.goto(base + '/login');
    await page.evaluate(() => localStorage.clear());
    await page.goto(base + '/login');
    await page.waitForSelector('#loginForm');
    await page.waitForTimeout(200);
    const loginFit = await scrollState();
    check(size, 'one screen', `Login fits ${size} with no vertical scroll, panels one screen tall`, loginFit.scrollHeight <= loginFit.viewport && loginFit.panels.every(p => p === vh), JSON.stringify(loginFit));
    const radarBeside = await page.evaluate(() => {
      const radar = document.querySelector('.radar').getBoundingClientRect();
      const headline = document.querySelector('.login-pitch h1').getBoundingClientRect();
      return headline.left >= radar.right - 1 && headline.top < radar.bottom && headline.bottom > radar.top;
    });
    check(size, 'one screen', `Login radar sits beside the headline at ${size}`, radarBeside);
    // Derived from the runs (policy phase C3b: one approved isolation of 1 minute, one run)
    const loginStats = await page.evaluate(() => [...document.querySelectorAll('.login-stats li')].map(li => [...li.children].map(c => c.textContent.trim()).join(' ')));
    check(size, 'login stats', `Login figures follow the data at ${size}: "1 min from exploit detected to host isolated", "1 of 1 responses completed", "10 services monitored in one console"`, loginStats[0] === '1 min from exploit detected to host isolated' && loginStats[1] === '1 of 1 responses completed' && loginStats[2] === '10 services monitored in one console' && loginStats.length === 3, loginStats.join(' | '));
    if (vw === 1280) await page.screenshot({ path: out + `login-${size}.png` });

    await page.click(`.demo-account:has-text("${roles.analyst.email}")`);
    await page.click('.login-submit');
    await page.waitForURL('**/mfa');
    await page.waitForSelector('#mfaForm');
    await page.waitForTimeout(200);
    const mfaFit = await scrollState();
    check(size, 'one screen', `MFA fits ${size} with no vertical scroll, panels one screen tall`, mfaFit.scrollHeight <= mfaFit.viewport && mfaFit.panels.every(p => p === vh), JSON.stringify(mfaFit));
    if (vw === 1280) await page.screenshot({ path: out + `mfa-${size}.png` });
  }

  // A very short window (or zoom) must still scroll, never clip
  await page.setViewportSize({ width: 1280, height: 480 });
  for (const route of ['login', 'mfa']) {
    if (route === 'login') {
      await page.goto(base + '/login');
    } else {
      await page.click(`.demo-account:has-text("${roles.analyst.email}")`);
      await page.click('.login-submit');
      await page.waitForURL('**/mfa');
    }
    await page.waitForTimeout(200);
    const short = await scrollState();
    check('1280x480', 'one screen', `${route}: a short window scrolls instead of clipping (no overflow: hidden)`, short.scrollHeight > short.viewport && short.clipped.length === 0, JSON.stringify(short));
  }

  // ---------- Attack path map at 1260px (the narrowest common laptop width checked) ----------
  // 1440 and 1280 get the same map checks in the main loop below.
  await page.setViewportSize({ width: 1260, height: 800 });
  await login(roles.analyst, '1260', 'analyst');
  await page.waitForTimeout(200);
  const layout1260 = await mapLayout();
  const words1260 = await page.evaluate(() => ({ nodes: [...document.querySelectorAll('.path-node')].map(b => ({ id: b.dataset.nodeId, caption: b.querySelector('.path-node-caption')?.textContent.trim(), status: b.querySelector('.path-node-status')?.textContent.trim() ?? null })) }));
  check('1260', 'dashboard', 'map: every node sits fully inside the map', layout1260.spill.length === 0, `${layout1260.spill.join(', ')} (canvas ${layout1260.canvasWidth}px)`);
  check('1260', 'dashboard', 'map: no node covers another', layout1260.overlapping.length === 0, `${layout1260.overlapping.join(', ')} (canvas ${layout1260.canvasWidth}px)`);
  check('1260', 'dashboard', 'map: source nodes show attack and status in words, endpoints their health', mapWordsOk(words1260), JSON.stringify(words1260.nodes.map(n => `${n.id}: ${n.caption} / ${n.status}`)));
  await page.screenshot({ path: out + 'analyst-dashboard-hero-1260.png' });

  // System health gauges at 1260px (the Service Panel's System health tab)
  await login(roles.admin, '1260', 'admin');
  await page.goto(base + '/app/service-panel?view=health');
  await page.waitForTimeout(300);
  check('1260', 'system health', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
  await page.screenshot({ path: out + 'admin-system-health-1260.png', fullPage: true });
  await page.goto(base + '/app/user-management');
  await page.waitForTimeout(300);
  check('1260', 'users', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
  await page.screenshot({ path: out + 'admin-users-1260.png', fullPage: true });
  await page.goto(base + '/app/audit-logs');
  await page.waitForTimeout(300);
  check('1260', 'audit', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
  await page.screenshot({ path: out + 'admin-audit-1260.png', fullPage: true });
  await page.goto(base + '/app/configuration');
  await page.waitForTimeout(300);
  check('1260', 'configuration', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
  await page.screenshot({ path: out + 'admin-configuration-1260.png', fullPage: true });
  await page.goto(base + '/app/settings');
  await page.waitForTimeout(300);
  check('1260', 'settings', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
  await page.screenshot({ path: out + 'admin-settings-1260.png', fullPage: true });

  for (const [wname, w, h] of [['desktop', 1440, 900], ['laptop', 1280, 800], ['mobile', 390, 844]]) {
    await page.setViewportSize({ width: w, height: h });

    // ---------- Login (C5, I10) ----------
    await page.goto(base + '/login');
    await page.evaluate(() => localStorage.clear());
    await page.goto(base + '/login');
    await page.waitForSelector('#loginForm');
    await page.waitForTimeout(250);
    await page.screenshot({ path: out + `login-${wname}.png`, fullPage: true });

    // I10: branding and head basics. Strict font check: Login renders all three
    // families, so after fonts.ready each must already be loaded (nothing forced).
    const head = await page.evaluate(async () => {
      await document.fonts.ready;
      const family = sel => { const el = document.querySelector(sel); return el ? getComputedStyle(el).fontFamily : 'missing'; };
      return {
        title: document.title,
        icon: document.querySelector('link[rel="icon"]')?.getAttribute('href'),
        description: !!document.querySelector('meta[name="description"]')?.content,
        themeColor: document.querySelector('meta[name="theme-color"]')?.content,
        plexLoaded: document.fonts.check('400 16px "IBM Plex Sans"') && document.fonts.check('600 16px "IBM Plex Sans"'),
        archivoLoaded: document.fonts.check('800 16px "Archivo Variable"'),
        monoLoaded: document.fonts.check('400 16px "IBM Plex Mono"'),
        bodyFont: getComputedStyle(document.body).fontFamily,
        headlineFont: family('.login-pitch h1'),
        demoEmailFont: family('.demo-email'),
        brandMark: !!document.querySelector('.auth-logo svg.brand-mark path'),
        externalFontCss: [...document.querySelectorAll('link[rel="stylesheet"], link[rel="preconnect"]')].map(l => l.href).filter(h => !h.startsWith(location.origin)),
        fontFiles: performance.getEntriesByType('resource').map(e => e.name).filter(n => /\.(woff2?|ttf|otf)(\?|$)/.test(n)),
      };
    });
    check(wname, 'I10 brand', 'title is "Sign in · AthenaSec" on Login (was "frontend"; "AthenaSec" before page titles)', head.title === 'Sign in · AthenaSec', head.title);
    check(wname, 'I10 brand', 'favicon is the AthenaSec mark', head.icon === '/athenasec-mark.svg', head.icon);
    check(wname, 'I10 brand', 'meta description and theme-color set', head.description && head.themeColor === '#120607', head.themeColor);
    check(wname, 'I10 brand', 'IBM Plex Sans loaded (400 and 600) and is the body font', head.plexLoaded && head.bodyFont.startsWith('"IBM Plex Sans"'), head.bodyFont);
    check(wname, 'I10 brand', 'Archivo 800 and IBM Plex Mono already loaded on Login (strict, nothing forced)', head.archivoLoaded && head.monoLoaded, JSON.stringify({ archivo: head.archivoLoaded, mono: head.monoLoaded }));
    check(wname, 'I10 brand', 'Login headline is Archivo, demo emails are IBM Plex Mono', head.headlineFont.startsWith('"Archivo Variable"') && head.demoEmailFont.startsWith('"IBM Plex Mono"'), JSON.stringify({ headline: head.headlineFont, demo: head.demoEmailFont }));
    check(wname, 'I10 brand', 'fonts are self-hosted: no Google Fonts links, font files from this origin', head.externalFontCss.length === 0 && head.fontFiles.every(f => f.startsWith(base)), JSON.stringify({ external: head.externalFontCss, files: head.fontFiles.map(f => f.split('/').pop()) }));
    check(wname, 'I10 brand', 'Inter is gone: no Inter font file requested', !head.fontFiles.some(f => /inter-/i.test(f.split('/').pop())), head.fontFiles.map(f => f.split('/').pop()).join(', '));
    check(wname, 'I10 brand', 'Login shows the AthenaSec shield mark', head.brandMark);

    const loginLayout = await page.evaluate(() => {
      const visible = el => el.getClientRects().length > 0;
      const short = [...document.querySelectorAll('.auth-split button, .auth-split a, .auth-split input:not([type="checkbox"]), .auth-split label.check-row')]
        .filter(visible).filter(el => el.getBoundingClientRect().height < 43.5).map(el => `${(el.textContent || el.id).trim().slice(0, 20)}=${el.getBoundingClientRect().height.toFixed(1)}`);
      const demo = document.querySelector('.demo-panel');
      return {
        short,
        demoLabel: document.querySelector('#demoModeTitle')?.textContent.trim(),
        demoLabelled: demo?.getAttribute('aria-labelledby') === 'demoModeTitle',
        demoButtons: document.querySelectorAll('.demo-account').length,
        // An email on more than one line has been broken mid-address
        brokenEmails: [...document.querySelectorAll('.demo-email')].filter(e => e.getClientRects().length > 1 || e.getBoundingClientRect().height > parseFloat(getComputedStyle(e).lineHeight) * 1.5).map(e => e.textContent),
        emailTop: Math.round(document.querySelector('#loginEmail').getBoundingClientRect().top),
      };
    });
    check(wname, 'C5 login', 'Demo mode panel is labelled "Demo mode" and offers both accounts', loginLayout.demoLabel === 'Demo mode' && loginLayout.demoLabelled && loginLayout.demoButtons === 2, JSON.stringify(loginLayout));
    check(wname, 'C5 login', 'Demo mode emails stay on one line', loginLayout.brokenEmails.length === 0, loginLayout.brokenEmails.join(', '));
    check(wname, 'C5 login', 'every Login control is at least 44px tall', loginLayout.short.length === 0, loginLayout.short.join(', '));
    check(wname, 'C5 login', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
    if (wname === 'mobile') check(wname, 'C5 login', 'the email field is on the first screen', loginLayout.emailTop < h, `top ${loginLayout.emailTop}px of ${h}px`);
    await readingOrder(wname, 'Login');

    // Wrong credentials: an announced error, still on /login
    await page.fill('#loginEmail', roles.analyst.email);
    await page.fill('#loginPassword', 'wrong-password');
    await page.click('.login-submit');
    await page.waitForTimeout(150);
    const loginError = await page.evaluate(() => ({ role: document.querySelector('#loginError')?.getAttribute('role'), text: document.querySelector('#loginError')?.textContent.trim(), path: location.pathname }));
    check(wname, 'C5 login', 'wrong password shows an alert-role error and stays on Login', loginError.role === 'alert' && loginError.text === 'Invalid email or password' && loginError.path === '/login', JSON.stringify(loginError));

    // Demo mode buttons reflect which account fills the form
    await page.click(`.demo-account:has-text("${roles.admin.email}")`);
    const pressed = await page.evaluate(() => [...document.querySelectorAll('.demo-account')].map(b => b.getAttribute('aria-pressed')));
    check(wname, 'C5 login', 'the chosen Demo mode account is aria-pressed, the other is not', pressed.join(',') === 'false,true', pressed.join(','));

    // Radar motion respects prefers-reduced-motion
    const radarMotion = () => page.evaluate(() => ['.radar-sweep', '.radar-ping'].map(sel => getComputedStyle(document.querySelector(sel)).animationName));
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const moving = await radarMotion();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const still = await radarMotion();
    if (wname === 'desktop') await page.screenshot({ path: out + 'login-reduced-motion-desktop.png' });
    check(wname, 'motion', 'radar sweep and pings animate by default', moving[0] === 'radarSweep' && moving[1] === 'radarPing', moving.join(','));
    check(wname, 'motion', 'radar sweep and pings stop with prefers-reduced-motion', still.every(a => a === 'none'), still.join(','));

    // Typing the credentials by hand still works
    await page.fill('#loginEmail', roles.analyst.email);
    await page.fill('#loginPassword', roles.analyst.pw);
    await page.click('.login-submit');
    await page.waitForURL('**/mfa');

    // ---------- MFA (C6, I6) ----------
    await page.waitForSelector('#mfaForm');
    await page.waitForTimeout(250);
    await page.screenshot({ path: out + `mfa-${wname}.png`, fullPage: true });
    const mfa = await page.evaluate(() => {
      const inputs = [...document.querySelectorAll('[data-mfa-digit]')];
      const vw = document.documentElement.clientWidth;
      const form = document.querySelector('#mfaForm').getBoundingClientRect();
      return {
        allInside: inputs.every(i => i.getBoundingClientRect().right <= vw && i.getBoundingClientRect().left >= 0),
        formInside: form.right <= vw && form.left >= 0,
        labels: inputs.map(i => i.getAttribute('aria-label')),
        inputMode: inputs.every(i => i.inputMode === 'numeric'),
      };
    });
    check(wname, 'C6 MFA', 'all 6 digit boxes inside viewport', mfa.allInside);
    check(wname, 'C6 MFA', 'form card inside viewport', mfa.formInside);
    check(wname, 'C6 MFA', 'no horizontal page overflow', (await hOverflow()) <= 0, await hOverflow());
    check(wname, 'I6 labels', 'MFA digits labelled 1-6', mfa.labels.join('|') === [1,2,3,4,5,6].map(n => `Digit ${n} of 6`).join('|'), mfa.labels.join('|'));
    check(wname, 'I6 labels', 'MFA digits use numeric keypad', mfa.inputMode);

    // I9: "Resend code" shows an inline, announced message instead of window.alert
    const dialogsBefore = nativeDialogs.length;
    await page.click('[data-action="resend-code"]');
    await page.waitForTimeout(200);
    const resend = await page.evaluate(() => {
      const el = [...document.querySelectorAll('#mfaForm [role="status"]')].find(e => e.textContent.trim());
      return el && { text: el.textContent.trim(), live: el.getAttribute('aria-live') };
    });
    check(wname, 'I9 dev notes', 'Resend code: no native alert dialog', nativeDialogs.length === dialogsBefore, nativeDialogs.slice(dialogsBefore).join(' | '));
    check(wname, 'I9 dev notes', 'Resend code: inline polite status message', resend && resend.live === 'polite', JSON.stringify(resend));

    // MFA design details: digits in Plex Mono, the shield emblem, demo code from data
    const mfaDetails = await page.evaluate(() => ({
      digitFont: getComputedStyle(document.querySelector('[data-mfa-digit]')).fontFamily,
      emblem: !!document.querySelector('.mfa-emblem .mfa-shield'),
      fieldset: document.querySelector('[data-mfa-digit]')?.closest('fieldset')?.querySelector('legend')?.textContent.trim(),
      firstAutocomplete: document.querySelector('[data-mfa-digit]')?.getAttribute('autocomplete'),
      demoNote: document.querySelector('.demo-inline')?.textContent.replace(/\s+/g, ' ').trim(),
      accountOneLine: (() => { const dd = document.querySelector('.mfa-account dd.mono'); return !!dd && dd.getBoundingClientRect().height <= parseFloat(getComputedStyle(dd).lineHeight) * 1.5; })(),
      short: [...document.querySelectorAll('.auth-split button, .auth-split a, .auth-split input')]
        .filter(el => el.getClientRects().length > 0 && el.getBoundingClientRect().height < 43.5)
        .map(el => `${(el.textContent || el.getAttribute('aria-label')).trim().slice(0, 20)}=${el.getBoundingClientRect().height.toFixed(1)}`),
    }));
    check(wname, 'C6 MFA', 'digits are IBM Plex Mono, grouped in a fieldset with a legend', mfaDetails.digitFont.startsWith('"IBM Plex Mono"') && mfaDetails.fieldset === 'Authentication code', JSON.stringify(mfaDetails));
    check(wname, 'C6 MFA', 'first digit offers one-time-code autofill', mfaDetails.firstAutocomplete === 'one-time-code', mfaDetails.firstAutocomplete);
    check(wname, 'C6 MFA', 'shield emblem is in the page', mfaDetails.emblem);
    check(wname, 'C6 MFA', 'account email stays on one line', mfaDetails.accountOneLine);
    check(wname, 'C6 MFA', 'Demo mode note shows the code', mfaDetails.demoNote === 'Demo mode Use code 123456.', mfaDetails.demoNote);
    check(wname, 'C6 MFA', 'every MFA control is at least 44px tall', mfaDetails.short.length === 0, mfaDetails.short.join(', '));
    await readingOrder(wname, 'MFA');

    // Rings respect prefers-reduced-motion
    const ringMotion = () => page.evaluate(() => [...document.querySelectorAll('.mfa-ring')].map(g => getComputedStyle(g).animationName));
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const ringsMoving = await ringMotion();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const ringsStill = await ringMotion();
    check(wname, 'motion', 'MFA rings spin by default and stop with prefers-reduced-motion', ringsMoving.length === 2 && ringsMoving.every(a => a === 'authSpin') && ringsStill.every(a => a === 'none'), `${ringsMoving.join(',')} / ${ringsStill.join(',')}`);

    // A wrong code shows an announced error
    const digitBoxes = page.locator('[data-mfa-digit]');
    for (let i = 0; i < 6; i++) await digitBoxes.nth(i).fill('9');
    await page.click('button:has-text("Verify")');
    await page.waitForTimeout(150);
    const mfaError = await page.evaluate(() => ({ role: document.querySelector('#mfaError')?.getAttribute('role'), text: document.querySelector('#mfaError')?.textContent.trim(), path: location.pathname }));
    check(wname, 'C6 MFA', 'wrong code shows an alert-role error and stays on MFA', mfaError.role === 'alert' && mfaError.text === 'Invalid authentication code' && mfaError.path === '/mfa', JSON.stringify(mfaError));

    // Pasted or autofilled code fills all six boxes (was: only the last digit kept)
    for (let i = 0; i < 6; i++) await digitBoxes.nth(i).fill('');
    await digitBoxes.first().fill('123456');
    await page.waitForTimeout(100);
    const spread = await page.evaluate(() => ({ values: [...document.querySelectorAll('[data-mfa-digit]')].map(i => i.value).join(''), focused: document.activeElement?.getAttribute('aria-label') }));
    check(wname, 'C6 MFA', 'a pasted or autofilled code fills all 6 boxes, focus on the last', spread.values === '123456' && spread.focused === 'Digit 6 of 6', JSON.stringify(spread));

    // Non-digits are rejected, and fast typing never leaves two digits in a box
    const boxState = () => page.evaluate(() => ({
      values: [...document.querySelectorAll('[data-mfa-digit]')].map(i => i.value),
      focused: document.activeElement?.getAttribute('aria-label'),
    }));
    const singleDigits = s => s.values.every(v => /^\d?$/.test(v));
    const clearBoxes = async () => { for (let i = 5; i >= 0; i--) await digitBoxes.nth(i).fill(''); };
    const junk = ['a', ' ', '-', 'e', '+'];

    await clearBoxes();
    await digitBoxes.nth(0).focus();
    for (const key of junk) await page.keyboard.type(key);
    let st = await boxState();
    check(wname, 'C6 MFA', 'letters, spaces and symbols are rejected in an empty box (stays empty, focus stays)', st.values[0] === '' && st.focused === 'Digit 1 of 6' && singleDigits(st), JSON.stringify(st));

    await digitBoxes.nth(0).fill('4');
    await digitBoxes.nth(0).focus();
    for (const key of junk) await page.keyboard.type(key);
    st = await boxState();
    check(wname, 'C6 MFA', 'letters, spaces and symbols on a filled box keep its digit', st.values[0] === '4' && singleDigits(st), JSON.stringify(st));

    await digitBoxes.nth(1).fill('abc');
    st = await boxState();
    check(wname, 'C6 MFA', 'pasting text with no digits changes nothing', st.values.join('') === '4' && singleDigits(st), JSON.stringify(st));

    await clearBoxes();
    await digitBoxes.nth(0).fill('12-34 56');
    st = await boxState();
    check(wname, 'C6 MFA', 'a pasted code with separators keeps only its digits', st.values.join('') === '123456' && singleDigits(st), JSON.stringify(st));

    await clearBoxes();
    await digitBoxes.nth(0).focus();
    await page.keyboard.type('123456');
    st = await boxState();
    check(wname, 'C6 MFA', 'fast typing fills one digit per box, focus on box 6', st.values.join('|') === '1|2|3|4|5|6' && st.focused === 'Digit 6 of 6', JSON.stringify(st));

    await page.keyboard.type('78');
    st = await boxState();
    check(wname, 'C6 MFA', 'typing past the last box keeps one digit there (the newest)', st.values.join('|') === '1|2|3|4|5|8' && singleDigits(st), JSON.stringify(st));

    await digitBoxes.nth(2).click();
    await page.keyboard.type('9');
    st = await boxState();
    check(wname, 'C6 MFA', 'typing over a filled box replaces it with one digit and moves on', st.values.join('|') === '1|2|9|4|5|8' && st.focused === 'Digit 4 of 6' && singleDigits(st), JSON.stringify(st));

    // "Use a different account" goes back to Login
    await page.click('.auth-back');
    await page.waitForURL('**/login');
    check(wname, 'C6 MFA', '"Use a different account" returns to Login', page.url().endsWith('/login'), page.url());

    for (const [rname, r] of Object.entries(roles)) {
      await login(r, wname, rname);

      // ---------- Sidebar (C1-C3) ----------
      const sb = await page.evaluate(() => {
        const s = document.querySelector('.sidebar').getBoundingClientRect();
        const t = document.querySelector('.sidebar-toggle');
        return {
          visible: s.right > 0 && getComputedStyle(document.querySelector('.sidebar')).visibility === 'visible',
          toggleShown: getComputedStyle(t).display !== 'none',
          width: Math.round(s.width),
          title: document.querySelector('.sidebar .side-title')?.textContent.trim(),
          links: [...document.querySelectorAll('.sidebar .side-item')].map(a => a.querySelector('.side-label')?.textContent.trim()),
          withIcon: [...document.querySelectorAll('.sidebar .side-item')].filter(a => a.querySelector('svg.side-icon path[d]')).length,
          current: [...document.querySelectorAll('.sidebar .side-item[aria-current="page"]')].map(a => a.querySelector('.side-label')?.textContent.trim()),
          // Measured with the drawer's visibility forced on so phones are checked too
          truncated: (() => {
            const s = document.querySelector('.sidebar');
            const prev = s.style.visibility;
            s.style.visibility = 'visible';
            const cut = [...s.querySelectorAll('.side-label')].filter(l => l.scrollWidth > l.clientWidth + 1).map(l => l.textContent.trim());
            s.style.visibility = prev;
            return cut;
          })(),
          counts: [...document.querySelectorAll('.sidebar .side-item')].map(a => [a.querySelector('span').textContent, a.querySelector('.count')?.textContent ?? null]),
        };
      });
      // Exact items and order from DESIGN-SPEC.md
      const spec = rname === 'admin'
        ? { title: 'Security management', links: ['Dashboard', 'Configuration', 'Response Policies', 'Approvals', 'User Management', 'Audit Logs', 'Service Panel', 'Settings'] }
        : { title: 'Analyst', links: ['Dashboard', 'Alerts', 'Case Management', 'Incident Response', 'Approvals'] };
      check(wname, 'C1 nav', `${rname}: menu items exactly match the spec, in order`, sb.links.join('|') === spec.links.join('|'), sb.links.join(', '));
      check(wname, 'C1 nav', `${rname}: group label is "${spec.title}"`, sb.title === spec.title, sb.title);
      check(wname, 'C1 nav', `${rname}: every item has an icon`, sb.withIcon === spec.links.length, `${sb.withIcon}/${spec.links.length}`);
      check(wname, 'C1 nav', `${rname}: no menu label is cut off`, sb.truncated.length === 0, sb.truncated.join(', '));
      check(wname, 'C1 nav', `${rname}: only Dashboard is aria-current="page" on the dashboard`, sb.current.join('|') === 'Dashboard', sb.current.join(', ') || 'none');
      if (w > 1024) check(wname, 'C1 nav', `${rname}: sidebar is 220px wide`, sb.width === 220, `${sb.width}px`);
      if (w > 1024) {
        check(wname, 'C2 sidebar', `${rname}: sidebar visible without clicking`, sb.visible);
        check(wname, 'C2 sidebar', `${rname}: hamburger hidden`, !sb.toggleShown);
      } else {
        check(wname, 'C2 sidebar', `${rname}: sidebar hidden by default`, !sb.visible);
        check(wname, 'C2 sidebar', `${rname}: hamburger shown`, sb.toggleShown);
        await page.click('.sidebar-toggle');
        await page.waitForTimeout(400);
        const open = await page.evaluate(() => ({
          sidebar: document.querySelector('.sidebar').getBoundingClientRect().left >= 0,
          backdrop: getComputedStyle(document.querySelector('.sidebar-backdrop')).opacity === '1',
          expanded: document.querySelector('.sidebar-toggle').getAttribute('aria-expanded'),
          label: document.querySelector('.sidebar-toggle').getAttribute('aria-label'),
          isOpenClass: document.querySelector('.sidebar-toggle').classList.contains('is-open'),
        }));
        await page.screenshot({ path: out + `${rname}-menu-open-mobile.png` });
        check(wname, 'C3 drawer', `${rname}: drawer opens`, open.sidebar);
        check(wname, 'C3 drawer', `${rname}: backdrop dims page`, open.backdrop);
        check(wname, 'C3 drawer', `${rname}: aria-expanded=true, label "Close", X icon`, open.expanded === 'true' && open.label === 'Close navigation menu' && open.isOpenClass, JSON.stringify(open));
        await page.keyboard.press('Escape');
        await page.waitForTimeout(400);
        check(wname, 'C3 drawer', `${rname}: Escape closes drawer`, await page.evaluate(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 0));
        await page.click('.sidebar-toggle');
        await page.waitForTimeout(400);
        // Inside the page, clear of the drawer and of the 15px scrollbar gutter.
        await page.mouse.click(w - 40, h - 20);
        await page.waitForTimeout(400);
        check(wname, 'C3 drawer', `${rname}: backdrop click closes drawer`, await page.evaluate(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 0));
      }
      if (rname === 'admin') {
        // One badge for the one service inventory: Service Panel counts every service that needs attention
        const healthEntry = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].some(a => a.querySelector('.side-label')?.textContent.trim() === 'System Health'));
        check(wname, 'I1 counts', 'there is no System Health entry (it is a tab of Service Panel), so the one badge sits on Service Panel', !healthEntry, String(healthEntry));
        const panel = sb.counts.find(c => c[0] === 'Service Panel')?.[1];
        const panelLabel = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Service Panel')?.querySelector('.count')?.getAttribute('aria-label'));
        check(wname, 'I1 counts', 'Service Panel badge = 2 (Ollama Runtime degraded, Wazuh Dashboard starting), labelled "2 services need attention"', panel === '2' && panelLabel === '2 services need attention', `${panel} / ${panelLabel}`);
      } else {
        const alerts = sb.counts.find(c => c[0] === 'Alerts')?.[1];
        const cases = sb.counts.find(c => c[0] === 'Case Management')?.[1];
        check(wname, 'I1 counts', 'Alerts badge = 4 open alerts (ALT-001, ALT-002, ALT-003, ALT-006)', alerts === '4', alerts);
        check(wname, 'I1 counts', 'Cases badge = 2 open cases (was 3)', cases === '2', cases);
      }

      // ---------- Status (C9) ----------
      const status = await page.evaluate(() => {
        const widget = document.querySelector('.system-status-widget');
        const link = widget.querySelector('a');
        const short = widget.querySelector('.status-short');
        const full = widget.querySelector('.status-text');
        return {
          text: full?.textContent.trim(),
          label: widget.getAttribute('aria-label'),
          role: widget.getAttribute('role'),
          href: link?.getAttribute('href') ?? null,
          shortText: short?.textContent.trim(),
          shortVisible: !!short && short.getBoundingClientRect().width > 0,
          fullVisible: !!full && full.getBoundingClientRect().width > 1,
        };
      });
      check(wname, 'C9 status', `${rname}: top bar counts the services needing attention ("2 services need attention")`, status.text === '2 services need attention' && /Attention Required/.test(status.label || '') && status.role === 'status', JSON.stringify(status));
      if (rname === 'admin') {
        check(wname, 'C9 status', 'admin: status links to the System health tab', status.href === '/app/service-panel?view=health', status.href);
      } else {
        check(wname, 'C9 status', 'analyst: status is not a link (the System health tab is admin-only)', status.href === null, status.href);
      }
      if (w <= 1180) {
        check(wname, 'C9 status', `${rname}: short status label "2 need attention" is visible (not screen-reader-only)`, status.shortVisible && status.shortText === '2 need attention', JSON.stringify(status));
      } else {
        check(wname, 'C9 status', `${rname}: full status line is visible`, status.fullVisible && !status.shortVisible, JSON.stringify(status));
      }
      const dot = await page.evaluate(() => getComputedStyle(document.querySelector('.status-indicator')).backgroundColor);
      check(wname, 'C9 status', `${rname}: degraded dot uses the design's yellow, not green`, dot === 'rgb(244, 193, 82)', dot);

      // ---------- Top bar (threat meter, bell, account, control sizes) ----------
      const bar = await page.evaluate(() => {
        const meter = document.querySelector('.threat-meter');
        const visible = el => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
        const controls = [...document.querySelectorAll('.topbar button, .topbar input, .topbar a, .sidebar-toggle')].filter(visible);
        const meta = document.querySelector('.user-avatar .user-meta');
        return {
          meterLabel: meter?.getAttribute('aria-label'),
          meterRole: meter?.getAttribute('role'),
          lit: document.querySelectorAll('.threat-segment.on').length,
          segments: document.querySelectorAll('.threat-segment').length,
          level: document.querySelector('.threat-label')?.textContent.trim(),
          bell: document.querySelector('.icon-btn')?.getAttribute('aria-label'),
          metaVisible: !!meta && visible(meta) && meta.getBoundingClientRect().width > 0,
          metaText: meta?.innerText.replace(/\s+/g, ' ').trim(),
          short: controls.filter(c => c.getBoundingClientRect().height < 43.5).map(c => `${c.className || c.tagName}=${c.getBoundingClientRect().height.toFixed(1)}`),
        };
      });
      // Open alerts (ALT-001 critical 3, ALT-003 medium 1, ALT-006 critical 3) plus failed containment (ALT-002 high 2) = 9
      check(wname, 'top bar', `${rname}: threat meter shows Severe, 5 of 5 lit (open alerts + failed containment)`, bar.lit === 5 && bar.segments === 5 && bar.level === 'Severe' && bar.meterRole === 'img' && bar.meterLabel === 'Threat level: Severe, 5 of 5', JSON.stringify(bar));
      // Policy phase C4a: the bell gains "Approval needed" for ALT-001's pending block (both roles can decide it)
      const unread = 3;
      check(wname, 'top bar', `${rname}: bell says "${unread} unread"`, bar.bell === `Notifications, ${unread} unread`, bar.bell);
      if (w >= 1440) {
        const want = rname === 'admin' ? 'System Administrator Administrator' : 'Analyst A Security analyst';
        check(wname, 'top bar', `${rname}: account pill shows name and role`, bar.metaVisible && bar.metaText === want, bar.metaText);
      }
      check(wname, 'top bar', `${rname}: every top bar control is at least 44px tall`, bar.short.length === 0, bar.short.join(', '));

      // ---------- Search shortcuts: Ctrl+K and "/", one handler only ----------
      const blurAll = () => page.evaluate(() => document.activeElement?.blur());
      const searchFocused = () => page.evaluate(() => document.activeElement?.id === 'globalSearch');
      await blurAll();
      await page.keyboard.press('Control+k');
      check(wname, 'shortcut', `${rname}: Ctrl+K focuses the search`, await searchFocused());
      await blurAll();
      await page.keyboard.press('/');
      const afterSlash = await page.evaluate(() => ({ focused: document.activeElement?.id === 'globalSearch', value: document.querySelector('#globalSearch').value }));
      check(wname, 'shortcut', `${rname}: "/" focuses the search without typing a slash`, afterSlash.focused && afterSlash.value === '', JSON.stringify(afterSlash));
      await page.keyboard.press('Escape');
      await blurAll();

      // "/" typed in another field stays in that field
      const otherField = 'main input.field-input';
      // The analyst dashboard has no field of its own; use the Alerts search box
      const borrowedField = rname === 'analyst' && !(await page.locator(otherField).count());
      if (borrowedField) {
        await page.goto(base + '/app/alerts');
        await page.waitForTimeout(250);
      }
      if (rname === 'analyst' || await page.locator(otherField).count()) {
        const field = page.locator(otherField).first();
        await field.click();
        await page.keyboard.type('a/b');
        const typed = await page.evaluate(sel => ({ value: document.querySelector(sel).value, stayed: document.activeElement === document.querySelector(sel) }), otherField);
        check(wname, 'shortcut', `${rname}: "/" typed in another field stays in that field`, typed.value === 'a/b' && typed.stayed, JSON.stringify(typed));
        await field.fill('');
        await blurAll();
      }
      if (borrowedField) {
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(250);
      }

      // Exactly one listener reacts to the shortcut
      const handlers = await page.evaluate(() => {
        const live = window.__keydownListeners || [];
        let focusing = 0;
        for (const { target, fn } of live) {
          document.activeElement?.blur();
          const ev = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true, cancelable: true });
          try { typeof fn === 'function' ? fn.call(target, ev) : fn.handleEvent(ev); } catch { /* not ours */ }
          if (document.activeElement?.id === 'globalSearch') focusing++;
        }
        document.activeElement?.blur();
        return { listeners: live.length, focusing };
      });
      check(wname, 'shortcut', `${rname}: exactly one keydown handler opens the search`, handlers.focusing === 1, JSON.stringify(handlers));

      // Neither shortcut fires while a dialog is open
      await page.click('.user-avatar');
      await page.click('.drop-item:has-text("Logout")');
      await page.waitForSelector('[role="dialog"]');
      await page.waitForTimeout(150);
      const openFocus = await page.evaluate(() => document.activeElement?.textContent.trim());
      check(wname, 'C8 modal', `${rname}: Logout dialog opens with focus on Cancel`, openFocus === 'Cancel', openFocus);
      await page.keyboard.press('Control+k');
      await page.keyboard.press('/');
      const inDialog = await page.evaluate(() => !!document.querySelector('[role="dialog"]')?.contains(document.activeElement));
      check(wname, 'shortcut', `${rname}: shortcuts don't fire while a dialog is open`, inDialog);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(200);
      const afterCancel = await page.evaluate(() => ({
        menuOpen: document.querySelector('.user-avatar').getAttribute('aria-expanded') === 'true',
        menuRendered: !!document.querySelector('.top-actions .dropdown'),
        focusOnAccount: document.activeElement === document.querySelector('.user-avatar'),
      }));
      check(wname, 'top bar', `${rname}: cancelling Logout closes the account menu and returns focus to the account button`, !afterCancel.menuOpen && !afterCancel.menuRendered && afterCancel.focusOnAccount, JSON.stringify(afterCancel));

      // Every notification opens a page this role can reach (no redirect to the dashboard)
      const reachable = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].map(a => a.getAttribute('href')));
      const notifCount = await (async () => {
        await page.click('.icon-btn');
        const n = await page.locator('.top-actions .dropdown .drop-item').count();
        await page.click('.icon-btn');
        return n;
      })();
      const landings = [];
      for (let i = 0; i < notifCount; i++) {
        await page.click('.icon-btn');
        const item = page.locator('.top-actions .dropdown .drop-item').nth(i);
        const title = (await item.locator('strong').textContent()).trim();
        await item.click();
        // Wait for the address to leave the dashboard (the notice navigates), not a fixed time; if it stays, the check below fails
        await page.waitForURL(u => u.pathname !== '/app/dashboard', { timeout: 4000 }).catch(() => {});
        await page.waitForFunction(() => document.querySelector('.page.active')?.getAttribute('data-page') === location.pathname.split('/').pop(), null, { timeout: 4000 }).catch(() => {});
        const landed = await page.evaluate(() => ({ path: location.pathname, page: document.querySelector('.page.active')?.getAttribute('data-page') ?? null }));
        landings.push({ title, ...landed, ok: reachable.includes(landed.path) && landed.path !== '/app/dashboard' && landed.path === `/app/${landed.page}` });
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(250);
      }
      check(wname, 'top bar', `${rname}: every notification opens a page this role can reach`, notifCount === unread && landings.every(l => l.ok), JSON.stringify(landings));

      // ---------- I8 global search ----------
      const own = rname === 'admin'
        ? { term: 'USR-003', page: 'user-management', id: 'USR-003', broad: 'analyst', foreign: 'ALT-001' }
        : { term: 'ALT-003', page: 'alerts', id: 'ALT-003', broad: 'brute', foreign: 'USR-001' };
      const search = page.locator('#globalSearch');
      const searchState = () => page.evaluate(() => {
        const input = document.querySelector('#globalSearch');
        const list = document.querySelector('#globalSearchResults');
        return {
          expanded: input.getAttribute('aria-expanded'),
          role: input.getAttribute('role'),
          active: input.getAttribute('aria-activedescendant'),
          options: list ? [...list.querySelectorAll('[role="option"]')].map(o => o.textContent.trim()) : [],
          groups: list ? [...list.querySelectorAll('[role="group"]')].map(g => g.getAttribute('aria-label')) : [],
          empty: list?.querySelector('.search-empty')?.textContent.trim() ?? null,
        };
      });

      await search.click();
      await search.fill(own.broad);
      await page.waitForTimeout(150);
      let st = await searchState();
      check(wname, 'I8 search', `${rname}: typing shows grouped results (combobox, expanded)`, st.role === 'combobox' && st.expanded === 'true' && st.options.length >= 2 && st.groups.length >= 1, `${st.options.length} results in ${st.groups.join(', ')}`);
      await page.keyboard.press('ArrowDown');
      st = await searchState();
      check(wname, 'I8 search', `${rname}: ArrowDown moves the active option`, st.active === 'globalSearchOption-1', st.active);
      await page.keyboard.press('Escape');
      st = await searchState();
      check(wname, 'I8 search', `${rname}: Escape closes the results`, st.expanded === 'false' && st.options.length === 0, st.expanded);

      // Scoping: the other role's records never appear. (An admin searching
      // an alert ID can still find the audit event that mentions it.)
      const otherRolePages = rname === 'admin'
        ? ['Alerts', 'Cases', 'Incident Response']
        : ['Response Policies', 'Users', 'Audit Logs', 'Service Panel · System health'];
      await search.fill(own.foreign);
      await page.waitForTimeout(150);
      st = await searchState();
      check(wname, 'I8 search', `${rname}: "${own.foreign}" returns nothing from the other role's pages`, !st.groups.some(g => otherRolePages.includes(g)), st.groups.join(', ') || 'no results');

      // ALT-001 appears in admin audit data (AUD-202). The Analyst must
      // find the alert itself and never the audit event that mentions it.
      if (rname === 'analyst') {
        await search.fill('ALT-001');
        await page.waitForTimeout(150);
        st = await searchState();
        check(wname, 'I8 search', 'analyst: "ALT-001" finds the alert and no Audit Logs result', st.groups.includes('Alerts') && !st.groups.includes('Audit Logs') && !st.options.some(o => o.includes('AUD-')), `groups: ${st.groups.join(', ') || 'none'} | options: ${st.options.join(' ; ')}`);
      }

      await search.fill('zzqx-no-such-record');
      await page.waitForTimeout(150);
      st = await searchState();
      check(wname, 'I8 search', `${rname}: unmatched query shows "No matches"`, st.options.length === 0 && /No matches/.test(st.empty || ''), st.empty);

      await search.fill(own.term);
      await page.waitForTimeout(150);
      await page.keyboard.press('Enter');
      await page.waitForURL(`**/app/${own.page}`);
      await page.waitForTimeout(450);
      const landed = await page.evaluate(id => {
        const row = document.querySelector(`[data-record-id="${id}"]`);
        const r = row?.getBoundingClientRect();
        return {
          highlighted: !!row?.classList.contains('is-highlighted'),
          focusInRow: !!row && row.contains(document.activeElement),
          inView: !!r && r.top >= 0 && r.bottom <= window.innerHeight,
          searchCleared: document.querySelector('#globalSearch').value === '',
        };
      }, own.id);
      check(wname, 'I8 search', `${rname}: Enter opens /app/${own.page} with ${own.id} highlighted`, landed.highlighted && landed.inView, JSON.stringify(landed));
      check(wname, 'I8 search', `${rname}: keyboard focus lands in the highlighted row`, landed.focusInRow, JSON.stringify(landed));
      if (rname === 'analyst') await page.screenshot({ path: out + `search-landed-${wname}.png` });
      await page.goto(base + '/app/dashboard');
      await page.waitForTimeout(250);

      // ---------- I11 mobile layout ----------
      if (wname === 'mobile') {
        const mob = await page.evaluate(() => {
          const top = sel => Math.round(document.querySelector(sel).getBoundingClientRect().top);
          // Admin stat cards, or the analyst posture strip
          const stats = [...document.querySelectorAll('.stats .stat, .posture li')].map(s => Math.round(s.getBoundingClientRect().top));
          return {
            // On phones .topbar is display: contents, so measure its rows instead.
            topbarHeight: Math.round(document.querySelector('.topbar-search').getBoundingClientRect().bottom - document.querySelector('.logo').getBoundingClientRect().top),
            logoRow: top('.logo'), statusRow: top('.system-status-widget'), searchRow: top('.search-wrap'), meterRow: top('.threat-meter'),
            twoStatsPerRow: stats.length >= 2 && stats[0] === stats[1],
            gutter: window.innerWidth - document.documentElement.clientWidth,
          };
        });
        check(wname, 'I11 mobile', `${rname}: top bar is two rows (threat meter, status and search share row 2)`, Math.abs(mob.statusRow - mob.searchRow) < 6 && Math.abs(mob.meterRow - mob.searchRow) < 6 && mob.searchRow > mob.logoRow + 20 && mob.topbarHeight <= 140, JSON.stringify(mob));
        check(wname, 'I11 mobile', `${rname}: stat cards two per row`, mob.twoStatsPerRow);
        check(wname, 'I11 mobile', `${rname}: no empty scrollbar strip on the right`, mob.gutter === 0, `${mob.gutter}px`);

        // At the top: the search row sits directly under the first row
        const atTop = await page.evaluate(() => ({
          logoBottom: Math.round(document.querySelector('.logo').getBoundingClientRect().bottom),
          searchRowTop: Math.round(document.querySelector('.topbar-search').getBoundingClientRect().top),
        }));
        check(wname, 'I11 mobile', `${rname}: search row sits directly under the first row`, Math.abs(atTop.searchRowTop - atTop.logoBottom) <= 1, JSON.stringify(atTop));

        // Scrolled: only the first row (hamburger, logo, icons) is sticky; the search row
        // scrolls away and the hamburger never floats over page content.
        // instant: html has scroll-behavior: smooth, which would catch the header mid-scroll
        await page.evaluate(() => window.scrollTo({ top: 700, behavior: 'instant' }));
        await page.waitForTimeout(150);
        const header = await page.evaluate(() => {
          const rect = sel => document.querySelector(sel).getBoundingClientRect();
          const logo = rect('.logo'), actions = rect('.top-actions'), t = rect('.sidebar-toggle'), searchRow = rect('.topbar-search');
          const row = { top: Math.min(logo.top, actions.top), bottom: Math.max(logo.bottom, actions.bottom) };
          // Sample points across the first row; each must hit the header (or the toggle), not content beneath it.
          const w = document.documentElement.clientWidth;
          const xs = [8, w / 2, w - 8];
          const ys = [row.top + 6, row.bottom - 6];
          const leaks = xs.flatMap(x => ys.map(y => document.elementFromPoint(x, y)))
            .filter(el => el && !el.closest('.topbar, .sidebar-toggle'))
            .map(el => el.tagName + '.' + el.className);
          return {
            scrollY: Math.round(window.scrollY),
            rowTop: Math.round(row.top),
            rowHeight: Math.round(row.bottom - row.top),
            searchRowBottom: Math.round(searchRow.bottom),
            sticky: getComputedStyle(document.querySelector('.logo')).position === 'sticky' && getComputedStyle(document.querySelector('.top-actions')).position === 'sticky',
            toggleInRow: t.top >= row.top && t.bottom <= row.bottom,
            leaks,
          };
        });
        if (rname === 'analyst') await page.screenshot({ path: out + 'analyst-scrolled-header-mobile.png' });
        await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
        check(wname, 'I11 mobile', `${rname}: first row stays at the top while the page scrolls`, header.scrollY > 0 && header.sticky && header.rowTop === 0 && header.rowHeight === 64, JSON.stringify(header));
        check(wname, 'I11 mobile', `${rname}: search row scrolls away with the page`, header.searchRowBottom <= 0, JSON.stringify(header));
        check(wname, 'I11 mobile', `${rname}: hamburger sits inside the sticky first row`, header.toggleInRow, JSON.stringify(header));
        check(wname, 'I11 mobile', `${rname}: page content doesn't show through the first row`, header.leaks.length === 0, header.leaks.join(', '));
      }

      // ---------- Per page ----------
      for (const p of r.pages) {
        await page.goto(base + '/app/' + p);
        await page.waitForTimeout(350);
        await page.screenshot({ path: out + `${rname}-${p.replace(/[?=]/g, '-')}-${wname}.png`, fullPage: true });
        const missing = await unlabeled();
        check(wname, 'I6 labels', `${rname}/${p}: no unlabelled controls`, missing.length === 0, missing.join(' ; '));
        check(wname, 'layout', `${rname}/${p}: no horizontal page overflow`, (await hOverflow()) <= 0, await hOverflow());

        // I3: collect pill colours per status word
        // Table cells, key/value rows, list items and detail facts.
        // Cases, freshly loaded: run-linked actions start from the runs' results
        if (p === 'cases' && rname === 'analyst') {
          const fresh = await page.evaluate(() => ['CASE-006', 'CASE-007', 'CASE-008'].map(id => document.querySelector(`.case-card[data-record-id="${id}"] .case-card-progress`)?.textContent.trim()).join(' | '));
          check(wname, 'cases', 'starting progress: 0 of 4 (the block waits for APR-002), 0 of 4 (nothing was isolated), 4 of 4', fresh === '0 of 4 actions | 0 of 4 actions | 4 of 4 actions', fresh);
        }

        // Alerts opens on "Needs decision"; show every alert so all severities are seen,
        // and select an Open one so its status badge is on screen (in the drawer on phones).
        if (p === 'alerts') {
          await page.click('.page.active .headline .segmented-option:has-text("All today")');
          await page.click('.queue-item[data-record-id="ALT-001"]');
          await page.waitForTimeout(150);
        }
        const pills = await page.evaluate(() => [...document.querySelectorAll('td .pill, .kv .pill, [data-record-id] .pill, .facts .pill')]
          .map(el => [el.textContent.trim(), getComputedStyle(el).backgroundColor]));
        if (p === 'alerts' && wname === 'mobile') {
          await page.keyboard.press('Escape');
          await page.waitForTimeout(150);
        }
        for (const [text, color] of pills) {
          if (/^\d/.test(text)) continue; // count badges, not statuses
          pillColors[text] = pillColors[text] || {};
          pillColors[text][color] = (pillColors[text][color] || []).concat(`${rname}/${p}`);
        }

        // I2: stat cards stack label and subtext, all left-aligned
        // Number cards only; System Health's donut cards have their own layout (checked below).
        const stats = await page.evaluate(() => [...document.querySelectorAll('.stat:not(.health-stat)')].map(s => {
          const card = s.getBoundingClientRect();
          const box = sel => s.querySelector(sel)?.getBoundingClientRect();
          const span = box(':scope > span'), small = box(':scope > small');
          return { label: s.querySelector('span')?.textContent.trim(), labelLeft: span ? Math.round(span.left - card.left) : null, separate: !small || !span || small.top >= span.bottom - 1 };
        }));
        if (stats.length) {
          const lefts = [...new Set(stats.map(s => s.labelLeft))];
          check(wname, 'I2 stats', `${rname}/${p}: label and subtext on separate lines`, stats.every(s => s.separate), stats.filter(s => !s.separate).map(s => s.label).join(', '));
          check(wname, 'I2 stats', `${rname}/${p}: all stat labels share one left edge`, lefts.length === 1 && lefts[0] < 40, `left offsets: ${lefts.join(', ')}px`);
        }

        // Users table: nothing clipped, no pill spilling into the next column
        // (Alerts is a queue now; see the list checks in the analyst section. Audit Logs is a list.)
        if (p === 'user-management') {
          const area = 'Users table';
          const at = await page.evaluate(() => {
            const cells = [...document.querySelectorAll('.table-scroll th, .table-scroll td')];
            const clipped = cells.filter(c => c.scrollWidth > c.clientWidth + 1).map(c => c.textContent.trim().slice(0, 24));
            const spilled = [...document.querySelectorAll('.table-scroll td .pill, .table-scroll td .btn')]
              .filter(el => el.getClientRects().length > 0)
              .filter(el => { const r = el.getBoundingClientRect(), td = el.closest('td').getBoundingClientRect(); return r.right > td.right + 0.5 || r.left < td.left - 0.5; })
              .map(el => el.textContent.trim());
            return { clipped, spilled };
          });
          check(wname, area, 'no header or cell is clipped (no stray "…")', at.clipped.length === 0, at.clipped.join(' | '));
          check(wname, area, 'no pill or button spills past its column', at.spilled.length === 0, at.spilled.join(', '));
        }

        // I9 + polish: copy, placeholders, number alignment
        const copy = await page.evaluate(() => {
          const text = document.querySelector('main').innerText;
          const devWords = ['frontend', 'loaded successfully', 'React state', 'connected later', 'static', 'prototype'].filter(w => text.toLowerCase().includes(w.toLowerCase()));
          const placeholders = [...document.querySelectorAll('input[placeholder^="Search"]')].filter(i => i.getClientRects().length).map(i => i.placeholder);
          const td = document.querySelector('main td');
          return { devWords, badPlaceholders: placeholders.filter(p => !p.endsWith('…')), tabular: td ? getComputedStyle(td).fontVariantNumeric : 'n/a' };
        });
        check(wname, 'I9 dev notes', `${rname}/${p}: no developer wording on screen`, copy.devWords.length === 0, copy.devWords.join(', '));
        check(wname, 'polish', `${rname}/${p}: search placeholders end with "…"`, copy.badPlaceholders.length === 0, copy.badPlaceholders.join(' | '));
        if (copy.tabular !== 'n/a') check(wname, 'polish', `${rname}/${p}: table numbers use tabular figures`, copy.tabular.includes('tabular-nums'), copy.tabular);

        // I12: filters sit in a toolbar above the card, like the other pages
        // (Incident Response has its own, stricter check in the Incident section.)
        if (p === 'alerts') {
          const tb = await page.evaluate(() => {
            const bar = document.querySelector('main .toolbar');
            return { exists: !!bar, insideCard: !!bar?.closest('.card'), hasSearch: !!bar?.querySelector('input[type="search"]') };
          });
          check(wname, 'I12 filters', `${rname}/${p}: filters in a toolbar outside the card, with search`, tb.exists && !tb.insideCard && tb.hasSearch, JSON.stringify(tb));
        }

        // Scroll cue: hint shown only while columns are hidden to the right
        const cue = await page.evaluate(() => [...document.querySelectorAll('.table-scroll-frame')].map(f => {
          const s = f.querySelector('.table-scroll');
          return { overflow: s.scrollWidth > s.clientWidth + 1, hint: !!f.querySelector('.table-scroll-hint'), region: s.getAttribute('role') === 'region' && s.tabIndex === 0 && !!s.getAttribute('aria-label') };
        }));
        cue.forEach((c, i) => check(wname, 'scroll cue', `${rname}/${p} table ${i + 1}: ${c.overflow ? 'overflowing table shows hint and is a focusable region' : 'table that fits shows no hint'}`, c.overflow ? c.hint && c.region : !c.hint && !c.region, JSON.stringify(c)));
        const firstOverflow = cue.findIndex(c => c.overflow);
        if (firstOverflow >= 0) {
          await page.evaluate(i => { const s = document.querySelectorAll('.table-scroll-frame')[i].querySelector('.table-scroll'); s.scrollLeft = s.scrollWidth; }, firstOverflow);
          await page.waitForTimeout(150);
          const atEnd = await page.evaluate(i => { const f = document.querySelectorAll('.table-scroll-frame')[i]; return { hint: !!f.querySelector('.table-scroll-hint'), fade: f.classList.contains('scrolled') }; }, firstOverflow);
          check(wname, 'scroll cue', `${rname}/${p}: hint hides at the end, left fade appears`, !atEnd.hint && atEnd.fade, JSON.stringify(atEnd));
          await page.evaluate(i => { document.querySelectorAll('.table-scroll-frame')[i].querySelector('.table-scroll').scrollLeft = 0; }, firstOverflow);
          if (rname === 'analyst' && p === 'alerts') await page.screenshot({ path: out + `alerts-scrolled-${wname}.png` });
        }

        // I4: no primary (filled) buttons inside table rows
        const rowPrimary = await page.evaluate(() => [...document.querySelectorAll('tbody .btn.primary')].map(b => b.textContent.trim()));
        check(wname, 'I4 buttons', `${rname}/${p}: no primary buttons in table rows`, rowPrimary.length === 0, rowPrimary.join(', '));

        // C7: Actions column reachable without sideways scrolling
        const act = await page.evaluate(() => {
          const vw = document.documentElement.clientWidth;
          return [...document.querySelectorAll('.table-scroll')].map(ts => {
            const row = ts.querySelector('tbody tr');
            if (!row) return null;
            // The rightmost cell in the row that holds buttons is the actions column.
            const cell = [...row.children].reverse().find(td => td.querySelector('button'));
            if (!cell) return null;
            // Only the buttons this layout renders (User Management swaps some for a "⋯" menu on phones).
            const btns = [...cell.querySelectorAll('button')].filter(b => b.getClientRects().length > 0);
            const box = ts.getBoundingClientRect();
            return {
              flush: !ts.scrollWidth || ts.scrollWidth <= ts.clientWidth || Math.abs(cell.getBoundingClientRect().right - box.right) <= 1,
              scrolls: ts.scrollWidth > ts.clientWidth,
              buttons: btns.length,
              allVisible: btns.every(b => { const r = b.getBoundingClientRect(); return r.left >= box.left - 1 && r.right <= Math.min(box.right, vw) + 1 && r.width > 0; }),
              cellWidth: Math.round(cell.getBoundingClientRect().width),
              tableVisible: Math.round(box.width),
            };
          }).filter(Boolean);
        });
        act.forEach((a, i) => {
          const detail = `scrolls=${a.scrolls} actionsWidth=${a.cellWidth}px of ${a.tableVisible}px`;
          check(wname, 'C7 tables', `${rname}/${p} table ${i + 1}: all ${a.buttons} action buttons visible`, a.allVisible, detail);
          if (a.scrolls) check(wname, 'C7 tables', `${rname}/${p} table ${i + 1}: pinned actions use at most half the table`, a.cellWidth <= a.tableVisible / 2, detail);
          if (a.scrolls) check(wname, 'C7 tables', `${rname}/${p} table ${i + 1}: pinned column flush with right edge (no gap)`, a.flush, detail);
        });
      }

      if (rname === 'analyst') {
        // The old System Health address is admin-only; an analyst lands on the dashboard
        await page.goto(base + '/app/system-health');
        await page.waitForTimeout(300);
        check(wname, 'system health', 'analyst: /app/system-health goes to the dashboard, not the System health tab', new URL(page.url()).pathname === '/app/dashboard', page.url());
      }

      if (rname === 'admin') {
        // The old System Health address lands on the Service Panel's System health tab
        await page.goto(base + '/app/system-health');
        await page.waitForTimeout(300);
        check(wname, 'system health', 'admin: /app/system-health redirects to /app/service-panel?view=health', new URL(page.url()).pathname + new URL(page.url()).search === '/app/service-panel?view=health', page.url());
        // C9 on the System health tab
        await page.goto(base + '/app/service-panel?view=health');
        await page.waitForTimeout(250);

        // ---------- System Health (5c): header, resource gauges, latency scale, events, totals ----------
        const hs = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const box = el => el.getBoundingClientRect();
          return {
            summary: t(document.querySelector('#healthSummary')),
            rows: [...document.querySelectorAll('tbody tr[data-record-id]')].map(r => ({ id: r.dataset.recordId, name: t(r.querySelector('strong')), group: t(r.querySelector('[data-field="group"]')), status: t(r.querySelector('.pill')) })),
            groupLine: t(document.querySelector('#groupCounts')),            gauges: [...document.querySelectorAll('.gauge-card')].map(c => {
              const svg = c.querySelector('svg.gauge');
              const card = box(c), ring = box(svg), text = box(c.querySelector('.gauge-text'));
              return {
                name: t(c.querySelector('.gauge-text strong')),
                label: svg?.getAttribute('aria-label'),
                shown: t(svg?.querySelector('text')),
                // The ring's inner width is about 28 of its 40 units
                textWidth: svg?.querySelector('text').getBBox().width,
                state: t(c.querySelector('.gauge-state')),
                beside: text.left >= ring.right - 1,
                inside: ring.left >= card.left - 1 && text.right <= card.right + 1,
              };
            }),
            // Only the pipeline group has a response time; the VM group shows a dash
            latency: [...document.querySelectorAll('tbody tr[data-record-id]')].filter(r => r.querySelector('.latency-bar')).map(r => ({
              id: r.dataset.recordId,
              ms: Number(t(r.querySelector('.latency-text'))?.replace(/\D/g, '')),
              pct: Number(r.querySelector('.latency-bar > span')?.style.getPropertyValue('--latency-pct')),
              over: r.querySelector('.latency-bar')?.classList.contains('over'),
              fill: Math.round(box(r.querySelector('.latency-bar > span')).width / box(r.querySelector('.latency-bar')).width * 100),
            })),
            events: [...document.querySelectorAll('.health-events > li')].map(li => ({
              badge: t(li.querySelector('.pill')),
              badgeStyle: li.querySelector('.pill')?.getAttribute('style'),
              anyStyle: li.querySelectorAll('[style]').length,
              text: t(li),
            })),
            totals: [...document.querySelectorAll('.card')].filter(c => t(c.querySelector('h2')) === 'Processing Totals').flatMap(c => [...c.querySelectorAll('.kv strong')].map(t)),
          };
        });
        check(wname, 'system health', 'subtitle is derived: "8 of 10 services healthy" and names the slow service and the one still starting', hs.summary?.startsWith('8 of 10 services healthy.') && hs.summary.includes('Ollama Runtime is responding slowly') && hs.summary.includes('Wazuh Dashboard is still starting'), hs.summary);
        check(wname, 'system health', '8 resource gauges, each naming its value and a state word (Good, Watch or Needs attention)', hs.gauges.length === 8 && hs.gauges.every(g => /^.+ \d+(\.\d+)?%$/.test(g.label) && g.label === `${g.name} ${parseFloat(g.shown)}%` && ['Good', 'Watch', 'Needs attention'].includes(g.state)), JSON.stringify(hs.gauges.map(g => `${g.label}:${g.state}`)));
        check(wname, 'system health', 'each gauge value fits inside its ring, one-decimal values ("38.4%", "71.2%") included', hs.gauges.every(g => g.textWidth <= 28), JSON.stringify(hs.gauges.map(g => `${g.shown}:${Math.round(g.textWidth)}`)));
        check(wname, 'system health', 'each gauge keeps its ring beside the text and inside its card', hs.gauges.every(g => g.beside && g.inside), JSON.stringify(hs.gauges.filter(g => !g.beside || !g.inside).map(g => g.name)));
        check(wname, 'system health', 'latency bar scale is the 400 ms target: fill = ms / 400 (capped at 100), over target flagged', hs.latency.length === 4 && hs.latency.every(l => l.pct === Math.min(100, Math.round(l.ms / 400 * 100)) && l.over === (l.ms > 400) && Math.abs(l.fill - l.pct) <= 2), JSON.stringify(hs.latency));
        check(wname, 'system health', 'Ollama Runtime (SVC-005) is the only service over target, at 486 ms', hs.latency.filter(l => l.over).map(l => `${l.id}:${l.ms}`).join() === 'SVC-005:486', JSON.stringify(hs.latency.filter(l => l.over)));
        check(wname, 'system health', 'recent health events: an ordered list of SeverityBadge pills with no inline style', hs.events.length > 0 && hs.events.every(e => e.badge && e.badgeStyle === null && e.anyStyle === 0), JSON.stringify(hs.events.map(e => `${e.badge}:${e.badgeStyle}:${e.anyStyle}`)));
        check(wname, 'system health', 'Processing Totals show the figures from the data', ['18,462', '1.8 seconds', '41 / 50'].every(v => hs.totals.includes(v)), hs.totals.join(' | '));
        const hp = await page.evaluate(() => document.querySelector('[data-field="healthStatus"]')?.textContent.trim());
        check(wname, 'C9 status', 'System health pill agrees with top bar', hp === 'Attention Required', hp);
        const rangeOverflow = await hOverflow();
        check(wname, 'system health', 'no horizontal page overflow', rangeOverflow <= 0, rangeOverflow);
        // The tab sits inside the Service Panel: its title, five tabs with System health selected, no Overview refresh controls, the tab dot matching the badge
        const healthTab = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const tabs = [...document.querySelectorAll('[role="tab"]')];
          const selected = tabs.find(b => b.getAttribute('aria-selected') === 'true');
          const badge = [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Service Panel')?.querySelector('.count')?.textContent.trim();
          return {
            title: t(document.querySelector('h1')),
            tabs: tabs.map(b => t(b)),
            selected: t(selected),
            refreshedLabel: !!document.querySelector('#servicePanelRefreshed'),
            overviewRefresh: [...document.querySelectorAll('.headline-actions .btn')].some(b => t(b) === 'Refresh'),
            ownRefresh: [...document.querySelectorAll('.health-actions .btn')].map(t),
            checkAll: [...document.querySelectorAll('.btn.primary')].some(b => t(b) === 'Check All Services'),
            badge,
          };
        });
        check(wname, 'system health', 'the tab opens from ?view=health: title "Service Panel", five tabs with System health second and selected, and its tab text counts 2 needing attention like the sidebar badge', healthTab.title === 'Service Panel' && healthTab.tabs.length === 5 && /^System health/.test(healthTab.tabs[1]) && /^System health/.test(healthTab.selected) && /2 need attention/.test(healthTab.selected) && healthTab.badge === '2', JSON.stringify(healthTab));
        check(wname, 'system health', 'the Overview\'s "last refreshed" and Refresh are hidden on this tab; the tab keeps its own Refresh and Check All Services', !healthTab.refreshedLabel && !healthTab.overviewRefresh && healthTab.ownRefresh.includes('Refresh') && healthTab.checkAll, JSON.stringify(healthTab));
        // A service found in the top-bar search opens the tab, with its row highlighted
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(250);
        await page.fill('#globalSearch', 'Suricata');
        await page.waitForTimeout(250);
        const serviceOption = await page.evaluate(() => [...document.querySelectorAll('#globalSearchResults [role="option"]')].map(o => (o.closest('[role="group"]')?.getAttribute('aria-label') || '') + ' > ' + o.textContent.replace(/\s+/g, ' ').trim()));
        await page.click('#globalSearchResults [role="option"]');
        await page.waitForTimeout(400);
        const searchLanded = await page.evaluate(() => ({ url: location.pathname + location.search, selected: [...document.querySelectorAll('[role="tab"]')].find(b => b.getAttribute('aria-selected') === 'true')?.textContent.trim(), row: !!document.querySelector('tr[data-record-id="SVC-003"]') }));
        check(wname, 'system health', 'a service search result (Suricata Sensor) opens the System health tab with its row on the page', serviceOption.length === 1 && /Service Panel/.test(serviceOption[0]) && searchLanded.url === '/app/service-panel?view=health' && /^System health/.test(searchLanded.selected) && searchLanded.row, JSON.stringify([serviceOption, searchLanded]));
        // R2a: one inventory of 10 services in two labelled groups
        check(wname, 'system health', 'one inventory: 10 services, each id and name once, 4 in "Detection and AI pipeline" and 6 in "Security stack on the VM"', hs.rows.length === 10 && new Set(hs.rows.map(r => r.id)).size === 10 && new Set(hs.rows.map(r => r.name)).size === 10 && hs.rows.filter(r => r.group === 'Detection and AI pipeline').length === 4 && hs.rows.filter(r => r.group === 'Security stack on the VM').length === 6, JSON.stringify(hs.rows));
        check(wname, 'system health', 'group lines agree with the table: "Detection and AI pipeline: 3 of 4 healthy · Security stack on the VM: 5 of 6 healthy"', hs.groupLine === 'Detection and AI pipeline: 3 of 4 healthy · Security stack on the VM: 5 of 6 healthy', hs.groupLine);
        check(wname, 'system health', 'only the shared words appear as service states (Running, Starting, Degraded, Failed, Stopped, Unverified); Ollama Runtime reads Degraded and Wazuh Dashboard reads Starting', hs.rows.every(r => ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified'].includes(r.status)) && hs.rows.find(r => r.id === 'SVC-005')?.status === 'Degraded' && hs.rows.find(r => r.id === 'SVC-009')?.status === 'Starting' && hs.rows.filter(r => r.status === 'Running').length === 8, JSON.stringify(hs.rows.map(r => `${r.id}:${r.status}`)));
        check(wname, 'system health', 'the CPU and Memory gauges show the VM usage, 38.4% and 71.2%, the same as the Service Panel meters', hs.gauges.find(g => g.name === 'CPU Usage')?.shown === '38.4%' && hs.gauges.find(g => g.name === 'Memory Usage')?.shown === '71.2%', JSON.stringify(hs.gauges.slice(0, 2).map(g => g.shown)));

        // ---------- Service Panel: overview, tabs, consoles, meters, demo wording ----------
        await page.goto(base + '/app/service-panel');
        await page.waitForTimeout(250);
        const sp = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const card = key => document.querySelector(`.sp-card[data-service="${key}"]`);
          return {
            title: t(document.querySelector('h1')),
            summary: t(document.querySelector('#servicePanelSummary')),
            refreshed: t(document.querySelector('#servicePanelRefreshed')),
            stats: Object.fromEntries([...document.querySelectorAll('.sp-summary [data-stat]')].map(d => [d.dataset.stat, t(d.querySelector('strong'))])),
            cards: [...document.querySelectorAll('.sp-card')].map(c => `${c.dataset.service}:${c.dataset.state}:${t(c.querySelector('[data-field="status"]'))}`),
            parts: [...document.querySelectorAll('.sp-parts li')].map(li => `${li.dataset.part}:${t(li.querySelector('.sp-part-state'))}`),
            dockerUptime: t(card('docker')?.querySelector('[data-field="uptime"]')),
            misp: t(card('misp')?.querySelector('[data-field="detail"]')),
            consoleButtons: [...document.querySelectorAll('.sp-card .btn')].map(b => `${t(card(b.closest('.sp-card').dataset.service)?.querySelector('h3'))}:${t(b)}`),
            tabs: [...document.querySelectorAll('[role="tab"]')].map(b => ({ label: t(b), dot: b.querySelector('.tab-dot')?.className ?? null, selected: b.getAttribute('aria-selected') })),
            meters: [...document.querySelectorAll('.sp-meter')].map(m => ({ label: m.getAttribute('aria-label'), now: m.getAttribute('aria-valuenow'), role: m.getAttribute('role'), fill: Math.round(m.firstElementChild.getBoundingClientRect().width / m.getBoundingClientRect().width * 100) })),
            ramText: t(document.querySelector('[data-meter="RAM"] .sp-meter-value')),
            legend: [...document.querySelectorAll('.sp-legend [data-state]')].map(d => d.dataset.state),
            demo: t(document.querySelector('#servicePanelDemoNote')),
            admin: document.querySelector('section.page')?.hasAttribute('data-admin-only'),
          };
        });
        check(wname, 'service panel', 'heading "Service Panel" with a derived sentence naming the Wazuh component that is starting', sp.title === 'Service Panel' && sp.summary === 'The AthenaSec stack on the Ubuntu VM. 3 of 4 service groups running; Wazuh Dashboard is still starting.', sp.summary);
        check(wname, 'service panel', 'summary card: 4 groups, 3 running, 1 issue', sp.stats.groups === '4' && sp.stats.running === '3' && sp.stats.issues === '1', JSON.stringify(sp.stats));
        check(wname, 'service panel', 'four service cards in order, each with its state: Wazuh partial, MISP, Cortex and Docker running', sp.cards.join('|') === 'wazuh:partial:Partially running — 2/3|misp:running:Available|cortex:running:Running|docker:running:Running', sp.cards.join('|'));
        check(wname, 'service panel', 'Wazuh lists Manager and Indexer running, Dashboard starting', sp.parts.join('|') === 'manager:Running|indexer:Running|dashboard:Starting', sp.parts.join('|'));
        // The Panel's rows are the VM records of the same inventory, so the two pages cannot disagree
        const vmState = name => hs.rows.find(r => r.name === name)?.status;
        check(wname, 'service panel', 'the Panel agrees with System Health on every VM service: Manager, Indexer, MISP, Cortex and Docker Running, Dashboard Starting', sp.parts.join('|') === `manager:${vmState('Wazuh Manager')}|indexer:${vmState('Wazuh Indexer')}|dashboard:${vmState('Wazuh Dashboard')}` && sp.cards.includes(`cortex:running:${vmState('Cortex')}`) && sp.cards.includes(`docker:running:${vmState('Docker Engine')}`) && vmState('MISP') === 'Running' && sp.cards.some(c => c.startsWith('misp:running:')), `${sp.parts.join('|')} / ${sp.cards.join('|')} / ${JSON.stringify(hs.rows.map(r => `${r.name}:${r.status}`))}`);
        check(wname, 'service panel', 'Docker uptime reads "Uptime: 2d 4h 12m"; MISP says availability only', sp.dockerUptime === 'Uptime: 2d 4h 12m' && /web availability only/.test(sp.misp), `${sp.dockerUptime} / ${sp.misp}`);
        check(wname, 'service panel', 'Open console button on Wazuh, MISP and Cortex only (not Docker)', sp.consoleButtons.join('|') === 'Wazuh:Open console|MISP:Open console|Cortex:Open console', sp.consoleButtons.join('|'));
        check(wname, 'service panel', 'five tabs (Overview, System health, Wazuh, Cortex, MISP), Overview selected; each tab dot has a matching hidden status word', sp.tabs.length === 5 && sp.tabs[0].selected === 'true' && sp.tabs.every(x => x.dot && x.dot.startsWith('tab-dot ')) && sp.tabs[0].label.includes('1 issue') && sp.tabs[1].label.includes('System health') && sp.tabs[1].label.includes('2 need attention') && sp.tabs[2].label.includes('Partially running'),JSON.stringify(sp.tabs));
        check(wname, 'service panel', 'CPU and RAM meters are role="meter"; fill matches the value (RAM 71.2 from bytes)', sp.meters.length === 2 && sp.meters.every(m => m.role === 'meter' && Math.abs(m.fill - Number(m.now)) <= 2) && sp.ramText === '71.2%', JSON.stringify(sp.meters) + sp.ramText);
        check(wname, 'service panel', 'status legend lists all six Panel states and Degraded (the shared service words)', sp.legend.join('|') === 'running|partial|stopped|starting|unhealthy|unknown|degraded', sp.legend.join('|'));
        check(wname, 'service panel', 'demo wording: "last refreshed HH:MM:SS", no "refreshes every", Demo mode note present', /^Demo data · last refreshed \d{2}:\d{2}:\d{2}$/.test(sp.refreshed) && !/refreshes every/i.test(sp.refreshed) && sp.demo.startsWith('Demo mode Demo data'), `${sp.refreshed} / ${sp.demo}`);
        check(wname, 'service panel', 'page is marked admin-only', sp.admin === true);
        // Refresh changes the time only when clicked
        const spBefore = await page.evaluate(() => document.querySelector('[data-field="refreshed"]').textContent);
        await page.waitForTimeout(1200);
        const spIdle = await page.evaluate(() => document.querySelector('[data-field="refreshed"]').textContent);
        await page.click('.headline-actions .btn.primary');
        await page.waitForTimeout(150);
        const spAfter = await page.evaluate(() => ({ time: document.querySelector('[data-field="refreshed"]').textContent, status: document.querySelector('.headline-actions [role="status"]').textContent }));
        check(wname, 'service panel', 'no timer: time unchanged while idle, changes on Refresh and is announced', spIdle === spBefore && spAfter.time !== spBefore && spAfter.status === `Demo data refreshed at ${spAfter.time}`, `${spBefore} / ${spIdle} / ${JSON.stringify(spAfter)}`);
        // Open console switches the tab and writes ?view= with replace
        const histBefore = await page.evaluate(() => history.length);
        await page.click('.sp-card[data-service="misp"] .btn');
        await page.waitForTimeout(150);
        const spConsole = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const open = document.querySelector('[data-field="open"]');
          return {
            url: location.search,
            hist: history.length,
            selected: [...document.querySelectorAll('[role="tab"]')].find(b => b.getAttribute('aria-selected') === 'true')?.textContent.trim(),
            origin: t(document.querySelector('[data-field="origin"]')),
            href: open?.getAttribute('href'), target: open?.getAttribute('target'), rel: open?.getAttribute('rel'),
            iframes: document.querySelectorAll('iframe').length,
            disabled: [...document.querySelectorAll('.sp-toolbar button')].map(b => `${t(b)}:${b.disabled}`).join('|'),
            notice: t(document.querySelector('.sp-cert')),
            h2: t(document.querySelector('.sp-placeholder h2')),
            marker: getComputedStyle(document.querySelector('.sp-placeholder h2'), '::before').content,
          };
        });
        check(wname, 'service panel', 'Open console on MISP selects the MISP tab via ?view=misp without adding history', spConsole.url === '?view=misp' && /^MISP/.test(spConsole.selected) && spConsole.hist === histBefore, JSON.stringify([spConsole.url, spConsole.selected, histBefore, spConsole.hist]));
        check(wname, 'service panel', 'MISP console: fixed origin, new-tab link with noopener, no iframe, Back/Reload/Home disabled', spConsole.origin === 'https://192.168.1.164:9445' && spConsole.href === 'https://192.168.1.164:9445' && spConsole.target === '_blank' && spConsole.rel === 'noopener noreferrer' && spConsole.iframes === 0 && spConsole.disabled === 'Back:true|Reload:true|Home:true', JSON.stringify(spConsole));
        check(wname, 'service panel', 'console view explains the self-signed certificate; heading has no red marker', /Self-signed certificate/.test(spConsole.notice) && spConsole.h2 === 'MISP console' && spConsole.marker === 'none', `${spConsole.notice} / ${spConsole.marker}`);
        // Deep link and unknown view fall back
        await page.goto(base + '/app/service-panel?view=cortex');
        await page.waitForTimeout(250);
        const spCortex = await page.evaluate(() => document.querySelector('.sp-console')?.dataset.console);
        await page.goto(base + '/app/service-panel?view=nonsense');
        await page.waitForTimeout(250);
        const spFallback = await page.evaluate(() => !!document.querySelector('.sp-summary'));
        check(wname, 'service panel', '?view=cortex opens the Cortex tab; an unknown view falls back to Overview', spCortex === 'cortex' && spFallback, `${spCortex} / ${spFallback}`);
        const spOverflow = await hOverflow();
        check(wname, 'service panel', 'no horizontal page overflow', spOverflow <= 0, spOverflow);
        await page.screenshot({ path: out + `admin-service-panel-${w}.png`, fullPage: true });

        // Polish (admin): duplicate badges, unit labels, header spacing, pinned hover
        await page.goto(base + '/app/settings');
        await page.waitForTimeout(250);
        const settingsBadges = await page.evaluate(() => [...document.querySelectorAll('.headline .pill')].map(p => p.textContent.trim()));
        check(wname, 'polish', 'Settings: "Administrator Only" badge removed', !settingsBadges.includes('Administrator Only'), settingsBadges.join(', '));

        // ---------- Configuration (5e): fields and ranges, bars, unsaved banner, validation, save, discard, restore ----------
        await page.goto(base + '/app/configuration');
        await page.waitForTimeout(250);
        const cfgIsPhone = wname === 'mobile';
        const cfgState = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const num = id => { const i = document.querySelector('#' + id); return i ? { value: i.value, min: i.min, max: i.max, type: i.type } : null; };
          const opts = id => [...(document.querySelector('#' + id)?.options ?? [])].map(o => o.textContent.trim());
          const fill = (bar, sel) => { const b = document.querySelector(bar), f = document.querySelector(sel); return b && f ? Math.round(f.getBoundingClientRect().width / b.getBoundingClientRect().width * 100) : null; };
          return {
            labels: [...document.querySelectorAll('.cfg-card .form-label')].map(t),
            org: document.querySelector('#organization')?.value,
            window: num('correlationWindowMinutes'), critical: num('criticalRiskThreshold'), hot: num('hotStorageDays'), audit: num('auditRetentionDays'),
            env: opts('workspace'), dest: opts('loggingDestination'), mode: opts('loggingMode'), envValue: document.querySelector('#workspace')?.value,
            units: [...document.querySelectorAll('.unit')].map(u => ({ text: t(u), pill: u.classList.contains('pill'), bg: getComputedStyle(u).backgroundColor })),
            choices: [...document.querySelectorAll('.cfg-choice')].map(b => `${t(b)}:${b.getAttribute('aria-pressed')}`),
            thresholdLabel: document.querySelector('.cfg-threshold')?.getAttribute('aria-label'),
            thresholdFill: fill('.cfg-threshold', '.cfg-threshold-fill'),
            retentionLabel: document.querySelector('.cfg-retention')?.getAttribute('aria-label'),
            retentionText: [...document.querySelectorAll('.cfg-retention > span')].map(t),
            retentionGrow: [...document.querySelectorAll('.cfg-retention > span')].map(s => s.style.flexGrow),
            retentionOff: !!document.querySelector('[data-field="retention-bar-off"]'),
            banner: t(document.querySelector('#configUnsaved .cfg-unsaved-text')),
            bannerButtons: [...document.querySelectorAll('#configUnsaved button')].map(t),
            pill: t(document.querySelector('#configState')),
            message: t(document.querySelector('.page[data-page="configuration"] > .notice[role="status"]')),
            alert: t(document.querySelector('.page[data-page="configuration"] > .notice[role="alert"] p')),
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          };
        });
        let cf = await cfgState();
        check(wname, 'configuration', 'every field is present with its design label: Organization name, Environment, Correlation window, Critical risk threshold, Destination, Mode, Hot storage, Audit retention', JSON.stringify(cf.labels) === JSON.stringify(['Organization name', 'Environment', 'Correlation window', 'Critical risk threshold', 'Destination', 'Mode', 'Hot storage', 'Audit retention']), cf.labels.join(' | '));
        check(wname, 'configuration', 'number inputs carry the data ranges: window 1-1440, critical 0-100, hot and audit retention 1-3650', [cf.window, cf.critical, cf.hot, cf.audit].every(f => f && f.type === 'number') && cf.window.min === '1' && cf.window.max === '1440' && cf.critical.min === '0' && cf.critical.max === '100' && cf.hot.min === '1' && cf.hot.max === '3650' && cf.audit.min === '1' && cf.audit.max === '3650' && [cf.window.value, cf.critical.value, cf.hot.value, cf.audit.value].join() === '5,90,30,365', JSON.stringify([cf.window, cf.critical, cf.hot, cf.audit]));
        check(wname, 'configuration', 'selects keep the data options: Production / Staging / Development / Testing, OpenSearch / Local File / Syslog, Realtime / Batch / Manual', cf.env.join() === 'Production,Staging,Development,Testing' && cf.dest.join() === 'OpenSearch,Local File,Syslog' && cf.mode.join() === 'Realtime,Batch,Manual' && cf.org === 'AthenaSec SOC' && cf.envValue === 'Production', JSON.stringify([cf.env, cf.dest, cf.mode]));
        check(wname, 'configuration', 'critical alert notifications are an aria-pressed group of 4 (Email + In-App pressed), with no Slack', cf.choices.join() === 'Email + In-App:true,Email Only:false,In-App Only:false,Disabled:false', cf.choices.join());
        check(wname, 'configuration', 'unit labels (minutes, / 100, days, days) are plain text, not badges', cf.units.length === 4 && cf.units.every(u => !u.pill && u.bg === 'rgba(0, 0, 0, 0)') && cf.units.map(u => u.text).join() === 'minutes,/ 100,days,days', cf.units.map(u => u.text).join(', '));
        check(wname, 'configuration', 'threshold bar says "90 out of 100" and fills 90% of its track; retention bar is sized 30 : 335 and labelled Hot 30 / Audit 365', cf.thresholdLabel === 'Critical risk threshold 90 out of 100' && Math.abs(cf.thresholdFill - 90) <= 1 && cf.retentionLabel === 'Hot storage 30 days, audit retention 365 days' && cf.retentionText.join('|') === 'Hot, 30 days|Audit retention, 365 days' && cf.retentionGrow.join() === '30,335', JSON.stringify({ label: cf.thresholdLabel, fill: cf.thresholdFill, retention: cf.retentionLabel, text: cf.retentionText, grow: cf.retentionGrow }));
        check(wname, 'configuration', 'clean start: state Saved, no unsaved banner, no page overflow', cf.pill === 'Saved' && cf.banner === null && cf.overflow <= 0, JSON.stringify({ pill: cf.pill, banner: cf.banner, overflow: cf.overflow }));
        await page.screenshot({ path: out + `admin-configuration-hero-${wname}.png` });
        // Editing: banner, Draft, bars follow the values
        await page.fill('#correlationWindowMinutes', '7');
        await page.fill('#hotStorageDays', '60');
        await page.click('.cfg-choice:has-text("Email Only")');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'editing shows the banner "You have unsaved changes. Saving is recorded in the audit log." with Discard and Save configuration, and the state turns Draft', cf.banner === 'You have unsaved changes. Saving is recorded in the audit log.' && cf.bannerButtons.join() === 'Discard,Save configuration' && cf.pill === 'Draft', JSON.stringify({ banner: cf.banner, buttons: cf.bannerButtons, pill: cf.pill }));
        check(wname, 'configuration', 'the retention bar follows the values (hot 60 : audit remainder 305) and the Email Only choice is pressed alone', cf.retentionLabel === 'Hot storage 60 days, audit retention 365 days' && cf.retentionGrow.join() === '60,305' && cf.choices.filter(c => c.endsWith(':true')).join() === 'Email Only:true', JSON.stringify({ retention: cf.retentionLabel, grow: cf.retentionGrow, choices: cf.choices }));
        // Discard
        await page.click('#configUnsaved button:has-text("Discard")');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'Discard restores the saved values, hides the banner, returns to Saved and says so', cf.window.value === '5' && cf.hot.value === '30' && cf.choices[0] === 'Email + In-App:true' && cf.banner === null && cf.pill === 'Saved' && cf.message === 'Unsaved changes were discarded.', JSON.stringify({ window: cf.window.value, hot: cf.hot.value, banner: cf.banner, pill: cf.pill, message: cf.message }));
        // Validation: window 0, then audit shorter than hot; the Error state stays and the banner stays
        await page.fill('#correlationWindowMinutes', '0');
        await page.click('#configUnsaved button:has-text("Save configuration")');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'window 0 is refused with a role="alert" error, state Error, banner still shown (not blocked by the browser)', cf.alert === 'Correlation window must be between 1 and 1440 minutes.' && cf.pill === 'Error' && cf.banner !== null && cf.message === 'Configuration could not be saved.', JSON.stringify({ alert: cf.alert, pill: cf.pill, message: cf.message }));
        await page.fill('#correlationWindowMinutes', '5');
        await page.fill('#hotStorageDays', '400');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'audit shorter than hot hides the retention bar and explains why; saving it is refused', cf.retentionOff && !cf.retentionLabel, JSON.stringify({ off: cf.retentionOff, label: cf.retentionLabel }));
        await page.click('#configUnsaved button:has-text("Save configuration")');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'audit retention 365 with hot storage 400 shows "Audit retention cannot be shorter than hot storage retention." and state Error', cf.alert === 'Audit retention cannot be shorter than hot storage retention.' && cf.pill === 'Error', JSON.stringify({ alert: cf.alert, pill: cf.pill }));
        await page.click('#configUnsaved button:has-text("Discard")');
        await page.waitForTimeout(100);
        // Restore defaults after a save of other values
        await page.fill('#criticalRiskThreshold', '80');
        await page.fill('#auditRetentionDays', '400');
        await page.click('#configUnsaved button:has-text("Save configuration")');
        await page.waitForTimeout(150);
        cf = await cfgState();
        check(wname, 'configuration', 'a valid save says "Configuration saved.", returns to Saved and hides the banner', cf.message === 'Configuration saved.' && cf.pill === 'Saved' && cf.banner === null && cf.alert === null, JSON.stringify({ message: cf.message, pill: cf.pill, banner: cf.banner }));
        await page.click('button:has-text("Restore Defaults")');
        await page.waitForTimeout(100);
        cf = await cfgState();
        check(wname, 'configuration', 'Restore Defaults puts the default values back as a Draft (critical 90, audit 365), shows the banner and says to save', cf.critical.value === '90' && cf.audit.value === '365' && cf.pill === 'Draft' && cf.banner !== null && cf.message === 'Default values restored. Save to keep these changes.', JSON.stringify({ critical: cf.critical.value, audit: cf.audit.value, pill: cf.pill, message: cf.message }));
        await page.click('#configUnsaved button:has-text("Discard")');
        await page.waitForTimeout(100);
        // The save reaches Audit Logs (retention pill) and the audit event, in-app
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('.admin-changes a:has-text("Open audit log")');
        await page.waitForURL('**/app/audit-logs');
        await page.waitForTimeout(250);
        await page.click('.audit-pick[data-record-id="AUD-207"]');
        if (cfgIsPhone) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const cfgAudit = await page.evaluate(() => ({ retention: document.querySelector('#auditRetention')?.textContent.replace(/\s+/g, ' ').trim(), first: document.querySelector('.audit-pick[data-record-id]')?.dataset.recordId, action: document.querySelector('[data-field="action"]')?.textContent.trim(), changes: [...document.querySelectorAll('[data-field="changes"] li')].map(li => li.textContent.trim()) }));
        check(wname, 'configuration', 'Save is audited (AUD-207, "Saved configuration") with old → new values, and the Audit Logs retention pill now reads "kept 400 days"', cfgAudit.first === 'AUD-207' && cfgAudit.action === 'Saved configuration' && JSON.stringify(cfgAudit.changes) === JSON.stringify(['Critical risk threshold: 90 → 80', 'Audit retention (days): 365 → 400']) && cfgAudit.retention === 'Read-only, kept 400 days in OpenSearch', JSON.stringify(cfgAudit));
        if (cfgIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // ---------- Settings (5e): profile summary, preference cards, switches, linked toggles, save / cancel / restore ----------
        await page.goto(base + '/app/settings');
        await page.waitForTimeout(250);
        const setIsPhone = wname === 'mobile';
        const setState = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const sw = [...document.querySelectorAll('.set-toggle')].map(li => { const b = li.querySelector('button[role="switch"]'); return { key: li.dataset.setting, name: b.getAttribute('aria-label'), on: b.getAttribute('aria-checked'), disabled: b.disabled, word: t(li.querySelector('.switch-label')) }; });
          const summary = {}; for (const kv of document.querySelectorAll('#setSummaryTitle ~ .kv')) summary[t(kv.querySelector('span'))] = t(kv.querySelector('strong'));
          const btn = label => [...document.querySelectorAll('.set-actions button')].find(b => t(b) === label);
          return {
            profile: { initials: t(document.querySelector('.set-profile-avatar')), name: t(document.querySelector('[data-field="name"]')), email: t(document.querySelector('[data-field="email"]')), role: t(document.querySelector('[data-field="role"]')), mfa: t(document.querySelector('[data-field="mfa"]')), where: t(document.querySelector('[data-field="where"]')) },
            switches: sw, summary,
            themes: [...document.querySelectorAll('.set-theme')].map(b => `${t(b)}:${b.getAttribute('aria-pressed')}`),
            language: { value: document.querySelector('#settingsLanguage')?.value, options: [...document.querySelectorAll('#settingsLanguage option')].map(o => o.textContent.trim()) },
            timeout: { value: document.querySelector('#sessionTimeout')?.value, options: [...document.querySelectorAll('#sessionTimeout option')].map(o => o.textContent.trim()) },
            pill: t(document.querySelector('#settingsState')),
            message: t(document.querySelector('.page[data-page="settings"] > .notice[role="status"]')),
            alert: t(document.querySelector('.page[data-page="settings"] > .notice[role="alert"] p')),
            save: btn('Save Settings')?.disabled, cancel: btn('Cancel Changes')?.disabled,
            mfaNotice: /123456/.test(document.querySelector('.page[data-page="settings"]').textContent),
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          };
        });
        let ss = await setState();
        check(wname, 'settings', 'the profile summary equals the signed-in user\'s record: SA, System Administrator, admin@athenasec.com, Administrator, MFA on, Security Management, Asia/Dubai', JSON.stringify(ss.profile) === JSON.stringify({ initials: 'SA', name: 'System Administrator', email: 'admin@athenasec.com', role: 'Administrator', mfa: 'MFA on', where: 'Security Management, Asia/Dubai' }), JSON.stringify(ss.profile));
        const wantSwitches = [['autoLogoutWarning', 'Show warning before automatic logout'], ['mfaEnabled', 'Enable MFA'], ['requireMfaForSensitiveActions', 'Require MFA for sensitive administrator actions'], ['notificationsEnabled', 'Enable notifications'], ['criticalAlertNotifications', 'Critical alert notifications'], ['caseNotifications', 'Case creation and assignment notifications'], ['systemHealthNotifications', 'System health warnings'], ['emailNotifications', 'Email notifications']];
        check(wname, 'settings', '8 switches (role=switch, aria-checked) each named by its setting, all On, with the state word beside them', ss.switches.length === 8 && ss.switches.every((s, i) => s.key === wantSwitches[i][0] && s.name === wantSwitches[i][1] && s.on === 'true' && !s.disabled && s.word === 'On'), JSON.stringify(ss.switches));
        check(wname, 'settings', 'theme swatches Dark Enterprise (pressed) and High Contrast; language English / Arabic; timeout 30 minutes / 60 minutes / 4 hours', ss.themes.join() === 'Dark Enterprise:true,High Contrast:false' && ss.language.value === 'English' && ss.language.options.join() === 'English,Arabic' && ss.timeout.value === '30 minutes' && ss.timeout.options.join() === '30 minutes,60 minutes,4 hours', JSON.stringify({ themes: ss.themes, language: ss.language, timeout: ss.timeout }));
        check(wname, 'settings', 'clean start: Saved, Save and Cancel disabled, the MFA-code notice (123456) is shown, no page overflow', ss.pill === 'Saved' && ss.save === true && ss.cancel === true && ss.mfaNotice && ss.overflow <= 0, JSON.stringify({ pill: ss.pill, save: ss.save, cancel: ss.cancel, notice: ss.mfaNotice, overflow: ss.overflow }));
        await page.screenshot({ path: out + `admin-settings-hero-${wname}.png` });
        const flip = key => page.click(`[data-setting="${key}"] button[role="switch"]`);
        // Linked toggles: MFA off clears and locks "Require MFA"
        await flip('mfaEnabled');
        await page.waitForTimeout(100);
        ss = await setState();
        const sw = key => ss.switches.find(s => s.key === key);
        check(wname, 'settings', 'MFA off: "Require MFA for sensitive actions" turns off and is disabled, the summary shows MFA Disabled, the state is Draft', sw('mfaEnabled').on === 'false' && sw('mfaEnabled').word === 'Off' && sw('requireMfaForSensitiveActions').on === 'false' && sw('requireMfaForSensitiveActions').disabled && ss.summary.MFA === 'Disabled' && ss.pill === 'Draft' && ss.message === 'Unsaved settings changes detected.', JSON.stringify({ mfa: sw('mfaEnabled'), require: sw('requireMfaForSensitiveActions'), summary: ss.summary.MFA, pill: ss.pill }));
        await flip('mfaEnabled');
        await page.waitForTimeout(100);
        ss = await setState();
        check(wname, 'settings', 'MFA back on: the requirement is enabled again but stays off until you turn it on', sw('mfaEnabled').on === 'true' && sw('requireMfaForSensitiveActions').on === 'false' && !sw('requireMfaForSensitiveActions').disabled, JSON.stringify(sw('requireMfaForSensitiveActions')));
        // Linked toggles: notifications off clears and locks every channel
        await flip('notificationsEnabled');
        await page.waitForTimeout(100);
        ss = await setState();
        const channels = ['criticalAlertNotifications', 'caseNotifications', 'systemHealthNotifications', 'emailNotifications'];
        check(wname, 'settings', 'notifications off: all 4 channel switches turn off and are disabled; the summary shows Notifications Disabled', channels.every(k => sw(k).on === 'false' && sw(k).disabled) && sw('notificationsEnabled').on === 'false' && ss.summary.Notifications === 'Disabled', JSON.stringify(channels.map(k => sw(k))));
        // Cancel puts everything back
        await page.click('.set-actions button:has-text("Cancel Changes")');
        await page.waitForTimeout(100);
        ss = await setState();
        check(wname, 'settings', 'Cancel Changes restores every switch, returns to Saved, disables Save and Cancel and says so', ss.switches.every(s => s.on === 'true' && !s.disabled) && ss.pill === 'Saved' && ss.save && ss.cancel && ss.message === 'Unsaved settings changes were discarded.', JSON.stringify({ pill: ss.pill, message: ss.message, off: ss.switches.filter(s => s.on !== 'true').map(s => s.key) }));
        // Save keeps the changes (theme, language, timeout, a switch)
        await page.click('.set-theme:has-text("High Contrast")');
        await page.selectOption('#settingsLanguage', 'Arabic');
        await page.selectOption('#sessionTimeout', '4 hours');
        await flip('autoLogoutWarning');
        await page.waitForTimeout(100);
        ss = await setState();
        check(wname, 'settings', 'editing turns the state Draft, enables Save, and the summary follows (High Contrast, Arabic, 4 hours)', ss.pill === 'Draft' && ss.save === false && ss.themes.join() === 'Dark Enterprise:false,High Contrast:true' && ss.summary.Theme === 'High Contrast' && ss.summary.Language === 'Arabic' && ss.summary['Session Timeout'] === '4 hours' && ss.summary['Unsaved Changes'] === 'Yes', JSON.stringify({ pill: ss.pill, summary: ss.summary }));
        await page.click('.set-actions button:has-text("Save Settings")');
        await page.waitForTimeout(100);
        ss = await setState();
        check(wname, 'settings', 'Save Settings says "Settings saved.", returns to Saved and shows Unsaved Changes No', ss.message === 'Settings saved.' && ss.pill === 'Saved' && ss.summary['Unsaved Changes'] === 'No' && ss.save, JSON.stringify({ message: ss.message, pill: ss.pill, summary: ss.summary['Unsaved Changes'] }));
        await page.click('.set-actions button:has-text("Restore Defaults")');
        await page.waitForTimeout(100);
        ss = await setState();
        check(wname, 'settings', 'Restore Defaults brings back Dark Enterprise, English, 30 minutes and the switches, as a Draft that says to save', ss.themes[0] === 'Dark Enterprise:true' && ss.language.value === 'English' && ss.timeout.value === '30 minutes' && sw('autoLogoutWarning').on === 'true' && ss.pill === 'Draft' && ss.message === 'Default settings restored. Save to keep these changes.', JSON.stringify({ themes: ss.themes, pill: ss.pill, message: ss.message }));
        // Edit profile opens the Profile page
        await page.click('#editProfileLink');
        await page.waitForURL('**/app/profile');
        await page.waitForTimeout(200);
        check(wname, 'settings', '"Edit profile" opens the Profile page', await page.evaluate(() => !!document.querySelector('.page[data-page="profile"]')), page.url());

        // Row hover tint on a pinned Actions cell (moved to the Users table when the Integrations page was removed)
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(300);
        const restBg = await page.evaluate(() => getComputedStyle(document.querySelector('tbody tr td.actions-cell')).backgroundColor);
        await page.locator('tbody tr').first().locator('td').first().hover();
        await page.waitForTimeout(250);
        const hoverBg = await page.evaluate(() => getComputedStyle(document.querySelector('tbody tr td.actions-cell')).backgroundColor);
        await page.mouse.move(0, 0);
        check(wname, 'polish', 'Row hover tint continues into the pinned Actions cell', hoverBg !== restBg, `${restBg} -> ${hoverBg}`);

        // ---------- Admin dashboard: posture, MITRE coverage, changes, tasks (replaces the C5 stat-card checks) ----------
        const adminPhone = wname === 'mobile';
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(300);
        const adminDash = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          return {
            posture: [...document.querySelectorAll('[data-posture]')].map(a => `${a.dataset.posture}|${t(a.querySelector('strong'))}|${t(a.querySelector('.posture-label'))}|${t(a.querySelector('.posture-note'))}`),
            // (a soft hyphen in "Recon-naissance" is not part of the name)
            tactics: [...document.querySelectorAll('.mitre-tactic')].map(p => t(p).replace(/­/g, '')),
            cells: [...document.querySelectorAll('.mitre-cell')].map(b => ({ id: b.dataset.technique, tag: b.tagName, state: ['failed', 'waiting', 'open', 'handled', 'quiet'].find(s => b.classList.contains(s)), label: t(b.querySelector('.mitre-cell-state')), name: b.getAttribute('aria-label') ?? '', pressed: b.getAttribute('aria-pressed') })),
            untracked: t(document.querySelector('.mitre-untracked')),
            grid: !!document.querySelector('.mitre-grid'),
            pick: { id: document.querySelector('.mitre-pick')?.dataset.picked, state: t(document.querySelector('.mitre-pick [data-field="pickState"]')), alerts: [...document.querySelectorAll('.mitre-pick [data-alert-id]')].map(li => t(li)), empty: t(document.querySelector('.mitre-pick-detail')), link: t(document.querySelector('.mitre-pick a')) },
            sub: t(document.querySelector('.mitre-head .sub')),
            changes: [...document.querySelectorAll('[data-change-id]')].map(li => `${li.dataset.changeId}|${t(li.querySelector('.change-action'))}|${t(li.querySelector('.change-target'))}|${t(li.querySelector('.pill'))}`),
            tasks: [...document.querySelectorAll('[data-task-id]')].map(li => `${li.dataset.taskId}|${t(li)}`),
          };
        });
        let ad = await adminDash();
        check(wname, 'admin dashboard', 'posture strip is derived from the data (services, policies, MFA, audit)', JSON.stringify(ad.posture) === JSON.stringify([
          'service-panel|8/10|Services healthy|Ollama Runtime and Wazuh Dashboard need attention',
          'response-policies|11/15|Actions on the whitelist|9 automatic, 2 need approval',
          'user-management|3/4|Users with MFA|Analyst C is missing MFA',
          'audit-logs|100%|Audit events stored|OpenSearch, kept 365 days',
        ]), ad.posture.join(' ; '));
        // From the live alerts, responses and the agent's assessments: T1110 has ALT-001 (a request waits) and ALT-005 (closed)
        const wantCells = { T1133: 'quiet', T1068: 'handled', T1548: 'open', T1110: 'waiting', 'T1110.003': 'open', T1046: 'quiet', T1021: 'quiet', T1071: 'handled' };
        const stateWords = { failed: 'Containment failed', waiting: 'Waiting for approval', open: 'Open', handled: 'Handled', quiet: 'Not seen' };
        const wantLabels = { T1133: 'Not seen', T1068: 'Handled · 1', T1548: 'Open · 1', T1110: 'Waiting for approval · 2', 'T1110.003': 'Open · 1', T1046: 'Not seen', T1021: 'Not seen', T1071: 'Handled · 1' };
        check(wname, 'admin dashboard', 'ATT&CK activity: every technique cell shows its state from the alerts and the agent\'s response (T1110 waiting, T1548 and T1110.003 open, T1068 and T1071 handled, the other three not seen)', ad.cells.length === 8 && ad.cells.every(c => wantCells[c.id] === c.state), JSON.stringify(ad.cells.map(c => `${c.id}:${c.state}`)));
        check(wname, 'admin dashboard', 'ATT&CK activity: every cell is a button that names its state in words, with its alert count, shown and in its accessible name ("T1110 Brute force: Waiting for approval, 2 alerts")', ad.cells.every(c => c.tag === 'BUTTON' && c.label === wantLabels[c.id] && c.name.startsWith(`${c.id} `) && c.name.includes(`: ${stateWords[c.state]}`)) && ad.cells.find(c => c.id === 'T1110')?.name === 'T1110 Brute force: Waiting for approval, 2 alerts' && ad.cells.find(c => c.id === 'T1133')?.name === 'T1133 External remote services: Not seen', JSON.stringify(ad.cells.map(c => `${c.id}:${c.label}:${c.name}`)));
        check(wname, 'admin dashboard', 'ATT&CK activity: exactly one cell pressed (T1110 to start); below it the state, both alerts with risk, the agent\'s outcome and where each stands, and a link to the waiting request', ad.cells.filter(c => c.pressed === 'true').map(c => c.id).join() === 'T1110' && ad.pick.id === 'T1110' && ad.pick.state === 'Waiting for approval' && JSON.stringify(ad.pick.alerts) === JSON.stringify(['ALT-001 Brute Force SSH, risk 77. The agent\'s outcome: Recommend IP block. Awaiting approval.', 'ALT-005 Brute Force - SSH Probe, risk 34. The agent\'s outcome: Monitor. Closed.']) && ad.pick.link === 'Open request APR-002', JSON.stringify(ad.pick));
        check(wname, 'admin dashboard', 'ATT&CK activity: the summary counts the techniques and tactics seen and those waiting for a person', ad.sub === '5 techniques seen in today\'s alerts across 3 tactics; 1 is waiting for a person or failed.', ad.sub);
        if (adminPhone) {
          check(wname, 'admin dashboard', 'ATT&CK activity on phones: a list of the 6 tactics with techniques, the other 5 named below', !ad.grid && ad.tactics.length === 6 && ad.untracked === 'No techniques tracked yet: Reconnaissance, Execution, Persistence, Defense evasion, Impact.', JSON.stringify({ tactics: ad.tactics, untracked: ad.untracked }));
        } else {
          check(wname, 'admin dashboard', 'ATT&CK activity: all 11 tactic columns in order (Command and control added), with how many techniques each had seen', ad.grid && JSON.stringify(ad.tactics) === JSON.stringify(['Reconnaissance None seen', 'Initial access None seen', 'Execution None seen', 'Persistence None seen', 'Privilege escalation 2 seen', 'Defense evasion None seen', 'Credential access 2 seen', 'Discovery None seen', 'Lateral movement None seen', 'Command and control 1 seen', 'Impact None seen']), ad.tactics.join(' | '));
          // The eleven columns share the card at a laptop width and up: nothing scrolls and nothing is cut off, "Impact" included
          const mitreFit = await page.evaluate(() => {
            const frame = document.querySelector('.mitre-card .table-scroll');
            const card = document.querySelector('.mitre-card').getBoundingClientRect();
            const columns = [...document.querySelectorAll('.mitre-column')];
            return {
              columns: columns.length,
              scrolls: frame.scrollWidth > frame.clientWidth + 1,
              hint: !!document.querySelector('.mitre-card .table-scroll-hint'),
              lastRight: Math.round(Math.max(...columns.map(c => c.getBoundingClientRect().right))),
              cardRight: Math.round(card.right),
              impact: document.querySelector('#tactic-Impact')?.getBoundingClientRect().right ? Math.round(document.querySelector('#tactic-Impact').getBoundingClientRect().right) : null,
              tacticsClipped: [...document.querySelectorAll('.mitre-tactic')].filter(t => t.scrollWidth > t.clientWidth + 1).map(t => t.textContent.trim()),
              // "Reconnaissance" must break at its soft hyphen ("Recon-" / "naissance"), never in the middle of a syllable: its first line ends at the hyphen
              recon: (() => { const el = document.querySelector('#tactic-Reconnaissance'); const range = document.createRange(); range.selectNodeContents(el.firstChild); const lines = [...range.getClientRects()].map(r => Math.round(r.top)); return { text: el.firstChild.textContent, lines: new Set(lines).size }; })(),
              cellsClipped: [...document.querySelectorAll('.mitre-cell')].filter(c => c.scrollWidth > c.clientWidth + 1).map(c => c.dataset.technique),
            };
          });
          check(wname, 'admin dashboard', `ATT&CK activity fits at ${wname === 'desktop' ? '1440' : '1280'}px: all 11 columns share the card with no sideways scroll and no scroll hint, the last column (Impact) ends inside the card, and no tactic name or technique cell is clipped`, mitreFit.columns === 11 && !mitreFit.scrolls && !mitreFit.hint && mitreFit.lastRight <= mitreFit.cardRight && mitreFit.impact !== null && mitreFit.impact <= mitreFit.cardRight && mitreFit.tacticsClipped.length === 0 && mitreFit.cellsClipped.length === 0 && mitreFit.recon.text.includes('­') && mitreFit.recon.lines <= 2, JSON.stringify(mitreFit));
        }
        check(wname, 'admin dashboard', 'recent changes: the 4 latest administrator events, newest first', JSON.stringify(ad.changes) === JSON.stringify([
          'AUD-206|Updated response policy|Response policy|Success',
          'AUD-204|Saved configuration|Workspace configuration|Success',
          'AUD-203|Updated response policy|Response policy|Success',
          'AUD-201|Created user account|USR-003 · Analyst B|Success',
        ]), ad.changes.join(' ; '));
        check(wname, 'admin dashboard', 'Needs an administrator: MFA, the 400 ms latency target and a service still starting (from data), most urgent first', JSON.stringify(ad.tasks) === JSON.stringify([
          'user-USR-004|Analyst C has MFA disabled and is suspended. Review user',
          'service-SVC-005|Ollama Runtime latency is 486 ms, above the 400 ms target. Check health',
          'service-SVC-009|Wazuh Dashboard is still starting. Check health',
        ]), ad.tasks.join(' ; '));

        // Keyboard: Enter and Space pick a technique; the alert list and the link follow its state
        await page.focus('.mitre-cell[data-technique="T1548"]');
        await page.keyboard.press('Enter');
        await page.waitForTimeout(100);
        ad = await adminDash();
        check(wname, 'admin dashboard', 'ATT&CK activity: Enter picks an open technique (T1548): its one alert with risk, the agent\'s outcome and state, and no request link', ad.pick.id === 'T1548' && ad.pick.state === 'Open' && JSON.stringify(ad.pick.alerts) === JSON.stringify(['ALT-002 Privilege Escalation, risk 50. The agent\'s outcome: Investigate further. Open.']) && ad.pick.link === null && ad.cells.filter(c => c.pressed === 'true').length === 1, JSON.stringify(ad.pick));
        await page.focus('.mitre-cell[data-technique="T1021"]');
        await page.keyboard.press('Space');
        await page.waitForTimeout(100);
        ad = await adminDash();
        check(wname, 'admin dashboard', 'ATT&CK activity: Space picks a technique no alert used (T1021): "Not seen" and "No alert has used this technique today."', ad.pick.id === 'T1021' && ad.pick.state === 'Not seen' && ad.pick.alerts.length === 0 && ad.pick.empty === 'No alert has used this technique today.' && ad.pick.link === null, JSON.stringify(ad.pick));
        await page.click('.mitre-cell[data-technique="T1110"]');
        await page.click('.mitre-pick a');
        await page.waitForURL('**/app/approvals');
        await page.waitForTimeout(450);
        check(wname, 'admin dashboard', '"Open request APR-002" opens Approvals on that request (highlighted)', await page.evaluate(() => !!document.querySelector('.queue-item[data-record-id="APR-002"].is-highlighted')));

        // Live: a change on Response Policies reaches search, the dashboard and the audit log (in-app navigation only)
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('[data-posture="response-policies"]');
        await page.waitForURL('**/app/response-policies');
        await page.waitForTimeout(250);
        await page.click('.perm [data-targets="isolate"] button[aria-expanded]');
        await page.fill('#add-isolate-value', 'SIEM-02');
        await page.keyboard.press('Enter');
        await page.locator('.perm-bar .btn.primary').click();
        await page.waitForTimeout(150);
        await page.locator('#globalSearch').fill('siem-02');
        await page.waitForTimeout(150);
        const ruleHit = await page.evaluate(() => [...document.querySelectorAll('#globalSearchResults [role="option"]')].map(o => o.textContent.replace(/\s+/g, ' ').trim()));
        check(wname, 'admin dashboard', 'admin search finds the saved policy by its new entry straight away: "Response policy · version 4" (siem-02 was added to Never isolate)', ruleHit.some(o => o.includes('Response policy · version 4') && o.includes('whitelisted')), ruleHit.join(' | '));
        await page.keyboard.press('Escape');
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        ad = await adminDash();
        check(wname, 'admin dashboard', 'after adding SIEM-02 to Never isolate: the whitelist figures are unchanged (11/15, 9 automatic, 2 need approval)', ad.posture[1] === 'response-policies|11/15|Actions on the whitelist|9 automatic, 2 need approval', ad.posture[1]);
        check(wname, 'admin dashboard', 'after adding SIEM-02 to Never isolate: the newest change is its audit event (AUD-207)', ad.changes[0] === 'AUD-207|Updated response policy|Response policy|Success' && ad.changes.length === 4, ad.changes.join(' ; '));
        await page.click('.admin-changes a:has-text("Open audit log")');
        await page.waitForURL('**/app/audit-logs');
        await page.waitForTimeout(250);
        const firstAudit = await page.evaluate(() => document.querySelector('.audit-pick[data-record-id]')?.dataset.recordId);
        await page.click('.audit-pick[data-record-id="AUD-207"]');
        if (wname === 'mobile') await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const recorded = await page.evaluate(() => [...document.querySelectorAll('[data-field="changes"] li')].map(s => s.textContent.trim()));
        check(wname, 'admin dashboard', 'Audit Logs lists AUD-207 first; its recorded change reads exactly "Never isolate: added SIEM-02"', firstAudit === 'AUD-207' && JSON.stringify(recorded) === JSON.stringify(['Never isolate: added SIEM-02']), JSON.stringify({ firstAudit, recorded }));
        await page.keyboard.press('Escape');
        await page.waitForTimeout(150);

        // Live: a service check reaches the sidebar badge and the top bar
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('[data-task-id="service-SVC-005"] a');
        await page.waitForURL('**/app/service-panel?view=health');
        await page.waitForTimeout(250);
        await page.locator('button', { hasText: 'Check All Services' }).click();
        await page.waitForTimeout(1300);
        const healthLive = await page.evaluate(() => {
          const statuses = [...document.querySelectorAll('tbody tr[data-record-id]')].map(r => [...r.querySelectorAll('.pill')].map(p => p.textContent.trim()).find(s => ['Running', 'Starting', 'Degraded', 'Failed', 'Stopped', 'Unverified'].includes(s)));
          const flagged = statuses.filter(s => s !== 'Running');
          const item = [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Service Panel');
          const summary = document.querySelector('#healthSummary')?.textContent.replace(/\s+/g, ' ').trim() ?? '';
          return { statuses, flagged: flagged.length, badge: Number(item?.querySelector('.count')?.textContent ?? 0), status: document.querySelector('.system-status-widget .status-text')?.textContent.trim(), summary, healthyOf: /^(\d+) of 10 services healthy/.exec(summary)?.[1] };
        });
        const wantStatus = healthLive.flagged === 0 ? 'All Systems Operational' : null;
        check(wname, 'admin dashboard', 'after "Check All Services": the Service Panel badge counts the services that need attention now (the Wazuh Dashboard, still starting, always counts)', healthLive.statuses.length === 10 &&healthLive.badge === healthLive.flagged && (wantStatus === null || healthLive.status === wantStatus), JSON.stringify(healthLive));

        // Live: the dashboard's Services healthy count agrees with System Health after the check
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        ad = await adminDash();
        check(wname, 'admin dashboard', 'after "Check All Services": the dashboard\'s "Services healthy" count equals System Health\'s own "N of 10 services healthy" line', new RegExp(`^service-panel\\|${healthLive.healthyOf}/10\\|Services healthy\\|`).test(ad.posture[0] ?? ''), `${healthLive.summary} | ${ad.posture[0]}`);

        // ---------- Response Policies: the Permissions tab (whitelist, blacklist, protected targets; replaces the If / Then card checks) ----------
        // (A fresh load: the dashboard checks above changed the session, and this page starts from the seed.)
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        const perm = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const rows = list => [...document.querySelectorAll(`[data-list="${list}"] li[data-action]`)];
          const bar = [...document.querySelectorAll('.perm-bar .btn')];
          return {
            h1: t(document.querySelector('h1')),
            tabs: [...document.querySelectorAll('[role="tab"]')].map(b => `${t(b)}:${b.getAttribute('aria-selected')}`).join(' | '),
            unsaved: t(document.querySelector('[data-field="unsaved"]')),
            save: bar.find(b => t(b) === 'Save changes')?.disabled,
            discard: bar.find(b => t(b) === 'Discard')?.disabled,
            counts: ['automaticCount', 'approvalCount', 'blacklistCount'].map(f => t(document.querySelector(`[data-field="${f}"]`))).join(','),
            unlisted: t(document.querySelector('[data-field="unlisted"]')),
            whitelist: rows('whitelist').map(li => ({ action: li.dataset.action, mode: li.dataset.mode, options: [...li.querySelectorAll('.segmented-option')].map(b => ({ text: t(b), pressed: b.getAttribute('aria-pressed'), disabled: b.disabled, name: b.getAttribute('aria-label') ?? t(b) })) })),
            blacklist: rows('blacklist').map(li => ({ action: li.dataset.action, required: li.dataset.required, text: t(li.querySelector('[data-field="required"]')), buttons: li.querySelectorAll('button').length })),
            notListed: rows('unlisted').map(li => `${li.dataset.action}:${[...li.querySelectorAll('button')].map(b => b.getAttribute('aria-label')).join('/')}`),
            block: [...document.querySelectorAll('[data-targets="block"] li[data-target]')].map(li => `${li.dataset.target}|${li.dataset.required}`),
            isolate: [...document.querySelectorAll('[data-targets="isolate"] li[data-target]')].map(li => `${li.dataset.target}|${li.dataset.required}`),
            history: [...document.querySelectorAll('[data-list="history"] li[data-event]')].map(li => `${li.dataset.event}|${t(li.querySelector('span:last-child'))}`),
            message: t(document.querySelector('[data-field="policyMessage"]')),
          };
        });
        const fieldVal = id => page.evaluate(i => document.getElementById(i)?.value, id);
        const clickPerm = label => page.click(`.perm button[aria-label="${label}"]`);
        const savePerm = async () => { await page.locator('.perm-bar .btn.primary').click(); await page.waitForTimeout(150); };
        const setField = async (id, value) => { await page.fill(`#${id}`, String(value)); };
        let pm = await perm();
        check(wname, 'permissions', 'Response Policies opens on the Permissions tab: title, tabs (Permissions selected, Action catalogue), "No unsaved changes" with Save and Discard disabled, and the summary 9 automatic, 2 needing approval, 6 blacklisted, anything not listed Denied', pm.h1 === 'Response Policies' && pm.tabs === 'Permissions:true | Action catalogue:false' && pm.unsaved === 'No unsaved changes' && pm.save === true && pm.discard === true && pm.counts === '9,2,6' && pm.unlisted === 'Denied', JSON.stringify(pm));
        check(wname, 'permissions', 'the Whitelist lists the nine Tier 1 actions then block_ip and isolate_host, in the catalogue\'s order', pm.whitelist.map(r => r.action).join() === 'get_logs,analyse_alert,check_ip_reputation,get_asset_context,monitor,create_alert,create_ticket,recommend_response,notify_analyst,block_ip,isolate_host', pm.whitelist.map(r => r.action).join());
        check(wname, 'permissions', 'a Tier 1 row is Automatic with "Needs approval" disabled (named "Needs approval: available later"); a Tier 2 row is Needs approval with "Automatic" disabled (named with its reason); each row names its mode in a group', pm.whitelist.filter(r => r.action !== 'block_ip' && r.action !== 'isolate_host').every(r => r.mode === 'Automatic' && r.options[0].pressed === 'true' && r.options[0].disabled === false && r.options[1].disabled === true && r.options[1].name === 'Needs approval: available later') && pm.whitelist.filter(r => ['block_ip', 'isolate_host'].includes(r.action)).every(r => r.mode === 'Needs approval' && r.options[1].pressed === 'true' && r.options[0].disabled === true && r.options[0].name === 'Automatic: a Tier 2 action always needs a person to approve it'), JSON.stringify(pm.whitelist.slice(8)));
        check(wname, 'permissions', 'the Blacklist holds the six prohibited actions, each Required and locked (no Remove); Not on either list holds suspend_user_session, kill_process, quarantine_file and reset_password, each with Whitelist and Blacklist buttons named for it', pm.blacklist.length === 6 && pm.blacklist.every(r => r.required === 'true' && r.text === 'Required' && r.buttons === 0) && pm.notListed.join() === 'suspend_user_session:Whitelist suspend_user_session/Blacklist suspend_user_session,kill_process:Whitelist kill_process/Blacklist kill_process,quarantine_file:Whitelist quarantine_file/Blacklist quarantine_file,reset_password:Whitelist reset_password/Blacklist reset_password', JSON.stringify([pm.blacklist, pm.notListed]));
        check(wname, 'permissions', 'Protected targets: Never block holds the PDF\'s seven entries and Never isolate dc-01, db-prod-01 and siem-01, all Required (no Remove); Change history lists AUD-206 and AUD-203 newest first with their first change', pm.block.join() === '10.0.0.0/8|true,172.16.0.0/12|true,192.168.0.0/16|true,127.0.0.0/8|true,192.0.2.10/32|true,192.0.2.128/25|true,10.0.1.15/32|true' && pm.isolate.join() === 'dc-01|true,db-prod-01|true,siem-01|true' && pm.history.join(' ; ') === 'AUD-206|block_ip: Automatic → Needs approval (+1 more) ; AUD-203|isolate_host: Automatic → Needs approval', JSON.stringify([pm.block, pm.isolate, pm.history]));

        // Against the design image (Phase 6 part 5, the seven marked fixes): one check per visible change
        const phone = wname === 'mobile';
        const design = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const rgb = s => (s.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
          const lum = ([r, g, b]) => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
          const ratio = (a, b) => { const [x, y] = [lum(rgb(a)), lum(rgb(b))].sort((p, q) => q - p); return Math.round(((x + 0.05) / (y + 0.05)) * 10) / 10; };
          const color = sel => getComputedStyle(document.querySelector(sel)).color;
          const pressed = (action, mode) => { const b = document.querySelector(`[data-list="whitelist"] li[data-action="${action}"] .segmented-option[data-mode="${mode}"][aria-pressed="true"]`); const cs = getComputedStyle(b); return { bg: cs.backgroundColor, color: cs.color, ratio: ratio(cs.color, cs.backgroundColor) }; };
          const headline = document.querySelector('.page.active .headline');
          const title = headline.firstElementChild.getBoundingClientRect();
          const bar = document.querySelector('.perm-bar').getBoundingClientRect();
          const rowsWrapped = [...document.querySelectorAll('[data-list="whitelist"] li[data-action] .perm-row')].filter(row => {
            const centres = [...row.querySelectorAll('.segmented, .perm-buttons .btn')].map(e => { const r = e.getBoundingClientRect(); return r.top + r.height / 2; });
            return Math.max(...centres) - Math.min(...centres) > 3;
          }).map(row => row.closest('li').dataset.action);
          const rowsOverflow = [...document.querySelectorAll('[data-list="whitelist"] li[data-action] .perm-row')].filter(row => row.scrollWidth > row.clientWidth + 1).length;
          const icons = [...document.querySelectorAll('[data-list="whitelist"] .perm-buttons .btn')].map(b => { const r = b.getBoundingClientRect(); return { named: !!b.getAttribute('aria-label'), tip: !!b.dataset.tip, text: b.textContent.trim(), w: Math.round(r.width), h: Math.round(r.height), svg: !!b.querySelector('svg[aria-hidden="true"]') }; });
          const unlisted = [...document.querySelectorAll('[data-list="unlisted"] li[data-action]')].map(li => { const r = li.getBoundingClientRect(); return { x: Math.round(r.left), y: Math.round(r.top + scrollY) }; });
          const titles = [...document.querySelectorAll('.perm-card h2')].map(h => ({ text: t(h), size: parseFloat(getComputedStyle(h).fontSize), font: getComputedStyle(h).fontFamily, marker: getComputedStyle(h, '::before').display }));
          return {
            tones: { automatic: color('[data-field="automaticCount"]'), approval: color('[data-field="approvalCount"]'), blacklist: color('[data-field="blacklistCount"]'), denied: t(document.querySelector('[data-field="unlisted"]')), deniedIcon: !!document.querySelector('[data-field="unlisted"] svg[aria-hidden="true"]'), labels: [...document.querySelectorAll('.perm-summary > div > span')].map(t) },
            fills: { automatic: pressed('get_logs', 'Automatic'), approval: pressed('block_ip', 'Needs approval') },
            wrapped: rowsWrapped, overflow: rowsOverflow, icons, unlisted, titles,
            subtitle: t(document.querySelector('#policySummary')),
            barInHeadline: !!document.querySelector('.perm-bar')?.closest('.headline'),
            barBeside: bar.top < title.bottom && bar.left >= title.right - 1,
            barUnder: bar.top >= title.bottom - 1,
            barText: [...document.querySelectorAll('.perm-bar > *')].map(e => t(e)).join(' | '),
          };
        });
        check(wname, 'permissions design', 'the summary numbers are coloured by meaning (automatic blue, needs approval amber, blacklisted red) and each label above still says it in words; "Denied" carries a lock icon beside its text', design.tones.automatic === 'rgb(185, 218, 255)' && design.tones.approval === 'rgb(245, 210, 122)' && design.tones.blacklist === 'rgb(255, 122, 138)' && design.tones.denied === 'Denied' && design.tones.deniedIcon && design.tones.labels.join('|') === 'Whitelisted, runs automatically|Whitelisted, needs approval|Blacklisted|Anything not listed', JSON.stringify(design.tones));
        check(wname, 'permissions design', 'the selected mode is filled by meaning: Automatic blue, Needs approval amber, each with text at 4.5:1 or better on its fill', design.fills.automatic.bg === 'rgb(29, 58, 102)' && design.fills.approval.bg === 'rgb(74, 58, 18)' && design.fills.automatic.ratio >= 4.5 && design.fills.approval.ratio >= 4.5, JSON.stringify(design.fills));
        check(wname, 'permissions design', 'the whitelist row buttons are icon buttons: each is an svg with no text, has its full aria-label and a tooltip text, and is at least 40 by 40 px', design.icons.length === 24 && design.icons.every(b => b.named && b.tip && b.text === '' && b.svg && b.w >= 40 && b.h >= 40), JSON.stringify(design.icons.filter(b => !(b.named && b.tip && b.text === '' && b.svg && b.w >= 40 && b.h >= 40))));
        if (!phone) check(wname, 'permissions design', 'no whitelist row wraps its control and buttons onto a second line (all share one line), and none overflows its card', design.wrapped.length === 0 && design.overflow === 0, JSON.stringify({ wrapped: design.wrapped, overflow: design.overflow }));
        else check(wname, 'permissions design', 'on a phone a whitelist row may wrap its control and buttons under the name, but nothing runs past the card', design.overflow === 0, String(design.overflow));
        await page.hover('[data-list="whitelist"] li[data-action="get_logs"] .btn[data-tip]');
        await page.waitForTimeout(100);
        const hoverTip = await page.evaluate(() => { const b = document.querySelector('[data-list="whitelist"] li[data-action="get_logs"] .btn[data-tip]'); const cs = getComputedStyle(b, '::after'); return { content: cs.content, visibility: cs.visibility, opacity: cs.opacity }; });
        await page.mouse.move(0, 0);
        await page.keyboard.press('Shift');
        await page.focus('[data-list="whitelist"] li[data-action="monitor"] .btn[data-tip]');
        await page.waitForTimeout(100);
        const focusTip = await page.evaluate(() => { const cs = getComputedStyle(document.activeElement, '::after'); return { content: cs.content, visibility: cs.visibility, name: document.activeElement.getAttribute('aria-label') }; });
        check(wname, 'permissions design', 'each icon button shows a visible tooltip on hover ("Move to blacklist") and on keyboard focus, and keeps its full aria-label', hoverTip.content === '"Move to blacklist"' && hoverTip.visibility === 'visible' && focusTip.content === '"Move to blacklist"' && focusTip.visibility === 'visible' && focusTip.name === 'Move monitor to the blacklist', JSON.stringify({ hoverTip, focusTip }));
        const gridXs = [...new Set(design.unlisted.map(c => c.x))].length;
        const gridYs = [...new Set(design.unlisted.map(c => c.y))].length;
        check(wname, 'permissions design', phone ? 'Not on either list is one column on a phone (four cards, one below the other)' : 'Not on either list is a 2 x 2 grid of cards at desktop and laptop widths (two columns, two rows)', design.unlisted.length === 4 && (phone ? gridXs === 1 && gridYs === 4 : gridXs === 2 && gridYs === 2), JSON.stringify(design.unlisted));
        check(wname, 'permissions design', 'the card titles are large display titles (26px, Archivo, no marker) on all five cards: Whitelist, Blacklist, Not on either list, Protected targets, Change history', design.titles.map(x => x.text).join('|') === 'Whitelist|Blacklist|Not on either list|Protected targets|Change history' && design.titles.every(x => x.size >= 24 && /Archivo/.test(x.font) && x.marker === 'none'), JSON.stringify(design.titles));
        check(wname, 'permissions design', 'the page subtitle is the design\'s sentence (whitelisted available, blacklisted blocked, anything not listed denied)', design.subtitle === 'The AthenaSec agent decides for itself how to respond to an alert. You decide what it is allowed to use. Whitelisted actions are available to it; blacklisted actions are blocked; anything not listed is denied.', design.subtitle);
        check(wname, 'permissions design', phone ? 'the version, unsaved line, Discard and Save changes sit in the headline and stack under the title on a phone' : 'the version, unsaved line, Discard and Save changes sit beside the title (top right of the headline), not on a row of their own', design.barInHeadline && (phone ? design.barUnder : design.barBeside) && design.barText === 'Version 3 | No unsaved changes | Discard | Save changes', JSON.stringify({ inHeadline: design.barInHeadline, beside: design.barBeside, under: design.barUnder, text: design.barText }));

        // Approval limits: opened on request, the PDF's cap beside each control
        const limitsToggle = '.perm button[aria-label="Approval limits for block_ip"]';
        await page.focus(limitsToggle);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(100);
        const limits = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const toggle = document.querySelector('.perm button[aria-label="Approval limits for block_ip"]');
          const box = document.getElementById('limits-block_ip');
          return {
            expanded: toggle.getAttribute('aria-expanded'), focusKept: document.activeElement === toggle,
            values: ['defaultMinutes', 'maxMinutes', 'approver', 'windowMinutes', 'minRisk'].map(f => document.getElementById(`limit-block_ip-${f}`)?.value).join(),
            labels: [...box.querySelectorAll('.form-label')].map(t).join(' | '),
            caps: [...box.querySelectorAll('.approval-hint')].map(t).join(' | '),
            named: [...box.querySelectorAll('input, select')].every(i => i.labels?.length === 1),
          };
        });
        check(wname, 'permissions', 'the Approval limits button opens block_ip\'s limits from the keyboard (aria-expanded, focus stays on it): 30, 1440, soc_analyst, 15, 70, each control labelled, with the PDF\'s cap beside it', limits.expanded === 'true' && limits.focusKept && limits.values === '30,1440,soc_analyst,15,70' && limits.labels === 'Default duration (minutes) | Longest allowed (minutes) | Who approves | Time to decide (minutes) | Minimum risk' && limits.caps.startsWith('At most the longest allowed | At most 24 h | SOC analyst or higher | At most 15 min | At least 70') && limits.named, JSON.stringify(limits));

        // A draft: edits change the counts and the unsaved line, Discard puts the saved policy back
        await clickPerm('Move block_ip to the blacklist');
        pm = await perm();
        const drafted = { counts: pm.counts, unsaved: pm.unsaved, save: pm.save, black: pm.blacklist.find(r => r.action === 'block_ip'), inWhite: pm.whitelist.some(r => r.action === 'block_ip') };
        check(wname, 'permissions', 'moving block_ip to the blacklist is a draft: the counts follow (9, 1, 7), "1 unsaved change", Save enabled, and block_ip shows in the Blacklist with a Remove button (not Required)', drafted.counts === '9,1,7' && drafted.unsaved === '1 unsaved change' && drafted.save === false && drafted.black?.required === 'false' && drafted.black?.buttons === 1 && !drafted.inWhite, JSON.stringify(drafted));
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(100);
        pm = await perm();
        check(wname, 'permissions', 'Discard puts the saved policy back: 9, 2, 6, "No unsaved changes", block_ip on the Whitelist again, and the status line is a live region', pm.counts === '9,2,6' && pm.unsaved === 'No unsaved changes' && pm.whitelist.some(r => r.action === 'block_ip') && !pm.blacklist.some(r => r.action === 'block_ip') && await page.evaluate(() => document.querySelector('[data-field="unsaved"]').getAttribute('role') === 'status'), JSON.stringify([pm.counts, pm.unsaved]));

        // Save past a cap is refused beside the field with the PDF's number, and writes nothing
        await clickPerm('Approval limits for isolate_host');
        await setField('limit-block_ip-maxMinutes', 1441);
        await setField('limit-block_ip-windowMinutes', 16);
        await setField('limit-block_ip-minRisk', 69);
        await page.selectOption('#limit-isolate_host-approver', 'soc_analyst');
        await setField('limit-isolate_host-maxMinutes', 241);
        await setField('limit-isolate_host-minRisk', 84);
        await savePerm();
        const refused = await page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const err = id => t(document.getElementById(`${id}-error`));
          return {
            maxBlock: err('limit-block_ip-maxMinutes'), windowBlock: err('limit-block_ip-windowMinutes'), riskBlock: err('limit-block_ip-minRisk'),
            approverIso: err('limit-isolate_host-approver'), maxIso: err('limit-isolate_host-maxMinutes'), riskIso: err('limit-isolate_host-minRisk'),
            invalid: [...document.querySelectorAll('.perm [aria-invalid="true"]')].length,
            described: document.getElementById('limit-block_ip-maxMinutes').getAttribute('aria-describedby'),
            message: t(document.querySelector('[data-field="policyMessage"]')),
            history: [...document.querySelectorAll('[data-list="history"] li[data-event]')].length,
          };
        });
        check(wname, 'permissions', 'Save past the PDF\'s caps is refused beside each field with the PDF\'s own number (24 h, 15 min, 70, SOC lead, 4 h, 85), the fields are marked invalid and tied to their reason, the message says nothing was saved, and no audit event is written', /24 h/.test(refused.maxBlock) && /15 min/.test(refused.windowBlock) && /70/.test(refused.riskBlock) && /SOC lead/.test(refused.approverIso) && /4 h/.test(refused.maxIso) && /85/.test(refused.riskIso) && refused.invalid === 6 && /limit-block_ip-maxMinutes-error/.test(refused.described) && /^Not saved: 6 limits are past/.test(refused.message) && refused.history === 2, JSON.stringify(refused));
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(100);
        pm = await perm();
        check(wname, 'permissions', 'Discard after a refused save clears the reasons and the draft', pm.unsaved === 'No unsaved changes' && await page.evaluate(() => document.querySelectorAll('.perm [aria-invalid="true"]').length === 0 && document.getElementById('limit-block_ip-maxMinutes').value === '1440'), pm.unsaved);

        // Protected targets: Add from the keyboard, refused when invalid, saved as one audited change
        await page.focus('.perm [data-targets="isolate"] button[aria-expanded]');
        await page.keyboard.press('Enter');
        await page.waitForTimeout(100);
        // F24: the field no longer takes focus by itself (it is a page-level field, not a dialog): focus stays on the button that opened the form, and one Tab reaches the field
        const stayedOnButton = await page.evaluate(() => document.activeElement?.getAttribute('aria-expanded') === 'true' && document.activeElement?.getAttribute('aria-controls') === 'add-isolate');
        await page.keyboard.press('Tab');
        const addFocus = await page.evaluate(() => document.activeElement?.id);
        await page.keyboard.press('Enter');
        const emptyErr = await page.evaluate(() => document.getElementById('add-isolate-error')?.textContent.trim());
        await page.fill('#add-isolate-value', 'dc-01');
        await page.keyboard.press('Enter');
        const dupErr = await page.evaluate(() => document.getElementById('add-isolate-error')?.textContent.trim());
        await page.fill('#add-isolate-value', 'SIEM-02');
        await page.keyboard.press('Enter');
        await page.waitForTimeout(100);
        pm = await perm();
        check(wname, 'permissions', 'Add to Never isolate works from the keyboard: Enter opens the form and focus stays on the button (no autofocus on a page field), one Tab reaches the field, an empty value and a duplicate (dc-01, capitals ignored) are refused with a reason, SIEM-02 is added as a draft ("1 unsaved change") with a Remove button, and the form closes', stayedOnButton && addFocus === 'add-isolate-value' && emptyErr === 'Enter a host name.' && /already on the Never isolate list/.test(dupErr) && pm.isolate.join() === 'dc-01|true,db-prod-01|true,siem-01|true,SIEM-02|false' && pm.unsaved === '1 unsaved change' && await page.evaluate(() => !document.getElementById('add-isolate') && !!document.querySelector('.perm button[aria-label="Remove SIEM-02 from Never isolate"]')), JSON.stringify({ addFocus, emptyErr, dupErr, isolate: pm.isolate }));
        await page.click('.perm [data-targets="block"] button[aria-expanded]');
        await page.fill('#add-block-value', 'not-an-ip');
        await page.keyboard.press('Enter');
        const badIp = await page.evaluate(() => document.getElementById('add-block-error')?.textContent.trim());
        await page.click('.perm [data-targets="block"] button:has-text("Cancel")');
        check(wname, 'permissions', 'Add to Never block refuses a value that is not an IP address or range, and Cancel closes the form without adding it', /is not an IP address or range/.test(badIp) && (await perm()).block.length === 7, badIp);
        await savePerm();
        pm = await perm();
        check(wname, 'permissions', 'Save writes one change: "Saved", "No unsaved changes", Save disabled again, and Change history gains AUD-207 first with "Never isolate: added SIEM-02" (old → new in the audit log)', /^Saved/.test(pm.message) && pm.unsaved === 'No unsaved changes' && pm.save === true && pm.history[0] === 'AUD-207|Never isolate: added SIEM-02' && pm.history.length === 3, JSON.stringify([pm.message, pm.history]));
        await clickPerm('Remove SIEM-02 from Never isolate');
        const removed = await perm();
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(100);
        const restored = await perm();
        check(wname, 'permissions', 'an administrator\'s own entry can be removed as a draft ("1 unsaved change"), and Discard puts it back', removed.unsaved === '1 unsaved change' && !removed.isolate.some(x => x.startsWith('SIEM-02')) && restored.unsaved === 'No unsaved changes' && restored.isolate.includes('SIEM-02|false'), JSON.stringify([removed.isolate, restored.isolate]));

        // Screen edits change outcomes. Each starts from a fresh load (the seed), saves, and looks at the alert, the request and Simulate an attempt.
        const go = path => page.evaluate(p => { history.pushState({}, '', p); window.dispatchEvent(new PopStateEvent('popstate')); }, path);
        const alt1Outcome = async () => {
          await go('/app/dashboard');
          await page.waitForTimeout(250);
          await page.click('.mitre-cell[data-technique="T1110"]');
          await page.waitForTimeout(100);
          return page.evaluate(() => [...document.querySelectorAll('.mitre-pick [data-alert-id]')].map(li => li.textContent.replace(/\s+/g, ' ').trim()).find(s => s.startsWith('ALT-001')));
        };
        const apr2Refusal = async () => {
          await go('/app/approvals');
          await page.waitForTimeout(300);
          await page.click('.queue-item[data-record-id="APR-002"]');
          if (wname === 'mobile') await page.waitForSelector('[role="dialog"]');
          await page.waitForTimeout(150);
          return page.evaluate(() => ({ text: document.querySelector('[data-field="refusal"]')?.textContent.replace(/\s+/g, ' ').trim() ?? null, disabled: !![...document.querySelectorAll('fieldset')].find(f => f.querySelector('button[type="submit"]'))?.disabled }));
        };
        const trySimulate = async (action, target) => {
          await go('/app/response-policies?view=catalogue');
          await page.waitForTimeout(250);
          await page.selectOption('#attemptAction', action);
          await page.fill('#attemptTarget', target);
          await page.fill('#attemptRisk', '90');
          await page.fill('#attemptConfidence', '0.90');
          await page.locator('.attempt-form button[type="submit"]').click();
          await page.waitForTimeout(150);
          return page.evaluate(() => ({ decision: document.querySelector('[data-field="attemptDecision"]')?.textContent.trim(), reason: document.querySelector('[data-field="attemptReason"]')?.textContent.trim(), rule: document.querySelector('[data-field="attemptRule"]')?.textContent.trim() }));
        };
        const savedHistory = () => page.evaluate(() => [...document.querySelectorAll('[data-list="history"] li[data-event]')].slice(0, 1).map(li => li.textContent.replace(/\s+/g, ' ').trim()).join());
        const openLimits = async name => { if ((await page.getAttribute(`.perm button[aria-label="Approval limits for ${name}"]`, 'aria-expanded')) !== 'true') await clickPerm(`Approval limits for ${name}`); };

        // 1. Raise block_ip's minimum risk above ALT-001's 77: the alert no longer qualifies and its request is refused
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        await openLimits('block_ip');
        await setField('limit-block_ip-minRisk', 78);
        await savePerm();
        const raisedHistory = await savedHistory();
        const raisedAlert = await alt1Outcome();
        const raisedRequest = await apr2Refusal();
        const raisedAttempt = await trySimulate('block_ip', '203.0.113.45');
        check(wname, 'permissions live', 'raising block_ip\'s minimum risk to 78 (above ALT-001\'s 77): the save is audited ("block_ip minimum risk: 70 → 78"), ALT-001 is no longer a block recommendation (Create alert and ticket), APR-002 cannot be decided (the policy\'s reason, form disabled), and Simulate an attempt for block_ip at risk 90 still needs approval but at 77 would be refused', /^2026-08-03 \d\d:\d\dblock_ip minimum risk: 70 → 78$/.test(raisedHistory) && /Create alert and ticket/.test(raisedAlert) && !/Recommend IP block/.test(raisedAlert) && /no longer allows this: Risk 77 is below the response policy's minimum risk of 78 for block_ip/.test(raisedRequest.text) && raisedRequest.disabled === true && raisedAttempt.decision === 'Needs approval', JSON.stringify({ raisedHistory, raisedAlert, raisedRequest, raisedAttempt }));
        await go('/app/response-policies?view=catalogue');
        await page.waitForTimeout(250);
        await page.fill('#attemptRisk', '77');
        await page.locator('.attempt-form button[type="submit"]').click();
        await page.waitForTimeout(150);
        const lowAttempt = await page.evaluate(() => ({ decision: document.querySelector('[data-field="attemptDecision"]')?.textContent.trim(), reason: document.querySelector('[data-field="attemptReason"]')?.textContent.trim() }));
        check(wname, 'permissions live', 'Simulate an attempt reads the saved policy: block_ip at risk 77 is refused with "Risk 77 is below the response policy\'s minimum risk of 78 for block_ip."', lowAttempt.decision === 'Refused' && lowAttempt.reason === 'Risk 77 is below the response policy\'s minimum risk of 78 for block_ip.', JSON.stringify(lowAttempt));
        // Discard reverts an unsaved edit and leaves the saved 78; putting it back to 70 qualifies the alert and the request again
        await go('/app/response-policies');
        await page.waitForTimeout(250);
        await openLimits('block_ip');
        await setField('limit-block_ip-minRisk', 95);
        const draftOnly = await perm();
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(100);
        const afterDiscard = await fieldVal('limit-block_ip-minRisk');
        check(wname, 'permissions live', 'Discard reverts: an unsaved minimum of 95 counts as a change ("1 unsaved change"), Discard shows the saved 78 again, and nothing was audited by it', draftOnly.unsaved === '1 unsaved change' && afterDiscard === '78' && (await perm()).history.length === 3, JSON.stringify({ draftOnly: draftOnly.unsaved, afterDiscard }));
        await openLimits('block_ip');
        await setField('limit-block_ip-minRisk', 70);
        await savePerm();
        const backHistory = await savedHistory();
        const backAlert = await alt1Outcome();
        const backRequest = await apr2Refusal();
        check(wname, 'permissions live', 'putting block_ip\'s minimum risk back to 70 is its own audited change ("78 → 70"), and ALT-001 is a block recommendation again with APR-002 open for a decision', /block_ip minimum risk: 78 → 70/.test(backHistory) && /Recommend IP block/.test(backAlert) && backRequest.text === null && backRequest.disabled === false, JSON.stringify({ backHistory, backAlert, backRequest }));

        // 2. Blacklist block_ip: the request is refused and the alert falls to a ticket; Simulate an attempt names the list
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        await clickPerm('Move block_ip to the blacklist');
        await savePerm();
        const blackHistory = await savedHistory();
        const blackAlert = await alt1Outcome();
        const blackRequest = await apr2Refusal();
        const blackAttempt = await trySimulate('block_ip', '203.0.113.45');
        check(wname, 'permissions live', 'blacklisting block_ip: the save is audited ("block_ip: Needs approval → Blacklisted"), ALT-001 is no longer a block recommendation, APR-002 is refused ("on the response policy\'s blacklist"), and Simulate an attempt for block_ip is Refused with the Blacklist as its rule', /block_ip: Needs approval → Blacklisted/.test(blackHistory) && !/Recommend IP block/.test(blackAlert) && /no longer allows this: block_ip is on the response policy's blacklist/.test(blackRequest.text) && blackRequest.disabled === true && blackAttempt.decision === 'Refused' && /blacklist/.test(blackAttempt.reason) && /Response policy: Blacklist/.test(blackAttempt.rule), JSON.stringify({ blackHistory, blackAlert, blackRequest, blackAttempt }));

        // 3. Never block 203.0.113.45: refused as a protected target, though block_ip stays whitelisted
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        await page.click('.perm [data-targets="block"] button[aria-expanded]');
        await page.fill('#add-block-value', '203.0.113.45');
        await page.keyboard.press('Enter');
        await savePerm();
        const protectedHistory = await savedHistory();
        const protectedRequest = await apr2Refusal();
        const protectedAttempt = await trySimulate('block_ip', '203.0.113.45');
        const otherAttempt = await trySimulate('block_ip', '203.0.113.46');
        check(wname, 'permissions live', 'adding 203.0.113.45 to Never block: audited ("Never block: added 203.0.113.45"), APR-002 is refused as a protected target, Simulate an attempt for that IP is Refused with Never block as its rule, and another external IP still needs approval (block_ip stays whitelisted)', /Never block: added 203.0.113.45/.test(protectedHistory) && /no longer allows this: 203.0.113.45 is on the Never block list/.test(protectedRequest.text) && protectedRequest.disabled === true && protectedAttempt.decision === 'Refused' && /Response policy: Never block/.test(protectedAttempt.rule) && otherAttempt.decision === 'Needs approval', JSON.stringify({ protectedHistory, protectedRequest, protectedAttempt, otherAttempt }));

        // 4. The audit log keeps each saved change as old → new
        await go('/app/audit-logs');
        await page.waitForTimeout(250);
        await page.click('.audit-pick[data-record-id="AUD-207"]');
        if (wname === 'mobile') await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const savedChange = await page.evaluate(() => ({ lines: [...document.querySelectorAll('[data-field="changes"] li')].map(s => s.textContent.trim()), meta: document.querySelector('[data-field="metadata"]')?.textContent.replace(/\s+/g, ' ').trim() ?? '' }));
        check(wname, 'permissions live', 'Audit Logs shows the saved change as its record: AUD-207 reads exactly "Never block: added 203.0.113.45", with the new policy version in its details', JSON.stringify(savedChange.lines) === JSON.stringify(['Never block: added 203.0.113.45']), JSON.stringify(savedChange));
        if (wname === 'mobile') { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(250);

        // The old filters, switches and Add / Edit / Delete forms went with the If / Then cards; the Permissions checks above replace them.
        // A tablist, labelled groups and no card filter bar: the page's controls are reachable by keyboard (checked above), and the generic checks (labels, focus rings, tap size) cover the rest.

        // ---------- User Management (5d): account health, access review, fields, self protection ----------
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(250);
        const umIsPhone = wname === 'mobile';
        const SELF_REASON = 'You cannot suspend, delete, or change the role of your own account.';
        const wantUsers = [
          ['USR-001', 'System Administrator (you)', 'admin@athenasec.com', 'Administrator', 'Active', 'Enabled', 'Security Management', 'Today, 20:46'],
          ['USR-002', 'Analyst A', 'analyst@athenasec.com', 'Analyst', 'Active', 'Enabled', 'Security Operations', 'Today, 20:31'],
          ['USR-003', 'Analyst B', 'analyst.b@athenasec.com', 'Analyst', 'Active', 'Enabled', 'Security Operations', 'Today, 18:42'],
          ['USR-004', 'Analyst C', 'analyst.c@athenasec.com', 'Analyst', 'Suspended', 'Disabled', 'Threat Detection', '3 days ago'],
        ];
        const umState = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          return {
            rows: [...document.querySelectorAll('tbody tr[data-record-id]')].map(r => ({
              id: r.dataset.recordId, name: t(r.querySelector('.um-user-text strong')), sub: t(r.querySelector('.um-user-sub')),
              role: t(r.querySelector('td:nth-child(2) .pill')), status: t(r.querySelector('[data-field="status"]')),
              mfa: t(r.querySelector('[data-field="mfa"]')), dept: t(r.querySelector('[data-field="department"]')), last: t(r.querySelector('td:last-child')),
              note: t(r.querySelector('.um-self-note')), noteShown: (r.querySelector('.um-self-note')?.getClientRects().length ?? 0) > 0,
            })),
            counts: Object.fromEntries([...document.querySelectorAll('.um-health-counts > div')].map(d => [d.dataset.count, t(d.querySelector('dd')) + ' ' + t(d.querySelector('dt'))])),
            bar: document.querySelector('.um-health-bar')?.getAttribute('aria-label'),
            total: t(document.querySelector('.um-health-head .sub')),
            review: [...document.querySelectorAll('.um-review-list > li')].map(li => ({ id: li.dataset.reviewId, text: t(li.querySelector('.um-review-text')), buttons: [...li.querySelectorAll('button')].map(b => t(b)) })),
            clear: t(document.querySelector('[data-review="clear"]')),
            message: t(document.querySelector('main .notice[role="status"]')),
          };
        });
        let us = await umState();
        check(wname, 'users', 'the fields table covers all 4 users: name, id, email, role, status, MFA, department and last sign-in', JSON.stringify(us.rows.map(r => [r.id, r.name, r.sub.split(' · ')[1], r.role, r.status, r.mfa, r.dept, r.last])) === JSON.stringify(wantUsers) && us.rows.every(r => r.sub === `${r.id} · ${r.sub.split(' · ')[1]}`), JSON.stringify(us.rows));
        check(wname, 'users', 'Account health is counted from the users: 3 active with MFA, 1 suspended, 1 administrator, 3 analysts', us.total === '4 accounts' && us.counts['active-with-mfa'] === '3 active with MFA' && us.counts.suspended === '1 suspended' && us.counts.administrators === '1 administrator' && us.counts.analysts === '3 analysts' && us.bar === '3 active with MFA, 0 active without MFA, 1 suspended', JSON.stringify({ total: us.total, counts: us.counts, bar: us.bar }));
        check(wname, 'users', 'Access review names Analyst C (suspended, MFA off, last sign-in 3 days ago) with Require MFA and Remove account', us.review.length === 1 && us.review[0].id === 'USR-004' && us.review[0].text.startsWith('Analyst C is suspended and has MFA turned off (last sign-in 3 days ago).') && us.review[0].buttons.join('|') === 'Require MFA|Remove account', JSON.stringify(us.review));
        check(wname, 'users', 'only your own row carries "(you)" and the caption "You can\'t suspend or delete your own account." (shown on wide screens, the "⋯" menu explains it on phones)', us.rows.filter(r => r.note).map(r => r.id).join() === 'USR-001' && us.rows[0].note === "You can't suspend or delete your own account." && us.rows[0].noteShown === !umIsPhone && us.rows.filter(r => r.name.includes('(you)')).length === 1, JSON.stringify(us.rows.map(r => [r.id, r.note, r.noteShown])));
        // Record ids (USR-001) stay on one line: each sits in a .record-id that is never split across lines
        const idWraps = scope => page.evaluate(sel => {
          const idRe = /\b[A-Z]{2,4}-\d{3}\b/;
          const holders = [...document.querySelectorAll(sel)].filter(e => e.getClientRects().length > 0);
          const ids = holders.flatMap(h => [...h.querySelectorAll('.record-id')]);
          return {
            holders: holders.length,
            ids: ids.length,
            broken: ids.filter(e => e.getClientRects().length > 1).map(e => e.textContent),
            bare: holders.filter(h => { const c = h.cloneNode(true); c.querySelectorAll('.record-id').forEach(n => n.remove()); return idRe.test(c.textContent); }).length,
          };
        }, scope);
        const userIds = await idWraps('.um-user-sub');
        check(wname, 'users', 'record ids in the user rows (USR-001) are never split across lines', userIds.holders === 4 && userIds.ids === 4 && userIds.broken.length === 0 && userIds.bare === 0, JSON.stringify(userIds));
        const noClip = await page.evaluate(() => [...document.querySelectorAll('.um-health, .um-review')].filter(c => c.scrollWidth > c.clientWidth + 1).map(c => c.className));
        check(wname, 'users', 'the summary cards are not clipped and the page does not scroll sideways', noClip.length === 0 && (await hOverflow()) <= 0, JSON.stringify({ noClip, overflow: await hOverflow() }));
        await page.screenshot({ path: out + `admin-users-hero-${wname}.png` });

        // Self protection, past the UI: call the disabled controls' own handlers; the shared state must refuse
        const callHandler = (rowId, label) => page.evaluate(([id, text]) => {
          const b = [...document.querySelector(`tr[data-record-id="${id}"]`).querySelectorAll('button')].find(x => x.textContent.trim() === text);
          const key = Object.keys(b).find(k => k.startsWith('__reactProps$'));
          b[key].onClick({});
          return b.disabled;
        }, [rowId, label]);
        const suspendWasDisabled = await callHandler('USR-001', 'Suspend');
        await page.waitForTimeout(150);
        us = await umState();
        check(wname, 'self protection', 'own Suspend: the control is disabled, and calling its handler anyway leaves the account Active (the shared state refuses it)', suspendWasDisabled && us.rows[0].status === 'Active' && us.message === SELF_REASON && us.counts.suspended === '1 suspended', JSON.stringify({ suspendWasDisabled, status: us.rows[0].status, message: us.message }));
        const deleteWasDisabled = await callHandler('USR-001', 'Delete');
        await page.waitForSelector('[role="dialog"]');
        await page.locator('[role="dialog"] button', { hasText: 'Delete User' }).click();
        await page.waitForTimeout(200);
        us = await umState();
        check(wname, 'self protection', 'own Delete: the control is disabled, and confirming a delete of your own id anyway removes nothing (the shared state refuses it)', deleteWasDisabled && us.rows.length === 4 && us.rows[0].id === 'USR-001' && us.message === SELF_REASON && !(await page.evaluate(() => !!document.querySelector('[role="dialog"]'))), JSON.stringify({ deleteWasDisabled, rows: us.rows.length, message: us.message }));
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('.admin-changes a:has-text("Open audit log")');
        await page.waitForURL('**/app/audit-logs');
        await page.waitForTimeout(250);
        const refusedAudit = await page.evaluate(() => document.querySelector('.audit-pick[data-record-id]')?.dataset.recordId);
        check(wname, 'self protection', 'the refused attempts wrote no audit event (newest is still AUD-206)', refusedAudit === 'AUD-206', refusedAudit);

        // Access review: Remove account opens the delete confirm; Require MFA clears the review and is audited
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('[data-posture="user-management"]');
        await page.waitForURL('**/app/user-management');
        await page.waitForTimeout(250);
        await page.locator('.um-review-list li[data-review-id="USR-004"] button', { hasText: 'Remove account' }).click();
        await page.waitForSelector('[role="dialog"]');
        const removeDialog = await page.evaluate(() => ({ label: document.querySelector('[role="dialog"]').getAttribute('aria-label'), text: document.querySelector('[role="dialog"]').textContent.includes('Analyst C') }));
        check(wname, 'users', '"Remove account" opens the existing delete confirm for Analyst C', removeDialog.label === 'Delete user' && removeDialog.text, JSON.stringify(removeDialog));
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);
        await page.locator('.um-review-list li[data-review-id="USR-004"] button', { hasText: 'Require MFA' }).click();
        await page.waitForTimeout(200);
        us = await umState();
        check(wname, 'users', 'Require MFA clears the access review (it says so) and turns Analyst C\'s MFA on', us.review.length === 0 && us.clear === 'No account needs review. Every suspended account has MFA turned on.' && us.rows[3].mfa === 'Enabled' && us.message === 'MFA is now required for Analyst C.', JSON.stringify({ review: us.review, clear: us.clear, mfa: us.rows[3].mfa, message: us.message }));
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        ad = await adminDash();
        check(wname, 'users', 'Require MFA reaches the dashboard: 4/4 with MFA, Analyst C\'s task is gone, AUD-207 is the newest change', ad.posture.some(p => p.startsWith('user-management|4/4|Users with MFA|')) && !ad.tasks.some(x => x.startsWith('user-USR-004')) && ad.changes[0] === 'AUD-207|Required MFA for user account|USR-004 · Analyst C|Success', JSON.stringify({ posture: ad.posture[3], tasks: ad.tasks, change: ad.changes[0] }));
        await page.click('.admin-changes a:has-text("Open audit log")');
        await page.waitForURL('**/app/audit-logs');
        await page.waitForTimeout(250);
        await page.click('.audit-pick[data-record-id="AUD-207"]');
        if (umIsPhone) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const mfaAudit = await page.evaluate(() => ({ first: document.querySelector('.audit-pick[data-record-id]')?.dataset.recordId, changes: [...document.querySelectorAll('[data-field="changes"] li')].map(s => s.textContent.trim()) }));
        check(wname, 'users', 'Audit Logs lists AUD-207 first; its recorded change reads exactly "MFA: Off → On"', mfaAudit.first === 'AUD-207' && JSON.stringify(mfaAudit.changes) === JSON.stringify(['MFA: Off → On']), JSON.stringify(mfaAudit));
        if (umIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('.audit-chip[data-category="User Management"]');
        await page.waitForTimeout(100);
        const umChip = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => b.dataset.recordId));
        check(wname, 'audit', 'the session event appears under its category chip: User Management lists AUD-207 and AUD-201', umChip.join() === 'AUD-207,AUD-201', umChip.join());

        // ---------- Audit Logs (5d): summary, chips, event list, panel, export, search ----------
        await page.goto(base + '/app/audit-logs');
        await page.waitForTimeout(250);
        const wantAudit = [
          ['AUD-206', '15:44', '2026-08-03 15:44:07', 'Updated response policy', 'Response policy', 'System Administrator', 'Administrator', 'Response Policy', '10.0.1.10', 'Success', 2, 2],
          ['AUD-205', '15:44', '2026-08-03 15:44:00', 'Executed host isolation', 'endpoint-12', 'AthenaSec AI', 'System', 'Incident Response', '127.0.0.1', 'Success', 4, 6],
          ['AUD-204', '15:42', '2026-08-03 15:42:18', 'Saved configuration', 'Workspace configuration', 'System Administrator', 'Administrator', 'System', '10.0.1.10', 'Success', 3, 4],
          ['AUD-203', '15:10', '2026-08-03 15:10:42', 'Updated response policy', 'Response policy', 'System Administrator', 'Administrator', 'Response Policy', '10.0.1.10', 'Success', 1, 2],
          ['AUD-202', '14:35', '2026-08-03 14:35:08', 'Took ownership of alert', 'ALT-001 · Brute Force SSH', 'Analyst A', 'Analyst', 'Incident Response', '10.0.2.25', 'Success', 3, 4],
          ['AUD-201', '14:21', '2026-08-03 14:21:08', 'Created user account', 'USR-003 · Analyst B', 'System Administrator', 'Administrator', 'User Management', '10.0.1.10', 'Success', 4, 4],
          ['AUD-200', '13:55', '2026-08-03 13:55:31', 'Checked service', 'SVC-002 · OpenSearch', 'System Administrator', 'Administrator', 'System', '10.0.1.10', 'Success', 4, 4],
          ['AUD-199', '12:10', '2026-08-03 12:10:04', 'Failed MFA verification', 'analyst.b@athenasec.com', 'Analyst B', 'Analyst', 'Authentication', '10.0.2.31', 'Failed', 3, 4],
          ['AUD-198', '11:42', '2026-08-03 11:42:37', 'Login denied', 'admin@athenasec.com', 'Unknown User', 'System', 'Authentication', '203.0.113.70', 'Denied', 3, 4],
          ['AUD-197', '10:55', '2026-08-03 10:55:22', 'Refreshed system health', '10 monitored services', 'System Administrator', 'Administrator', 'System', '10.0.1.10', 'Success', 3, 4],
          ['AUD-196', '10:15', '2026-08-03 10:15:08', 'Completed audit synchronization', 'OpenSearch audit index', 'System', 'System', 'System', '127.0.0.1', 'Success', 3, 4],
        ];
        const auditShape = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          return {
            summary: [...document.querySelectorAll('.audit-summary > div')].map(d => d.innerText.replace(/\s+/g, ' ').trim()),
            retention: t(document.querySelector('#auditRetention')),
            chips: [...document.querySelectorAll('.audit-chip')].map(c => `${t(c)}:${c.getAttribute('aria-pressed')}`),
            count: t(document.querySelector('#visibleAuditCount')),
            rows: [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => ({ id: b.dataset.recordId, tag: b.tagName, time: t(b.querySelector('.audit-time')), action: t(b.querySelector('.audit-action')), meta: t(b.querySelector('.audit-meta')), result: t(b.querySelector('.pill')) })),
          };
        });
        let au = await auditShape();
        check(wname, 'audit', 'summary strip is counted from the events: 11 recorded, 9 successful, 1 failed operation, 1 denied security event', JSON.stringify(au.summary) === JSON.stringify(['11 events recorded', '9 successful', '1 failed operation', '1 denied security event']), JSON.stringify(au.summary));
        check(wname, 'audit', 'header says "Read-only, kept 365 days in OpenSearch" (retention from the configuration) beside "Export shown events"', au.retention === 'Read-only, kept 365 days in OpenSearch' && await page.evaluate(() => [...document.querySelectorAll('.headline-actions .btn')].some(b => b.textContent.trim() === 'Export shown events')), au.retention);
        check(wname, 'audit', 'category chips: All plus all 5 categories (including System), only All pressed', JSON.stringify(au.chips) === JSON.stringify(['All:true', 'Authentication:false', 'Response Policy:false', 'User Management:false', 'Incident Response:false', 'System:false']), au.chips.join(' '));
        check(wname, 'audit', 'the list shows all 11 events: time, action and target, "user · category · IP" and the result in words', au.rows.length === 11 && au.rows.every((r, i) => r.id === wantAudit[i][0] && r.tag === 'BUTTON' && r.time === wantAudit[i][1] && r.action === `${wantAudit[i][3]} ${wantAudit[i][4]}` && r.meta === `${wantAudit[i][5]} · ${wantAudit[i][7]} · ${wantAudit[i][8]}` && r.result === wantAudit[i][9]), JSON.stringify(au.rows.filter((r, i) => r.action !== `${wantAudit[i][3]} ${wantAudit[i][4]}` || r.meta !== `${wantAudit[i][5]} · ${wantAudit[i][7]} · ${wantAudit[i][8]}`)));
        await listChecks(wname, 'audit list', '.audit-pick', 11);
        // Record ids in event targets (SVC-002, ALT-001, USR-003) never break after the hyphen
        const listIds = await idWraps('.audit-target');
        await page.click('.audit-pick[data-record-id="AUD-202"]');
        if (umIsPhone) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(100);
        const panelIds = await idWraps('[data-field="target"]');
        if (umIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        check(wname, 'audit', 'record ids in event targets stay on one line, in the list and in the panel', listIds.ids === 3 && listIds.broken.length === 0 && listIds.bare === 0 && panelIds.ids === 1 && panelIds.broken.length === 0 && panelIds.bare === 0, JSON.stringify({ listIds, panelIds }));
        // Every event's panel: id, result, action, when, who + role, category, target, IP, description, changes, metadata
        const panelMisses = [];
        for (const w of wantAudit) {
          await page.click(`.audit-pick[data-record-id="${w[0]}"]`);
          await page.waitForTimeout(60);
          const pnl = await page.evaluate(() => {
            const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
            const f = n => t(document.querySelector(`[data-field="${n}"]`));
            return { id: f('id'), result: f('result'), action: f('action'), when: f('when'), who: f('who'), category: f('category'), target: f('target'), ip: f('sourceIp'), description: f('description'), changes: document.querySelectorAll('[data-field="changes"] li').length, meta: document.querySelectorAll('[data-field="metadata"] > div').length, note: /can't be edited or deleted/.test(document.querySelector('.audit-detail')?.textContent ?? '') };
          });
          const ok = pnl.id === w[0] && pnl.result === w[9] && pnl.action === w[3] && pnl.when === w[2] && pnl.who === `${w[5]} (${w[6]})` && pnl.category === w[7] && pnl.target === w[4] && pnl.ip === w[8] && pnl.description && pnl.changes === w[10] && pnl.meta === w[11] && pnl.note;
          if (!ok) panelMisses.push(`${w[0]}: ${JSON.stringify(pnl)}`);
          if (umIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(120); }
        }
        check(wname, 'audit', 'selecting each of the 11 events shows every old column and drawer field in the panel (id, result, when, who + role, category, target, IP, description, changes, metadata, read-only note)', panelMisses.length === 0, panelMisses.join(' | '));
        // The block_ip minimum-risk change (90 → 70) is an audited administrator change, not a silent data edit
        await page.click('.audit-pick[data-record-id="AUD-206"]');
        if (umIsPhone) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(100);
        const polAudit = await page.evaluate(() => ({
          action: document.querySelector('[data-field="action"]')?.textContent.trim(),
          target: document.querySelector('[data-field="target"]')?.textContent.replace(/\s+/g, ' ').trim(),
          who: document.querySelector('[data-field="who"]')?.textContent.replace(/\s+/g, ' ').trim(),
          changes: [...document.querySelectorAll('[data-field="changes"] li')].map(li => li.textContent.trim()),
        }));
        check(wname, 'audit', 'AUD-206 records the response policy\'s version 3 by the System Administrator: "block_ip: Automatic → Needs approval" and "block_ip minimum risk: 90 → 70"', polAudit.action === 'Updated response policy' && polAudit.target === 'Response policy' && polAudit.who === 'System Administrator (Administrator)' && polAudit.changes.length === 2 && polAudit.changes[0] === 'block_ip: Automatic → Needs approval' && polAudit.changes[1] === 'block_ip minimum risk: 90 → 70', JSON.stringify(polAudit));
        if (umIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        // Same colour everywhere for the result words, and the action words (Validated, Created, Completed) are plain text, never status pills
        const resultColours = await page.evaluate(() => {
          const out = {};
          for (const b of document.querySelectorAll('.audit-pick[data-record-id]')) { const p = b.querySelector('.pill'); out[p.textContent.trim()] = (out[p.textContent.trim()] ?? new Set()).add(getComputedStyle(p).backgroundColor + '/' + getComputedStyle(p).color); }
          return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v]]));
        });
        // Failed and Denied are both red app-wide (one colour per word); the words tell them apart
        check(wname, 'audit', 'Success, Failed and Denied each have one colour in the list; Success is green, Failed and Denied the app-wide red', Object.keys(resultColours).sort().join() === 'Denied,Failed,Success' && Object.values(resultColours).every(v => v.length === 1) && resultColours.Success[0] === 'rgb(16, 41, 31)/rgb(126, 224, 176)' && resultColours.Failed[0] === 'rgb(58, 18, 24)/rgb(255, 122, 138)' && resultColours.Denied[0] === resultColours.Failed[0], JSON.stringify(resultColours));
        const stripColours = await page.evaluate(() => [...document.querySelectorAll('.audit-summary strong')].map(s => getComputedStyle(s).color));
        check(wname, 'audit', 'the summary strip uses the same colours as the pills: successful green, failed and denied red', stripColours[1] === 'rgb(126, 224, 176)' && stripColours[2] === 'rgb(255, 122, 138)' && stripColours[3] === 'rgb(255, 122, 138)', stripColours.join(' | '));
        if (umIsPhone) { await page.click('.audit-pick[aria-pressed="true"]'); await page.waitForSelector('[role="dialog"]'); await page.waitForTimeout(100); }
        const panelPillMatch = await page.evaluate(() => {
          const sel = document.querySelector('.audit-pick[aria-pressed="true"]');
          const rowPill = getComputedStyle(sel.querySelector('.pill')), panelPill = getComputedStyle(document.querySelector('[data-field="result"]'));
          return rowPill.backgroundColor === panelPill.backgroundColor && rowPill.color === panelPill.color;
        });
        check(wname, 'audit', 'the selected event\'s result has the same colour in the list and in the panel (I3)', panelPillMatch);
        if (umIsPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        const plainActionWords = await page.evaluate(() => [...document.querySelectorAll('.pill')].map(p => p.textContent.trim()).filter(x => /^(Validated|Created|Completed)/.test(x)));
        check(wname, 'audit', '"Validated", "Created" and "Completed" appear only inside action names, never as coloured status pills (so no colour to keep in sync)', plainActionWords.length === 0, plainActionWords.join(', '));
        // Chips and filters
        await page.click('.audit-chip[data-category="Response Policy"]');
        await page.waitForTimeout(100);
        au = await auditShape();
        check(wname, 'audit', 'the Response Policy chip filters to AUD-206 and AUD-203, shows "2 visible", and is the only chip pressed', au.rows.map(r => r.id).join() === 'AUD-206,AUD-203' && au.count === '2 visible' && au.chips.filter(c => c.endsWith(':true')).join() === 'Response Policy:true', JSON.stringify({ rows: au.rows.map(r => r.id), count: au.count }));
        await page.click('.audit-chip[data-category="System"]');
        await page.waitForTimeout(100);
        au = await auditShape();
        check(wname, 'audit', 'the System chip (a category the old filter lacked in the chips) lists the four System events: AUD-204 (saved configuration), AUD-200 (OpenSearch check), AUD-197 (health refresh) and AUD-196', au.rows.map(r => r.id).join() === 'AUD-204,AUD-200,AUD-197,AUD-196' && au.count === '4 visible', `${au.rows.map(r => r.id).join()} | ${au.count}`);
        if (umIsPhone) { /* drawer is closed here */ }
        // Export only what is shown
        await page.click('.audit-chip[data-category="Response Policy"]');
        await page.waitForTimeout(100);
        const [download] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export shown events")')]);
        let csv = '';
        for await (const chunk of await download.createReadStream()) csv += chunk.toString();
        const csvIds = [...csv.matchAll(/"(AUD-\d+)"/g)].map(m => m[1]);
        check(wname, 'audit', 'Export shown events writes only the 2 visible events (AUD-206, AUD-203), under the original file name', csvIds.join() === 'AUD-206,AUD-203' && download.suggestedFilename() === 'athenasec-audit-logs.csv', `${csvIds.join()} | ${download.suggestedFilename()}`);
        // Search finds an event the chip is hiding: the filter clears and the event is selected and focused
        await page.locator('#globalSearch').fill('AUD-199');
        await page.waitForTimeout(200);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(500);
        const searched = await page.evaluate(() => ({
          pressed: [...document.querySelectorAll('.audit-pick[aria-pressed="true"]')].map(b => b.dataset.recordId),
          chip: [...document.querySelectorAll('.audit-chip')].filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.textContent.trim()),
          focused: document.activeElement?.dataset?.recordId,
          visible: document.querySelectorAll('.audit-pick[data-record-id]').length,
        }));
        check(wname, 'audit', 'search for AUD-199 while the Response Policy chip hides it: the filter clears, the event is selected and focused', searched.pressed.join() === 'AUD-199' && searched.chip.join() === 'All' && searched.focused === 'AUD-199' && searched.visible === 11, JSON.stringify(searched));
        if (umIsPhone) {
          await dialogKeyboard(wname, 'Audit event drawer', () => page.click('.audit-pick[data-record-id="AUD-198"]'));
          check(wname, 'C8 modal', 'Audit event drawer: focus returns to the event that opened it', await page.evaluate(() => document.activeElement?.dataset?.recordId === 'AUD-198'));
        }
        await page.screenshot({ path: out + `admin-audit-${wname}.png`, fullPage: true });

        // I5 self protection
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(250);
        const um = await page.evaluate(() => {
          const rows = [...document.querySelectorAll('tbody tr')];
          const self = rows.find(r => r.textContent.includes('admin@athenasec.com'));
          const other = rows.find(r => r.textContent.includes('analyst@athenasec.com'));
          const btn = (r, t) => [...r.querySelectorAll('button')].find(b => b.textContent.trim() === t);
          return {
            selfSuspend: btn(self, 'Suspend').disabled, selfDelete: btn(self, 'Delete').disabled,
            title: btn(self, 'Delete').title,
            otherSuspend: btn(other, 'Suspend').disabled, otherDelete: btn(other, 'Delete').disabled,
          };
        });
        check(wname, 'I5 self', 'own Suspend & Delete disabled', um.selfSuspend && um.selfDelete, um.title);
        check(wname, 'I5 self', "other users' Suspend & Delete still enabled", !um.otherSuspend && !um.otherDelete);
        const selfRow = page.locator('tbody tr[data-record-id="USR-001"]');
        if (wname === 'mobile') {
          // On phones Edit lives in the row's "⋯" menu.
          await tap('tr[data-record-id="USR-001"] .overflow-trigger');
          await page.locator('[role="menu"] [role="menuitem"]', { hasText: 'Edit' }).click();
        } else {
          await selfRow.locator('button', { hasText: 'Edit' }).click();
        }
        await page.waitForSelector('#userRole');
        const ed = await page.evaluate(() => ({ role: document.querySelector('#userRole').disabled, status: document.querySelector('#userStatus').disabled, note: !!document.querySelector('#selfEditNote') }));
        check(wname, 'I5 self', 'editing own account: role & status locked with note', ed.role && ed.status && ed.note, JSON.stringify(ed));
        if (wname === 'mobile') await page.screenshot({ path: out + 'admin-edit-self-mobile.png' });
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);

        // ---------- User Management row actions: every button on wide screens, View + "⋯" on phones ----------
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(250);
        const umRows = await page.evaluate(() => [...document.querySelectorAll('tbody tr[data-record-id]')].map(r => {
          const cell = r.querySelector('td.actions-cell');
          const shown = [...cell.querySelectorAll('button')].filter(b => b.getClientRects().length > 0).map(b => b.classList.contains('overflow-trigger') ? b.getAttribute('aria-label') : b.textContent.trim());
          const userTd = r.querySelector('td:first-child');
          const email = userTd.querySelector('.sub');
          const range = document.createRange();
          range.selectNodeContents(email);
          const lines = [...range.getClientRects()];
          const td = userTd.getBoundingClientRect();
          const pinnedLeft = cell.getBoundingClientRect().left;
          return {
            id: r.dataset.recordId,
            shown,
            height: Math.round(r.getBoundingClientRect().height),
            emailText: email.textContent,
            emailInCell: lines.every(l => l.right <= td.right + 0.5 && l.left >= td.left - 0.5),
            emailClearOfPinned: lines.every(l => l.right <= pinnedLeft + 0.5),
            ellipsis: getComputedStyle(userTd).textOverflow === 'ellipsis' && getComputedStyle(userTd).whiteSpace === 'nowrap',
          };
        }));
        check(wname, 'UM menu', 'full email shown in every row (wraps, never truncated)', umRows.length > 0 && umRows.every(u => u.emailInCell && !u.ellipsis && /@athenasec\.com$/.test(u.emailText)), JSON.stringify(umRows.filter(u => !u.emailInCell || u.ellipsis).map(u => u.id)));
        if (wname === 'mobile') {
          check(wname, 'UM menu', 'phone: each row shows only View and a "⋯" button', umRows.every(u => u.shown.length === 2 && u.shown[0] === 'View' && /^More actions for /.test(u.shown[1])), umRows.map(u => `${u.id}: ${u.shown.join('/')}`).join(' ; '));
          check(wname, 'UM menu', 'phone: rows are one button tall (no stacked buttons)', umRows.every(u => u.height <= 90), umRows.map(u => `${u.id}=${u.height}px`).join(', '));
          check(wname, 'UM menu', 'phone: email is not hidden behind the pinned Actions column', umRows.every(u => u.emailClearOfPinned), umRows.filter(u => !u.emailClearOfPinned).map(u => u.id).join(', '));
        } else {
          const want = /^View\|Edit\|Reset Password\|(Suspend|Activate)\|Delete$/;
          check(wname, 'UM menu', 'wide screen: all five action buttons shown, no "⋯" menu', umRows.every(u => want.test(u.shown.join('|'))), umRows.map(u => `${u.id}: ${u.shown.join('/')}`).join(' ; '));
        }

        if (wname === 'mobile') {
          const menuState = id => page.evaluate(rowId => {
            const trigger = document.querySelector(`tr[data-record-id="${rowId}"] .overflow-trigger`);
            const menu = document.querySelector('[role="menu"]');
            const r = menu?.getBoundingClientRect();
            const active = document.activeElement;
            return {
              open: !!menu,
              expanded: trigger.getAttribute('aria-expanded'),
              haspopup: trigger.getAttribute('aria-haspopup'),
              controls: !!menu && trigger.getAttribute('aria-controls') === menu.id,
              items: menu ? [...menu.querySelectorAll('[role="menuitem"]')].map(i => i.textContent.trim()) : [],
              disabled: menu ? [...menu.querySelectorAll('[role="menuitem"][aria-disabled="true"]')].map(i => i.textContent.trim()) : [],
              note: menu?.querySelector('.overflow-note')?.textContent.trim() ?? null,
              inViewport: !!r && r.left >= 0 && r.top >= 0 && r.right <= document.documentElement.clientWidth && r.bottom <= window.innerHeight,
              focused: active?.getAttribute('role') === 'menuitem' ? active.textContent.trim() : active === trigger ? 'trigger' : (active?.tagName ?? 'none'),
            };
          }, id);

          const otherTrigger = 'tr[data-record-id="USR-002"] .overflow-trigger';
          await tap(otherTrigger);
          await page.waitForTimeout(150);
          let ms = await menuState('USR-002');
          await page.screenshot({ path: out + 'admin-user-menu-mobile.png' });
          check(wname, 'UM menu', '"⋯" opens a menu with Edit, Reset Password, Suspend, Delete', ms.open && ms.items.join('|') === 'Edit|Reset Password|Suspend|Delete', ms.items.join('|'));
          check(wname, 'UM menu', '"⋯" button: aria-haspopup=menu, aria-expanded=true, aria-controls the menu', ms.haspopup === 'menu' && ms.expanded === 'true' && ms.controls, JSON.stringify(ms));
          check(wname, 'UM menu', 'menu opens with focus on its first item', ms.focused === 'Edit', ms.focused);
          check(wname, 'UM menu', 'menu fits inside the viewport', ms.inViewport, JSON.stringify(ms));
          check(wname, 'UM menu', "another user's menu has nothing disabled", ms.disabled.length === 0 && ms.note === null, ms.disabled.join(', '));

          await page.keyboard.press('ArrowDown');
          const afterDown = (await menuState('USR-002')).focused;
          await page.keyboard.press('End');
          const afterEnd = (await menuState('USR-002')).focused;
          await page.keyboard.press('ArrowDown');
          const afterWrap = (await menuState('USR-002')).focused;
          check(wname, 'UM menu', 'ArrowDown, End and wrap-around move focus between items', afterDown === 'Reset Password' && afterEnd === 'Delete' && afterWrap === 'Edit', `${afterDown} / ${afterEnd} / ${afterWrap}`);
          await page.keyboard.press('Escape');
          await page.waitForTimeout(100);
          ms = await menuState('USR-002');
          check(wname, 'UM menu', 'Escape closes the menu and returns focus to "⋯"', !ms.open && ms.expanded === 'false' && ms.focused === 'trigger', JSON.stringify(ms));
          const tableScrollLeft = await page.evaluate(() => document.querySelector('.page[data-page="user-management"] .table-scroll').scrollLeft);
          check(wname, 'UM menu', 'returning focus to "⋯" does not scroll the table sideways', tableScrollLeft === 0, `scrollLeft=${tableScrollLeft}`);

          await tap(otherTrigger);
          await page.waitForTimeout(100);
          await page.keyboard.press('Tab');
          await page.waitForTimeout(100);
          ms = await menuState('USR-002');
          check(wname, 'UM menu', 'Tab closes the menu and returns focus to "⋯"', !ms.open && ms.focused === 'trigger', JSON.stringify(ms));

          await tap(otherTrigger);
          await page.waitForTimeout(100);
          // The main area's left padding: always on screen, never under the menu, nothing clickable.
          // (Clicking an off-screen element instead would make Playwright scroll, and scrolling a
          // sticky cell into view also scrolls its table sideways.)
          await page.mouse.click(8, 400);
          await page.waitForTimeout(100);
          check(wname, 'UM menu', 'clicking outside closes the menu', !(await menuState('USR-002')).open);

          // Choosing an item runs it; a dialog it opens hands focus back to "⋯" when closed.
          await tap(otherTrigger);
          await page.locator('[role="menu"] [role="menuitem"]', { hasText: 'Reset Password' }).click();
          await page.waitForTimeout(200);
          const resetDialog = await page.evaluate(() => document.querySelector('[role="dialog"]')?.getAttribute('aria-label') ?? null);
          check(wname, 'UM menu', 'Reset Password item opens the reset dialog and closes the menu', resetDialog === 'Reset user password' && !(await menuState('USR-002')).open, resetDialog);
          await page.keyboard.press('Escape');
          await page.waitForTimeout(200);
          check(wname, 'UM menu', 'closing that dialog returns focus to "⋯"', (await menuState('USR-002')).focused === 'trigger');
          const afterDialogScrollLeft = await page.evaluate(() => document.querySelector('.page[data-page="user-management"] .table-scroll').scrollLeft);
          check(wname, 'UM menu', 'closing that dialog does not scroll the table sideways', afterDialogScrollLeft === 0, `scrollLeft=${afterDialogScrollLeft}`);

          await tap(otherTrigger);
          await page.locator('[role="menu"] [role="menuitem"]', { hasText: 'Suspend' }).click();
          await page.waitForTimeout(150);
          const suspended = await page.evaluate(() => [...document.querySelectorAll('tr[data-record-id="USR-002"] [data-field="status"]')].map(p => p.textContent.trim()));
          await tap(otherTrigger);
          await page.waitForTimeout(100);
          ms = await menuState('USR-002');
          check(wname, 'UM menu', 'Suspend item suspends the user and the menu then offers Activate', suspended.includes('Suspended') && ms.items.includes('Activate') && !ms.items.includes('Suspend'), `${suspended.join(', ')} | ${ms.items.join('|')}`);
          await page.locator('[role="menu"] [role="menuitem"]', { hasText: 'Activate' }).click();
          await page.waitForTimeout(100);

          // Own account: Suspend and Delete stay listed but disabled, with the reason shown
          await tap('tr[data-record-id="USR-001"] .overflow-trigger');
          await page.waitForTimeout(150);
          ms = await menuState('USR-001');
          if (rname === 'admin') await page.screenshot({ path: out + 'admin-user-menu-self-mobile.png' });
          check(wname, 'UM menu', 'own account: Suspend and Delete disabled in the menu, reason shown', ms.disabled.join('|') === 'Suspend|Delete' && /own account/.test(ms.note || ''), JSON.stringify({ disabled: ms.disabled, note: ms.note }));
          // force: Playwright won't click an aria-disabled item, but a user can tap it.
          await page.locator('[role="menu"] [role="menuitem"]', { hasText: 'Delete' }).click({ force: true });
          await page.waitForTimeout(150);
          const selfDeleteDialog = await page.evaluate(() => !!document.querySelector('[role="dialog"]'));
          check(wname, 'UM menu', 'own account: choosing disabled Delete does nothing', !selfDeleteDialog);
          await page.keyboard.press('Escape');
          await page.waitForTimeout(100);
        }

        // I4: three visually distinct variants (Permissions has Save changes, a plain Blacklist button on the Whitelist and a red Blacklist button under "Not on either list")
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(250);
        const variants = await page.evaluate(() => {
          const style = el => { const cs = getComputedStyle(el); return { bg: cs.backgroundColor, img: cs.backgroundImage !== 'none', border: cs.borderTopColor, color: cs.color }; };
          return {
            primary: style(document.querySelector('.perm-bar .btn.primary')),
            secondary: style(document.querySelector('[data-list="whitelist"] .btn.small:not(.ghost):not(.danger)')),
            danger: style(document.querySelector('[data-list="unlisted"] .btn.danger')),
          };
        });
        check(wname, 'I4 buttons', 'primary is a filled gradient', variants.primary.img, JSON.stringify(variants.primary));
        check(wname, 'I4 buttons', 'destructive is a red outline with no fill', variants.danger.bg === 'rgba(0, 0, 0, 0)' && variants.danger.border === 'rgb(255, 61, 87)' && !variants.danger.img, JSON.stringify(variants.danger));
        check(wname, 'I4 buttons', 'secondary is a filled surface with no gradient', !variants.secondary.img && variants.secondary.bg === 'rgb(58, 20, 25)', JSON.stringify(variants.secondary));
        await page.locator('[data-list="unlisted"] .btn.danger').first().hover();
        await page.waitForTimeout(300);
        const dangerHover = await page.evaluate(() => getComputedStyle(document.querySelector('[data-list="unlisted"] .btn.danger')).backgroundColor);
        check(wname, 'I4 buttons', 'destructive gets a red fill on hover', dangerHover === 'rgb(58, 18, 24)', dangerHover);
        await page.mouse.move(0, 0);

        // Shape: every visible button meets the 40px minimum, and radii follow the spec
        const shape = await page.evaluate(() => {
          const visible = el => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
          const short = [...document.querySelectorAll('.page.active .btn')].filter(visible).filter(b => b.getBoundingClientRect().height < 39.5).map(b => `${b.textContent.trim()}=${b.getBoundingClientRect().height.toFixed(1)}`);
          const radius = sel => { const el = document.querySelector(sel); return el ? getComputedStyle(el).borderTopLeftRadius : 'missing'; };
          return { short, btn: radius('.page.active .btn'), card: radius('.page.active .card'), pill: radius('.page.active .pill') };
        });
        check(wname, 'shape', 'every visible button is at least 40px tall', shape.short.length === 0, shape.short.join(', '));
        check(wname, 'shape', 'radii: buttons 8px, cards 12px, badges 5px', shape.btn === '8px' && shape.card === '12px' && shape.pill === '5px', JSON.stringify(shape));

        // Palette tokens resolve, the page carries the two red glows, titles use condensed Archivo
        const palette = await page.evaluate(() => {
          const h1 = getComputedStyle(document.querySelector('.page.active h1'));
          return {
            token: getComputedStyle(document.documentElement).getPropertyValue('--color-bg').trim(),
            screenBg: getComputedStyle(document.querySelector('.screen')).backgroundImage,
            h1Font: h1.fontFamily,
            h1Stretch: h1.fontStretch,
            h1Size: h1.fontSize,
          };
        });
        check(wname, 'palette', 'page background token is #120607', palette.token === '#120607', palette.token);
        check(wname, 'palette', 'screen carries the two radial glows', (palette.screenBg.match(/radial-gradient/g) || []).length === 2, palette.screenBg.slice(0, 80));
        // High contrast mode: the gradient title must fall back to a solid, visible fill
        await page.emulateMedia({ forcedColors: 'active' });
        const forcedTitle = await page.evaluate(() => {
          const cs = getComputedStyle(document.querySelector('.page.active h1'));
          return { fill: cs.webkitTextFillColor, image: cs.backgroundImage };
        });
        await page.emulateMedia({ forcedColors: 'none' });
        check(wname, 'palette', 'page title stays visible in forced-colors mode (solid fill, no gradient)', forcedTitle.fill !== 'rgba(0, 0, 0, 0)' && forcedTitle.image === 'none', JSON.stringify(forcedTitle));
        check(wname, 'palette', 'page title: Archivo, condensed (<= 80%), 40px', palette.h1Font.startsWith('"Archivo Variable"') && parseFloat(palette.h1Stretch) <= 80 && palette.h1Size === '40px', JSON.stringify({ font: palette.h1Font, stretch: palette.h1Stretch, size: palette.h1Size }));

        // Leftover: hamburger must not sit above a modal backdrop
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(250);
        await page.click('button:has-text("+ Add User")');
        await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(250);
        const hit = await page.evaluate(() => {
          const t = document.querySelector('.sidebar-toggle').getBoundingClientRect();
          const el = document.elementFromPoint(t.left + t.width / 2, t.top + t.height / 2);
          return { toggleShown: getComputedStyle(document.querySelector('.sidebar-toggle')).display !== 'none', hitToggle: !!el?.closest('.sidebar-toggle'), hit: el && (el.tagName + '.' + el.className) };
        });
        if (wname === 'mobile') {
          await page.screenshot({ path: out + 'admin-modal-over-hamburger-mobile.png' });
          check(wname, 'leftovers', 'hamburger is covered by the modal backdrop', hit.toggleShown && !hit.hitToggle, hit.hit);
        }
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);

        // C8 on a form modal and a confirm modal
        await dialogKeyboard(wname, 'Add user form', () => page.click('button:has-text("+ Add User")'));
        // (The Delete Policy confirm went with the policy cards; Reset demo and Logout cover the confirm modal.)

        // ---------- Approvals as the Administrator: the same queue, no alert links, decisions in the audit log (policy phase C4a) ----------
        // (Last in the admin pass: it adds audit events, so nothing that counts them may come after it.)
        const adminApr = wname === 'mobile';
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        let aa = await aprState();
        const adminBadge = await sideBadge('Approvals');
        check(wname, 'approvals', 'admin: the queue lists APR-002 as waiting for the administrator (a lead may decide an analyst\'s request), with no link to Alerts (an analyst page), and the badge says 1', aa.sub === '1 request is waiting for you. Nothing runs until a person approves it.' && aa.rows.length === 1 && aa.rows[0].id === 'APR-002' && aa.rows[0].link === null && adminBadge === '1', JSON.stringify([aa.sub, aa.rows[0], adminBadge]));
        await page.click('.queue-item[data-record-id="APR-002"]');
        await page.waitForTimeout(300);
        aa = await aprState();
        check(wname, 'approvals', 'admin: the detail shows the same request and the decision form, with no "Open ALT-001" button', aa.panel?.id === 'APR-002' && aa.panel.form && aa.panel.links === '', JSON.stringify([aa.panel?.id, aa.panel?.form, aa.panel?.links]));
        // Reject: a reason is required, no token is issued, the request leaves Waiting
        await page.locator(`${APR_SCOPE} .approval-choice:has-text("Reject") input`).check();
        await page.fill('#reason-APR-002', 'A partner scan, not an attack.');
        await page.click(`${APR_SCOPE} button:has-text("Reject request")`);
        await page.waitForTimeout(300);
        aa = await aprState();
        check(wname, 'approvals', 'admin: Reject moves APR-002 to Decided as Rejected by the System Administrator (SOC lead) at 15:46 with its reason, no token, no stepper and no form; the badge goes', aa.rows[0]?.state === 'Rejected' && aa.panel?.fields.decision === 'Rejected by System Administrator (SOC lead) at 15:46' && aa.panel.fields.reason === 'A partner scan, not an attack.' && aa.panel.fields.token === null && aa.panel.stage === null && !aa.panel.form && await sideBadge('Approvals') === null, JSON.stringify([aa.rows[0], aa.panel?.fields]));
        if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Audit Logs', adminApr);
        await page.click('.audit-pick[data-record-id="AUD-207"]');
        if (adminApr) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const rejAudit = await page.evaluate(() => ({ action: document.querySelector('[data-field="action"]')?.textContent.trim(), who: document.querySelector('[data-field="who"]')?.textContent.replace(/\s+/g, ' ').trim(), target: document.querySelector('[data-field="target"]')?.textContent.replace(/\s+/g, ' ').trim(), category: document.querySelector('[data-field="category"]')?.textContent.trim(), changes: [...document.querySelectorAll('[data-field="changes"] li')].map(li => li.textContent.trim()), meta: document.querySelector('[data-field="metadata"]')?.textContent.replace(/\s+/g, ' ').trim() }));
        check(wname, 'approvals', 'audit: AUD-207 "Rejected action" by the System Administrator, target "APR-002 · Block 203.0.113.45", category Incident Response, change "Decision: Pending → Rejected", with the reason in its details', rejAudit.action === 'Rejected action' && rejAudit.who === 'System Administrator (Administrator)' && rejAudit.target === 'APR-002 · Block 203.0.113.45' && rejAudit.category === 'Incident Response' && rejAudit.changes.join('|') === 'Decision: Pending → Rejected' && /A partner scan, not an attack\./.test(rejAudit.meta), JSON.stringify(rejAudit));
        if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        // A fresh load is the seed again: approve with a shorter duration (modify) and watch the steps
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        await page.click('.queue-item[data-record-id="APR-002"]');
        await page.waitForTimeout(300);
        await page.locator(`${APR_SCOPE} .approval-choice:has-text("Shorten") input`).check();
        await page.fill('#minutes-APR-002', '10');
        await page.fill('#reason-APR-002', 'Ten minutes is enough for the review.');
        await page.click(`${APR_SCOPE} button:has-text("Approve with a shorter duration")`);
        const run2 = await sampleStages();
        await page.waitForTimeout(200);
        aa = await aprState();
        check(wname, 'approvals', 'admin: Shorten (30 → 10 min) shows Approved, Executing, Done; under reduced motion the Executing step does not pulse', run2.seen.join(',') === 'Approved,Executing,Done' && run2.pulse === 'none', JSON.stringify(run2));
        check(wname, 'approvals', 'admin: the decided request says "Approved as Block 203.0.113.45 for 10 min (shortened from 30)", approved by the System Administrator (SOC lead) at 15:46, TKN-002 used, window until 15:56', aa.panel?.fields.approvedAs === 'Block 203.0.113.45 for 10 min (shortened from 30)' && aa.panel.fields.decision === 'Approved by System Administrator (SOC lead) at 15:46' && /^TKN-002, used at 15:46/.test(aa.panel.fields.token || '') && aa.panel.fields.window === 'Active until 15:56' && aa.panel.steps === 'Approved=done,Executing=done,Done=done', JSON.stringify(aa.panel?.fields));
        if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Audit Logs', adminApr);
        const flowRows = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].slice(0, 3).map(b => `${b.dataset.recordId}:${b.querySelector('.audit-action')?.textContent.replace(/\s+/g, ' ').trim()}`));
        check(wname, 'approvals', 'audit: the flow wrote three events in order, newest first: AUD-209 Executed block, AUD-208 Used approval token, AUD-207 Modified approval', flowRows.join(' | ') === 'AUD-209:Executed block 203.0.113.45 | AUD-208:Used approval token TKN-002 · APR-002 | AUD-207:Modified approval APR-002 · Block 203.0.113.45', flowRows.join(' | '));
        const auditDetail = async id => {
          await page.click(`.audit-pick[data-record-id="${id}"]`);
          if (adminApr) await page.waitForSelector('[role="dialog"]');
          await page.waitForTimeout(150);
          const d = await page.evaluate(() => ({ who: document.querySelector('[data-field="who"]')?.textContent.replace(/\s+/g, ' ').trim(), ip: document.querySelector('[data-field="sourceIp"]')?.textContent.trim(), changes: [...document.querySelectorAll('[data-field="changes"] li')].map(li => li.textContent.trim()) }));
          if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
          return d;
        };
        const aud207 = await auditDetail('AUD-207');
        const aud208 = await auditDetail('AUD-208');
        const aud209 = await auditDetail('AUD-209');
        check(wname, 'approvals', 'audit old → new: AUD-207 "Decision: Pending → Approved", "Duration: 30 → 10 min", "Token: None → TKN-002 (unused, expires 15:51)"; AUD-208 by AthenaSec AI "Token TKN-002: Unused → Used"; AUD-209 by AthenaSec AI with the block, the 15:56 reversal and "Execution marked Completed"', aud207.who === 'System Administrator (Administrator)' && aud207.changes.join('|') === 'Decision: Pending → Approved|Duration: 30 → 10 min|Token: None → TKN-002 (unused, expires 15:51)' && aud208.who === 'AthenaSec AI (System)' && aud208.changes.join('|') === 'Token TKN-002: Unused → Used' && aud209.who === 'AthenaSec AI (System)' && aud209.changes.join('|') === '203.0.113.45 blocked|Reverses automatically at 15:56|Execution marked Completed', JSON.stringify({ aud207, aud208, aud209 }));

        // ---------- Demo mode as the Administrator: Demo audit events with old → new time, a timeout that escalates to them (policy phase C4b) ----------
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        await demoAdvance(5);
        await page.click('[data-demo-panel] button:has-text("Make the next execution fail")');
        await page.waitForTimeout(120);
        await demoAdvance(15);
        const adminDemoNow = await demoNow();
        const adminTimeout = await aprState();
        check(wname, 'demo mode', 'admin: Advance 5, arm a failure, Advance 15 reaches 16:06:00 and times APR-002 out (nothing waits, the badge goes)', adminDemoNow === '16:06:00' && adminTimeout.seg === 'Waiting 0:true | Decided 2:false' && await sideBadge('Approvals') === null, JSON.stringify([adminDemoNow, adminTimeout.seg]));
        if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('.icon-btn');
        const adminBell = await page.evaluate(() => [...document.querySelectorAll('.top-actions .dropdown .drop-item')].map(i => `${i.querySelector('strong')?.textContent.trim()}|${i.querySelector('p')?.textContent.trim()}`));
        const adminBellLabel = await bellLabel();
        await page.locator('.top-actions .dropdown .drop-item').first().click();
        await page.waitForTimeout(300);
        check(wname, 'demo mode', 'admin: the timeout is escalated to the Administrator: the bell (3 unread) lists "Approval timed out" saying it is escalated to them, and it opens the Approvals page', adminBellLabel === 'Notifications, 3 unread' && adminBell[0] === 'Approval timed out|Block 203.0.113.45 (ALT-001) was not decided in time and nothing ran. It is escalated to you.' && new URL(page.url()).pathname === '/app/approvals', JSON.stringify([adminBellLabel, adminBell[0], page.url()]));
        // A 1-hour step as well (16:06:00 → 17:06:00): the same Demo event format
        await demoAdvance(60);
        check(wname, 'demo mode', 'admin: Advance 1 h moves demo time 16:06:00 → 17:06:00', await demoNow() === '17:06:00', await demoNow());
        await goSide('Audit Logs', adminApr);
        const demoRows = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].slice(0, 5).map(b => {
          const action = b.querySelector('.audit-action').cloneNode(true);
          const tagged = !!action.querySelector('.audit-demo-tag');
          action.querySelectorAll('.audit-demo-tag').forEach(n => n.remove());
          return `${b.dataset.recordId}|${tagged ? 'Demo' : 'no label'}|${action.textContent.replace(/\s+/g, ' ').trim()}`;
        }));
        check(wname, 'demo mode', 'admin audit: newest first AUD-211 Advanced demo time (the 1 h step), AUD-210 Approval timed out (no Demo label), AUD-209 Advanced demo time, AUD-208 Armed a failed execution and AUD-207 Advanced demo time, each of the Demo events with the Demo label', demoRows.join(' ; ') === 'AUD-211|Demo|Advanced demo time Demo clock ; AUD-210|no label|Approval timed out APR-002 · Block 203.0.113.45 ; AUD-209|Demo|Advanced demo time Demo clock ; AUD-208|Demo|Armed a failed execution Executor ; AUD-207|Demo|Advanced demo time Demo clock', JSON.stringify(demoRows));
        const demoDetail = async id => {
          await page.click(`.audit-pick[data-record-id="${id}"]`);
          if (adminApr) await page.waitForSelector('[role="dialog"]');
          await page.waitForTimeout(150);
          const d = await page.evaluate(() => ({ who: document.querySelector('[data-field="who"]')?.textContent.replace(/\s+/g, ' ').trim(), demo: document.querySelector('[data-field="demo"]')?.textContent.trim() ?? null, changes: [...document.querySelectorAll('[data-field="changes"] li')].map(li => li.textContent.trim()), category: document.querySelector('[data-field="category"]')?.textContent.trim() }));
          if (adminApr) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
          return d;
        };
        const d207 = await demoDetail('AUD-207');
        const d208 = await demoDetail('AUD-208');
        const d209 = await demoDetail('AUD-209');
        const d210 = await demoDetail('AUD-210');
        const d211 = await demoDetail('AUD-211');
        check(wname, 'demo mode', 'admin audit, the 1 h step: AUD-211 "Demo time: 16:06:00 → 17:06:00" by the System Administrator with the Demo label, the same format as the 5 and 15 minute steps', d211.demo === 'Demo' && d211.changes.join() === 'Demo time: 16:06:00 → 17:06:00' && d211.who === 'System Administrator (Administrator)' && d211.category === 'Incident Response', JSON.stringify(d211));
        check(wname, 'demo mode', 'admin audit old → new: AUD-207 "Demo time: 15:46:00 → 15:51:00", AUD-208 "Next execution: Will succeed → Will fail", AUD-209 "Demo time: 15:51:00 → 16:06:00", all by the System Administrator with a Demo label; AUD-210 by AthenaSec AI "Decision: Pending → Timed out" with no Demo label', d207.demo === 'Demo' && d207.changes.join() === 'Demo time: 15:46:00 → 15:51:00' && d208.demo === 'Demo' && d208.changes.join() === 'Next execution: Will succeed → Will fail' && d209.demo === 'Demo' && d209.changes.join() === 'Demo time: 15:51:00 → 16:06:00' && d207.who === 'System Administrator (Administrator)' && d210.demo === null && d210.who === 'AthenaSec AI (System)' && d210.changes.join() === 'Decision: Pending → Timed out' && d210.category === 'Incident Response', JSON.stringify({ d207, d208, d209, d210 }));
      } else {
        // ---------- Analyst dashboard: attack paths, posture, queue, log ----------
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(300);
        const dashState = () => page.evaluate(() => {
          const text = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const root = document.querySelector('.page.active[data-page="dashboard"]');
          return {
            maxWidth: root ? getComputedStyle(root).maxWidth : null,
            subtitle: text(root?.querySelector('.headline .sub')),
            posture: [...document.querySelectorAll('.posture li')].map(li => `${text(li.querySelector('strong'))}|${text(li.querySelector('.posture-label'))}|${text(li.querySelector('.posture-note'))}`),
            queue: [...document.querySelectorAll('[data-decision-id]')].map(li => li.dataset.decisionId),
            queueAssigned: Object.fromEntries([...document.querySelectorAll('[data-decision-id]')].map(li => [li.dataset.decisionId, text(li.querySelector('.decision-assigned'))])),
            log: [...document.querySelectorAll('[data-log-id]')].map(li => `${li.dataset.logId}:${text(li.querySelector('.response-log-result'))}`),
            logBy: Object.fromEntries([...document.querySelectorAll('[data-log-id]')].map(li => [li.dataset.logId, text(li.querySelector('.response-log-by'))])),
            panel: {
              id: document.querySelector('[data-selected-path]')?.dataset.selectedPath,
              title: text(document.querySelector('#pathTitle')),
              route: text(document.querySelector('.dash-path-route')),
              risk: text(document.querySelector('.dash-risk-score'))?.split(' ')[0],
              assigned: text(document.querySelector('.dash-assigned')),
              state: text(document.querySelector('.dash-path-meta .path-status')),
              timeline: [...document.querySelectorAll('.dash-path .step-timeline-label')].map(text),
              live: text(document.querySelector('.dash-path [role="status"]')),
            },
            map: !!document.querySelector('.path-map'),
            list: [...document.querySelectorAll('.path-list-item')].map(b => ({ id: b.dataset.pathId, pressed: b.getAttribute('aria-pressed'), text: text(b) })),
            segmented: !!document.querySelector('.dash-map-head .segmented'),
            nodes: [...document.querySelectorAll('.path-node')].map(b => {
              const r = b.getBoundingClientRect();
              return { id: b.dataset.nodeId, zone: ['Internet', 'Perimeter', 'Internal', 'Endpoints'].indexOf(b.dataset.zone), tag: b.tagName, label: b.getAttribute('aria-label'), pressed: b.getAttribute('aria-pressed'), caption: text(b.querySelector('.path-node-caption')), status: text(b.querySelector('.path-node-status')), isolated: b.classList.contains('isolated'), cx: r.left + r.width / 2, cy: r.top + r.height / 2 };
            }),
            legend: [...document.querySelectorAll('.path-legend li')].map(text),
            summary: text(document.querySelector('#pathSummary')),
            describedBy: document.querySelector('.path-map, .path-list')?.getAttribute('aria-describedby'),
          };
        });

        let ds = await dashState();
        check(wname, 'dashboard', 'root is the .page section with the 1320px cap', ds.maxWidth === '1320px', ds.maxWidth);
        check(wname, 'dashboard', 'posture strip matches the data', ds.posture.join(' ; ') === [
          '3|Active attack paths|ALT-001, ALT-002, ALT-003',
          '4|Open alerts|of 6 today',
          '2|Critical, needs decision|ALT-001, ALT-006',
          '0|Sources blocked|None',
          '1|Host isolated|endpoint-12',
          '2|Open cases|Analyst A, Analyst B',
        ].join(' ; '), ds.posture.join(' ; '));
        check(wname, 'dashboard', 'Needs a decision: by risk, with the isolated host and the pending block first', ds.queue.join(',') === 'ALT-006,ALT-001,ALT-003,ALT-002', ds.queue.join(','));
        check(wname, 'dashboard', 'response log lists the one run that happened, approved by a person', ds.log.join(',') === 'EXE-001:Done' && /^Approved by System Administrator, Response policy v2: isolate_host/.test(ds.logBy['EXE-001'] || ''), JSON.stringify({ log: ds.log, by: ds.logBy }));
        check(wname, 'dashboard', 'selected path starts on the most urgent active one, ALT-001 (awaiting approval), not the contained ALT-006', ds.panel.id === 'ALT-001' && ds.panel.title === 'Brute Force SSH' && ds.panel.route === '203.0.113.45 to endpoint-01' && ds.panel.risk === '77' && ds.panel.assigned === 'Analyst A' && ds.panel.state === 'Awaiting approval', JSON.stringify(ds.panel));
        check(wname, 'dashboard', 'panel timeline: the detection, the case, the agent\'s recommendation at 15:44 and the active "Waiting for a SOC analyst to approve it, by 15:59" step; nothing failed', ds.panel.timeline.some(l => /Agent recommended: block 203\.0\.113\.45 for 30 min \(risk 77\)/.test(l)) && ds.panel.timeline.some(l => /In progress: Waiting for a SOC analyst to approve it, by 15:59/.test(l)) && !ds.panel.timeline.some(l => /^Failed:/.test(l)), ds.panel.timeline.join(' | '));
        check(wname, 'dashboard', 'text summary lists every path and its status', ['ALT-001', 'ALT-002', 'ALT-003', 'ALT-004', 'ALT-005', 'ALT-006'].every(id => ds.summary?.includes(id)) && /awaiting approval/.test(ds.summary) && /contained/.test(ds.summary) && /closed/.test(ds.summary) && !/containment failed|source blocked/.test(ds.summary) && ds.describedBy === 'pathSummary', ds.summary);

        if (wname === 'mobile') {
          check(wname, 'dashboard', 'phones show the paths as a list, not the map', !ds.map && !ds.segmented && ds.list.length === 6, JSON.stringify({ map: ds.map, list: ds.list.length }));
          check(wname, 'dashboard', 'list: exactly one path pressed, each shows its status in words', ds.list.filter(i => i.pressed === 'true').length === 1 && ds.list.every(i => /Awaiting approval|Source blocked|Contained|Closed|Open/.test(i.text)), ds.list.map(i => i.text).join(' | '));
          await page.click('[data-path-id="ALT-004"]');
          ds = await dashState();
          check(wname, 'dashboard', 'list: selecting a path updates the panel', ds.panel.id === 'ALT-004' && ds.panel.state === 'Closed' && ds.list.find(i => i.id === 'ALT-004')?.pressed === 'true', JSON.stringify(ds.panel));
          await page.click('[data-path-id="ALT-002"]');
        } else {
          check(wname, 'dashboard', 'map: 12 nodes, all real buttons whose names give their status', ds.nodes.length === 12 && ds.nodes.every(n => n.tag === 'BUTTON' && /awaiting approval|source blocked|contained|closed|open/i.test(n.label)), ds.nodes.map(n => n.label).join(' | '));
          // DOM (and Tab) order follows the picture: zone by zone, top to bottom
          const ordered = ds.nodes.every((n, i) => i === 0 || n.zone > ds.nodes[i - 1].zone || (n.zone === ds.nodes[i - 1].zone && n.cy > ds.nodes[i - 1].cy)) && ds.nodes.every(n => n.zone >= 0);
          check(wname, 'dashboard', 'map: node order follows the zones, left to right then top to bottom', ordered, ds.nodes.map(n => n.id).join(' > '));
          await page.focus('.path-node >> nth=0');
          const tabbed = [await page.evaluate(() => document.activeElement?.dataset.nodeId)];
          for (let i = 1; i < 12; i++) { await page.keyboard.press('Tab'); tabbed.push(await page.evaluate(() => document.activeElement?.dataset.nodeId)); }
          check(wname, 'dashboard', 'map: every node is reachable with Tab, in map order', tabbed.join(',') === ds.nodes.map(n => n.id).join(','), tabbed.join(','));
          const pressedNodes = ds.nodes.filter(n => n.pressed === 'true').map(n => n.id).sort().join(',');
          check(wname, 'dashboard', 'map: the selected path\'s nodes (and only those) are pressed', pressedNodes === 'endpoint-01,firewall,src-203.0.113.45', pressedNodes);
          const layout = await mapLayout();
          check(wname, 'dashboard', 'map: every node sits fully inside the map', layout.spill.length === 0, `${layout.spill.join(', ')} (canvas ${layout.canvasWidth}px)`);
          check(wname, 'dashboard', 'map: no node covers another', layout.overlapping.length === 0, `${layout.overlapping.join(', ')} (canvas ${layout.canvasWidth}px)`);
          check(wname, 'dashboard', 'map: source nodes show attack and status in words, endpoints their health', mapWordsOk(ds), JSON.stringify(ds.nodes.map(n => `${n.id}: ${n.caption} / ${n.status}`)));
          check(wname, 'dashboard', 'map: legend uses words', ds.legend.length === 4 && ds.legend.every(l => /[a-z]{4,}/i.test(l)), ds.legend.join(' | '));
          await page.focus('[data-node-id="src-203.0.113.45"]');
          await page.keyboard.press('Enter');
          ds = await dashState();
          check(wname, 'dashboard', 'map: Enter on a node selects its path and announces it', ds.panel.id === 'ALT-001' && /Showing ALT-001/.test(ds.panel.live), JSON.stringify(ds.panel));
          await page.focus('[data-node-id="endpoint-09"]');
          await page.keyboard.press('Space');
          ds = await dashState();
          check(wname, 'dashboard', 'map: Space on a node selects its path', ds.panel.id === 'ALT-004', ds.panel.id);

          // Map | List switch gives the same paths as a list
          await page.click('.dash-map-head .segmented-option:has-text("List")');
          ds = await dashState();
          check(wname, 'dashboard', 'List view shows all 6 paths with the selection kept', !ds.map && ds.list.length === 6 && ds.list.find(i => i.id === 'ALT-004')?.pressed === 'true', JSON.stringify(ds.list.map(i => `${i.id}:${i.pressed}`)));
          await page.click('.dash-map-head .segmented-option:has-text("Map")');
          await page.click('[data-node-id="src-10.0.2.18"]');

          // Motion: the active path flows and the live threat pulses, unless reduced
          const motion = () => page.evaluate(() => [getComputedStyle(document.querySelector('.path-edge.active.selected')).animationName, getComputedStyle(document.querySelector('.path-node.active .path-node-dot')).animationName]);
          await page.emulateMedia({ reducedMotion: 'no-preference' });
          const moving = await motion();
          await page.emulateMedia({ reducedMotion: 'reduce' });
          const still = await motion();
          check(wname, 'motion', 'active path flows and live threat pulses by default', moving.join(',') === 'pathFlow,livePulse', moving.join(','));
          check(wname, 'motion', 'path flow and pulse stop with prefers-reduced-motion', still.every(a => a === 'none'), still.join(','));
        }
        await page.screenshot({ path: out + `analyst-dashboard-hero-${wname}.png` });

        // ---------- Simulated actions reach every place they should ----------
        // Global search results, read from the top bar's listbox
        const searchFor = async query => {
          await page.fill('#globalSearch', query);
          await page.waitForTimeout(150);
          const options = await page.evaluate(() => [...document.querySelectorAll('#globalSearchResults [role="option"]')].map(o => o.textContent.replace(/\s+/g, ' ').trim()));
          await page.fill('#globalSearch', '');
          await page.evaluate(() => document.activeElement?.blur());
          return options;
        };
        // (Search matches words as substrings, so compare the result line, not the query.)
        const before = (await searchFor('ALT-002')).find(o => o.startsWith('ALT-002')) || '';
        check(wname, 'actions', 'search baseline: ALT-002 shows Analyst B and Open', /· Open ·/.test(before) && /Analyst B/.test(before), before);

        // Assign to me (signed in as Analyst A) on ALT-002, from the queue
        await page.click('[data-decision-id="ALT-002"] button:has-text("Assign to me")');
        await page.waitForTimeout(150);
        ds = await dashState();
        check(wname, 'actions', 'Assign to me: queue row shows Analyst A', ds.queueAssigned['ALT-002'] === 'Analyst A', JSON.stringify(ds.queueAssigned));
        check(wname, 'actions', 'Assign to me: side panel and timeline show the new assignee', ds.panel.id === 'ALT-002' && ds.panel.assigned === 'Analyst A' && ds.panel.timeline.includes('Assigned to Analyst A'), JSON.stringify(ds.panel));
        check(wname, 'actions', 'Assign to me: the button is replaced by "Assigned to you"', await page.locator('[data-decision-id="ALT-002"] button:has-text("Assign to me")').count() === 0 && await page.locator('[data-decision-id="ALT-002"] .assigned-note').count() === 1);
        // In-app link (no reload), so the session state carries over
        await page.click('.dash-path-actions a:has-text("Open in Alerts")');
        await page.waitForURL('**/app/alerts');
        await page.waitForTimeout(300);
        const alertRow = await page.evaluate(() => document.querySelector('[data-record-id="ALT-002"]')?.textContent ?? '');
        check(wname, 'actions', 'Assign to me: the Alerts page shows ALT-002 assigned to Analyst A', alertRow.includes('Analyst A') && !alertRow.includes('Analyst B'), alertRow.replace(/\s+/g, ' ').slice(0, 160));
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);

        // Close alert on ALT-002, from the side panel (replaces the Retry isolation round trip; it returns with Approve in C4)
        await page.click('[data-node-id="src-10.0.2.18"], [data-path-id="ALT-002"]');
        await page.click('.dash-path-actions button:has-text("Close alert")');
        await page.waitForTimeout(200);
        ds = await dashState();
        const meterAfter = await page.evaluate(() => document.querySelector('.threat-meter')?.getAttribute('aria-label'));
        check(wname, 'actions', 'Close alert on ALT-002: it leaves Needs a decision', ds.queue.join(',') === 'ALT-006,ALT-001,ALT-003', ds.queue.join(','));
        check(wname, 'actions', 'Close alert on ALT-002: threat level drops to High, 4 of 5', meterAfter === 'Threat level: High, 4 of 5', meterAfter);
        check(wname, 'actions', 'Close alert on ALT-002: the panel shows Closed and the closing in the timeline', ds.panel.state === 'Closed' && ds.panel.timeline.includes('Closed by Analyst A'), JSON.stringify(ds.panel));
        check(wname, 'actions', 'Close alert on ALT-002: posture shows 2 active paths (ALT-001, ALT-003) and 3 open alerts; the isolated host stays', ds.posture[0] === '2|Active attack paths|ALT-001, ALT-003' && ds.posture[1] === '3|Open alerts|of 6 today' && ds.posture[4] === '1|Host isolated|endpoint-12', ds.posture.join(' ; '));
        check(wname, 'actions', 'Close alert on ALT-002: the response log is unchanged', ds.log.join(',') === 'EXE-001:Done', ds.log.join(','));
        check(wname, 'actions', 'Close alert on ALT-002: headline says 2 attack paths are still active', /^2 attack paths are still active/.test(ds.subtitle || ''), ds.subtitle);
        if (wname === 'mobile') {
          check(wname, 'actions', 'Close alert on ALT-002: the list shows ALT-002 closed', /Closed/.test(ds.list.find(i => i.id === 'ALT-002')?.text || ''), JSON.stringify(ds.list.find(i => i.id === 'ALT-002')));
        } else {
          const ep12 = ds.nodes.find(n => n.id === 'endpoint-12');
          const src2 = ds.nodes.find(n => n.id === 'src-10.0.2.18');
          check(wname, 'actions', 'Close alert on ALT-002: the map shows its path closed, and endpoint-12 still isolated', src2?.status === 'Closed' && /closed/i.test(src2.label || '') && ep12?.caption === 'Isolated' && ep12.isolated, JSON.stringify({ ep12, src2 }));
        }
        await page.click('.dash-log a:has-text("Incident Response")');
        await page.waitForURL('**/app/incident');
        await page.waitForTimeout(300);
        const runRow = await page.evaluate(() => {
          const row = document.querySelector('.run-row[data-record-id="EXE-001"]');
          return { result: row?.querySelector('.run-result')?.textContent.replace('Result:', '').trim(), executed: row?.querySelector('[data-stage="Executed"] .stage-label')?.textContent.trim() };
        });
        check(wname, 'actions', 'Close alert on ALT-002: Incident Response still shows EXE-001 completed and done', runRow.result === 'Completed' && runRow.executed === 'Done', JSON.stringify(runRow));

        // Close alert (existing action) still flows to the sidebar badge
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        await page.click('[data-decision-id="ALT-003"] button:has-text("Close alert")');
        await page.waitForTimeout(150);
        ds = await dashState();
        const badge = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Alerts')?.querySelector('.count')?.textContent);
        check(wname, 'actions', 'Close alert: queue, posture and sidebar badge update', ds.queue.join(',') === 'ALT-006,ALT-001' && ds.posture[1] === '2|Open alerts|of 6 today' && badge === '2', JSON.stringify({ queue: ds.queue, open: ds.posture[1], badge }));

        // Global search reads the same shared state
        const alt002 = (await searchFor('ALT-002')).find(o => o.startsWith('ALT-002')) || '';
        check(wname, 'actions', 'search: ALT-002 shows the new assignee and its closed state', /· Closed ·/.test(alt002) && /Analyst A/.test(alt002) && !/Analyst B/.test(alt002), alt002);
        const closed = (await searchFor('ALT-003')).find(o => o.startsWith('ALT-003')) || '';
        check(wname, 'actions', 'search: a closed alert shows Closed', /· Closed ·/.test(closed), closed);
        const run = (await searchFor('EXE-001')).find(o => o.startsWith('EXE-001')) || '';
        check(wname, 'actions', 'search: EXE-001 shows its target, Completed and its policy', /endpoint-12/.test(run) && /Completed/.test(run) && /Response policy v2: isolate_host/.test(run), run);
        const approverHit = (await searchFor('System Administrator')).filter(o => o.startsWith('EXE-001'));
        check(wname, 'actions', 'search: the approver\'s name finds the run they approved', approverHit.length === 1, approverHit.join(' ; '));
        await page.goto(base + '/app/incident');
        await page.waitForTimeout(200);
        const incidentHeaderPills = await page.evaluate(() => document.querySelectorAll('main > .page > .headline .pill').length);
        check(wname, 'polish', 'Incident: duplicate "completed" header pill removed', incidentHeaderPills === 0, `${incidentHeaderPills}`);

        // ---------- Alerts: queue + workspace (replaces the table and drawer checks) ----------
        await page.goto(base + '/app/alerts');
        await page.waitForTimeout(300);
        const ITEM = '.queue-item[data-record-id]';
        const isPhone = wname === 'mobile';
        const segText = () => page.evaluate(() => [...document.querySelectorAll('.page.active .headline .segmented-option')].map(b => `${b.textContent.replace(/\s+/g, ' ').trim()}:${b.getAttribute('aria-pressed')}`));
        const visibleIds = async () => (await listGeometry(ITEM)).ids.join(',');
        const visibleCount = () => page.evaluate(() => document.querySelector('#visibleAlertCount')?.textContent.trim());

        // Views: counts and contents from data
        check(wname, 'alerts', 'views show counts from data, Needs decision first', (await segText()).join(' | ') === 'Needs decision 4:true | All today 6:false | Resolved 2:false', (await segText()).join(' | '));
        check(wname, 'alerts', 'Needs decision lists ALT-006, ALT-001, ALT-003, ALT-002 (highest risk first)', await visibleIds() === 'ALT-006,ALT-001,ALT-003,ALT-002', await visibleIds());
        await listChecks(wname, 'alerts list', ITEM, 4);
        await page.click('.page.active .headline .segmented-option:has-text("Resolved")');
        check(wname, 'alerts', 'Resolved lists ALT-004, ALT-005', await visibleIds() === 'ALT-004,ALT-005', await visibleIds());
        await page.click('.page.active .headline .segmented-option:has-text("All today")');
        check(wname, 'alerts', 'All today lists all 6 by risk', await visibleIds() === 'ALT-006,ALT-001,ALT-003,ALT-004,ALT-002,ALT-005', await visibleIds());
        await listChecks(wname, 'alerts list', ITEM, 6);
        // Count lines (distinct box tops): each text node on one line gets its own box
        const splitAddresses = await page.evaluate(() => [...document.querySelectorAll('.queue-route .nowrap')].filter(s => new Set([...s.getClientRects()].filter(r => r.width > 0).map(r => Math.round(r.top))).size > 1).map(s => s.textContent));
        check(wname, 'alerts list', 'no IP or endpoint name is split across lines', splitAddresses.length === 0, splitAddresses.join(', '));

        // Filters and search above the list, same options as before
        const toolbar = await page.evaluate(() => {
          const bar = document.querySelector('main .toolbar');
          const queue = document.querySelector('.card.queue');
          return { exists: !!bar, insideCard: !!bar?.closest('.card'), above: !!bar && !!queue && bar.getBoundingClientRect().bottom <= queue.getBoundingClientRect().top, hasSearch: !!bar?.querySelector('input[type="search"]'), selects: [...(bar?.querySelectorAll('select') ?? [])].map(s => s.id) };
        });
        check(wname, 'I12 filters', 'alerts: search and filters sit above the list, outside the card', toolbar.exists && !toolbar.insideCard && toolbar.above && toolbar.hasSearch && toolbar.selects.join(',') === 'attackFilter,riskFilter,riskSort', JSON.stringify(toolbar));
        await page.selectOption('#attackFilter', 'Privilege Escalation');
        check(wname, 'alerts', 'attack filter: Privilege Escalation gives ALT-004, ALT-002', await visibleIds() === 'ALT-004,ALT-002' && await visibleCount() === '2 visible', `${await visibleIds()} / ${await visibleCount()}`);
        await page.selectOption('#attackFilter', 'all');
        await page.selectOption('#riskFilter', 'critical');
        check(wname, 'alerts', 'risk filter: Critical (90-100) gives ALT-006', await visibleIds() === 'ALT-006', await visibleIds());
        await page.selectOption('#riskFilter', 'high');
        check(wname, 'alerts', 'risk filter: High (70-89) gives ALT-001', await visibleIds() === 'ALT-001', await visibleIds());
        await page.selectOption('#attackFilter', 'Command and Control');
        await page.selectOption('#riskFilter', 'all');
        check(wname, 'alerts', 'attack filter: Command and Control gives ALT-006', await visibleIds() === 'ALT-006' && await visibleCount() === '1 visible', `${await visibleIds()} / ${await visibleCount()}`);
        await page.selectOption('#attackFilter', 'all');
        await page.selectOption('#riskFilter', 'all');
        await page.fill('#alertSearch', 'brute');
        check(wname, 'alerts', 'search: "brute" gives ALT-001, ALT-003, ALT-005', await visibleIds() === 'ALT-001,ALT-003,ALT-005', await visibleIds());
        await page.selectOption('#riskSort', 'asc');
        check(wname, 'alerts', 'sort: lowest risk first reverses the order', await visibleIds() === 'ALT-005,ALT-003,ALT-001', await visibleIds());
        await page.fill('#alertSearch', 'zzqx');
        const empty = await page.evaluate(() => document.querySelector('.card.queue .empty')?.textContent.trim());
        check(wname, 'alerts', 'no matches shows an empty state', /No alerts match/.test(empty || '') && await visibleCount() === '0 visible', empty);
        await page.click('main .toolbar button:has-text("Reset Filters")');
        check(wname, 'alerts', 'Reset Filters restores all 6, highest risk first', await visibleIds() === 'ALT-006,ALT-001,ALT-003,ALT-004,ALT-002,ALT-005' && await visibleCount() === '6 visible', await visibleIds());

        // Every old table field, for every alert, in the list item or the workspace
        const ALERT_FIELDS = {
          'ALT-001': { severity: 'Critical', attackType: 'Brute Force SSH', sourceIp: '203.0.113.45', destinationIp: '10.0.4.21', endpoint: 'endpoint-01', risk: '77 / 100', status: 'Open', assignedAnalyst: 'Analyst A', time: '14:32', mitre: 'T1110 - Brute Force' },
          'ALT-002': { severity: 'High', attackType: 'Privilege Escalation', sourceIp: '10.0.2.18', destinationIp: '10.0.4.33', endpoint: 'endpoint-03', risk: '50 / 100', status: 'Open', assignedAnalyst: 'Analyst B', time: '14:41', mitre: 'T1548 - Abuse Elevation Control Mechanism' },
          'ALT-003': { severity: 'Medium', attackType: 'Brute Force - Password Spray', sourceIp: '203.0.113.88', destinationIp: '10.0.4.41', endpoint: 'vpn-gateway-02', risk: '54 / 100', status: 'Open', assignedAnalyst: 'Analyst A', time: '15:02', mitre: 'T1110.003 - Password Spraying' },
          'ALT-004': { severity: 'Critical', attackType: 'Privilege Escalation - Kernel Exploit Attempt', sourceIp: '10.0.7.51', destinationIp: '10.0.7.51', endpoint: 'endpoint-09', risk: '52 / 100', status: 'Closed', assignedAnalyst: 'Analyst C', time: '15:17', mitre: 'T1068 - Exploitation for Privilege Escalation' },
          'ALT-005': { severity: 'Low', attackType: 'Brute Force - SSH Probe', sourceIp: '198.51.100.77', destinationIp: '10.0.4.21', endpoint: 'endpoint-01', risk: '34 / 100', status: 'Closed', assignedAnalyst: 'Analyst A', time: '15:36', mitre: 'T1110 - Brute Force' },
          'ALT-006': { severity: 'Critical', attackType: 'Malware - C2 Beaconing', sourceIp: '203.0.113.9', destinationIp: '10.0.7.64', endpoint: 'endpoint-12', risk: '90 / 100', status: 'Open', assignedAnalyst: 'Analyst B', time: '15:41', mitre: 'T1071 - Application Layer Protocol' },
        };
        const fieldMisses = [];
        for (const [id, want] of Object.entries(ALERT_FIELDS)) {
          await page.click(`${ITEM}[data-record-id="${id}"]`);
          await page.waitForTimeout(120);
          const got = await page.evaluate(alertId => {
            const text = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
            const field = name => text(document.querySelector(`[data-workspace-id="${alertId}"] ~ .tabs [data-field="${name}"], [role="dialog"] [data-field="${name}"]`));
            return {
              item: text(document.querySelector(`.queue-item[data-record-id="${alertId}"]`)),
              title: text(document.querySelector('#alertWorkspaceTitle')),
              fields: Object.fromEntries(['sourceIp', 'destinationIp', 'endpoint', 'risk', 'status', 'assignedAnalyst', 'time', 'mitre'].map(n => [n, field(n)])),
              dialog: !!document.querySelector('[role="dialog"]'),
            };
          }, id);
          const inItem = ['severity', 'attackType', 'sourceIp', 'destinationIp', 'endpoint', 'assignedAnalyst', 'time'].filter(k => !got.item?.includes(want[k]));
          const inPanel = ['sourceIp', 'destinationIp', 'endpoint', 'risk', 'status', 'assignedAnalyst', 'time', 'mitre'].filter(k => got.fields[k] !== want[k]);
          if (inItem.length || inPanel.length || got.title !== want.attackType || got.dialog !== isPhone) fieldMisses.push(`${id}: item[${inItem}] panel[${inPanel}] title=${got.title} dialog=${got.dialog}`);
          if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        }
        check(wname, 'alerts', `every old table field for all 6 alerts is shown (list item + ${isPhone ? 'drawer' : 'inline workspace'})`, fieldMisses.length === 0, fieldMisses.join(' ; '));

        // Policy phase C2: every alert's risk, confidence, outcome and score breakdown come from the formula
        const ASSESS = {
          'ALT-001': { outcome: 'Recommend IP block', confidence: 'Confidence 0.88 (high)', points: [30.33, 15, 23, 9], sum: '77.33', total: '77 / 100' },
          'ALT-002': { outcome: 'Investigate further', confidence: 'Confidence 0.75 (medium)', points: [25.67, 15, 0, 9], sum: '49.67', total: '50 / 100' },
          'ALT-003': { outcome: 'Investigate further', confidence: 'Confidence 0.70 (medium)', points: [18.67, 15, 16.25, 4.5], sum: '54.42', total: '54 / 100' },
          'ALT-004': { outcome: 'Investigate further', confidence: 'Confidence 0.90 (high)', points: [32.67, 10, 0, 9], sum: '51.67', total: '52 / 100' },
          'ALT-005': { outcome: 'Monitor', confidence: 'Confidence 0.40 (low)', points: [11.67, 5, 8.75, 9], sum: '34.42', total: '34 / 100' },
          'ALT-006': { outcome: 'Recommend host isolation', confidence: 'Confidence 0.92 (high)', points: [32.67, 25, 23.75, 9], sum: '90.42', total: '90 / 100' },
        };
        const assessMisses = [];
        for (const [id, want] of Object.entries(ASSESS)) {
          await page.click(`${ITEM}[data-record-id="${id}"]`);
          await page.waitForTimeout(120);
          const got = await page.evaluate(alertId => {
            const text = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
            const box = document.querySelector(`[data-assessment-for="${alertId}"]`);
            return {
              listOutcome: text(document.querySelector(`.queue-item[data-record-id="${alertId}"] .queue-outcome`)),
              outcome: text(box?.querySelector('[data-field="outcome"]')),
              confidence: text(box?.querySelector('[data-field="confidence"]')),
              rows: [...(box?.querySelectorAll('tbody tr') ?? [])].map(tr => ({ key: tr.dataset.input, points: parseFloat(tr.lastElementChild.textContent) })),
              total: text(box?.querySelector('[data-field="riskTotal"]')),
              sum: text(box?.querySelector('[data-field="riskSum"]')),
              alternatives: box?.querySelectorAll('[data-field="alternatives"] li').length ?? 0,
              formula: text(box?.querySelector('.assessment-formula')),
            };
          }, id);
          const pointsOk = got.rows.length === 4 && got.rows.map(r => r.key).join('') === 'SERA' && got.rows.every((r, i) => Math.abs(r.points - want.points[i]) < 0.006);
          // The parts shown add up exactly (to the cent) to the sum shown, which rounds to the risk shown
          const sumOk = got.sum === want.sum && Math.round(got.rows.reduce((s, r) => s + Math.round(r.points * 100), 0)) === Math.round(parseFloat(got.sum) * 100) && Math.round(parseFloat(got.sum)) === parseInt(want.total, 10);
          if (!got.listOutcome?.startsWith(want.outcome) || got.outcome !== want.outcome || got.confidence !== want.confidence || !pointsOk || !sumOk || got.total !== want.total || got.alternatives !== 4 || !/0\.35 S \+ 0\.25 E \+ 0\.25 R \+ 0\.15 A/.test(got.formula || '')) assessMisses.push(`${id}: ${JSON.stringify(got)}`);
          if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        }
        check(wname, 'assessment', 'all 6 alerts show outcome, confidence band, the S / E / R / A points to the cent that add up exactly to the sum shown (which rounds to the risk), the formula and 4 alternatives considered (list line and workspace)', assessMisses.length === 0, assessMisses.join(' ; '));
        await page.click(`${ITEM}[data-record-id="ALT-004"]`);
        await page.waitForTimeout(120);
        const whyNot = await page.evaluate(() => [...document.querySelectorAll('[data-field="alternatives"] li')].map(li => li.textContent.replace(/\s+/g, ' ').trim()));
        check(wname, 'assessment', 'ALT-004 (internal source): host isolation is recorded as not met because its risk is below 85, and the lower outcomes as rejected', whyNot.some(t => /^Recommend host isolation.*Not met: .*risk 52 is below 85/.test(t)) && whyNot.some(t => /^Monitor.*Rejected/.test(t)), whyNot.join(' | '));
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // Keyboard: Enter and Space select an item
        await page.focus(`${ITEM}[data-record-id="ALT-003"]`);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(120);
        const enterPick = await page.evaluate(() => ({ pressed: document.querySelector('.queue-item[aria-pressed="true"]')?.dataset.recordId, title: document.querySelector('#alertWorkspaceTitle')?.textContent }));
        check(wname, 'alerts', 'Enter on an item selects it and shows its workspace', enterPick.pressed === 'ALT-003' && enterPick.title === 'Brute Force - Password Spray', JSON.stringify(enterPick));
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.focus(`${ITEM}[data-record-id="ALT-004"]`);
        await page.keyboard.press('Space');
        await page.waitForTimeout(120);
        check(wname, 'alerts', 'Space on an item selects it', await page.evaluate(() => document.querySelector('.queue-item[aria-pressed="true"]')?.dataset.recordId) === 'ALT-004');
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // Phones: the workspace is a drawer with the shared dialog behaviour; wide screens: inline, no dialog
        if (isPhone) {
          check(wname, 'alerts', 'phone: no workspace until an item is chosen', await page.evaluate(() => !document.querySelector('[role="dialog"]') && !document.querySelector('.card.detail-panel')));
          await dialogKeyboard(wname, 'Alert workspace drawer', () => page.click(`${ITEM}[data-record-id="ALT-001"]`));
          check(wname, 'C8 modal', 'Alert workspace drawer: focus returns to the chosen alert', await page.evaluate(() => document.activeElement?.dataset.recordId === 'ALT-001'));
          await page.click(`${ITEM}[data-record-id="ALT-001"]`);
          await page.waitForTimeout(250);
          await page.screenshot({ path: out + 'analyst-alert-drawer-mobile.png' });
        } else {
          check(wname, 'alerts', 'wide screen: the workspace is inline beside the list, no dialog', await page.evaluate(() => !document.querySelector('[role="dialog"]') && !!document.querySelector('.card.detail-panel #alertWorkspaceTitle')));
          await page.click(`${ITEM}[data-record-id="ALT-001"]`);
        }

        // Tabs follow the ARIA pattern
        const tabState = () => page.evaluate(() => {
          const list = document.querySelector('.workspace [role="tablist"]');
          const tabs = [...(list?.querySelectorAll('[role="tab"]') ?? [])];
          const panel = document.getElementById(tabs[0]?.getAttribute('aria-controls') ?? '');
          return {
            labels: tabs.map(t => t.textContent.trim()),
            selected: tabs.filter(t => t.getAttribute('aria-selected') === 'true').map(t => t.textContent.trim()),
            tabbable: tabs.filter(t => t.tabIndex === 0).map(t => t.textContent.trim()),
            focused: document.activeElement?.getAttribute('role') === 'tab' ? document.activeElement.textContent.trim() : null,
            panelRole: panel?.getAttribute('role'),
            panelLabelledBy: panel && document.getElementById(panel.getAttribute('aria-labelledby'))?.textContent.trim(),
            evidence: [...(panel?.querySelectorAll('.evidence-list li') ?? [])].length,
            steps: [...(panel?.querySelectorAll('.next-steps li') ?? [])].length,
            hasFacts: !!panel?.querySelector('.facts'),
          };
        });
        let ts = await tabState();
        check(wname, 'alerts tabs', 'three tabs, Overview selected and the only one in the Tab order', ts.labels.join(',') === 'Overview,Evidence,Response' && ts.selected.join() === 'Overview' && ts.tabbable.join() === 'Overview' && ts.panelRole === 'tabpanel' && ts.panelLabelledBy === 'Overview' && ts.hasFacts, JSON.stringify(ts));
        await page.focus('.workspace [role="tab"]:has-text("Overview")');
        await page.keyboard.press('ArrowRight');
        ts = await tabState();
        check(wname, 'alerts tabs', 'ArrowRight moves to Evidence and shows ALT-001\'s 5 evidence items', ts.selected.join() === 'Evidence' && ts.focused === 'Evidence' && ts.tabbable.join() === 'Evidence' && ts.evidence === 5, JSON.stringify(ts));
        await page.keyboard.press('End');
        ts = await tabState();
        check(wname, 'alerts tabs', 'End moves to Response with 4 next steps', ts.selected.join() === 'Response' && ts.focused === 'Response' && ts.steps === 4, JSON.stringify(ts));
        await page.keyboard.press('ArrowRight');
        ts = await tabState();
        check(wname, 'alerts tabs', 'ArrowRight wraps from Response to Overview', ts.selected.join() === 'Overview' && ts.focused === 'Overview', JSON.stringify(ts));
        await page.keyboard.press('ArrowLeft');
        await page.keyboard.press('Home');
        ts = await tabState();
        check(wname, 'alerts tabs', 'ArrowLeft wraps to Response, Home returns to Overview', ts.selected.join() === 'Overview' && ts.focused === 'Overview', JSON.stringify(ts));
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // Policy phase C3b: approval records on the Response tab (nothing runs without a person's approval)
        const approvalView = async id => {
          await page.click(`${ITEM}[data-record-id="${id}"]`);
          await page.waitForTimeout(150);
          const timeline = await page.evaluate(() => [...document.querySelectorAll('.workspace .step-timeline-label')].map(l => l.textContent.replace(/\s+/g, ' ').trim()));
          await page.click('.workspace [role="tab"]:has-text("Response")');
          await page.waitForTimeout(450);
          const got = await page.evaluate(() => {
            const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
            const scope = document.querySelector('.workspace');
            const field = n => t(scope?.querySelector(`.approval-facts [data-field="${n}"]`));
            return { state: t(scope?.querySelector('.dash-path-meta .path-status')), request: field('request'), requestedBy: field('requestedBy'), decision: field('decision'), policy: field('policy'), token: field('token'), window: field('window'), hasApproval: !!scope?.querySelector('.approval-facts'), note: t(scope?.querySelector('.policy-note')) };
          });
          if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
          return { ...got, timeline };
        };
        const a1 = await approvalView('ALT-001');
        check(wname, 'approvals', 'ALT-001: "Awaiting approval", APR-002 block 203.0.113.45 for 30 min asked by AthenaSec AI at 15:44, waiting for a SOC analyst (13 min left, by 15:59), under response policy version 3; no token yet, nothing has run', a1.state === 'Awaiting approval' && a1.request === 'APR-002 · Block 203.0.113.45 for 30 min' && a1.requestedBy === 'AthenaSec AI at 15:44' && a1.decision === 'Waiting for a SOC analyst (13 min left, by 15:59)' && a1.policy === 'Response policy version 3, block_ip: SOC analyst approves, minimum risk 70' && a1.token === null && a1.window === null && /Nothing has run for this alert/.test(a1.note || ''), JSON.stringify(a1));
        check(wname, 'approvals', 'ALT-001 timeline: the agent\'s recommendation at 15:44 and "Waiting for a SOC analyst to approve it, by 15:59" as the active step', a1.timeline.some(l => /Agent recommended: block 203\.0\.113\.45 for 30 min \(risk 77\)/.test(l)) && a1.timeline.some(l => /Waiting for a SOC analyst to approve it, by 15:59/.test(l)), a1.timeline.join(' | '));
        const a6 = await approvalView('ALT-006');
        check(wname, 'approvals', 'ALT-006: "Contained", APR-001 approved by the System Administrator (SOC lead) at 15:43, TKN-001 used at 15:44, isolation active until 17:44', a6.state === 'Contained' && a6.request === 'APR-001 · Isolate endpoint-12 for 120 min' && a6.decision === 'Approved by System Administrator (SOC lead) at 15:43' && a6.policy === 'Response policy version 2, isolate_host: SOC lead approves, minimum risk 90' && /^TKN-001, used at 15:44 bound to sha256 [0-9a-f]{12}…$/.test(a6.token || '') && a6.window === 'Active until 17:44' && /Response ran under Response policy v2: isolate_host/.test(a6.note || ''), JSON.stringify(a6));
        const a2 = await approvalView('ALT-002');
        check(wname, 'approvals', 'ALT-002 (investigate further): no approval record and "No response policy ran for this alert."', a2.state === 'Open' && !a2.hasApproval && a2.note === 'No response policy ran for this alert.', JSON.stringify(a2));

        // Global search selects an alert hidden by the current view (ALT-005 is resolved)
        await page.click('.page.active .headline .segmented-option:has-text("Needs decision")');
        await page.fill('#globalSearch', 'ALT-005');
        await page.waitForTimeout(150);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(450);
        const landed5 = await page.evaluate(() => {
          const item = document.querySelector('.queue-item[data-record-id="ALT-005"]');
          const r = item?.getBoundingClientRect();
          return {
            view: document.querySelector('.page.active .headline .segmented-option[aria-pressed="true"]')?.textContent.replace(/\s+/g, ' ').trim(),
            pressed: item?.getAttribute('aria-pressed'),
            focused: document.activeElement === item,
            inView: !!r && r.top >= 0 && r.bottom <= window.innerHeight,
            box: r && { top: Math.round(r.top), bottom: Math.round(r.bottom), viewport: window.innerHeight, scrollY: Math.round(window.scrollY), pageHeight: document.documentElement.scrollHeight },
            workspace: document.querySelector('.card.detail-panel [data-workspace-id]')?.dataset.workspaceId ?? null,
            dialog: !!document.querySelector('[role="dialog"]'),
          };
        });
        check(wname, 'I8 search', 'search for a hidden alert switches the view, selects, scrolls to and focuses it', landed5.view === 'All today 6' && landed5.pressed === 'true' && landed5.focused && landed5.inView && !landed5.dialog && (isPhone || landed5.workspace === 'ALT-005'), JSON.stringify(landed5));

        // Workspace links carry the selection to Cases and Incident Response
        await page.click(`${ITEM}[data-record-id="ALT-001"]`);
        await page.click('.workspace a:has-text("Open CASE-006")');
        await page.waitForURL('**/app/cases');
        await page.waitForTimeout(450);
        const caseLanding = await page.evaluate(() => {
          const card = document.querySelector('.case-card[data-record-id="CASE-006"]');
          return { highlighted: !!card?.classList.contains('is-highlighted'), pressed: card?.getAttribute('aria-pressed'), focused: document.activeElement === card, detail: document.querySelector('.card.detail-panel [data-case-id]')?.dataset.caseId ?? null };
        });
        check(wname, 'alerts', '"Open CASE-006" lands on Cases with CASE-006 selected, highlighted and focused', caseLanding.highlighted && caseLanding.pressed === 'true' && caseLanding.focused && (isPhone || caseLanding.detail === 'CASE-006'), JSON.stringify(caseLanding));
        await page.goBack();
        await page.waitForURL('**/app/alerts');
        await page.waitForTimeout(300);

        // Actions in the workspace reach the sidebar, top bar and dashboard (in-app navigation keeps the state)
        await page.click(`${ITEM}[data-record-id="ALT-003"]`);
        await page.click('.workspace button:has-text("Close alert")');
        await page.waitForTimeout(150);
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        const afterClose = await page.evaluate(() => ({
          badge: [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Alerts')?.querySelector('.count')?.textContent,
          decision: document.querySelector('.page.active .headline .segmented-option')?.textContent.replace(/\s+/g, ' ').trim(),
        }));
        check(wname, 'alerts', 'Close alert in the workspace updates the sidebar badge and view counts', afterClose.badge === '3' && afterClose.decision === 'Needs decision 3', JSON.stringify(afterClose));
        await page.click(`${ITEM}[data-record-id="ALT-002"]`);
        await page.click('.workspace button:has-text("Close alert")');
        await page.waitForTimeout(150);
        const afterSecondClose = await page.evaluate(() => ({
          state: document.querySelector('.workspace .dash-path-meta .path-status')?.textContent.trim(),
          meter: document.querySelector('.threat-meter')?.getAttribute('aria-label'),
          badge: [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Alerts')?.querySelector('.count')?.textContent,
        }));
        // ALT-001 and ALT-006 (critical, 3 each) still count: High
        check(wname, 'alerts', 'Close alert on ALT-002 in the workspace: Closed, badge 2, threat level High (ALT-001 and ALT-006 left)', afterSecondClose.state === 'Closed' && afterSecondClose.badge === '2' && afterSecondClose.meter === 'Threat level: High, 4 of 5', JSON.stringify(afterSecondClose));
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        const dashQueue = await page.evaluate(() => [...document.querySelectorAll('[data-decision-id]')].map(li => li.dataset.decisionId).join(','));
        check(wname, 'alerts', 'the dashboard queue reflects both actions (ALT-006 and ALT-001 left)', dashQueue === 'ALT-006,ALT-001', dashQueue);

        // ---------- Case Management: board + detail (replaces the Cases table and drawer) ----------
        // Through the sidebar, not a reload, so the alert closings made above are still in effect.
        if (isPhone) {
          await page.click('.sidebar-toggle');
          await page.waitForTimeout(350);
        }
        await page.click('.sidebar .side-item:has-text("Case Management")');
        await page.waitForURL('**/app/cases');
        await page.waitForTimeout(300);
        const CARD = '.case-card[data-record-id]';
        const caseIds = async () => (await listGeometry(CARD)).ids.join(',');
        const closeDrawer = async () => { if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); } };
        const board = () => page.evaluate(() => [...document.querySelectorAll('.board-column')].map(col => ({
          title: col.querySelector('.board-column-title')?.textContent.replace(/\s+/g, ' ').trim(),
          ids: [...col.querySelectorAll('.case-card')].map(c => c.dataset.recordId),
          empty: col.querySelector('.board-empty')?.textContent.trim() ?? null,
        })));
        const cardProgress = id => page.evaluate(cid => document.querySelector(`.case-card[data-record-id="${cid}"] .case-card-progress`)?.textContent.trim(), id);

        const caseSub = await page.evaluate(() => document.querySelector('.page.active .headline .sub')?.textContent.trim());
        check(wname, 'cases', 'subtitle counts from data: 2 in progress, 1 closed', /2 in progress, 1 closed/.test(caseSub || ''), caseSub);
        let cols = await board();
        check(wname, 'cases', 'board: Investigating 2 (CASE-006, CASE-007), Closed 1 (CASE-008)', JSON.stringify(cols.map(c => [c.title, c.ids])) === JSON.stringify([['Investigating 2', ['CASE-006', 'CASE-007']], ['Closed 1', ['CASE-008']]]), JSON.stringify(cols));
        await listChecks(wname, 'cases list', CARD, 3);
        // (The fresh starting state is checked in the per-page pass.)
        const nowProgress = [await cardProgress('CASE-006'), await cardProgress('CASE-007'), await cardProgress('CASE-008')].join(' | ');
        check(wname, 'cases', 'progress after closing alerts (no run changed): 0 of 4, 0 of 4, 4 of 4', nowProgress === '0 of 4 actions | 0 of 4 actions | 4 of 4 actions', nowProgress);

        // Every old table and drawer field, for every case
        const CASE_FIELDS = {
          'CASE-006': { attackType: 'Brute Force SSH', sourceAlert: 'ALT-001', severity: 'Critical', status: 'Open', assignedAnalyst: 'Analyst A', endpoint: 'endpoint-01', sourceIp: '203.0.113.45', riskScore: '77 / 100', mitre: 'T1110 - Brute Force', createdAt: 'Today, 14:34', lastUpdated: 'Today, 15:44' },
          'CASE-007': { attackType: 'Privilege Escalation', sourceAlert: 'ALT-002', severity: 'High', status: 'Open', assignedAnalyst: 'Analyst B', endpoint: 'endpoint-03', sourceIp: '10.0.2.18', riskScore: '50 / 100', mitre: 'T1548 - Abuse Elevation Control Mechanism', createdAt: 'Today, 14:43', lastUpdated: 'Today, 14:55' },
          'CASE-008': { attackType: 'Kernel Exploit Attempt', sourceAlert: 'ALT-004', severity: 'Critical', status: 'Closed', assignedAnalyst: 'Analyst C', endpoint: 'endpoint-09', sourceIp: '10.0.7.51', riskScore: '52 / 100', mitre: 'T1068 - Exploitation for Privilege Escalation', createdAt: 'Today, 15:18', lastUpdated: 'Today, 15:42' },
        };
        const caseMisses = [];
        for (const [id, want] of Object.entries(CASE_FIELDS)) {
          await page.click(`${CARD}[data-record-id="${id}"]`);
          await page.waitForTimeout(120);
          const got = await page.evaluate(cid => {
            const text = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
            const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel');
            return {
              card: text(document.querySelector(`.case-card[data-record-id="${cid}"]`)),
              title: text(scope?.querySelector('#caseDetailTitle')),
              detailId: scope?.querySelector('[data-case-id]')?.dataset.caseId,
              fields: Object.fromEntries(['status', 'assignedAnalyst', 'sourceAlert', 'severity', 'endpoint', 'sourceIp', 'riskScore', 'mitre', 'createdAt', 'lastUpdated'].map(n => [n, text(scope?.querySelector(`[data-field="${n}"]`))])),
              evidence: scope?.querySelectorAll('.case-evidence li').length ?? 0,
              timeline: scope?.querySelectorAll('.step-timeline-item').length ?? 0,
              dialog: !!document.querySelector('[role="dialog"]'),
            };
          }, id);
          const inCard = ['severity', 'sourceAlert', 'assignedAnalyst', 'endpoint'].filter(k => !got.card?.includes(want[k]));
          const inPanel = Object.keys(got.fields).filter(k => got.fields[k] !== want[k]);
          if (inCard.length || inPanel.length || got.title !== want.attackType || got.detailId !== id || got.evidence < 1 || got.timeline < 4 || got.dialog !== isPhone) caseMisses.push(`${id}: card[${inCard}] panel[${inPanel}] title=${got.title} ev=${got.evidence} tl=${got.timeline} dialog=${got.dialog}`);
          await closeDrawer();
        }
        check(wname, 'cases', `every old table and drawer field for all 3 cases is shown (card + ${isPhone ? 'drawer' : 'inline detail'})`, caseMisses.length === 0, caseMisses.join(' ; '));

        // Filters above the board
        const caseToolbar = await page.evaluate(() => {
          const bar = document.querySelector('main .toolbar');
          const boardEl = document.querySelector('.board');
          return { insideCard: !!bar?.closest('.card'), above: !!bar && !!boardEl && bar.getBoundingClientRect().bottom <= boardEl.getBoundingClientRect().top, search: !!bar?.querySelector('input[type="search"]'), selects: [...(bar?.querySelectorAll('select') ?? [])].map(s => s.id).join(',') };
        });
        check(wname, 'I12 filters', 'cases: search and filters sit above the board, outside a card', !caseToolbar.insideCard && caseToolbar.above && caseToolbar.search && caseToolbar.selects === 'caseseverity,casestatus', JSON.stringify(caseToolbar));
        await page.selectOption('#caseseverity', 'Critical');
        check(wname, 'cases', 'severity Critical: CASE-006, CASE-008', await caseIds() === 'CASE-006,CASE-008', await caseIds());
        await page.selectOption('#caseseverity', 'High');
        check(wname, 'cases', 'severity High: CASE-007', await caseIds() === 'CASE-007', await caseIds());
        await page.selectOption('#caseseverity', 'all');
        await page.selectOption('#casestatus', 'Closed');
        cols = await board();
        check(wname, 'cases', 'status Closed: only CASE-008, Investigating shows an empty state', await caseIds() === 'CASE-008' && cols[0].empty === 'No matching cases' && cols[0].title === 'Investigating 0', JSON.stringify(cols));
        await page.selectOption('#casestatus', 'all');
        await page.fill('#casesearch', 'endpoint-03');
        check(wname, 'cases', 'search "endpoint-03": CASE-007', await caseIds() === 'CASE-007' && await page.evaluate(() => document.querySelector('#visibleCaseCount')?.textContent.trim()) === '1 visible', await caseIds());
        await page.click('main .toolbar button:has-text("Reset Filters")');
        check(wname, 'cases', 'Reset Filters restores all 3', await caseIds() === 'CASE-006,CASE-007,CASE-008', await caseIds());

        // Keyboard selection
        await page.focus(`${CARD}[data-record-id="CASE-007"]`);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(120);
        check(wname, 'cases', 'Enter on a card selects it', await page.evaluate(() => document.querySelector('.case-card[aria-pressed="true"]')?.dataset.recordId) === 'CASE-007');
        await closeDrawer();
        await page.focus(`${CARD}[data-record-id="CASE-008"]`);
        await page.keyboard.press('Space');
        await page.waitForTimeout(120);
        check(wname, 'cases', 'Space on a card selects it', await page.evaluate(() => document.querySelector('.case-card[aria-pressed="true"]')?.dataset.recordId) === 'CASE-008');
        await closeDrawer();

        // Phones: drawer with the shared dialog behaviour; wide screens: inline
        if (isPhone) {
          await dialogKeyboard(wname, 'Case detail drawer', () => page.click(`${CARD}[data-record-id="CASE-007"]`));
          check(wname, 'C8 modal', 'Case detail drawer: focus returns to the chosen case', await page.evaluate(() => document.activeElement?.dataset.recordId === 'CASE-007'));
        } else {
          check(wname, 'cases', 'wide screen: case detail is inline beside the board, no dialog', await page.evaluate(() => !document.querySelector('[role="dialog"]') && !!document.querySelector('.card.detail-panel #caseDetailTitle')));
        }

        // Recommended actions: manual ticks update text, bar and card, and persist across pages
        const actionState = () => page.evaluate(() => {
          const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel');
          return {
            id: scope?.querySelector('[data-case-id]')?.dataset.caseId,
            progress: scope?.querySelector('.case-progress-text')?.textContent.trim(),
            live: scope?.querySelector('.case-progress-text')?.getAttribute('role'),
            boxes: [...(scope?.querySelectorAll('.case-action') ?? [])].map(l => ({ label: l.querySelector('.case-action-text > span')?.textContent.trim(), checked: l.querySelector('input').checked, disabled: l.querySelector('input').disabled, run: l.querySelector('.case-action-run')?.textContent.trim() ?? null })),
          };
        });
        await page.click(`${CARD}[data-record-id="CASE-006"]`);
        await page.waitForTimeout(120);
        let as = await actionState();
        check(wname, 'cases actions', 'CASE-006: labelled checkboxes; "Block the source IP" waits for APR-002 (not done, not hand-editable)', as.boxes.length === 4 && as.boxes.every(b => b.label) && !as.boxes[0].checked && as.boxes[0].disabled && as.boxes[0].run === 'Waiting for approval (APR-002)' && as.boxes.slice(1).every(b => !b.disabled && !b.checked) && as.progress === '0 of 4 done' && as.live === 'status', JSON.stringify(as));
        await page.click('.case-action:has-text("Review authentication logs") input');
        await page.waitForTimeout(120);
        as = await actionState();
        const bar006 = await page.evaluate(() => document.querySelector('.case-card[data-record-id="CASE-006"] .case-bar-fill')?.style.width);
        check(wname, 'cases actions', 'ticking an action updates the progress text, the card and its bar', as.progress === '1 of 4 done' && await cardProgress('CASE-006') === '1 of 4 actions' && bar006 === '25%', JSON.stringify({ progress: as.progress, card: await cardProgress('CASE-006'), bar006 }));
        await closeDrawer();
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.goBack();
        await page.waitForURL('**/app/cases');
        await page.waitForTimeout(300);
        check(wname, 'cases actions', 'ticks survive leaving the page and coming back', await cardProgress('CASE-006') === '1 of 4 actions', await cardProgress('CASE-006'));

        // CASE-007: the agent only investigated, so no action waits on a run or an approval
        await page.click(`${CARD}[data-record-id="CASE-007"]`);
        await page.waitForTimeout(120);
        as = await actionState();
        check(wname, 'cases actions', 'CASE-007: 4 manual actions, none run-linked or disabled, none done (nothing was isolated)', as.boxes.length === 4 && as.boxes.every(b => b.label && !b.disabled && !b.checked && b.run === null) && !as.boxes.some(b => /Isolate/.test(b.label)) && as.progress === '0 of 4 done' && await cardProgress('CASE-007') === '0 of 4 actions', JSON.stringify(as));
        const caseTl = await page.evaluate(() => [...(document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel')).querySelectorAll('.step-timeline-item')].map(li => `${li.className.replace('step-timeline-item', '').trim()}:${li.querySelector('.step-timeline-label')?.textContent.trim()}`));
        check(wname, 'cases', 'CASE-007 timeline: "Agent assessment" replaces the failed isolation, and no step is failed', caseTl.some(l => /Agent assessment/.test(l)) && !caseTl.some(l => l.startsWith('fail:')) && !caseTl.some(l => /isolation failed/i.test(l)), caseTl.join(' | '));
        await closeDrawer();

        // Close case: board, sidebar badge, timeline, search and dashboard all follow
        await page.click(`${CARD}[data-record-id="CASE-006"]`);
        await page.click('.case-detail button:has-text("Close case")');
        await page.waitForTimeout(150);
        const closedDetail = await page.evaluate(() => {
          const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel');
          return { status: scope?.querySelector('[data-field="status"]')?.textContent.trim(), updated: scope?.querySelector('[data-field="lastUpdated"]')?.textContent.trim(), tl: [...(scope?.querySelectorAll('.step-timeline-label') ?? [])].map(l => l.textContent.trim()) };
        });
        await closeDrawer();
        cols = await board();
        const caseBadge = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Case Management')?.querySelector('.count')?.textContent ?? '0');
        check(wname, 'cases', 'Close case: card moves to Closed, sidebar badge 1, status Closed, updated "Just now", timeline entry', JSON.stringify(cols.map(c => c.ids)) === JSON.stringify([['CASE-007'], ['CASE-006', 'CASE-008']]) && caseBadge === '1' && closedDetail.status === 'Closed' && closedDetail.updated === 'Just now' && closedDetail.tl.includes('Closed by Analyst A'), JSON.stringify({ cols, caseBadge, closedDetail }));
        const caseResult = (await searchFor('CASE-006')).find(o => o.startsWith('CASE-006')) || '';
        check(wname, 'cases', 'global search shows CASE-006 as Closed', /· Closed ·/.test(caseResult), caseResult);
        await page.click('.logo');
        await page.waitForURL('**/app/dashboard');
        await page.waitForTimeout(250);
        const openCasesFigure = await page.evaluate(() => [...document.querySelectorAll('.posture li')].map(li => li.innerText.replace(/\s+/g, ' ').trim()).find(t => /Open cases/.test(t)));
        check(wname, 'cases', 'dashboard "Open cases" drops to 1 (Analyst B)', /^1 Open cases Analyst B$/.test(openCasesFigure || ''), openCasesFigure);
        await page.goBack();
        await page.waitForURL('**/app/cases');
        await page.waitForTimeout(300);
        await page.click(`${CARD}[data-record-id="CASE-006"]`);
        await page.click('.case-detail button:has-text("Reopen case")');
        await page.waitForTimeout(150);
        await closeDrawer();
        const reopenedBadge = await page.evaluate(() => [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Case Management')?.querySelector('.count')?.textContent);
        check(wname, 'cases', 'Reopen case restores the board and the sidebar badge', JSON.stringify((await board()).map(c => c.ids)) === JSON.stringify([['CASE-006', 'CASE-007'], ['CASE-008']]) && reopenedBadge === '2', `${reopenedBadge}`);

        // Global search selects a case hidden by a filter
        await page.selectOption('#casestatus', 'Closed');
        await page.fill('#globalSearch', 'CASE-006');
        await page.waitForTimeout(150);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(450);
        const caseLanded = await page.evaluate(() => {
          const card = document.querySelector('.case-card[data-record-id="CASE-006"]');
          const r = card?.getBoundingClientRect();
          return { filter: document.querySelector('#casestatus')?.value, pressed: card?.getAttribute('aria-pressed'), focused: document.activeElement === card, inView: !!r && r.top >= 0 && r.bottom <= window.innerHeight, detail: document.querySelector('.card.detail-panel [data-case-id]')?.dataset.caseId ?? null, dialog: !!document.querySelector('[role="dialog"]') };
        });
        check(wname, 'I8 search', 'search for a filtered-out case clears the filter, selects, scrolls to and focuses it', caseLanded.filter === 'all' && caseLanded.pressed === 'true' && caseLanded.focused && caseLanded.inView && !caseLanded.dialog && (isPhone || caseLanded.detail === 'CASE-006'), JSON.stringify(caseLanded));
        if (wname !== 'laptop') await page.screenshot({ path: out + `analyst-cases-board-${wname}.png`, fullPage: true });

        // ---------- Incident Response: pipeline + "why" panel (replaces the table and drawer) ----------
        // A reload gives the starting state, so this section (and its own retry below)
        // doesn't depend on anything the Alerts or dashboard checks did.
        await page.goto(base + '/app/incident');
        await page.waitForTimeout(300);
        const RUN = '.run-row[data-record-id]';
        const runIds = async () => (await listGeometry(RUN)).ids.join(',');
        const runCount = () => page.evaluate(() => document.querySelector('main .toolbar [role="status"]')?.textContent.trim());
        // Each figure as "<number> <words>"
        const figures = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.response-summary [data-figure]')].map(d => [d.dataset.figure, [...d.children].map(c => c.textContent.replace(/\s+/g, ' ').trim()).join(' ')])));
        const failedFigureFlagged = () => page.evaluate(() => !!document.querySelector('.response-summary [data-figure="failed"].attention'));
        // Each row's stages as "Stage=label", then the result
        const runStages = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.run-row')].map(r => [r.dataset.recordId, [...r.querySelectorAll('.run-stage')].map(s => `${s.dataset.stage}=${s.querySelector('.stage-label')?.textContent.trim()}`).join(',') + '|' + r.querySelector('.run-result')?.textContent.replace('Result:', '').trim()])));
        // The open drawer on phones, the inline panel otherwise
        const runPanel = () => page.evaluate(() => {
          const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel');
          const text = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          return {
            id: scope?.querySelector('[data-workspace-id]')?.dataset.workspaceId ?? null,
            title: text(scope?.querySelector('#runPanelTitle')),
            fields: Object.fromEntries(['triggeringAlert', 'action', 'target', 'policy', 'approvedBy', 'result', 'startTime', 'endTime', 'duration', 'rollbackStatus', 'failureReason'].map(n => [n, text(scope?.querySelector(`[data-field="${n}"]`))])),
            approval: Object.fromEntries(['request', 'requestedBy', 'decision', 'reason', 'policy', 'token', 'window'].map(n => [n, text(scope?.querySelector(`.approval-facts [data-field="${n}"]`))])),
            digestTitle: scope?.querySelector('.approval-digest')?.getAttribute('title') ?? null,
            texts: ['happened', 'classified', 'responseReason'].map(n => text(scope?.querySelector(`[data-field="${n}"]`))),
            evidence: scope?.querySelectorAll('[data-field="evidence"] li').length ?? 0,
            timeline: [...(scope?.querySelectorAll('.step-timeline-item') ?? [])].map(li => `${li.className.replace('step-timeline-item', '').trim() || 'done'}:${li.querySelector('.step-timeline-label')?.textContent.trim()}`),
            alertLink: text(scope?.querySelector('a[href="/app/alerts"]')),
            dialog: !!document.querySelector('[role="dialog"]'),
          };
        });

        // Summary strip from data (starting state)
        let figs = await figures();
        check(wname, 'incident', 'summary: 1 of 1 succeeded, fastest 1 min (EXE-001), 1 approved by a person (1 SOC lead) and 1 awaiting approval, 0 failed (not flagged)', figs.succeeded === '1 of 1 responses succeeded' && figs.fastest === '1 min fastest containment, EXE-001' && figs.approval === '1 approved by a person (1 SOC lead, 0 analyst), 1 awaiting approval' && figs.failed === '0 failed runs' && !(await failedFigureFlagged()), JSON.stringify(figs));
        check(wname, 'incident', 'pipeline lists EXE-001 only (nothing else was approved), 1 visible', await runIds() === 'EXE-001' && await runCount() === '1 visible', `${await runIds()} / ${await runCount()}`);

        // Stages come from the approval record (who approved) and the result
        const STAGE_WANT = {
          'EXE-001': 'Detected=Done,Scored=Done,Policy matched=Done,Approved=SOC lead,Executed=Done|Completed',
        };
        const stagesNow = await runStages();
        check(wname, 'incident', 'stages match the run\'s approval (SOC lead) and result', JSON.stringify(stagesNow) === JSON.stringify(STAGE_WANT), JSON.stringify(stagesNow));
        const stageText = await page.evaluate(() => {
          const stages = [...document.querySelectorAll('.run-stage')];
          return {
            unlabelled: stages.filter(s => !s.querySelector('.stage-label')?.textContent.trim()).length,
            unnamed: stages.filter(s => s.querySelector('.visually-hidden')?.textContent !== `${s.dataset.stage}: `).length,
            legend: [...document.querySelectorAll('.stage-legend li')].map(li => li.textContent.trim()).join(' | '),
            failedRows: [...document.querySelectorAll('.run-row.failed')].map(r => r.dataset.recordId).join(','),
          };
        });
        check(wname, 'incident', 'every stage has a visible label and a screen-reader stage name; legend explains the dots', stageText.unlabelled === 0 && stageText.unnamed === 0 && stageText.legend === 'Done | Analyst: approved by an analyst | SOC lead: approved by a SOC lead | Failed', JSON.stringify(stageText));
        check(wname, 'incident', 'no run is highlighted as failed (none failed)', stageText.failedRows === '', stageText.failedRows);
        const rowName = await page.evaluate(() => document.querySelector('.run-row[data-record-id="EXE-001"]')?.textContent.replace(/\s+/g, ' ').trim());
        check(wname, 'incident', 'a row\'s text names each stage with its state (not colour alone)', rowName === 'Isolate endpoint-12 EXE-001 for ALT-006 Detected: Done Scored: Done Policy matched: Done Approved: SOC lead Executed: Done Result: Completed', rowName);

        // Rows: buttons, tall enough, one selected (the first run by default), no indent
        const rg = await listGeometry(RUN);
        check(wname, 'incident list', '1 row, a button at least 40px tall', rg.count === 1 && rg.notButtons.length === 0 && rg.short.length === 0, JSON.stringify(rg));
        check(wname, 'incident list', 'no text cut off in the row, no stray indent', rg.clipped.length === 0 && rg.indented.length === 0, JSON.stringify({ clipped: rg.clipped, indented: rg.indented }));
        check(wname, 'incident list', 'exactly one row is pressed: the first run by default', rg.pressed.join() === 'EXE-001', rg.pressed.join(', ') || 'none');
        const fit = await page.evaluate(() => {
          const scroller = document.querySelector('.card.pipeline .table-scroll');
          const grid = document.querySelector('.pipeline-grid').getBoundingClientRect();
          const rows = [...document.querySelectorAll('.run-row')].map(r => r.getBoundingClientRect());
          return {
            overflow: scroller.scrollWidth > scroller.clientWidth + 1,
            hint: !!document.querySelector('.card.pipeline .table-scroll-hint'),
            region: scroller.getAttribute('role') === 'region' && scroller.tabIndex === 0 && /Response pipeline/.test(scroller.getAttribute('aria-label') || ''),
            rowsInGrid: rows.every(r => r.left >= grid.left - 0.5 && r.right <= grid.right + 0.5),
            pageScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
          };
        });
        if (isPhone) {
          check(wname, 'incident list', 'phone: the pipeline scrolls sideways inside its card, with the hint, as a focusable region; the page itself does not', fit.overflow && fit.hint && fit.region && fit.rowsInGrid && !fit.pageScroll, JSON.stringify(fit));
        } else {
          check(wname, 'incident list', 'wide screen: every row fully on screen, no sideways scroll or hint', rg.offscreen.length === 0 && !fit.overflow && !fit.hint && !fit.region, JSON.stringify({ offscreen: rg.offscreen, fit }));
        }

        // Every table and drawer field of the run, and its approval record
        const RUN_FIELDS = {
          'EXE-001': { title: 'Isolate endpoint-12', triggeringAlert: 'ALT-006', action: 'Isolate Host', target: 'endpoint-12', policy: 'Response policy v2: isolate_host', approvedBy: 'System Administrator (SOC lead)', result: 'Completed', startTime: '15:44', endTime: '15:45', duration: '1 minute', rollbackStatus: 'Reconnects automatically at 17:44', failureReason: 'None', steps: 5 },
        };
        const runMisses = [];
        let runApproval = null;
        for (const [id, want] of Object.entries(RUN_FIELDS)) {
          await page.click(`${RUN}[data-record-id="${id}"]`);
          await page.waitForTimeout(400);
          const got = await runPanel();
          runApproval = got;
          const wrong = Object.keys(got.fields).filter(k => got.fields[k] !== (want[k] ?? null));
          const failSteps = got.timeline.filter(s => s.startsWith('fail:'));
          if (got.id !== id || got.title !== want.title || wrong.length || got.texts.some(t => !t) || got.evidence < 1 || got.timeline.length !== want.steps || failSteps.length !== 0 || got.alertLink !== `View ${want.triggeringAlert}` || got.dialog !== isPhone) runMisses.push(`${id}: id=${got.id} title=${got.title} fields[${wrong}] texts=${got.texts.map(t => !!t)} ev=${got.evidence} tl=${got.timeline.join('/')} link=${got.alertLink} dialog=${got.dialog}`);
          if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        }
        check(wname, 'incident', `every table and drawer field of EXE-001 is shown (row + ${isPhone ? 'drawer' : 'inline panel'}), no failed step`, runMisses.length === 0, runMisses.join(' ; '));
        {
        const ap = runApproval?.approval ?? {};
        check(wname, 'incident', 'approval record: APR-001 isolate endpoint-12 for 120 min, asked by AthenaSec AI at 15:42, approved by the System Administrator (SOC lead) at 15:43, response policy version 2 (isolate_host, SOC lead), with the reason given', ap.request === 'APR-001 · Isolate endpoint-12 for 120 min' && ap.requestedBy === 'AthenaSec AI at 15:42' && ap.decision === 'Approved by System Administrator (SOC lead) at 15:43' && ap.policy === 'Response policy version 2, isolate_host: SOC lead approves, minimum risk 90' && ap.reason === 'Beaconing to a known-bad address with EDR findings; isolate as recommended.', JSON.stringify(ap));
        check(wname, 'incident', 'approval record: TKN-001 is used at 15:44, bound to a SHA-256 of the approved action (digest computed in the browser), and the isolation is active until 17:44 on the demo clock', /^TKN-001, used at 15:44 bound to sha256 [0-9a-f]{12}…$/.test(ap.token || '') && /^[0-9a-f]{64}$/.test(runApproval?.digestTitle || '') && (ap.token || '').includes((runApproval?.digestTitle || 'x').slice(0, 12)) && ap.window === 'Active until 17:44', JSON.stringify({ token: ap.token, window: ap.window, digest: runApproval?.digestTitle }));
        }

        // Keyboard: Enter and Space select a row
        await page.focus(`${RUN}[data-record-id="EXE-001"]`);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(120);
        check(wname, 'incident', 'Enter on a row selects it and shows its panel', (await runPanel()).id === 'EXE-001' && await page.evaluate(() => document.querySelector('.run-row[aria-pressed="true"]')?.dataset.recordId) === 'EXE-001');
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.focus(`${RUN}[data-record-id="EXE-001"]`);
        await page.keyboard.press('Space');
        await page.waitForTimeout(120);
        check(wname, 'incident', 'Space on a row selects it', await page.evaluate(() => document.querySelector('.run-row[aria-pressed="true"]')?.dataset.recordId) === 'EXE-001');
        if (isPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // Phones: drawer with the shared dialog behaviour; wide screens: inline under the pipeline
        if (isPhone) {
          check(wname, 'incident', 'phone: no panel until a run is chosen', await page.evaluate(() => !document.querySelector('[role="dialog"]') && !document.querySelector('.card.detail-panel')));
          await dialogKeyboard(wname, 'Response details drawer', () => page.click(`${RUN}[data-record-id="EXE-001"]`));
          check(wname, 'C8 modal', 'Response details drawer: focus returns to the chosen run', await page.evaluate(() => document.activeElement?.dataset.recordId === 'EXE-001'));
          await page.click(`${RUN}[data-record-id="EXE-001"]`);
          await page.waitForTimeout(250);
          await page.screenshot({ path: out + 'analyst-incident-drawer-mobile.png' });
          await page.keyboard.press('Escape');
          await page.waitForTimeout(150);
        } else {
          check(wname, 'incident', 'wide screen: the panel is inline below the pipeline, no dialog', await page.evaluate(() => {
            const panel = document.querySelector('.card.detail-panel');
            const pipe = document.querySelector('.card.pipeline');
            return !document.querySelector('[role="dialog"]') && !!panel?.querySelector('#runPanelTitle') && panel.getBoundingClientRect().top >= pipe.getBoundingClientRect().bottom;
          }));
        }

        // (The failed-stage pulse check is removed: no run can fail in the seed. It returns with the failed-run demo in C4.)

        // Filters and search above the pipeline, same options as before
        const ACTION_SEL = 'main .toolbar select[aria-label="Filter by action"]';
        const RESULT_SEL = 'main .toolbar select[aria-label="Filter by result"]';
        const runToolbar = await page.evaluate(() => {
          const bar = document.querySelector('main .toolbar');
          const pipe = document.querySelector('.card.pipeline');
          return { insideCard: !!bar?.closest('.card'), above: !!bar && !!pipe && bar.getBoundingClientRect().bottom <= pipe.getBoundingClientRect().top, search: bar?.querySelector('input[type="search"]')?.getAttribute('aria-label'), options: [...(bar?.querySelectorAll('select') ?? [])].map(s => [...s.options].map(o => o.textContent).join('/')).join(' ; ') };
        });
        // Cut-off text: the search placeholder fits inside its box (text width measured in the box's font)
        const ph = await page.evaluate(() => {
          const input = document.querySelector('main .toolbar input[type="search"]');
          const cs = getComputedStyle(input);
          const ctx = document.createElement('canvas').getContext('2d');
          ctx.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
          const room = input.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
          return { placeholder: input.placeholder, text: Math.ceil(ctx.measureText(input.placeholder).width), room: Math.floor(room) };
        });
        check(wname, 'incident list', `search placeholder "${ph.placeholder}" is not cut off`, ph.placeholder === 'Search runs, alerts, targets…' && ph.text <= ph.room, JSON.stringify(ph));
        check(wname, 'I12 filters', 'incident: search and filters sit above the pipeline, outside a card, same options as before', !runToolbar.insideCard && runToolbar.above && runToolbar.search === 'Search executions, alerts, policies, or targets' && runToolbar.options === 'All Actions/Block IP/Isolate Host ; All Results/Completed/Failed', JSON.stringify(runToolbar));
        await page.selectOption(ACTION_SEL, 'Block IP');
        check(wname, 'incident', 'action Block IP: none (the one run isolates a host), 0 visible', await runIds() === '' && await runCount() === '0 visible', `${await runIds()} / ${await runCount()}`);
        await page.selectOption(ACTION_SEL, 'Isolate Host');
        check(wname, 'incident', 'action Isolate Host: EXE-001', await runIds() === 'EXE-001' && await runCount() === '1 visible', await runIds());
        await page.selectOption(ACTION_SEL, 'all');
        await page.selectOption(RESULT_SEL, 'Failed');
        check(wname, 'incident', 'result Failed: none, 0 visible', await runIds() === '' && await runCount() === '0 visible', await runIds());
        await page.selectOption(RESULT_SEL, 'all');
        await page.fill('main .toolbar input[type="search"]', 'endpoint-12');
        check(wname, 'incident', 'search "endpoint-12": EXE-001', await runIds() === 'EXE-001', await runIds());
        await page.fill('main .toolbar input[type="search"]', 'administrator');
        check(wname, 'incident', 'search "administrator" finds the run the System Administrator approved: EXE-001', await runIds() === 'EXE-001', await runIds());
        await page.fill('main .toolbar input[type="search"]', 'zzqx');
        const runEmpty = await page.evaluate(() => document.querySelector('.card.pipeline .empty')?.textContent.trim());
        check(wname, 'incident', 'no matches shows an empty state with Clear Filters', /No response runs match/.test(runEmpty || '') && /Clear Filters/.test(runEmpty || '') && await runCount() === '0 visible', runEmpty);
        await page.click('main .toolbar button:has-text("Reset Filters")');
        check(wname, 'incident', 'Reset Filters restores the run', await runIds() === 'EXE-001' && await runCount() === '1 visible', await runIds());

        // Global search selects a run hidden by a filter
        await page.selectOption(RESULT_SEL, 'Failed');
        await page.fill('#globalSearch', 'EXE-001');
        await page.waitForTimeout(150);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(450);
        const runLanded = await page.evaluate(() => {
          const row = document.querySelector('.run-row[data-record-id="EXE-001"]');
          const r = row?.getBoundingClientRect();
          return { filter: document.querySelector('main .toolbar select[aria-label="Filter by result"]')?.value, pressed: row?.getAttribute('aria-pressed'), focused: document.activeElement === row, inView: !!r && r.top >= 0 && r.bottom <= window.innerHeight, panel: document.querySelector('.card.detail-panel [data-workspace-id]')?.dataset.workspaceId ?? null, dialog: !!document.querySelector('[role="dialog"]') };
        });
        check(wname, 'I8 search', 'search for a filtered-out run clears the filter, selects, scrolls to and focuses it', runLanded.filter === 'all' && runLanded.pressed === 'true' && runLanded.focused && runLanded.inView && !runLanded.dialog && (isPhone || runLanded.panel === 'EXE-001'), JSON.stringify(runLanded));
        if (!isPhone) await page.screenshot({ path: out + `analyst-incident-${wname}.png`, fullPage: true });

        // Links between the run and its alert (the retry round trip that used to be here returns with Approve in C4)
        await page.click(`${RUN}[data-record-id="EXE-001"]`);
        await page.waitForTimeout(150);
        await page.click(':is([role="dialog"], .card.detail-panel) a:has-text("View ALT-006")');
        await page.waitForURL('**/app/alerts');
        await page.waitForTimeout(450);
        const alertPicked = await page.evaluate(() => document.querySelector('.queue-item[aria-pressed="true"]')?.dataset.recordId);
        check(wname, 'incident', '"View ALT-006" lands on Alerts with ALT-006 selected', alertPicked === 'ALT-006', alertPicked);
        if (isPhone) {
          await page.click('.queue-item[data-record-id="ALT-006"]');
          await page.waitForTimeout(250);
        }
        await page.click('.workspace a:has-text("View EXE-001")');
        await page.waitForURL('**/app/incident');
        await page.waitForTimeout(450);
        const runBack = await page.evaluate(() => document.querySelector('.run-row[aria-pressed="true"]')?.dataset.recordId);
        check(wname, 'incident', '"View EXE-001" on the alert returns to Incident Response with EXE-001 selected', runBack === 'EXE-001', runBack);

        // ---------- Approvals: the queue, the decision rules, the executor's steps (policy phase C4a) ----------
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        const aprPhone = wname === 'mobile';
        let ap = await aprState();
        check(wname, 'approvals', 'heading, summary and views: "1 request is waiting for you. Nothing runs until a person approves it.", Waiting 1 and Decided 1', ap.h1 === 'Approvals' && ap.sub === '1 request is waiting for you. Nothing runs until a person approves it.' && ap.seg === 'Waiting 1:true | Decided 1:false', JSON.stringify([ap.h1, ap.sub, ap.seg]));
        const r2 = ap.rows[0] ?? {};
        check(wname, 'approvals', 'waiting row APR-002: action and target, alert and attack, policy and version, required role, risk and confidence, time left from the demo clock (13 min), state word, and a link to the alert', ap.rows.length === 1 && r2.id === 'APR-002' && r2.name === 'Block 203.0.113.45 for 30 min' && r2.route === 'ALT-001 · Brute Force SSH' && r2.meta === 'Response policy version 3 · needs a SOC analyst' && r2.outcome === 'Risk 77, confidence 0.88 · 13 min left' && r2.state === 'Waiting' && r2.link === '/app/alerts' && r2.linkText === 'Open ALT-001', JSON.stringify(r2));
        const aprBadge = await page.evaluate(() => { const c = [...document.querySelectorAll('.sidebar .side-item')].find(a => a.querySelector('.side-label')?.textContent.trim() === 'Approvals')?.querySelector('.count'); return [c?.textContent ?? null, c?.getAttribute('aria-label') ?? null]; });
        check(wname, 'approvals', 'sidebar badge: Approvals 1, labelled "1 request waiting for you"', aprBadge[0] === '1' && aprBadge[1] === '1 request waiting for you', aprBadge.join(' / '));
        await page.click('.page.active .headline .segmented-option:has-text("Decided")');
        await page.waitForTimeout(150);
        ap = await aprState();
        const r1 = ap.rows[0] ?? {};
        check(wname, 'approvals', 'Decided view: APR-001 (the SOC lead\'s isolation of endpoint-12) is Done, needs a SOC lead, decided 15:43', ap.rows.length === 1 && r1.id === 'APR-001' && r1.name === 'Isolate endpoint-12 for 120 min' && r1.route === 'ALT-006 · Malware - C2 Beaconing' && r1.meta === 'Response policy version 2 · needs a SOC lead' && r1.outcome === 'Risk 90, confidence 0.92 · decided 15:43' && r1.state === 'Done', JSON.stringify(r1));
        await page.click('.page.active .headline .segmented-option:has-text("Waiting")');
        await page.waitForTimeout(150);
        await page.click('.queue-item[data-record-id="APR-002"]');
        await page.waitForTimeout(300);
        ap = await aprState();
        const pn = ap.panel ?? { fields: {} };
        check(wname, 'approvals', 'detail of APR-002: request, asked by AthenaSec AI at 15:44, waiting for a SOC analyst (13 min left, by 15:59), response policy version 3 (block_ip, SOC analyst), no token yet, 4 other outcomes considered', pn.id === 'APR-002' && pn.title === 'Block 203.0.113.45 for 30 min' && pn.fields.request === 'APR-002 · Block 203.0.113.45 for 30 min' && pn.fields.requestedBy === 'AthenaSec AI at 15:44' && pn.fields.decision === 'Waiting for a SOC analyst (13 min left, by 15:59)' && pn.fields.policy === 'Response policy version 3, block_ip: SOC analyst approves, minimum risk 70' && pn.fields.token === null && pn.fields.window === null && pn.alternatives === 4, JSON.stringify(pn));
        check(wname, 'approvals', 'the decision form offers Approve, Shorten the duration and Reject, enabled for an analyst, with no refusal shown and no stepper yet', pn.form && pn.radios.join('|') === 'Approve|Shorten the duration|Reject' && pn.refusal === null && pn.stage === null && /Open ALT-001/.test(pn.links), JSON.stringify([pn.radios, pn.refusal, pn.stage, pn.links]));
        await page.screenshot({ path: out + `analyst-approvals-waiting-${wname}.png`, fullPage: true });
        // Each decision needs a reason; the refusal says so and nothing changes
        await page.click(`${APR_SCOPE} button:has-text("Approve request")`);
        await page.waitForTimeout(150);
        ap = await aprState();
        const noReasonApprove = ap.panel?.message;
        await page.locator(`${APR_SCOPE} .approval-choice:has-text("Reject") input`).check();
        await page.click(`${APR_SCOPE} button:has-text("Reject request")`);
        await page.waitForTimeout(150);
        ap = await aprState();
        const noReasonReject = ap.panel?.message;
        check(wname, 'approvals', 'approving or rejecting without a reason is refused in words and changes nothing (still Waiting, no stepper)', noReasonApprove === 'Enter a reason to approve this request.' && noReasonReject === 'Enter a reason to reject this request.' && ap.rows[0].state === 'Waiting' && ap.panel.stage === null && await sideBadgeApr() === '1', JSON.stringify([noReasonApprove, noReasonReject, ap.rows[0]?.state]));
        // Shortening: only down, and the field says so
        await page.locator(`${APR_SCOPE} .approval-choice:has-text("Shorten") input`).check();
        const minutesField = await page.evaluate(() => { const i = document.querySelector('input[id^="minutes-"]'); return { min: i?.min, max: i?.max, value: i?.value, hint: document.querySelector('#minutes-hint-APR-002')?.textContent.replace(/\s+/g, ' ').trim() }; });
        await page.fill('#reason-APR-002', 'Too long for a first block.');
        await page.fill('#minutes-APR-002', '40');
        await page.click(`${APR_SCOPE} button:has-text("Approve with a shorter duration")`);
        await page.waitForTimeout(150);
        const extendMsg = (await aprState()).panel?.message;
        await page.fill('#minutes-APR-002', '30');
        await page.click(`${APR_SCOPE} button:has-text("Approve with a shorter duration")`);
        await page.waitForTimeout(150);
        const sameMsg = (await aprState()).panel?.message;
        check(wname, 'approvals', 'Shorten the duration: the field runs 1 to 29 min (the recommended 30 is the ceiling), extending to 40 or keeping 30 is refused in words, and the hint says only the duration can change', minutesField.min === '1' && minutesField.max === '29' && /can only be shortened, never extended/.test(minutesField.hint) && /action and its target stay as recommended/.test(minutesField.hint) && extendMsg === 'A duration can only be shortened: 30 min is the most you can approve.' && sameMsg === 'Modify needs a duration shorter than the recommended 30 min.', JSON.stringify({ minutesField, extendMsg, sameMsg }));
        // Approve: the executor's steps are visible, in order, and the pulse follows prefers-reduced-motion
        await page.locator(`${APR_SCOPE} .approval-choice:has-text("Approve") input`).first().check();
        await page.fill('#reason-APR-002', 'Confirmed brute force from a known scanner.');
        await page.emulateMedia({ reducedMotion: 'no-preference' });
        await page.click(`${APR_SCOPE} button:has-text("Approve request")`);
        const run1 = await sampleStages();
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await page.waitForTimeout(200);
        ap = await aprState();
        check(wname, 'approvals', 'after Approve the steps show in order: Approved, Executing, then Done', run1.seen.join(',') === 'Approved,Executing,Done', run1.seen.join(','));
        check(wname, 'motion', 'approvals: the Executing step pulses by default (stagePulse)', run1.pulse === 'stagePulse', String(run1.pulse));
        await page.screenshot({ path: out + `analyst-approvals-done-${wname}.png`, fullPage: true });
        const pa = ap.panel ?? { fields: {} };
        check(wname, 'approvals', 'once done: the request moves to Decided and stays selected, steps all done, approved by Analyst A at the demo time with its reason, TKN-002 used and bound to a SHA-256, window until 16:16, no form', ap.seg.startsWith('Waiting 0:false') && ap.rows[0]?.id === 'APR-002' && ap.rows[0].state === 'Done' && pa.steps === 'Approved=done,Executing=done,Done=done' && pa.fields.decision === 'Approved by Analyst A (SOC analyst) at 15:46' && pa.fields.reason === 'Confirmed brute force from a known scanner.' && /^TKN-002, used at 15:46 bound to sha256 [0-9a-f]{12}…$/.test(pa.fields.token || '') && pa.fields.window === 'Active until 16:16' && !pa.form && /View EXE-002/.test(pa.links), JSON.stringify(pa));
        check(wname, 'approvals', 'afterwards the Approvals badge is gone, the bell says "2 unread" and the summary says no request is waiting', await sideBadgeApr() === null && (await bellLabel()) === 'Notifications, 2 unread' && ap.sub.startsWith('No request is waiting for a decision.'), JSON.stringify([await sideBadgeApr(), await bellLabel(), ap.sub]));
        const aprHit = (await searchFor('APR-002')).find(o => o.startsWith('APR-002')) || '';
        check(wname, 'approvals', 'global search finds APR-002 with its alert, state and required role', /APR-002 · Block 203\.0\.113\.45/.test(aprHit) && /ALT-001 · Approved · SOC analyst/.test(aprHit), aprHit);
        // The same approval reaches the other pages
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Incident Response', aprPhone);
        const incAfter = await page.evaluate(() => ({
          rows: [...document.querySelectorAll('.run-row')].map(r => r.dataset.recordId).join(','),
          figs: Object.fromEntries([...document.querySelectorAll('.response-summary [data-figure]')].map(d => [d.dataset.figure, [...d.children].map(c => c.textContent.replace(/\s+/g, ' ').trim()).join(' ')])),
          exe2: (() => { const r = document.querySelector('.run-row[data-record-id="EXE-002"]'); return r ? [...r.querySelectorAll('.run-stage')].map(s => `${s.dataset.stage}=${s.querySelector('.stage-label')?.textContent.trim()}`).join(',') + '|' + r.querySelector('.run-result')?.textContent.replace('Result:', '').trim() : null; })(),
        }));
        check(wname, 'approvals', 'Incident Response gains EXE-002: 2 of 2 succeeded, 2 approved by a person (1 SOC lead, 1 analyst), 0 awaiting, fastest still EXE-001, and EXE-002\'s Approved stage reads Analyst', incAfter.rows === 'EXE-001,EXE-002' && incAfter.figs.succeeded === '2 of 2 responses succeeded' && incAfter.figs.approval === '2 approved by a person (1 SOC lead, 1 analyst), 0 awaiting approval' && incAfter.figs.fastest === '1 min fastest containment, EXE-001' && incAfter.exe2 === 'Detected=Done,Scored=Done,Policy matched=Done,Approved=Analyst,Executed=Done|Completed', JSON.stringify(incAfter));
        await page.click('.run-row[data-record-id="EXE-002"]');
        await page.waitForTimeout(450);
        const exe2 = await runPanel();
        check(wname, 'approvals', 'EXE-002\'s panel: Block IP 203.0.113.45, approved by Analyst A, 15:46 to 15:47, "1 minute", the block lifts at 16:16, with APR-002 and TKN-002 in its approval record', exe2.id === 'EXE-002' && exe2.fields.action === 'Block IP' && exe2.fields.target === '203.0.113.45' && exe2.fields.approvedBy === 'Analyst A (SOC analyst)' && exe2.fields.startTime === '15:46' && exe2.fields.endTime === '15:47' && exe2.fields.duration === '1 minute' && exe2.fields.rollbackStatus === 'Block lifts automatically at 16:16' && exe2.approval.request === 'APR-002 · Block 203.0.113.45 for 30 min' && /^TKN-002, used at 15:46/.test(exe2.approval.token || '') && exe2.approval.window === 'Active until 16:16', JSON.stringify(exe2));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Alerts', aprPhone);
        const alertAfter = await page.evaluate(() => document.querySelector('.queue-item[data-record-id="ALT-001"] .queue-state')?.textContent.trim());
        const alt1 = await approvalView('ALT-001');
        check(wname, 'approvals', 'Alerts: ALT-001 now reads "Source blocked" and its Response tab shows the approved request, the used token and the window', alertAfter === 'Source blocked' && alt1.state === 'Source blocked' && alt1.decision === 'Approved by Analyst A (SOC analyst) at 15:46' && /^TKN-002, used at 15:46/.test(alt1.token || '') && alt1.window === 'Active until 16:16' && /Response ran under Response policy v3: block_ip: Block IP on 203\.0\.113\.45, completed\./.test(alt1.note || ''), JSON.stringify([alertAfter, alt1]));
        await goSide('Case Management', aprPhone);
        await page.click(`${CARD}[data-record-id="CASE-006"]`);
        await page.waitForTimeout(200);
        const caseAfter = await actionState();
        const caseCard = await cardProgress('CASE-006');
        check(wname, 'approvals', 'CASE-006: "Block the source IP" is done by EXE-002 and the card says 1 of 4 actions', caseAfter.boxes[0]?.checked && caseAfter.boxes[0].disabled && caseAfter.boxes[0].run === 'Done by EXE-002' && caseAfter.progress === '1 of 4 done' && caseCard === '1 of 4 actions', JSON.stringify([caseAfter.boxes[0], caseAfter.progress, caseCard]));
        await closeDrawer();
        await goSide('Dashboard', aprPhone);
        await page.click('[data-node-id="src-203.0.113.45"], [data-path-id="ALT-001"]');
        await page.waitForTimeout(200);
        const dashAfter = await dashState();
        const meterNow = await page.evaluate(() => document.querySelector('.threat-meter')?.getAttribute('aria-label'));
        check(wname, 'approvals', 'Dashboard: 2 active paths (ALT-002, ALT-003), 1 source blocked (203.0.113.45), the log lists EXE-002 first, ALT-001 reads Source blocked with the approval in its timeline; the threat level is unchanged (open alerts still count)', dashAfter.posture[0] === '2|Active attack paths|ALT-002, ALT-003' && dashAfter.posture[3] === '1|Source blocked|203.0.113.45' && dashAfter.log.join(',') === 'EXE-002:Done,EXE-001:Done' && dashAfter.panel.id === 'ALT-001' && dashAfter.panel.state === 'Source blocked' && dashAfter.panel.timeline.some(l => /Approved by Analyst A \(SOC analyst\)/.test(l)) && dashAfter.panel.timeline.some(l => /203\.0\.113\.45 blocked successfully/.test(l)) && meterNow === 'Threat level: Severe, 5 of 5', JSON.stringify({ posture: dashAfter.posture, log: dashAfter.log, panel: dashAfter.panel, meterNow }));

        // ---------- Restored propagation checks (removed in C3b with Retry isolation), now driven by Approve ----------
        const queueDetail = await page.evaluate(() => document.querySelector('[data-decision-id="ALT-001"] .decision-detail')?.textContent.replace(/\s+/g, ' ').trim());
        check(wname, 'approve propagation', 'Approve: ALT-001 stays in Needs a decision (it is still open) and the row says the source was blocked and to confirm and close', dashAfter.queue.join(',') === 'ALT-006,ALT-001,ALT-003,ALT-002' && /203\.0\.113\.45 blocked at 15:47, confirm and close/.test(queueDetail || ''), JSON.stringify([dashAfter.queue, queueDetail]));
        check(wname, 'approve propagation', 'Approve: the threat level stays Severe, 5 of 5 (open alerts still count); the response log names the approver ("Approved by Analyst A, Critical Authentication Abuse")', meterNow === 'Threat level: Severe, 5 of 5' && /^Approved by Analyst A, Response policy v3: block_ip/.test(dashAfter.logBy['EXE-002'] || ''), JSON.stringify([meterNow, dashAfter.logBy]));
        check(wname, 'approve propagation', 'Approve: the headline says 2 attack paths are still active', /^2 attack paths are still active/.test(dashAfter.subtitle || ''), dashAfter.subtitle);
        if (aprPhone) {
          check(wname, 'approve propagation', 'Approve: the list shows ALT-001 as Source blocked', /Source blocked/.test(dashAfter.list.find(i => i.id === 'ALT-001')?.text || ''), JSON.stringify(dashAfter.list.find(i => i.id === 'ALT-001')));
        } else {
          const src1 = dashAfter.nodes.find(n => n.id === 'src-203.0.113.45');
          check(wname, 'approve propagation', 'Approve: the map shows the 203.0.113.45 path as Source blocked, in words, and endpoint-01 still At risk (ALT-005 closed, the others open)', src1?.status === 'Source blocked' && /source blocked/i.test(src1.label || '') && !/awaiting approval/i.test(src1.label || ''), JSON.stringify(src1));
        }
        const alt1Search = (await searchFor('ALT-001')).find(o => o.startsWith('ALT-001')) || '';
        check(wname, 'approve propagation', 'Approve: global search shows ALT-001 as Source blocked', /· Source blocked ·/.test(alt1Search) && /Analyst A/.test(alt1Search), alt1Search);
        await page.click('[data-decision-id="ALT-001"] button:has-text("Close alert")');
        await page.waitForTimeout(150);
        const afterCloseDash = await dashState();
        const meterClosed = await page.evaluate(() => document.querySelector('.threat-meter')?.getAttribute('aria-label'));
        check(wname, 'approve propagation', 'Close alert on the blocked ALT-001: it leaves Needs a decision, the threat level drops to High (4 of 5), open alerts 3, the host stays isolated', afterCloseDash.queue.join(',') === 'ALT-006,ALT-003,ALT-002' && meterClosed === 'Threat level: High, 4 of 5' && afterCloseDash.posture[1] === '3|Open alerts|of 6 today' && afterCloseDash.posture[4] === '1|Host isolated|endpoint-12', JSON.stringify([afterCloseDash.queue, meterClosed, afterCloseDash.posture]));

        // ---------- Demo mode: time passing, timeout and expiry, the two-person isolation flow (policy phase C4b) ----------
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        const demoPanel = await page.evaluate(() => ({ badge: document.querySelector('[data-demo-panel] .demo-badge')?.textContent.trim(), buttons: [...document.querySelectorAll('[data-demo-panel] button')].map(b => b.textContent.trim()).join(' | '), now: document.querySelector('[data-field="demoNow"]')?.textContent.trim(), arm: document.querySelector('[data-field="armState"]')?.textContent.trim(), text: document.querySelector('[data-demo-panel] .demo-head span')?.textContent.replace(/\s+/g, ' ').trim() }));
        check(wname, 'demo mode', 'the Demo mode panel is labelled, says each use is a Demo audit event and none reads the real clock, shows demo time 15:46:00 and offers only Advance 5 min, Advance 15 min, Advance 1 h, Make the next execution fail and Reset demo', demoPanel.badge === 'Demo mode' && /Demo event/.test(demoPanel.text) && /real clock/.test(demoPanel.text) && demoPanel.now === '15:46:00' && demoPanel.buttons === 'Advance 5 min | Advance 15 min | Advance 1 h | Make the next execution fail | Reset demo' && demoPanel.arm === 'The next approved action will succeed.', JSON.stringify(demoPanel));
        await demoAdvance(5);
        ap = await aprState();
        check(wname, 'demo mode', 'Advance 5 min: demo time 15:51:00, APR-002 now has 8 min left (measured from the demo clock)', await demoNow() === '15:51:00' && ap.rows[0]?.outcome === 'Risk 77, confidence 0.88 · 8 min left' && ap.rows[0].state === 'Waiting', JSON.stringify([await demoNow(), ap.rows[0]]));
        await demoAdvance(15);
        ap = await aprState();
        const timedOut = ap.seg;
        check(wname, 'demo mode', 'Advance 15 min (16:06:00): APR-002 passes its deadline and times out: nothing waits, the badge goes, and the summary says no request is waiting', await demoNow() === '16:06:00' && timedOut === 'Waiting 0:true | Decided 2' + ':false' && ap.sub.startsWith('No request is waiting for a decision.') && await sideBadgeApr() === null, JSON.stringify([await demoNow(), timedOut, ap.sub]));
        await page.click('.page.active .headline .segmented-option:has-text("Decided")');
        await page.waitForTimeout(150);
        ap = await aprState();
        check(wname, 'demo mode', 'Decided view: APR-002 is Timed out (first, newest), APR-001 still Done', ap.rows.map(r => `${r.id}:${r.state}`).join(',') === 'APR-002:Timed out,APR-001:Done', JSON.stringify(ap.rows.map(r => `${r.id}:${r.state}`)));
        await page.click('.queue-item[data-record-id="APR-002"]');
        await page.waitForTimeout(250);
        ap = await aprState();
        check(wname, 'demo mode', 'a timed-out request reads "Timed out: nobody decided by 15:59, so nothing ran", has no token, no form and no steps', ap.panel?.fields.decision === 'Timed out: nobody decided by 15:59, so nothing ran' && ap.panel.fields.token === null && !ap.panel.form && ap.panel.stage === null, JSON.stringify(ap.panel?.fields));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('.icon-btn');
        const bellItems = await page.evaluate(() => [...document.querySelectorAll('.top-actions .dropdown .drop-item')].map(i => `${i.querySelector('strong')?.textContent.trim()}|${i.querySelector('p')?.textContent.trim()}`));
        await page.click('.icon-btn');
        check(wname, 'demo mode', 'the bell now says "3 unread" with an "Approval timed out" notice that says it is escalated to the Administrator (and no "Approval needed")', (await bellLabel()) === 'Notifications, 3 unread' && bellItems[0] === 'Approval timed out|Block 203.0.113.45 (ALT-001) was not decided in time and nothing ran. It is escalated to the Administrator.' && !bellItems.some(i => /^Approval needed/.test(i)), JSON.stringify(bellItems));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Alerts', aprPhone);
        const timedOutAlert = await page.evaluate(() => document.querySelector('.queue-item[data-record-id="ALT-001"] .queue-state')?.textContent.trim());
        check(wname, 'demo mode', 'after the timeout ALT-001 is just Open (nothing ran, nothing blocked) and still needs a decision', timedOutAlert === 'Open', timedOutAlert);

        // Expiry: two 1-hour steps reach 17:46:00, past the isolation's 17:44:00 end
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        for (let i = 0; i < 2; i++) await demoAdvance(60);
        ap = await aprState();
        check(wname, 'demo mode', 'two Advance 1 h steps reach 17:46:00; APR-001\'s isolation lapsed and reads Reversed, APR-002 Timed out', await demoNow() === '17:46:00' && (await page.evaluate(() => [...document.querySelectorAll('.page.active .headline .segmented-option')].map(b => b.textContent.replace(/\s+/g, ' ').trim()).join(' | '))) === 'Waiting 0 | Decided 2', await demoNow());
        await page.click('.page.active .headline .segmented-option:has-text("Decided")');
        await page.click('.queue-item[data-record-id="APR-001"]');
        await page.waitForTimeout(250);
        ap = await aprState();
        check(wname, 'demo mode', 'APR-001 reads Reversed, its window "Reversed at 17:44", steps all done', ap.rows.map(r => `${r.id}:${r.state}`).join(',') === 'APR-002:Timed out,APR-001:Reversed' && ap.panel?.fields.window === 'Reversed at 17:44' && ap.panel.steps === 'Approved=done,Executing=done,Done=done', JSON.stringify([ap.rows.map(r => r.state), ap.panel?.fields.window, ap.panel?.steps]));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Incident Response', aprPhone);
        await page.click('.run-row[data-record-id="EXE-001"]');
        await page.waitForTimeout(450);
        const lapsed = await runPanel();
        const lapsedRow = await page.evaluate(() => document.querySelector('.run-row[data-record-id="EXE-001"] [data-stage="Executed"] .stage-label')?.textContent.trim());
        check(wname, 'demo mode', 'Incident Response: EXE-001\'s Executed stage reads Reversed, its rollback status "Reconnected at 17:44", and its timeline ends with "endpoint-12 reconnected automatically"', lapsedRow === 'Reversed' && lapsed.fields.rollbackStatus === 'Reconnected at 17:44' && lapsed.timeline[lapsed.timeline.length - 1] === 'done:endpoint-12 reconnected automatically' && lapsed.approval.window === 'Reversed at 17:44', JSON.stringify([lapsedRow, lapsed.fields.rollbackStatus, lapsed.timeline, lapsed.approval.window]));
        // Ask again for the isolation: the analyst asks, cannot decide it, and the Administrator does
        const againBefore = await page.evaluate(() => ({ present: !!document.querySelector('[data-field="requestAgain"] button'), disabled: document.querySelector('[data-field="requestAgain"] button')?.disabled }));
        await page.click('[data-field="requestAgain"] button');
        await page.waitForTimeout(250);
        const againAfter = await page.evaluate(() => ({ message: document.querySelector('[data-field="requestAgainMessage"]')?.textContent.trim(), reason: document.querySelector('[data-field="requestAgainReason"]')?.textContent.trim(), disabled: document.querySelector('[data-field="requestAgain"] button')?.disabled }));
        check(wname, 'demo mode', 'Request again on the lapsed isolation: the button is there and enabled, asking creates the request and the button then refuses a second one ("already waiting")', againBefore.present && againBefore.disabled === false && /^Asked again\./.test(againAfter.message || '') && againAfter.disabled === true && /already waiting/.test(againAfter.reason || ''), JSON.stringify({ againBefore, againAfter }));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Approvals', aprPhone);
        ap = await aprState();
        const row3 = ap.rows[0] ?? {};
        check(wname, 'demo mode', 'the new request APR-003 (new id) is Waiting: Isolate endpoint-12 for 120 min, ALT-006, response policy version 3, needs a SOC lead, 15 min left; the analyst has 0 waiting for them and 1 for someone else, and no badge', ap.rows.length === 1 && row3.id === 'APR-003' && row3.name === 'Isolate endpoint-12 for 120 min' && row3.route === 'ALT-006 · Malware - C2 Beaconing' && row3.meta === 'Response policy version 3 · needs a SOC lead' && row3.outcome === 'Risk 90, confidence 0.92 · 15 min left' && ap.sub === '0 requests are waiting for you, 1 for someone else. Nothing runs until a person approves it.' && await sideBadgeApr() === null, JSON.stringify([row3, ap.sub]));
        await page.click('.queue-item[data-record-id="APR-003"]');
        await page.waitForTimeout(250);
        ap = await aprState();
        const askedBy = ap.panel?.fields.requestedBy;
        const formState = await page.evaluate(() => ({ disabled: document.querySelector('[data-field="decisionForm"] fieldset')?.disabled, refusal: document.querySelector('[data-field="refusal"]')?.textContent.trim() }));
        check(wname, 'demo mode', 'the requester cannot decide: asked by Analyst A at 17:46, the form is disabled and says "You requested this action, so you cannot decide on it."', askedBy === 'Analyst A at 17:46' && formState.disabled === true && formState.refusal === 'You requested this action, so you cannot decide on it.', JSON.stringify([askedBy, formState]));
        const direct = await page.evaluate(async () => { const form = document.querySelector('[data-field="decisionForm"]'); const key = Object.keys(form).find(k => k.startsWith('__reactProps$')); form[key].onSubmit({ preventDefault() {} }); return new Promise(resolve => setTimeout(() => resolve(document.querySelector('[data-field="decisionMessage"]')?.textContent.trim()), 250)); });
        ap = await aprState();
        check(wname, 'demo mode', 'calling the disabled form\'s handler anyway is refused with the same words, and APR-003 is still Waiting with no token and no steps', direct === 'You requested this action, so you cannot decide on it.' && ap.rows[0].state === 'Waiting' && ap.panel?.fields.token === null && ap.panel.stage === null, JSON.stringify([direct, ap.rows[0]?.state, ap.panel?.fields.token]));
        const whyAnalyst = await page.evaluate(() => { const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel'); const box = scope.querySelector('[data-assessment-for="ALT-006"]'); return { evidence: [...scope.querySelectorAll('[data-field="keyEvidence"] li')].map(li => li.textContent.replace(/\s+/g, ' ').trim()), rows: [...(box?.querySelectorAll('tbody tr') ?? [])].map(tr => `${tr.dataset.input}:${parseFloat(tr.lastElementChild.textContent)}`).join(','), total: box?.querySelector('[data-field="riskTotal"]')?.textContent.replace(/\s+/g, ' ').trim(), sum: box?.querySelector('[data-field="riskSum"]')?.textContent.trim(), outcome: box?.querySelector('[data-field="outcome"]')?.textContent.trim(), alternatives: box?.querySelectorAll('[data-field="alternatives"] li').length }; });
        check(wname, 'demo mode', 'the request shows the alert\'s risk breakdown inline (ALT-006: S 32.67, E 25, R 23.75, A 9 add up to 90.42, shown as 90 / 100, Recommend host isolation, 4 other outcomes) and its 6 key evidence lines (source tag then text)', whyAnalyst.rows === 'S:32.67,E:25,R:23.75,A:9' && whyAnalyst.sum === '90.42' && whyAnalyst.total === '90 / 100' && whyAnalyst.outcome === 'Recommend host isolation' && whyAnalyst.alternatives === 4 && whyAnalyst.evidence.length === 6 && /^EndpointEDR flagged the web service/.test(whyAnalyst.evidence[0]) && /^Responseendpoint-12 isolated at 15:44/.test(whyAnalyst.evidence[5]), JSON.stringify(whyAnalyst));
        // Sign out, sign in as the Administrator without a reload: the request is still there
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await signOutInApp();
        await signInInApp(roles.admin);
        await goSide('Approvals', aprPhone);
        ap = await aprState();
        const adminBadge3 = await sideBadgeApr();
        check(wname, 'demo mode', 'signed in as the Administrator (in the same browser, no reload): APR-003 is waiting for them, the badge says 1, and the demo time is still 17:46:00', ap.sub === '1 request is waiting for you. Nothing runs until a person approves it.' && ap.rows[0]?.id === 'APR-003' && adminBadge3 === '1' && await demoNow() === '17:46:00', JSON.stringify([ap.sub, ap.rows[0]?.id, adminBadge3, await demoNow()]));
        await page.click('.queue-item[data-record-id="APR-003"]');
        await page.waitForTimeout(250);
        ap = await aprState();
        const adminForm = await page.evaluate(() => ({ disabled: document.querySelector('[data-field="decisionForm"] fieldset')?.disabled, refusal: document.querySelector('[data-field="refusal"]')?.textContent.trim() ?? null }));
        const whyAdmin = await page.evaluate(() => { const scope = document.querySelector('[role="dialog"]') ?? document.querySelector('.card.detail-panel'); const box = scope.querySelector('[data-assessment-for="ALT-006"]'); return { rows: [...(box?.querySelectorAll('tbody tr') ?? [])].map(tr => `${tr.dataset.input}:${parseFloat(tr.lastElementChild.textContent)}`).join(','), total: box?.querySelector('[data-field="riskTotal"]')?.textContent.replace(/\s+/g, ' ').trim(), sum: box?.querySelector('[data-field="riskSum"]')?.textContent.trim(), evidence: scope.querySelectorAll('[data-field="keyEvidence"] li').length, alertLinks: [...scope.querySelectorAll('a[href="/app/alerts"]')].length }; });
        check(wname, 'demo mode', 'the Administrator can decide it (form enabled, no refusal) and sees the same risk breakdown and evidence inline without any link to Alerts', adminForm.disabled === false && adminForm.refusal === null && whyAdmin.rows === 'S:32.67,E:25,R:23.75,A:9' && whyAdmin.sum === '90.42' && whyAdmin.total === '90 / 100' && whyAdmin.evidence === 6 && whyAdmin.alertLinks === 0, JSON.stringify({ adminForm, whyAdmin }));
        await page.fill('#reason-APR-003', 'Beaconing resumed; isolate again for two hours.');
        await page.click(`${APR_SCOPE} button:has-text("Approve request")`);
        if (!aprPhone) {
          // Desktop and laptop only (no drawer, reliable timing): wait for "Executing", then sign out in the middle of the run
          await page.waitForFunction(() => document.querySelector('.approval-steps')?.dataset.stage === 'Executing', null, { timeout: 5000 });
          const atSignOut = await signOutInApp();
          await signInInApp(roles.admin);
          await goSide('Approvals', aprPhone);
          await page.click('.page.active .headline .segmented-option:has-text("Decided")');
          await page.click('.queue-item[data-record-id="APR-003"]');
          await page.waitForFunction(() => document.querySelector('.approval-steps')?.dataset.stage === 'Done', null, { timeout: 8000 });
          const executorAfter = await page.evaluate(() => document.querySelector('[data-page="approvals"]')?.dataset.executor ?? null);
          ap = await aprState();
          check(wname, 'demo mode', 'signing out in the middle of a run does not strand it: at the sign-out confirm the executor was busy and not Done, and after the next sign-in it completes (executor idle, steps all done)', atSignOut.executor === 'busy' && atSignOut.stage !== 'Done' && executorAfter === 'idle' && ap.panel?.stage === 'Done' && ap.panel.steps === 'Approved=done,Executing=done,Done=done', JSON.stringify([atSignOut, executorAfter, ap.panel?.stage]));
        } else {
          // Phones: the rest of the flow without the mid-run sign-out (a drawer and timing make that unreliable); the run completes
          await page.waitForFunction(() => document.querySelector('.approval-steps')?.dataset.stage === 'Done', null, { timeout: 8000 });
          await page.keyboard.press('Escape');
          await page.waitForTimeout(150);
          await page.click('.page.active .headline .segmented-option:has-text("Decided")');
          await page.click('.queue-item[data-record-id="APR-003"]');
          await page.waitForTimeout(250);
          ap = await aprState();
          const executorPhone = await page.evaluate(() => document.querySelector('[data-page="approvals"]')?.dataset.executor ?? null);
          check(wname, 'demo mode', 'phones: the Administrator\'s approval runs to completion (executor idle, steps all done); the mid-run sign-out is checked at desktop and laptop widths only', executorPhone === 'idle' && ap.panel?.stage === 'Done' && ap.panel.steps === 'Approved=done,Executing=done,Done=done', JSON.stringify([executorPhone, ap.panel?.stage]));
        }
        check(wname, 'demo mode', 'the isolation ran once under TKN-002 (a new token, not a reused one), approved by the System Administrator at 17:46, active until 19:46', ap.panel?.fields.decision === 'Approved by System Administrator (SOC lead) at 17:46' && /^TKN-002, used at 17:46/.test(ap.panel.fields.token || '') && ap.panel.fields.window === 'Active until 19:46' && ap.rows.find(r => r.id === 'APR-003')?.state === 'Done', JSON.stringify(ap.panel?.fields));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Audit Logs', aprPhone);
        const trail = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => ({ id: Number(b.dataset.recordId.replace('AUD-', '')), action: b.querySelector('.audit-action')?.textContent.replace(/\s+/g, ' ').trim(), demo: !!b.querySelector('.audit-demo-tag'), who: b.querySelector('.audit-meta')?.textContent.replace(/\s+/g, ' ').trim() })).filter(r => r.id > 206));
        const count = text => trail.filter(r => r.action.includes(text)).length;
        check(wname, 'demo mode', 'the Administrator\'s audit log holds the whole story across both people: 2 Demo "Advanced demo time" events (each with the Demo label), one Requested approval by Analyst A, one Approved action, exactly one Used approval token, one Action expired, one Approval timed out, one Executed host isolation (new events only)', count('Advanced demo time') === 2 && count('Requested approval') === 1 && count('Approved action') === 1 && count('Used approval token') === 1 && count('Action expired') === 1 && count('Approval timed out') === 1 && count('Executed host isolation') === 1 && trail.filter(r => r.demo).length === 2 && trail.find(r => r.action.includes('Requested approval'))?.who.startsWith('Analyst A'), JSON.stringify(trail.map(r => `${r.id}:${r.action}`)));

        // ---------- A failed run: highlight and pulse, the failed alert, ask again, the old token never reused, reset ----------
        // (Back to the analyst, in the app; the page load below then starts the seed again.)
        await signOutInApp();
        await signInInApp(roles.analyst);
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(500);
        await page.click('[data-demo-panel] button:has-text("Make the next execution fail")');
        await page.waitForTimeout(150);
        const armed = await page.evaluate(() => ({ button: [...document.querySelectorAll('[data-demo-panel] button')].find(b => b.textContent.includes('armed'))?.disabled, text: document.querySelector('[data-field="armState"]')?.textContent.trim() }));
        check(wname, 'demo mode', 'arming a failure: the button reads "Failure armed" and is disabled, and says the next approved action will fail after using up its token', armed.button === true && armed.text === 'The next approved action will fail after using up its token.', JSON.stringify(armed));
        await page.click('.queue-item[data-record-id="APR-002"]');
        await page.waitForTimeout(250);
        await page.fill('#reason-APR-002', 'Confirmed brute force from a known scanner.');
        await page.emulateMedia({ reducedMotion: 'no-preference' });
        await page.click(`${APR_SCOPE} button:has-text("Approve request")`);
        const run3 = await sampleStages('Failed');
        const failedPulse = await page.evaluate(() => { const dot = document.querySelector('.approval-step.failed .approval-dot'); return dot ? getComputedStyle(dot).animationName : null; });
        await page.emulateMedia({ reducedMotion: 'reduce' });
        const failedStill = await page.evaluate(() => { const dot = document.querySelector('.approval-step.failed .approval-dot'); return dot ? getComputedStyle(dot).animationName : null; });
        ap = await aprState();
        check(wname, 'demo mode', 'the armed failure shows Approved, Executing, then Failed (the last step names the failure); its token is still used (TKN-002 used at 15:46), the window is "None: the execution failed", and the row reads Failed', run3.seen.join(',') === 'Approved,Executing,Failed' && ap.panel?.steps === 'Approved=done,Executing=done,Done=failed' && /^TKN-002, used at 15:46/.test(ap.panel.fields.token || '') && ap.panel.fields.window === 'None: the execution failed' && ap.rows.find(r => r.id === 'APR-002')?.state === 'Failed', JSON.stringify([run3.seen, ap.panel?.steps, ap.panel?.fields.window]));
        check(wname, 'motion', 'approvals: the Failed step pulses by default and stops with prefers-reduced-motion', failedPulse === 'stagePulse' && failedStill === 'none', `${failedPulse} / ${failedStill}`);
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Incident Response', aprPhone);
        const failFigs = await page.evaluate(() => ({
          rows: [...document.querySelectorAll('.run-row')].map(r => r.dataset.recordId).join(','),
          failedRows: [...document.querySelectorAll('.run-row.failed')].map(r => r.dataset.recordId).join(','),
          pressed: [...document.querySelectorAll('.run-row[aria-pressed="true"]')].map(r => r.dataset.recordId).join(','),
          figs: Object.fromEntries([...document.querySelectorAll('.response-summary [data-figure]')].map(d => [d.dataset.figure, [...d.children].map(c => c.textContent.replace(/\s+/g, ' ').trim()).join(' ')])),
          flagged: !!document.querySelector('.response-summary [data-figure="failed"].attention'),
          stages: (() => { const r = document.querySelector('.run-row[data-record-id="EXE-002"]'); return [...r.querySelectorAll('.run-stage')].map(s => `${s.dataset.stage}=${s.querySelector('.stage-label')?.textContent.trim()}`).join(',') + '|' + r.querySelector('.run-result')?.textContent.replace('Result:', '').trim(); })(),
        }));
        check(wname, 'incident', 'a failed run (restored): only EXE-002 is highlighted and it is the row selected by default; the summary says 1 of 2 succeeded and "1 failed and needs a person" (flagged); its stages end Executed = Failed', failFigs.rows === 'EXE-001,EXE-002' && failFigs.failedRows === 'EXE-002' && failFigs.pressed === 'EXE-002' && failFigs.figs.succeeded === '1 of 2 responses succeeded' && failFigs.figs.failed === '1 failed and needs a person' && failFigs.flagged && failFigs.stages === 'Detected=Done,Scored=Done,Policy matched=Done,Approved=Analyst,Executed=Failed|Failed', JSON.stringify(failFigs));
        const pulseF = () => page.evaluate(() => getComputedStyle(document.querySelector('.run-row[data-record-id="EXE-002"] .stage-dot.failed')).animationName);
        await page.emulateMedia({ reducedMotion: 'no-preference' });
        const pulsingF = await pulseF();
        await page.emulateMedia({ reducedMotion: 'reduce' });
        const stillF = await pulseF();
        check(wname, 'motion', 'incident: the failed stage pulses by default and stops with prefers-reduced-motion (restored)', pulsingF === 'stagePulse' && stillF === 'none', `${pulsingF} / ${stillF}`);
        await page.click('.run-row[data-record-id="EXE-002"]');
        await page.waitForTimeout(450);
        const failedRun = await runPanel();
        check(wname, 'incident', 'the failed run\'s panel: Failed, no rollback ("Not applicable"), the reason ("The firewall did not acknowledge the block before the execution timeout."), and the timeline marks "Block command timed out" as failed', failedRun.fields.result === 'Failed' && failedRun.fields.rollbackStatus === 'Not applicable' && failedRun.fields.failureReason === 'The firewall did not acknowledge the block before the execution timeout.' && failedRun.timeline[failedRun.timeline.length - 1] === 'fail:Failed: Block command timed out', JSON.stringify([failedRun.fields, failedRun.timeline]));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Alerts', aprPhone);
        const failedAlert = await page.evaluate(() => document.querySelector('.queue-item[data-record-id="ALT-001"] .queue-state')?.textContent.trim());
        check(wname, 'incident', 'the failed alert (restored): ALT-001 reads Containment failed on Alerts', failedAlert === 'Containment failed', failedAlert);
        await goSide('Incident Response', aprPhone);
        await page.click('.run-row[data-record-id="EXE-002"]');
        await page.waitForTimeout(450);
        await page.click(`${APR_SCOPE} [data-field="requestAgain"] button`);
        await page.waitForTimeout(250);
        const askedAgain = await page.evaluate(() => document.querySelector('[data-field="requestAgainMessage"]')?.textContent.trim());
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Approvals', aprPhone);
        ap = await aprState();
        const newOne = ap.rows.find(r => r.id === 'APR-003');
        await page.click('.queue-item[data-record-id="APR-003"]');
        await page.waitForTimeout(250);
        ap = await aprState();
        const oldView = await (async () => { if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); } await page.click('.page.active .headline .segmented-option:has-text("Decided")'); await page.waitForTimeout(150); await page.click('.queue-item[data-record-id="APR-002"]'); await page.waitForTimeout(250); return aprState(); })();
        check(wname, 'demo mode', 'Request again after the failure: a new request APR-003 (new id) is Waiting, asked by Analyst A and needing a SOC analyst, with no token; the old APR-002 still shows TKN-002 used and is never offered a second run', /^Asked again\./.test(askedAgain || '') && newOne?.state === 'Waiting' && newOne.name === 'Block 203.0.113.45 for 30 min' && ap.panel?.fields.requestedBy === 'Analyst A at 15:47' && ap.panel.fields.token === null && /^TKN-002, used at 15:46/.test(oldView.panel?.fields.token || '') && oldView.panel.stage === 'Failed', JSON.stringify([askedAgain, newOne, ap.panel?.fields, oldView.panel?.fields.token]));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('.page.active .headline .segmented-option:has-text("Waiting")');
        await page.click('.queue-item[data-record-id="APR-003"]');
        await page.waitForTimeout(250);
        const self3 = await page.evaluate(async () => { const form = document.querySelector('[data-field="decisionForm"]'); const key = Object.keys(form).find(k => k.startsWith('__reactProps$')); form[key].onSubmit({ preventDefault() {} }); return new Promise(resolve => setTimeout(() => resolve({ message: document.querySelector('[data-field="decisionMessage"]')?.textContent.trim(), disabled: document.querySelector('[data-field="decisionForm"] fieldset')?.disabled }), 250)); });
        check(wname, 'demo mode', 'the analyst cannot approve their own second request, even by calling the handler: refused ("You requested this action, so you cannot decide on it.")', self3.disabled === true && self3.message === 'You requested this action, so you cannot decide on it.', JSON.stringify(self3));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await goSide('Dashboard', aprPhone);
        // Wait for the dashboard to show ALT-001 with its new state, not a fixed time
        await page.waitForFunction(() => document.querySelector('[data-selected-path]')?.dataset.selectedPath === 'ALT-001' && /Awaiting approval/.test(document.querySelector('.dash-path-meta .path-status')?.textContent ?? '') && document.querySelectorAll('[data-log-id]').length > 0, null, { timeout: 5000 }).catch(() => {});
        const ds2 = await dashState();
        check(wname, 'demo mode', 'the dashboard follows: ALT-001 reads Awaiting approval again (the new request outranks the failure) and is the path shown, the response log keeps the failed EXE-002', ds2.panel.id === 'ALT-001' && ds2.panel.state === 'Awaiting approval' && ds2.log.join(',') === 'EXE-002:Failed,EXE-001:Done', JSON.stringify([ds2.panel.state, ds2.log]));
        // Reset: confirm dialog, then everything back to the seed
        await goSide('Approvals', aprPhone);
        await dialogKeyboard(wname, 'Reset demo confirm', () => page.click('[data-demo-panel] button:has-text("Reset demo")'));
        await page.click('[data-demo-panel] button:has-text("Reset demo")');
        await page.waitForSelector('[role="dialog"]');
        const confirmText = await page.evaluate(() => document.querySelector('[role="dialog"]')?.textContent.replace(/\s+/g, ' ').trim());
        await page.click('[role="dialog"] button:has-text("Reset demo")');
        await page.waitForSelector('#approvalsSummary');
        await page.waitForTimeout(900);
        ap = await aprState();
        const afterReset = { now: await demoNow(), seg: ap.seg, rows: ap.rows.map(r => `${r.id}:${r.state}`).join(','), badge: await sideBadgeApr(), arm: await page.evaluate(() => document.querySelector('[data-field="armState"]')?.textContent.trim()) };
        check(wname, 'demo mode', 'Reset demo asks first ("Reset the demo?", everything back to the starting data) and then returns to the seed: demo time 15:46:00, APR-002 waiting again, no failure armed, badge 1', /Reset the demo\?/.test(confirmText) && /starting data/.test(confirmText) && afterReset.now === '15:46:00' && afterReset.seg === 'Waiting 1:true | Decided 1:false' && afterReset.rows === 'APR-002:Waiting' && afterReset.badge === '1' && afterReset.arm === 'The next approved action will succeed.', JSON.stringify([confirmText, afterReset]));

        // ---------- Policy phase C5b: tier rules, the action catalogue, the threshold floor, "Simulate an attempt" (Administrator, seed state) ----------
        await signOutInApp();
        await signInInApp(roles.admin);
        await goSide('Approvals', aprPhone);
        const aprBefore = await aprState();
        const stateBefore = { rows: aprBefore.rows.map(r => `${r.id}:${r.state}`).join(','), now: await demoNow(), badge: await sideBadgeApr() };
        await goSide('Response Policies', aprPhone);
        await page.waitForTimeout(250);

        // Tabs
        const polTabs = () => page.evaluate(() => ({
          list: document.querySelectorAll('[role="tablist"][aria-label="Response policy views"]').length,
          tabs: [...document.querySelectorAll('[role="tablist"] [role="tab"]')].map(t => `${t.textContent.trim()}:${t.getAttribute('aria-selected')}`).join(' | '),
          panelLabelled: document.querySelector('[role="tabpanel"]')?.getAttribute('aria-labelledby') === document.querySelector('[role="tab"][aria-selected="true"]')?.id,
          permissions: !!document.querySelector('[data-view="permissions"]'),
          catalogue: !!document.querySelector('[data-catalogue]'),
          focusOnSelected: document.activeElement === document.querySelector('[role="tab"][aria-selected="true"]'),
          search: location.search,
          history: history.length,
        }));
        const tabsStart = await polTabs();
        await page.focus('[role="tab"][aria-selected="true"]');
        await page.keyboard.press('ArrowRight');
        await page.waitForTimeout(200);
        const tabsCat = await polTabs();
        await page.keyboard.press('Home');
        await page.waitForTimeout(200);
        const tabsBack = await polTabs();
        check(wname, 'C5 tabs', 'Response Policies has a real tablist "Response policy views": Permissions (selected) and Action catalogue, the panel labelled by the selected tab; the whitelist, blacklist and protected targets sit on the Permissions tab', tabsStart.list === 1 && tabsStart.tabs === 'Permissions:true | Action catalogue:false' && tabsStart.panelLabelled && tabsStart.permissions && !tabsStart.catalogue && tabsStart.search === '', JSON.stringify(tabsStart));
        check(wname, 'C5 tabs', 'ArrowRight opens Action catalogue (focus moves with it, ?view=catalogue, the Permissions view is gone); Home returns to Permissions; the history does not grow (replace, not push)', tabsCat.tabs === 'Permissions:false | Action catalogue:true' && tabsCat.focusOnSelected && tabsCat.search === '?view=catalogue' && tabsCat.catalogue && !tabsCat.permissions && tabsBack.tabs === 'Permissions:true | Action catalogue:false' && tabsBack.search === '' && tabsBack.permissions && tabsBack.history === tabsStart.history && tabsCat.history === tabsStart.history, JSON.stringify([tabsCat, tabsBack]));

        // (The tier rules on the policy cards, the View dialog and the threshold-floor form went with the If / Then policies.
        // The caps they enforced are checked on the Permissions tab above (each refused beside its field with the PDF's number)
        // and the catalogue now shows where each action stands in the policy, below.)

        // The action catalogue tab: 18 rows, every value from the PDF
        await page.click('[role="tab"]:has-text("Action catalogue")');
        await page.waitForTimeout(250);
        const catRows = await page.evaluate(() => [...document.querySelectorAll('[data-catalogue-row]')].map(tr => {
          const t = f => tr.querySelector(`[data-field="${f}"]`)?.textContent.replace(/\s+/g, ' ').trim();
          return { key: tr.dataset.catalogueRow, action: t('action'), tier: t('tier'), when: t('when'), def: t('default'), max: t('maximum'), approver: t('approver'), reversible: t('reversible'), source: t('source'), assumed: [...tr.querySelectorAll('[data-assumption]')].map(a => a.dataset.assumption).join(',') };
        }));
        const NA = '— Not applicable';
        const T1 = (key, action, rev, max = NA) => [key, action, 'Tier 1 Runs automatically', NA, max, NA, rev, 'PDF p.3', ''];
        const wantCat = [
          T1('get_logs', 'get_logs(source, time_range)', 'Nothing to reverse'),
          T1('analyse_alert', 'analyse_alert(alert_id)', 'Nothing to reverse'),
          T1('check_ip_reputation', 'check_ip_reputation(ip)', 'Nothing to reverse'),
          T1('get_asset_context', 'get_asset_context(host)', 'Nothing to reverse'),
          T1('monitor', 'monitor(entity, duration)', 'Expires after at most 24 h', '24 h'),
          T1('create_alert', 'create_alert(alert)', 'No change to systems'),
          T1('create_ticket', 'create_ticket(case)', 'No change to systems'),
          T1('recommend_response', 'recommend_response(rec)', 'Nothing to reverse'),
          T1('notify_analyst', 'notify_analyst(channel, message)', 'Nothing to reverse'),
          ['block_ip', 'block_ip(ip, duration)', 'Tier 2 Needs a SOC analyst’s approval', '30 min', '24 h', 'SOC analyst 15 min window', 'Yes: auto-unblock on expiry', 'PDF p.4', 'does'],
          ['isolate_host', 'isolate_host(host, path)', 'Tier 2 Needs a SOC lead’s approval', '2 h', '4 h', 'SOC lead 15 min window', 'Yes: reconnects at expiry', 'PDF p.4', 'does,reversible'],
          ['suspend_user_session', 'suspend_user_session(user, duration)', 'Tier 2 Needs a SOC analyst’s approval', '30 min', '60 min', 'SOC analyst 15 min window', 'Yes: expires automatically', 'PDF p.4', 'does'],
          ['kill_process', 'kill_process(host, process)', 'Tier 2 Needs a SOC lead’s approval', NA, NA, 'SOC lead 15 min window', 'No: a person restarts the process', 'PDF p.4', 'does,reversible'],
          ['quarantine_file', 'quarantine_file(host, path)', 'Tier 2 Needs a SOC lead’s approval', NA, NA, 'SOC lead 15 min window', 'No: a person restores the file', 'PDF p.4', 'does,reversible'],
          ['reset_password', 'reset_password(user)', 'Tier 2 Needs a SOC lead’s approval', NA, NA, 'SOC lead 15 min window', 'No: a person decides what happens next', 'PDF p.4', 'does,reversible'],
          ...[
            ['block_ip_permanent', 'Permanent blocking, or any block longer than 24 h', 'Irreversible lockouts of legitimate users and partners'],
            ['delete_logs', 'Deleting or modifying logs, alerts, cases or evidence', 'Destroys the audit trail and forensic value'],
            ['disable_security_control', 'Disabling or reconfiguring security controls (Wazuh agents, rules, firewall, EDR)', 'Blinds the SOC; a common attacker goal'],
            ['modify_privileged_account', 'Creating, changing or disabling privileged accounts, credentials or group memberships', 'Highest-impact change; must stay with identity administrators'],
            ['isolate_critical_host', 'Isolating a Critical system without authorised approval', 'Can take the business offline; a person decides and acts'],
            ['change_policy', 'Changing its own policies, thresholds or allow-list', 'The agent cannot widen its own permissions'],
          ].map(([key, action, why]) => [key, action, 'Tier 3 Never allowed', NA, NA, NA, 'Not applicable: never runs', 'PDF p.5', '', why]),
        ];
        const catMisses = [];
        if (catRows.length !== 21) catMisses.push(`${catRows.length} rows`);
        wantCat.forEach(([key, action, tier, def, max, approver, reversible, source, assumed, why], i) => {
          const got = catRows[i];
          if (!got || got.key !== key) { catMisses.push(`row ${i}: ${got?.key} (want ${key})`); return; }
          if (!got.action.startsWith(action)) catMisses.push(`${key}.action: "${got.action}"`);
          if (got.tier !== tier) catMisses.push(`${key}.tier: "${got.tier}"`);
          if (got.def !== def) catMisses.push(`${key}.default: "${got.def}"`);
          if (got.max !== max) catMisses.push(`${key}.maximum: "${got.max}"`);
          if (got.approver !== approver) catMisses.push(`${key}.approver: "${got.approver}"`);
          if (!got.reversible.startsWith(reversible)) catMisses.push(`${key}.reversible: "${got.reversible}"`);
          if (got.source !== source) catMisses.push(`${key}.source: "${got.source}"`);
          if (got.assumed !== assumed) catMisses.push(`${key}.assumed: "${got.assumed}"`);
          if (why && !(got.when.includes('Never, under any input') && got.when.includes(`Why: ${why}`))) catMisses.push(`${key}.when: "${got.when}"`);
        });
        check(wname, 'C5 catalogue', 'the Action catalogue tab lists the 21 actions in order (9 Tier 1, 6 Tier 2, 6 Tier 3), each with its tier in words, default, maximum, approver and window, reversible, source page and (Tier 3) why: the PDF\'s values, and for the three added Tier 2 rows a SOC lead, 15 min, no default or maximum', catMisses.length === 0, catMisses.join(' ; '));
        check(wname, 'C5 catalogue', 'assumptions are tagged and explained in the table: exactly 10 (the three PDF Tier 2 descriptions and isolation\'s reversal, and what and whether it reverses for the three added rows), each with its note visible; nothing from the PDF is tagged', catRows.flatMap(r => r.assumed.split(',').filter(Boolean).map(f => `${r.key}:${f}`)).join(',') === 'block_ip:does,isolate_host:does,isolate_host:reversible,suspend_user_session:does,kill_process:does,kill_process:reversible,quarantine_file:does,quarantine_file:reversible,reset_password:does,reset_password:reversible' && await page.evaluate(() => [...document.querySelectorAll('[data-assumption]')].every(a => a.querySelector('.assumption-tag')?.textContent === 'Assumption' && a.textContent.replace('Assumption', '').trim().length > 40)), catRows.map(r => r.assumed).filter(Boolean).join(','));
        check(wname, 'C5 catalogue', 'Tier 2 rows show their floor (risk and confidence): block 70 / 0.80, isolation 85 / 0.85, session 75 / 0.80, and 75 / 0.80 for each added row', await page.evaluate(() => [...document.querySelectorAll('[data-catalogue-row] [data-field="floor"]')].map(f => f.textContent.trim()).join(' | ')) === 'Floor: risk 70 and confidence 0.80 | Floor: risk 85 and confidence 0.85 | Floor: risk 75 and confidence 0.80 | Floor: risk 75 and confidence 0.80 | Floor: risk 75 and confidence 0.80 | Floor: risk 75 and confidence 0.80', '');
        const catPolicy = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('[data-catalogue-row]')].map(tr => [tr.dataset.catalogueRow, `${tr.querySelector('[data-field="policy"] .pill')?.textContent.trim()}${tr.querySelector('[data-field="policyLimits"]') ? ` (${tr.querySelector('[data-field="policyLimits"]').textContent.trim()})` : ''}`])));
        check(wname, 'C5 catalogue', 'each row says where the action stands in the response policy: the nine Tier 1 actions Automatic; block_ip and isolate_host Needs approval with their limits; suspend_user_session, kill_process, quarantine_file and reset_password Not listed; the six Tier 3 actions Blacklisted', ['get_logs', 'analyse_alert', 'check_ip_reputation', 'get_asset_context', 'monitor', 'create_alert', 'create_ticket', 'recommend_response', 'notify_analyst'].every(k => catPolicy[k] === 'Automatic') && catPolicy.block_ip === 'Needs approval (30 min default · 24 h longest · SOC analyst · 15 min to decide · minimum risk 70)' && catPolicy.isolate_host === 'Needs approval (2 h default · 4 h longest · SOC lead · 15 min to decide · minimum risk 90)' && ['suspend_user_session', 'kill_process', 'quarantine_file', 'reset_password'].every(k => catPolicy[k] === 'Not listed') && ['block_ip_permanent', 'delete_logs', 'disable_security_control', 'modify_privileged_account', 'isolate_critical_host', 'change_policy'].every(k => catPolicy[k] === 'Blacklisted'), JSON.stringify(catPolicy));
        const catTable = await page.evaluate(() => { const frame = document.querySelector('[data-catalogue] .table-scroll'); const table = frame?.querySelector('table'); const region = frame?.getAttribute('role') === 'region'; return { caption: table?.querySelector('caption')?.textContent.replace(/\s+/g, ' ').trim(), heads: [...(table?.querySelectorAll('thead th') ?? [])].map(th => th.textContent.trim()).join(','), scopes: [...(table?.querySelectorAll('thead th') ?? [])].every(th => th.getAttribute('scope') === 'col'), overflow: frame ? frame.scrollWidth > frame.clientWidth + 1 : null, region, label: frame?.getAttribute('aria-label'), tab: frame?.getAttribute('tabindex'), tierPills: [...document.querySelectorAll('[data-catalogue-row] [data-field="tier"] .pill')].map(p => `${p.textContent.trim()}:${p.className.replace('pill ', '')}`).filter((v, i, a) => a.indexOf(v) === i).join(',') }; });
        check(wname, 'C5 catalogue', 'the table has a caption and column headers with scope, a text tier label on every row (pill Tier 1 ok, Tier 2 warn, Tier 3 danger), and when it overflows it is a focusable labelled scroll region (always at 390px)', catTable.caption === 'The 21 actions of the agent action catalogue, grouped by tier, with where each stands in the response policy' && catTable.heads === 'Action,Tier,When the agent uses it,Default,Maximum,Approver and window,Reversible,Response policy,Source' && catTable.scopes && catTable.tierPills === 'Tier 1:ok,Tier 2:warn,Tier 3:danger' && (catTable.overflow ? catTable.region && catTable.label === 'Action catalogue (scrolls sideways)' && catTable.tab === '0' : wname !== 'mobile'), JSON.stringify(catTable));
        await page.screenshot({ path: out + `catalogue-${wname}.png`, fullPage: true });

        // "Simulate an attempt": the engine's answer, the rule it came from, nothing executed
        const attemptPanel = await page.evaluate(() => { const p = document.querySelector('[data-attempt-panel]'); return { exists: !!p, demoBadge: p?.querySelector('.demo-badge')?.textContent.trim(), labels: [...(p?.querySelectorAll('label') ?? [])].map(l => l.textContent.trim()).join('|'), groups: [...(p?.querySelectorAll('#attemptAction optgroup') ?? [])].map(g => `${g.label}:${g.children.length}`).join(','), other: [...(p?.querySelectorAll('#attemptAction option') ?? [])].pop()?.textContent, result: p?.querySelector('[data-field="attemptResult"]')?.getAttribute('role'), submit: p?.querySelector('button[type="submit"]')?.textContent.trim() }; });
        check(wname, 'C5 attempt', 'the Demo panel on the catalogue tab is labelled Demo mode, offers the 21 actions grouped by tier plus "Not in the catalogue", and has labelled fields (action, target, duration, risk, confidence, asset class, privileged account) and a live result region', attemptPanel.exists && attemptPanel.demoBadge === 'Demo mode' && attemptPanel.groups === 'Tier 1: runs automatically:9,Tier 2: needs approval:6,Tier 3: never allowed:6' && attemptPanel.other === 'Not in the catalogue' && attemptPanel.labels === 'Action|IP address|Duration (minutes)|Risk (0 to 100)|Confidence (0 to 1)|Asset class|The account is privileged' && attemptPanel.result === 'status' && attemptPanel.submit === 'Simulate attempt', JSON.stringify(attemptPanel));

        const attemptRead = () => page.evaluate(() => { const r = document.querySelector('[data-field="attemptResult"]'); return { decision: r?.dataset.decision, label: r?.querySelector('[data-field="attemptDecision"]')?.textContent.trim(), reason: r?.querySelector('[data-field="attemptReason"]')?.textContent.trim(), rule: r?.querySelector('[data-field="attemptRule"]')?.textContent.trim(), executed: r?.querySelector('[data-field="attemptExecuted"]')?.textContent.trim(), tone: r?.querySelector('[data-field="attemptDecision"]')?.className.replace('pill ', ''), error: document.querySelector('[data-field="attemptError"]')?.textContent.trim() ?? null }; });
        // A run states everything it depends on (the form keeps its values between runs)
        const tier2Start = { block_ip: ['203.0.113.45', 30], isolate_host: ['endpoint-09', 120], suspend_user_session: ['j.smith', 30] };
        const simulate = async ({ action, other, target = tier2Start[action]?.[0], duration = tier2Start[action]?.[1], risk = 90, confidence = 0.9, asset = 'Business', privileged = false }) => {
          await page.selectOption('#attemptAction', action);
          if (other !== undefined) await page.fill('#attemptName', other);
          if (target !== undefined) await page.fill('#attemptTarget', target);
          if (duration !== undefined) await page.fill('#attemptDuration', String(duration));
          await page.fill('#attemptRisk', String(risk));
          await page.fill('#attemptConfidence', String(confidence));
          await page.selectOption('#attemptAsset', asset);
          await page.setChecked('#attemptPrivileged', privileged);
          await page.click('[data-attempt-panel] button[type="submit"]');
          await page.waitForTimeout(120);
          return attemptRead();
        };
        const R = rule => `Rule: ${rule}`;
        const t1 = await simulate({ action: 'get_logs' });
        check(wname, 'C5 attempt', 'get_logs (Tier 1): Allowed (ok), "Tier 1: allowed without approval.", the rule "Tier 1 · get_logs(source, time_range) · PDF p.3", and "Nothing was executed."', t1.decision === 'allowed' && t1.label === 'Allowed' && t1.tone === 'ok' && t1.reason === 'Tier 1: allowed without approval.' && t1.rule === R('Tier 1 · get_logs(source, time_range) · PDF p.3') && t1.executed === 'Nothing was executed.', JSON.stringify(t1));
        const n1 = await simulate({ action: 'block_ip' });
        const n2 = await simulate({ action: 'isolate_host' });
        const n3 = await simulate({ action: 'suspend_user_session' });
        check(wname, 'C5 attempt', 'a whitelisted Tier 2 action with every check passing is "Needs approval" (warn) with its approver and window and its page 4 rule: block_ip a SOC analyst, isolate_host a SOC lead, each within 15 min; suspend_user_session is on neither list, so it is Refused (danger) as not on the whitelist, with the policy list in its rule', [n1, n2].every(r => r.decision === 'needs_approval' && r.label === 'Needs approval' && r.tone === 'warn' && r.executed === 'Nothing was executed.') && n1.reason === 'block_ip is a Tier 2 action: it runs only after a SOC analyst approves it within 15 min.' && n2.reason === 'isolate_host is a Tier 2 action: it runs only after a SOC lead approves it within 15 min.' && n1.rule === R('Tier 2 · block_ip(ip, duration) · PDF p.4') && n2.rule === R('Tier 2 · isolate_host(host, path) · PDF p.4') && n3.decision === 'refused' && n3.label === 'Refused' && n3.tone === 'danger' && n3.reason === 'suspend_user_session is not on the response policy\'s whitelist, so it is denied.' && n3.rule === R('Tier 2 · suspend_user_session(user, duration) · PDF p.4 · Response policy: not on either list') && n3.executed === 'Nothing was executed.', JSON.stringify([n1, n2, n3]));
        const x1 = await simulate({ action: 'block_ip', target: '192.168.1.5' });
        const x2 = await simulate({ action: 'block_ip', target: '192.0.2.10' });
        const x3 = await simulate({ action: 'block_ip', duration: 1441 });
        const x4 = await simulate({ action: 'block_ip', risk: 69 });
        const x5 = await simulate({ action: 'isolate_host', confidence: 0.84 });
        const x6 = await simulate({ action: 'isolate_host', asset: 'Critical' });
        // (The privileged-account refusal needs suspend_user_session or reset_password on the whitelist: checked in verify:policy.)
        // A Tier 1 action in its place keeps the count of attempts: monitor is on the whitelist as Automatic, so it is allowed
        const x7 = await simulate({ action: 'monitor', target: '203.0.113.45' });
        const refusedAll = [x1, x2, x3, x4, x5, x6].every(r => r.decision === 'refused' && r.label === 'Refused' && r.tone === 'danger' && r.executed === 'Nothing was executed.') && x7.decision === 'allowed';
        check(wname, 'C5 attempt', 'each Tier 2 refusal names its reason and rule: an internal IP, an allow-listed IP, a block of 1441 min (max 1440), risk 69 (floor 70), isolation at confidence 0.84 (floor 0.85), isolation of a Critical asset; and monitor (Tier 1, whitelisted) is allowed', refusedAll && x1.reason === '192.168.1.5 is an internal address and can never be blocked.' && x2.reason === '192.0.2.10 is on the allow-list (or not a valid IP) and can never be blocked.' && x3.reason === 'block_ip can never run longer than 1440 min.' && x4.reason === 'Risk or confidence is below the block_ip thresholds.' && x5.reason === 'Risk or confidence is below the isolate_host thresholds.' && x6.reason === 'A Critical asset is never isolated by the agent.' && x1.rule === n1.rule && x6.rule === n2.rule, JSON.stringify([x1, x2, x3, x4, x5, x6, x7].map(r => r.reason)));
        const p3 = await simulate({ action: 'block_ip_permanent', target: 'any' });
        const po = await simulate({ action: '__other__', other: 'format_disk', target: '' });
        check(wname, 'C5 attempt', 'a Tier 3 action is refused whatever the risk ("block_ip_permanent is a prohibited action and is never executed.", rule "Tier 3 · Permanent blocking, or any block longer than 24 h · PDF p.5") and a name outside the catalogue is refused ("format_disk is not in the action catalogue.")', p3.decision === 'refused' && p3.reason === 'block_ip_permanent is a prohibited action and is never executed.' && p3.rule === R('Tier 3 · Permanent blocking, or any block longer than 24 h · PDF p.5') && po.decision === 'refused' && po.reason === 'format_disk is not in the action catalogue.' && po.rule === R('Anything outside the catalogue is refused · PDF p.5'), JSON.stringify([p3, po]));
        await page.fill('#attemptRisk', '101');
        await page.click('[data-attempt-panel] button[type="submit"]');
        await page.waitForTimeout(120);
        const badRisk = await attemptRead();
        check(wname, 'C5 attempt', 'a risk of 101 is not simulated: an error says "Risk must be a number from 0 to 100." and the last answer stays', badRisk.error === 'Risk must be a number from 0 to 100.' && badRisk.rule === po.rule, JSON.stringify(badRisk));

        // Nothing changed: requests, tokens, demo time, badge
        await goSide('Approvals', aprPhone);
        const aprAfter = await aprState();
        const stateAfter = { rows: aprAfter.rows.map(r => `${r.id}:${r.state}`).join(','), now: await demoNow(), badge: await sideBadgeApr() };
        check(wname, 'C5 attempt', 'after 13 attempts nothing else moved: the Approvals queue, demo time and sidebar badge are exactly as before (APR-002 still waiting, 15:46:00, badge 1)', JSON.stringify(stateAfter) === JSON.stringify(stateBefore) && stateAfter.rows === 'APR-002:Waiting' && stateAfter.now === '15:46:00', JSON.stringify([stateBefore, stateAfter]));

        // The audit log: 13 Demo "Simulated an attempt" events (Success) and 9 Demo "Policy violation blocked" events (Denied)
        await goSide('Audit Logs', aprPhone);
        const attemptTrail = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => ({ id: Number(b.dataset.recordId.replace('AUD-', '')), action: b.querySelector('.audit-action')?.textContent.replace(/\s+/g, ' ').trim(), demo: !!b.querySelector('.audit-demo-tag'), result: b.dataset.result, who: b.querySelector('.audit-meta')?.textContent.replace(/\s+/g, ' ').trim() })).filter(r => r.id > 206));
        const sims = attemptTrail.filter(r => r.action.includes('Simulated an attempt'));
        const viols = attemptTrail.filter(r => r.action.includes('Policy violation blocked'));
        check(wname, 'C5 attempt', 'the audit log records every attempt as Demo: 13 "Simulated an attempt" (Success, by System Administrator) and 9 "Policy violation blocked" (Denied, by AthenaSec AI), one per refusal, and nothing else was added', attemptTrail.length === 22 && sims.length === 13 && sims.every(r => r.demo && r.result === 'Success' && r.who.startsWith('System Administrator')) && viols.length === 9 && viols.every(r => r.demo && r.result === 'Denied' && r.who.startsWith('AthenaSec AI')), JSON.stringify(attemptTrail.map(r => `${r.id}:${r.action}:${r.result}`).slice(0, 6)));
        await page.click(`.audit-pick[data-record-id="AUD-${viols[0].id}"]`);
        await page.waitForTimeout(250);
        const violDetail = await page.evaluate(() => ({ action: document.querySelector('[data-field="action"]')?.textContent.trim(), result: document.querySelector('[data-field="result"]')?.textContent.trim(), demo: !!document.querySelector('[data-field="demo"]'), changes: [...document.querySelectorAll('[data-field="changes"] li')].map(l => l.textContent.trim()), meta: Object.fromEntries([...document.querySelectorAll('[data-field="metadata"] > div')].map(d => [d.querySelector('dt').textContent.trim(), d.querySelector('dd').textContent.trim()])) }));
        check(wname, 'C5 attempt', 'the newest violation event shows Denied with the Demo tag, the change "format_disk: Requested → Blocked", and the rule, code and "Executed: No" in its metadata', violDetail.action === 'Policy violation blocked' && violDetail.result === 'Denied' && violDetail.demo && violDetail.changes.join('|') === 'format_disk: Requested → Blocked' && violDetail.meta.Rule === 'Anything outside the catalogue is refused · PDF p.5' && violDetail.meta.Code === 'not_in_catalogue' && violDetail.meta.Executed === 'No', JSON.stringify(violDetail));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }

        // ---------- Policy phase C6b: the chain's indicator, event types, hashes, the tamper cycle, the bell ----------
        const integ = () => page.evaluate(() => { const e = document.querySelector('[data-field="integrity"]'); return { state: e?.dataset.state, count: e?.dataset.count, text: e?.textContent.replace(/\s+/g, ' ').trim(), role: e?.getAttribute('role') }; });
        await page.waitForSelector('[data-field="integrity"][data-state="intact"]');
        const intact33 = await integ();
        check(wname, 'C6 chain', 'the Audit Logs integrity line is a status region reading "Chain intact: 33 events verified" (11 seed events and the 22 recorded so far)', intact33.role === 'status' && intact33.state === 'intact' && intact33.count === '33' && intact33.text === 'Chain intact: 33 events verified', JSON.stringify(intact33));
        const openAudit = async id => { await page.click(`.audit-pick[data-record-id="${id}"]`); await page.waitForTimeout(150); if (aprPhone) await page.waitForSelector('[role="dialog"]'); };
        const closeAudit = async () => { if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); } };
        const auditPanel = () => page.evaluate(() => {
          const t = el => el?.textContent.replace(/\s+/g, ' ').trim() ?? null;
          const rows = Object.fromEntries([...document.querySelectorAll('[data-field="record"] [data-record-field]')].map(r => [r.dataset.recordField, [...r.querySelectorAll('dd li')].length ? [...r.querySelectorAll('dd li')].map(li => t(li)).join(' ') : t(r.querySelector('dd'))]));
          return { id: t(document.querySelector('[data-field="id"]')), eventType: t(document.querySelector('[data-field="eventType"]')), hasRecord: !!document.querySelector('[data-field="record"]'), rows, prev: t(document.querySelector('[data-field="prevHash"]')), hash: t(document.querySelector('[data-field="hash"]')), mismatch: t(document.querySelector('[data-field="mismatch"]')), description: t(document.querySelector('[data-field="description"]')), copyLabels: [...document.querySelectorAll('.audit-hash-cell button')].map(b => b.getAttribute('aria-label')).join('|') };
        });
        await openAudit('AUD-205');
        const p205 = await auditPanel();
        check(wname, 'C6 chain', 'AUD-205 (the seeded isolation) shows its PDF event type "action_executed Action executed" and its structured record: REC-001, ALT-006, response-policy-v2, agent, tier 2, isolate_host with host endpoint-12 and 120 min, risk 90, confidence 0.92, approved, success, expires 17:44:00, and model_version "Not recorded"', p205.eventType === 'action_executed Action executed' && p205.rows.recommendation_id === 'REC-001' && p205.rows.alert_id === 'ALT-006' && p205.rows.policy_id === 'response-policy-v2' && p205.rows.actor === 'agent' && p205.rows.actor_role === 'agent' && p205.rows.tier === '2' && p205.rows.action === 'isolate_host' && p205.rows.params === 'host: endpoint-12 path: edr_network_isolation duration_min: 120' && p205.rows.risk_score === '90' && p205.rows.confidence === '0.92' && p205.rows.decision === 'approved' && p205.rows.execution_result === 'success' && p205.rows.expires_at === '2026-08-03T17:44:00' && p205.rows.model_version === 'Not recorded' && !('evidence' in p205.rows), JSON.stringify(p205));
        const hash205 = p205.hash;
        await closeAudit();
        await openAudit('AUD-196');
        const p196 = await auditPanel();
        check(wname, 'C6 chain', 'an event the policy has no type for (AUD-196) reads "No PDF event type" and has no structured record, but still has its hashes', p196.eventType === 'No PDF event type' && !p196.hasRecord && /^[0-9a-f]{64}$/.test(p196.hash), JSON.stringify(p196));
        check(wname, 'C6 chain', 'the oldest record follows no other: its previous hash is 64 zeros', p196.prev === '0'.repeat(64), p196.prev);
        await closeAudit();
        const typedIds = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].filter(b => /Policy violation blocked/.test(b.querySelector('.audit-action').textContent)).map(b => ({ id: b.dataset.recordId, target: b.querySelector('.audit-target').textContent.trim() })));
        const permanent = typedIds.find(v => v.target === 'block_ip_permanent');
        await openAudit(permanent.id);
        const pv = await auditPanel();
        check(wname, 'C6 chain', 'a refused attempt (block_ip_permanent) shows policy_violation_blocked and its record: actor agent, tier 3, params target: any, risk 90, confidence 0.90, not_executed, model_version "Not recorded"', pv.eventType === 'policy_violation_blocked Policy violation blocked' && pv.rows.actor === 'agent' && pv.rows.actor_role === 'agent' && pv.rows.tier === '3' && pv.rows.action === 'block_ip_permanent' && pv.rows.params === 'target: any' && pv.rows.risk_score === '90' && pv.rows.confidence === '0.90' && pv.rows.execution_result === 'not_executed' && pv.rows.model_version === 'Not recorded', JSON.stringify(pv));
        await closeAudit();
        // The hashes: 64 hex each, and each record's previous hash is the older record's hash
        const hashOf = async id => { await openAudit(id); const p = await auditPanel(); await closeAudit(); return p; };
        const h204 = await hashOf('AUD-204');
        const h205b = await hashOf('AUD-205');
        const h206 = await hashOf('AUD-206');
        check(wname, 'C6 chain', 'the hashes are 64 hex characters each, all different, and each previous hash is the older record\'s hash (AUD-205 follows AUD-204, AUD-206 follows AUD-205)', [h204, h205b, h206].every(h => /^[0-9a-f]{64}$/.test(h.hash) && /^[0-9a-f]{64}$/.test(h.prev)) && new Set([h204.hash, h205b.hash, h206.hash]).size === 3 && h205b.prev === h204.hash && h206.prev === h205b.hash && h205b.hash === hash205, JSON.stringify([h204.hash, h205b.prev, h205b.hash, h206.prev]));
        await openAudit('AUD-206');
        check(wname, 'C6 chain', 'each hash has a labelled Copy button ("Copy previous hash", "Copy hash")', (await auditPanel()).copyLabels === 'Copy previous hash|Copy hash', (await auditPanel()).copyLabels);
        await page.click('.audit-hash-cell button[aria-label="Copy hash"]');
        await page.waitForTimeout(200);
        const copied = await page.evaluate(() => document.querySelector('[data-field="hash"]')?.closest('dd').querySelector('[data-field="copyMessage"]')?.textContent.trim());
        check(wname, 'C6 chain', 'Copy answers in words: "Copied", or "Select the text to copy it" when the browser blocks the clipboard', copied === 'Copied' || copied === 'Select the text to copy it', copied);
        const fits = await page.evaluate(() => ({ overflow: document.documentElement.scrollWidth - window.innerWidth, hashRight: Math.max(...[...document.querySelectorAll('.audit-hash')].map(h => h.getBoundingClientRect().right)), width: window.innerWidth }));
        check(wname, 'C6 chain', 'the full hashes wrap inside the panel: no horizontal page scroll and no hash past the screen edge', fits.overflow <= 0 && fits.hashRight <= fits.width, JSON.stringify(fits));
        await closeAudit();

        // The event type filter, its count, the export and the search
        const typeOptions = await page.evaluate(() => [...document.querySelectorAll('select[aria-label="Filter by event type"] option')].map(o => o.textContent.trim()).join('|'));
        check(wname, 'C6 chain', 'the event type filter lists All Event Types, the PDF\'s seven types by name, and "No event type"', typeOptions === 'All Event Types|Recommendation created|Decision recorded|Action executed|Action failed|Action expired|Approval timed out|Policy violation blocked|No event type', typeOptions);
        const typeCount = async label => { await page.selectOption('select[aria-label="Filter by event type"]', { label }); await page.waitForTimeout(150); return page.evaluate(() => ({ count: document.querySelector('#visibleAuditCount')?.textContent.trim(), ids: [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => b.dataset.recordId) })); };
        const tViol = await typeCount('Policy violation blocked');
        const tExec = await typeCount('Action executed');
        const tNone = await typeCount('No event type');
        const tNoApproval = await typeCount('Approval timed out');
        await typeCount('Policy violation blocked');
        const [dl] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export shown events")')]);
        let csv2 = '';
        for await (const chunk of await dl.createReadStream()) csv2 += chunk.toString();
        const csvViol = [...csv2.matchAll(/"(AUD-\d+)"/g)].map(m => m[1]);
        check(wname, 'C6 chain', 'the type filter counts: 9 policy violations, 1 executed action (AUD-205), 0 timeouts, 23 events with no type; the export writes only the 9 filtered events', tViol.count === '9 visible' && tExec.count === '1 visible' && tExec.ids.join() === 'AUD-205' && tNoApproval.count === '0 visible' && tNone.count === '23 visible' && csvViol.length === 9 && csvViol.join() === tViol.ids.join(), JSON.stringify([tViol.count, tExec.count, tNone.count, tNoApproval.count, csvViol.length]));
        await page.click('button:has-text("Reset Filters")');
        await page.waitForTimeout(150);
        const typeReset = await page.evaluate(() => ({ type: document.querySelector('select[aria-label="Filter by event type"]').value, count: document.querySelector('#visibleAuditCount')?.textContent.trim() }));
        await page.fill('input[aria-label="Search audit events"]', 'policy_violation_blocked');
        await page.waitForTimeout(150);
        const byCode = await page.evaluate(() => document.querySelector('#visibleAuditCount')?.textContent.trim());
        await page.fill('input[aria-label="Search audit events"]', 'REC-001');
        await page.waitForTimeout(150);
        const byRec = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].map(b => b.dataset.recordId).join());
        await page.fill('input[aria-label="Search audit events"]', '');
        await page.waitForTimeout(150);
        check(wname, 'C6 chain', 'Reset Filters clears the type filter (All, 33 visible); searching the type code finds the 9 violations and searching REC-001 finds AUD-205', typeReset.type === 'all' && typeReset.count === '33 visible' && byCode === '9 visible' && byRec === 'AUD-205', JSON.stringify([typeReset, byCode, byRec]));

        // Alter, then Restore: the chain notices, then verifies again from the recorded hashes
        await openAudit('AUD-200');
        const before200 = await auditPanel();
        const tamperPanel = await page.evaluate(() => { const p = document.querySelector('[data-tamper-panel]'); return { exists: !!p, badge: p?.querySelector('.demo-badge')?.textContent.trim(), buttons: [...(p?.querySelectorAll('button') ?? [])].map(b => `${b.textContent.trim()}:${b.disabled}`).join('|'), hint: p?.querySelector('[data-field="tamperHint"]')?.textContent.trim() }; });
        check(wname, 'C6 tamper', 'the Demo panel is labelled Demo mode, offers "Alter this record (demo)" (enabled once the chain is checked) and says which record it would alter (AUD-200); nothing to restore yet', tamperPanel.exists && tamperPanel.badge === 'Demo mode' && tamperPanel.buttons === 'Alter this record (demo):false' && tamperPanel.hint === 'This alters AUD-200. Restore puts it back and the chain is checked again.', JSON.stringify(tamperPanel));
        if (aprPhone) { await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        await page.click('[data-tamper-panel] button:has-text("Alter this record")');
        await page.waitForSelector('[data-field="integrity"][data-state="broken"]');
        const brokenLine = await integ();
        const afterAlterList = await page.evaluate(() => ({ ids: [...document.querySelectorAll('.audit-pick[data-record-id]')].slice(0, 2).map(b => `${b.dataset.recordId}:${b.querySelector('.audit-action').textContent.replace(/\s+/g, ' ').trim()}:${!!b.querySelector('.audit-demo-tag')}`), btns: [...document.querySelectorAll('[data-tamper-panel] button')].map(b => `${b.textContent.trim()}:${b.disabled}`).join('|'), hint: document.querySelector('[data-field="tamperHint"]')?.textContent.trim() }));
        await openAudit('AUD-200');
        const alt200 = await auditPanel();
        await closeAudit();
        await openAudit('AUD-199');
        const alt199 = await auditPanel();
        await closeAudit();
        check(wname, 'C6 tamper', 'Alter: the chain line turns to "Chain broken at AUD-200" (danger, never colour alone), the altered record says "This record no longer matches its hash." and shows its new text, its recorded hash is unchanged, and the record before it is not flagged', brokenLine.state === 'broken' && /^Chain broken at AUD-200: /.test(brokenLine.text) && alt200.mismatch === 'This record no longer matches its hash.' && /\(altered after it was recorded\)$/.test(alt200.description) && alt200.hash === before200.hash && alt200.prev === before200.prev && alt199.mismatch === null, JSON.stringify([brokenLine, alt200.mismatch, alt200.description?.slice(-40)]));
        check(wname, 'C6 tamper', 'the Alter use is a Demo event in the trail ("Tampered with a record", Demo tag, newest), the Alter button is disabled with its reason ("AUD-200 is altered. Restore it first.") and "Restore AUD-200" is offered', /^AUD-\d+:Demo Tampered with a record AUD-200:true$/.test(afterAlterList.ids[0]) && afterAlterList.btns === 'Alter this record (demo):true|Restore AUD-200:false' && afterAlterList.hint === 'AUD-200 is altered. Restore it first.', JSON.stringify(afterAlterList));
        await page.click('[data-tamper-panel] button:has-text("Restore AUD-200")');
        await page.waitForSelector('[data-field="integrity"][data-state="intact"]');
        const restoredLine = await integ();
        const afterRestore = await page.evaluate(() => ({ ids: [...document.querySelectorAll('.audit-pick[data-record-id]')].slice(0, 2).map(b => `${b.querySelector('.audit-action').textContent.replace(/\s+/g, ' ').trim()}:${!!b.querySelector('.audit-demo-tag')}`), btns: [...document.querySelectorAll('[data-tamper-panel] button')].map(b => `${b.textContent.trim()}:${b.disabled}`).join('|') }));
        await openAudit('AUD-200');
        const rest200 = await auditPanel();
        await closeAudit();
        check(wname, 'C6 tamper', 'Restore: the content is back (no "altered" text, no mismatch notice) and the line reads "Chain intact: 35 events verified", checked again from the recorded hashes; both Demo events ("Restored a record", "Tampered with a record") stay in the trail with their Demo tag; Alter is available again', restoredLine.state === 'intact' && restoredLine.text === 'Chain intact: 35 events verified' && rest200.mismatch === null && !/altered after it was recorded/.test(rest200.description) && rest200.hash === before200.hash && afterRestore.ids.join('|') === 'Demo Restored a record AUD-200:true|Demo Tampered with a record AUD-200:true' && afterRestore.btns === 'Alter this record (demo):false', JSON.stringify([restoredLine, afterRestore, rest200.mismatch]));

        // The Demo label is a separate word from the action it labels, in the list and for a screen reader (not "DemoTampered")
        const demoLabelText = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[data-record-id]')].filter(b => b.querySelector('.audit-demo-tag')).map(b => b.querySelector('.audit-action').textContent.replace(/\s+/g, ' ').trim()));
        check(wname, 'C6 chain', 'every Demo event in the list reads "Demo" and then its action as separate words ("Demo Tampered with a record ...", never "DemoTampered"): 24 Demo events (13 attempts, 9 violations, the Alter and the Restore)', demoLabelText.length === 24 && demoLabelText.every(text => /^Demo [A-Z]/.test(text)), JSON.stringify(demoLabelText.slice(0, 3)));

        // The bell: one high-severity notice per violation for the Administrator, opening the event
        await page.click('.icon-btn');
        await page.waitForTimeout(150);
        const bellAdmin = await page.evaluate(() => ({ label: document.querySelector('.icon-btn')?.getAttribute('aria-label'), items: [...document.querySelectorAll('.dropdown .drop-item')].map(i => ({ title: i.querySelector('strong')?.textContent.trim(), text: i.querySelector('p')?.textContent.trim() })) }));
        const violationItems = bellAdmin.items.filter(i => i.title === 'Policy violation blocked');
        check(wname, 'C6 notice', 'the Administrator\'s bell lists one "Policy violation blocked" notice per refusal (9), each Demo-labelled high severity saying nothing ran, and the unread count follows (12: 2 fixed, 1 approval, 9 violations)', violationItems.length === 9 && violationItems.every(i => /^Demo, high severity: .+ was refused and nothing ran\. Tier|^Demo, high severity: .+ was refused and nothing ran\. Anything outside/.test(i.text)) && bellAdmin.label === 'Notifications, 12 unread', JSON.stringify([bellAdmin.label, violationItems.length, violationItems[0]]));
        await page.click('.dropdown .drop-item:has-text("Policy violation blocked")');
        await page.waitForURL('**/app/audit-logs');
        // Wait for the notice's event to be the selected one (the page selects it a moment after it opens), not a fixed time
        await page.waitForFunction(id => [...document.querySelectorAll('.audit-pick[aria-pressed="true"]')].some(b => b.dataset.recordId === id), `AUD-${viols[0].id}`, { timeout: 5000 }).catch(() => {});
        const landed = await page.evaluate(() => [...document.querySelectorAll('.audit-pick[aria-pressed="true"]')].map(b => b.dataset.recordId).join());
        if (aprPhone) { await page.waitForSelector('[role="dialog"]').catch(() => {}); await page.keyboard.press('Escape'); await page.waitForTimeout(150); }
        check(wname, 'C6 notice', 'choosing a violation notice opens Audit Logs with that event selected (the newest violation, the one for format_disk)', landed === `AUD-${viols[0].id}`, `${landed} / AUD-${viols[0].id}`);

        // Administrator only: an analyst cannot reach Audit Logs, so never sees the tamper panel, and gets no violation notice
        await signOutInApp();
        await signInInApp(roles.analyst);
        await page.goto(base + '/app/audit-logs');
        await page.waitForTimeout(300);
        const analystView = await page.evaluate(() => ({ path: location.pathname, tamper: document.querySelectorAll('[data-tamper-panel]').length, integrity: document.querySelectorAll('[data-field="integrity"]').length }));
        await page.click('.icon-btn');
        await page.waitForTimeout(150);
        const bellAnalyst = await page.evaluate(() => [...document.querySelectorAll('.dropdown .drop-item strong')].map(s => s.textContent.trim()));
        check(wname, 'C6 tamper', 'the tamper panel is Administrator only: an analyst opening /app/audit-logs is sent to the dashboard, no Demo tamper panel or integrity line is on screen, and their bell has no policy violation notice', analystView.path === '/app/dashboard' && analystView.tamper === 0 && analystView.integrity === 0 && !bellAnalyst.includes('Policy violation blocked'), JSON.stringify([analystView, bellAnalyst]));
        await page.keyboard.press('Escape');
        await signOutInApp();
        await signInInApp(roles.admin);
        await goSide('Audit Logs', aprPhone);
        await page.waitForSelector('[data-field="integrity"][data-state="intact"]');
        const freshLine = await integ();
        check(wname, 'C6 chain', 'after a reload and a new sign-in the chain starts again from the seed: "Chain intact: 11 events verified" (the session\'s events do not outlive the page)', freshLine.text === 'Chain intact: 11 events verified', JSON.stringify(freshLine));
        await goSide('Response Policies', aprPhone);
        await page.waitForTimeout(250);

        // Taking an action off the whitelist is never blocked by a cap (a draft only: the saved policy stays as the seed for what follows)
        await goSide('Response Policies', aprPhone);
        await page.waitForTimeout(250);
        await page.click('.perm button[aria-label="Remove block_ip from the whitelist"]');
        await page.waitForTimeout(100);
        const dropped = await page.evaluate(() => ({
          unsaved: document.querySelector('[data-field="unsaved"]')?.textContent.trim(),
          save: [...document.querySelectorAll('.perm-bar .btn')].find(b => b.textContent.trim() === 'Save changes')?.disabled,
          inWhitelist: !!document.querySelector('[data-list="whitelist"] li[data-action="block_ip"]'),
          notListed: [...document.querySelectorAll('[data-list="unlisted"] li[data-action]')].map(li => li.dataset.action).join(),
          counts: ['automaticCount', 'approvalCount', 'blacklistCount'].map(f => document.querySelector(`[data-field="${f}"]`)?.textContent.trim()).join(),
        }));
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(100);
        const kept = await page.evaluate(() => ({ unsaved: document.querySelector('[data-field="unsaved"]')?.textContent.trim(), inWhitelist: !!document.querySelector('[data-list="whitelist"] li[data-action="block_ip"]') }));
        check(wname, 'C5 floor', 'removing block_ip from the whitelist is a plain draft that no cap blocks: it moves to Not on either list (denied), the counts follow (9, 1, 6), Save is enabled, and Discard puts it back', dropped.unsaved === '1 unsaved change' && dropped.save === false && !dropped.inWhitelist && dropped.notListed === 'block_ip,suspend_user_session,kill_process,quarantine_file,reset_password' && dropped.counts === '9,1,6' && kept.unsaved === 'No unsaved changes' && kept.inWhitelist, JSON.stringify({ dropped, kept }));

        // ---------- Phase 6 guidelines fixes F01, F09, F10, F11: the phone search results, the header's Tab order, the menu drawer and the menus ----------
        const phone = wname === 'mobile';
        const nameNow = () => page.evaluate(() => { const el = document.activeElement; return (el.getAttribute('aria-label') || el.textContent || el.id || el.tagName).replace(/\s+/g, ' ').trim().slice(0, 40); });
        const tabFromTop = async count => {
          // Tabbing starts on the skip link (the first stop since F07), so the count begins at the header
          await page.evaluate(() => { window.scrollTo(0, 0); const s = document.createElement('span'); s.id = '__t0'; s.tabIndex = 0; document.body.prepend(s); (document.querySelector('.skip-link') ?? s).focus(); });
          const names = [];
          for (let i = 0; i < count; i++) { await page.keyboard.press('Tab'); names.push(await nameNow()); }
          await page.evaluate(() => document.getElementById('__t0')?.remove());
          return names;
        };
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(300);
        await page.fill('#globalSearch', 'siem');
        await page.waitForSelector('#globalSearchResults [role="option"]');
        const resultsBox = await page.evaluate(() => { const r = document.querySelector('#globalSearchResults').getBoundingClientRect(); return { left: Math.round(r.left), right: Math.round(r.right), vw: innerWidth, scrollW: document.documentElement.scrollWidth, clientW: document.documentElement.clientWidth }; });
        check(wname, 'a11y header', `the search results stay on the screen (${resultsBox.vw}px): the panel runs from ${resultsBox.left} to ${resultsBox.right}, inside the screen, and the page does not scroll sideways`, resultsBox.left >= 0 && resultsBox.right <= resultsBox.vw && resultsBox.scrollW <= resultsBox.clientW && (!phone || resultsBox.left >= 15), JSON.stringify(resultsBox));
        await page.keyboard.press('Escape');
        await page.fill('#globalSearch', '');
        const headerTabs = await tabFromTop(phone ? 6 : 5);
        if (phone) check(wname, 'a11y header', 'on a phone Tab follows the screen: the menu button, the logo, the bell, the account menu (first row), then the status link and the search box (second row)', headerTabs[0] === 'Open navigation menu' && headerTabs[1] === 'AthenaSec' && /^Notifications/.test(headerTabs[2]) && /^Account menu/.test(headerTabs[3]) && /attention|degraded|Stopped|Failed|Starting/.test(headerTabs[4]) && /^Search policies/.test(headerTabs[5]), headerTabs.join(' > '));
        else check(wname, 'a11y header', 'on desktop and laptop Tab runs along the bar: the logo, the status link, the search box, the bell, the account menu (the hamburger is hidden)', headerTabs[0] === 'AthenaSec' && /attention|degraded|Stopped|Failed|Starting/.test(headerTabs[1]) && /^Search policies/.test(headerTabs[2]) && /^Notifications/.test(headerTabs[3]) && /^Account menu/.test(headerTabs[4]), headerTabs.join(' > '));
        if (phone) {
          await page.click('.sidebar-toggle');
          await page.waitForTimeout(200);
          const lockedOpen = await page.evaluate(() => ({ main: document.querySelector('main').hasAttribute('inert'), bar: document.querySelector('.topbar').hasAttribute('inert') }));
          const drawerStops = [];
          for (let i = 0; i < 14; i++) { await page.keyboard.press('Tab'); drawerStops.push(await page.evaluate(() => { const el = document.activeElement; return el.closest('.sidebar') ? 'drawer' : el.classList.contains('sidebar-toggle') ? 'toggle' : el === document.body ? 'browser' : `OUTSIDE ${el.tagName}`; })); }
          await page.keyboard.press('Escape');
          await page.waitForTimeout(200);
          const afterEscape = await page.evaluate(() => ({ focus: document.activeElement?.classList.contains('sidebar-toggle'), main: document.querySelector('main').hasAttribute('inert'), bar: document.querySelector('.topbar').hasAttribute('inert') }));
          await page.click('.sidebar-toggle');
          await page.waitForTimeout(200);
          await page.mouse.click(w - 40, h - 20);
          await page.waitForTimeout(200);
          const afterBackdrop = await page.evaluate(() => document.activeElement?.classList.contains('sidebar-toggle'));
          check(wname, 'a11y header', 'while the phone menu drawer is open the page behind it is inert and Tab stays in the drawer and its button (14 presses, none on page content; the one step out to the controls of the browser itself, which shows as the body, is allowed); Escape closes it, puts focus back on the menu button and lifts the inert; so does a click on the backdrop', lockedOpen.main && lockedOpen.bar && drawerStops.every(s => s === 'drawer' || s === 'toggle' || s === 'browser') && afterEscape.focus && !afterEscape.main && !afterEscape.bar && afterBackdrop === true, JSON.stringify({ lockedOpen, drawerStops, afterEscape, afterBackdrop }));
        }
        const menuTab = async (toggleSel, shift) => {
          await page.goto(base + '/app/dashboard');
          await page.waitForTimeout(250);
          await page.click(toggleSel);
          await page.waitForSelector('.dropdown');
          const opened = await page.locator('.dropdown').count();
          let presses = 0;
          if (shift) { await page.focus(toggleSel); await page.keyboard.press('Shift+Tab'); presses = 1; }
          else { while (presses < 8 && (await page.locator('.dropdown').count()) > 0) { await page.keyboard.press('Tab'); presses++; } }
          await page.waitForTimeout(100);
          return { opened, closed: (await page.locator('.dropdown').count()) === 0, presses, inMenu: await page.evaluate(() => !!document.activeElement.closest('.dropdown')) };
        };
        const bellTab = await menuTab('.icon-btn', false);
        const accountTab = await menuTab('.user-avatar', false);
        const accountBack = await menuTab('.user-avatar', true);
        check(wname, 'a11y header', 'the bell and account menus close when Tab leaves them, so focus never moves on with a menu still open over the page: Tab out of the last item (bell, account) and Shift+Tab out of the account button each close the menu', bellTab.opened === 1 && bellTab.closed && !bellTab.inMenu && accountTab.opened === 1 && accountTab.closed && !accountTab.inMenu && accountBack.closed, JSON.stringify({ bellTab, accountTab, accountBack }));

        // ---------- Phase 6 guidelines fixes F02 and F04: field edges and placeholders on the app's own pages ----------
        const fieldPages = [];
        const collectFields = async (label, path, prepare) => {
          await page.goto(base + path);
          await page.waitForTimeout(300);
          if (prepare) await prepare();
          fieldPages.push([label, await fieldContrast('.field-input, .select-input, .textarea-input, .search-input')]);
        };
        await collectFields('Profile', '/app/profile');
        await collectFields('Approvals', '/app/approvals', async () => { await page.click('.queue-item[data-record-id="APR-002"]'); if (phone) await page.waitForSelector('[role="dialog"]'); await page.waitForTimeout(150); });
        await collectFields('User Management', '/app/user-management');
        await collectFields('Permissions limits', '/app/response-policies', async () => { await page.click('.perm button[aria-label="Approval limits for block_ip"]'); await page.waitForTimeout(150); });
        const faintFields = fieldPages.flatMap(([label, list]) => list.filter(f => f.border < 3 || (f.placeholder !== null && f.placeholder < 4.5)).map(f => `${label}: ${f.id} edge ${f.border}:1, placeholder ${f.placeholder}`));
        check(wname, 'a11y fields', 'every text field, select and search box on Profile, the Approvals reason box, User Management and the Permissions limits (and the top-bar search on each) shows its edge at 3:1 or more, and every placeholder reads at 4.5:1 or more', fieldPages.every(([, list]) => list.length > 0) && faintFields.length === 0, faintFields.slice(0, 6).join(' ; ') || fieldPages.map(([l, list]) => `${l} ${list.length}`).join(', '));

        // ---------- Phase 6 guidelines fixes F15, F16, F17, F24 on the dialogs and forms the page walk does not open ----------
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(250);
        await page.click('button:has-text("+ Add User")');
        await page.waitForSelector('[role="dialog"]');
        const addUserFaults = await fieldFaults('[role="dialog"]');
        await page.keyboard.press('Escape');
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(250);
        await page.click('.perm button[aria-label="Approval limits for block_ip"]');
        await page.focus('.perm [data-targets="block"] button[aria-expanded]');
        await page.keyboard.press('Enter');
        await page.waitForSelector('#add-block-value');
        const permFaults = await fieldFaults('.perm');
        const addFieldFocused = await page.evaluate(() => document.activeElement?.id === 'add-block-value');
        check(wname, 'a11y forms', 'the Add user dialog fields (name, email, role, status, department, phone, Require MFA) and the Permissions limits and Add form fields have names and autocomplete, the email field turns spellcheck off and placeholders end with "…"', addUserFaults.count >= 7 && addUserFaults.faults.length === 0 && permFaults.count >= 6 && permFaults.faults.length === 0, JSON.stringify({ addUserFaults, permFaults }));
        check(wname, 'a11y forms', 'opening the Permissions Add form does not move focus into the field (autofocus stays for dialogs only; inside the Add user dialog the first field is focused by the dialog)', !addFieldFocused, String(addFieldFocused));

        // ---------- Phase 6 F05: the Permissions draft survives tabs and pages, is shown in the menu, asks before the tab closes,
        // is named on sign-out, and never carries over to another user ----------
        const permUnsaved = () => page.evaluate(() => document.querySelector('[data-field="unsaved"]')?.textContent.trim() ?? null);
        const beforeUnloadAsks = () => page.evaluate(() => { const e = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(e); return e.defaultPrevented; });
        const permTag = () => page.evaluate(() => { const a = document.querySelector('.sidebar a[href="/app/response-policies"]'); const tag = a?.querySelector('.unsaved-tag'); const r = tag?.getBoundingClientRect(); const label = a?.querySelector('.side-label'); return { tag: tag ? tag.textContent.trim() : null, hiddenFromReaders: tag?.getAttribute('aria-hidden') === 'true', name: a ? a.getAttribute('aria-label') : null, labelCut: label ? label.scrollWidth > label.clientWidth : null, inside: r ? r.left >= 0 && r.right <= innerWidth : null }; });
        const signOut = async () => {
          await page.click('.user-avatar');
          await page.click('.drop-item:has-text("Logout")');
          await page.waitForSelector('[role="dialog"]');
        };
        const noteText = () => page.evaluate(() => document.querySelector('[role="dialog"] [data-field="confirmNote"]')?.textContent.trim() ?? null);
        const signInAs = async acct => {
          await page.waitForSelector('#loginEmail');
          await page.click(`.demo-account:has-text("${acct.email}")`);
          await page.click('.login-submit');
          await page.waitForURL('**/mfa');
          const boxes = page.locator('[data-mfa-digit]');
          for (let i = 0; i < 6; i++) await boxes.nth(i).fill(String(i + 1));
          await page.click('button:has-text("Verify")');
          await page.waitForURL('**/app/dashboard');
          await page.waitForSelector('.sidebar .side-item', { state: 'attached' });
          await page.waitForTimeout(300);
        };
        const phoneW = wname === 'mobile';
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        const cleanBefore = { line: await permUnsaved(), tag: (await permTag()).tag, asks: await beforeUnloadAsks() };
        await page.click('.perm button[aria-label="Whitelist kill_process"]');
        await page.waitForTimeout(150);
        const withDraft = { line: await permUnsaved(), tag: await permTag(), asks: await beforeUnloadAsks() };
        await page.click('[role="tab"]:has-text("Action catalogue")');
        await page.waitForSelector('[role="tab"][aria-selected="true"]:has-text("Action catalogue")');
        await page.click('[role="tab"]:has-text("Permissions")');
        await page.waitForSelector('[data-field="unsaved"]');
        const afterTab = await permUnsaved();
        await goSide('Audit Logs', phoneW);
        await page.waitForSelector('.page.active[data-page="audit-logs"]');
        if (phoneW) { await page.click('.sidebar-toggle'); await page.waitForTimeout(350); }
        const elsewhere = await permTag();
        const nameElsewhere = await page.getByRole('link', { name: 'Response Policies, unsaved changes', includeHidden: true }).count();
        if (phoneW) { await page.keyboard.press('Escape'); await page.waitForTimeout(250); }
        await goSide('Response Policies', phoneW);
        await page.waitForSelector('[data-field="unsaved"]');
        const back = await page.evaluate(() => { const r = document.querySelector('[data-field="unsaved"]').getBoundingClientRect(); return { line: document.querySelector('[data-field="unsaved"]').textContent.trim(), top: Math.round(r.top), bottom: Math.round(r.bottom), vh: innerHeight, scrollY: Math.round(window.scrollY + (document.querySelector('.main')?.scrollTop ?? 0)) }; });
        check(wname, 'F05 draft', 'with nothing edited the line reads "No unsaved changes", there is no Unsaved tag in the menu and closing the tab is not interrupted; one edit (Whitelist kill_process) makes it "1 unsaved change", adds the tag and the tab-close prompt', cleanBefore.line === 'No unsaved changes' && cleanBefore.tag === null && cleanBefore.asks === false && withDraft.line === '1 unsaved change' && withDraft.tag.tag === 'Unsaved' && withDraft.asks === true, JSON.stringify({ cleanBefore, withDraft }));
        check(wname, 'F05 draft', 'the draft survives a switch to Action catalogue and back, and a trip to another page and back through the menu (still "1 unsaved change"), and the line is on screen without scrolling', afterTab === '1 unsaved change' && back.line === '1 unsaved change' && back.top >= 0 && back.bottom <= back.vh && back.scrollY === 0, JSON.stringify({ afterTab, back }));
        check(wname, 'F05 draft', `the menu shows an "Unsaved" tag on Response Policies while the draft is open and you are on another page${phoneW ? ' (in the phone drawer)' : ''}: a dot and the word, hidden from readers, the link named "Response Policies, unsaved changes", the label not cut off, the tag inside the screen`, elsewhere.tag === 'Unsaved' && elsewhere.hiddenFromReaders && elsewhere.name === 'Response Policies, unsaved changes' && nameElsewhere === 1 && elsewhere.labelCut === false && elsewhere.inside === true, JSON.stringify({ elsewhere, nameElsewhere }));
        await signOut();
        const withNote = await noteText();
        await page.click('[role="dialog"] button:has-text("Cancel")');
        await page.waitForTimeout(150);
        await page.locator('.perm-bar .btn', { hasText: 'Discard' }).click();
        await page.waitForTimeout(150);
        const afterDiscard = { line: await permUnsaved(), tag: (await permTag()).tag, asks: await beforeUnloadAsks() };
        await signOut();
        const withoutNote = await noteText();
        await page.click('[role="dialog"] button:has-text("Cancel")');
        await page.waitForTimeout(150);
        check(wname, 'F05 draft', 'Discard clears the draft (line, menu tag and tab-close prompt); the sign-out dialog adds "You have unsaved changes to the response policy. They will be lost." only while a draft exists', afterDiscard.line === 'No unsaved changes' && afterDiscard.tag === null && afterDiscard.asks === false && withNote === 'You have unsaved changes to the response policy. They will be lost.' && withoutNote === null, JSON.stringify({ afterDiscard, withNote, withoutNote }));
        await page.click('.perm button[aria-label="Whitelist kill_process"]');
        await page.waitForTimeout(150);
        await signOut();
        await page.click('[role="dialog"] button:has-text("Sign Out")');
        await page.waitForURL('**/login');
        await signInAs(roles.analyst);
        const analystSees = await page.evaluate(() => ({ tag: !!document.querySelector('.unsaved-tag'), asks: null }));
        analystSees.asks = await beforeUnloadAsks();
        await signOut();
        await page.click('[role="dialog"] button:has-text("Sign Out")');
        await page.waitForURL('**/login');
        await signInAs(roles.admin);
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        const nextUser = { line: await permUnsaved(), tag: (await permTag()).tag, asks: await beforeUnloadAsks(), whitelist: await page.evaluate(() => [...document.querySelectorAll('.perm [data-action]')].some(r => r.dataset.action === 'kill_process' && r.dataset.mode)) };
        check(wname, 'F05 draft', 'the draft is cleared on sign-out and never carries over: after signing out with a draft, signing in as the Analyst shows no tag and no tab-close prompt, and signing back in as the Administrator shows "No unsaved changes" with kill_process still unlisted', analystSees.tag === false && analystSees.asks === false && nextUser.line === 'No unsaved changes' && nextUser.tag === null && nextUser.asks === false && nextUser.whitelist === false, JSON.stringify({ analystSees, nextUser }));
        await page.click('.perm button[aria-label="Whitelist kill_process"]');
        await page.waitForTimeout(150);
        await goSide('Approvals', phoneW);
        await page.waitForSelector('[data-demo-panel]');
        await page.click('[data-demo-panel] button:has-text("Reset demo")');
        await page.waitForSelector('[role="dialog"]');
        // A browser "leave this page?" prompt would block the page, so one is answered and counted here
        let leavePrompted = false;
        const onPrompt = d => { leavePrompted = true; d.accept().catch(() => {}); };
        page.on('dialog', onPrompt);
        await page.click('[role="dialog"] button:has-text("Reset demo")');
        await page.waitForSelector('#approvalsSummary');
        await page.waitForTimeout(900);
        page.off('dialog', onPrompt);
        await page.goto(base + '/app/response-policies');
        await page.waitForTimeout(300);
        const resetDraft = { line: await permUnsaved(), tag: (await permTag()).tag, asks: await beforeUnloadAsks() };
        check(wname, 'F05 draft', 'Reset demo (already confirmed in its own dialog) clears the draft without the browser asking to leave the page (back to "No unsaved changes", no tag, no tab-close prompt)', !leavePrompted && resetDraft.line === 'No unsaved changes' && resetDraft.tag === null && resetDraft.asks === false, JSON.stringify({ leavePrompted, ...resetDraft }));

        // ---------- Phase 6 guidelines fixes F03 and F14: target sizes ----------
        const heightsOf = sel => page.evaluate(s => [...document.querySelectorAll(s)].filter(e => e.getClientRects().length > 0).map(e => Math.round(e.getBoundingClientRect().height)), sel);
        await page.goto(base + '/app/user-management');
        await page.waitForTimeout(300);
        const umButtons = await heightsOf('td.actions-cell .btn');
        await page.click('button:has-text("+ Add User")');
        await page.waitForSelector('[role="dialog"]');
        const checkRows = await heightsOf('[role="dialog"] .check-row');
        await page.keyboard.press('Escape');
        check(wname, 'a11y targets', 'the checkbox row in the Add user dialog (Require MFA for this user) is at least 40px tall, so its whole label is a target (WCAG 2.5.8)', checkRows.length >= 1 && checkRows.every(h => h >= 40), JSON.stringify(checkRows));
        await page.goto(base + '/app/audit-logs');
        await page.waitForTimeout(300);
        const chipHeights = await heightsOf('.audit-chip');
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(300);
        const taskLinks = await heightsOf('.task-link');
        await page.goto(base + '/app/approvals');
        await page.waitForTimeout(300);
        await page.click('.queue-item[data-record-id="APR-002"]');
        if (phone) await page.waitForSelector('[role="dialog"]');
        await page.waitForTimeout(150);
        const choiceHeights = await heightsOf('.approval-choice');
        const floor = phone ? 40 : 24;
        const sizes = { umButtons, chipHeights, taskLinks, choiceHeights };
        check(wname, 'a11y targets', phone ? 'at 390px the touch controls are 40px tall: User Management row buttons, Audit Logs filter chips, Dashboard task links and the Approvals decision choices' : 'on desktop and laptop the dense table-row and chip controls stay at 24px or more (WCAG 2.2 AA 2.5.8; the exception is written in DESIGN-SPEC)', Object.values(sizes).every(list => list.length > 0 && list.every(h => h >= floor)), JSON.stringify(sizes));

        // ---------- Motion, in both directions (Phase 6 part 1): the walk runs under reduced motion, so here each thing that moves is
        // opened under reduced motion (nothing may animate) and again without the preference (each must animate, so a gate
        // cannot silently remove one); reduced motion is switched back on afterwards, as every later check expects ----------
        const running = () => page.evaluate(() => document.getAnimations()
          .filter(a => a.playState === 'running' && a.effect && a.effect.getComputedTiming().duration >= 1)
          .map(a => `${a.constructor.name === 'CSSTransition' ? 'transition' : 'animation'} ${a.animationName ?? a.transitionProperty}`));
        const motionProbe = async mode => {
          await page.emulateMedia({ reducedMotion: mode });
          const seen = {};
          const probe = async (label, act) => { await act(); await page.waitForTimeout(40); seen[label] = [...new Set(await running())]; };
          await page.goto(base + '/app/dashboard');
          await page.waitForTimeout(300);
          await probe('bell menu', () => page.click('.icon-btn'));
          await page.keyboard.press('Escape');
          await probe('account menu', () => page.click('.user-avatar'));
          await page.keyboard.press('Escape');
          await probe('search results', () => page.fill('#globalSearch', 'siem'));
          await page.waitForSelector('#globalSearchResults [role="option"]');
          await probe('search highlight', async () => { await page.click('#globalSearchResults [role="option"]'); await page.waitForSelector('.is-highlighted'); });
          await page.goto(base + '/app/user-management');
          await page.waitForTimeout(300);
          await probe('dialog', () => page.click('button:has-text("+ Add User")'));
          await page.keyboard.press('Escape');
          if (wname === 'mobile') {
            await page.goto(base + '/app/dashboard');
            await page.waitForTimeout(300);
            await probe('phone menu drawer', () => page.click('.sidebar-toggle'));
            await page.keyboard.press('Escape');
          }
          const scrollBehavior = await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior);
          return { seen, scrollBehavior };
        };
        const calm = await motionProbe('reduce');
        const lively = await motionProbe('no-preference');
        await page.emulateMedia({ reducedMotion: 'reduce' });
        const restored = await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches);
        const motionWhere = Object.keys(calm.seen);
        check(wname, 'motion all', `under reduced motion nothing animates or transitions after each of: ${motionWhere.join(', ')}; scrolling is instant`, motionWhere.length === (wname === 'mobile' ? 6 : 5) && motionWhere.every(k => calm.seen[k].length === 0) && calm.scrollBehavior === 'auto', JSON.stringify(calm));
        const wantMotion = { 'bell menu': 'animation dropdownIn', 'account menu': 'animation dropdownIn', 'search results': 'animation dropdownIn', 'search highlight': 'animation highlightPulse', dialog: 'animation modalIn', 'phone menu drawer': 'transition transform' };
        check(wname, 'motion all', 'without the preference each of them does animate (a menu drops in, the highlight pulses, the dialog and its backdrop fade in, the phone drawer slides) and scrolling is smooth, so no gate has quietly removed one', motionWhere.every(k => lively.seen[k].includes(wantMotion[k])) && lively.seen.dialog.includes('animation fadeIn') && lively.scrollBehavior === 'smooth', JSON.stringify(lively));
        check(wname, 'motion all', 'reduced motion is switched back on after the no-preference walk (the media query matches again)', restored === true, String(restored));

        // Back to the analyst for what follows
        await signOutInApp();
        await signInInApp(roles.analyst);

        // logout ConfirmModal uses the same hook
        await page.goto(base + '/app/dashboard');
        await page.waitForTimeout(200);
        await dialogKeyboard(wname, 'Logout confirm', async () => {
          await page.click('.user-avatar');
          await page.click('.drop-item:has-text("Logout")');
        });
        check(wname, 'C8 modal', 'Logout confirm: Escape keeps you signed in', page.url().includes('/app/'));
      }

      // I7: keyboard focus ring visible on a button
      await page.goto(base + '/app/dashboard');
      await page.waitForTimeout(200);
      // Tab until a button has focus, then until the search input does.
      let ring = null;
      let glow = null;
      for (let i = 0; i < 30 && !(ring && glow); i++) {
        await page.keyboard.press('Tab');
        const info = await page.evaluate(() => { const el = document.activeElement; const cs = getComputedStyle(el); return { tag: el.tagName, text: (el.getAttribute('aria-label') || el.textContent).trim().slice(0, 30), outline: cs.outlineStyle + ' ' + cs.outlineWidth, shadow: cs.boxShadow }; });
        if (!ring && info.tag === 'BUTTON') ring = info;
        if (!glow && info.tag === 'INPUT') glow = info;
      }
      check(wname, 'I7 focus', `${rname}: keyboard-focused button shows 2px ring`, ring && /solid 2px/.test(ring.outline), JSON.stringify(ring));
      check(wname, 'I7 focus', `${rname}: focused input shows visible glow`, glow && /rgba\(232, 52, 76/.test(glow.shadow), JSON.stringify(glow));
    }
  }

  // I3: one colour per status word, across every page and both widths
  for (const [text, colors] of Object.entries(pillColors)) {
    const list = Object.keys(colors);
    check('both', 'I3 tones', `"${text}" has one colour everywhere`, list.length === 1, list.map(c => `${c} on ${[...new Set(colors[c])].join(', ')}`).join(' | '));
  }
  const toneOf = t => Object.keys(pillColors[t] || {})[0];
  check('both', 'I3 tones', '"Open" is amber (warn) on both Alerts and Cases', toneOf('Open') && toneOf('Open') === 'rgb(58, 35, 18)' && Object.values(pillColors.Open)[0].some(p => p.includes('alerts')) && Object.values(pillColors.Open)[0].some(p => p.includes('cases')), JSON.stringify(pillColors.Open));
  check('both', 'I3 tones', '"Low" severity is neutral', toneOf('Low') === 'rgb(58, 26, 30)', toneOf('Low'));
  check('both', 'I3 tones', '"Medium" severity is caution yellow (not info blue)', toneOf('Medium') === 'rgb(51, 39, 14)', toneOf('Medium'));
  check('both', 'I3 tones', '"High" severity is orange (warn)', toneOf('High') === 'rgb(58, 35, 18)', toneOf('High'));
  check('both', 'I3 tones', '"Critical" stays red', toneOf('Critical') === 'rgb(58, 18, 24)', toneOf('Critical'));

  return JSON.stringify({ total: results.length, failed: results.filter(r => !r.pass), results, pillColors, errors: [...new Set(errors)] });
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

// On Windows playwright-cli is a .cmd/.ps1 shim, so it needs a shell, and
// arguments must then be quoted by hand.
const useShell = process.platform === 'win32'
const quote = (value) => (useShell ? `"${value}"` : value)

function playwrightCli(args) {
  const result = spawnSync('playwright-cli', [`-s=${SESSION}`, ...args], {
    shell: useShell,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })

  if (result.error) {
    throw result.error
  }

  return result
}

function fail(message, code = 2) {
  console.error(`verify:ui: ${message}`)
  process.exit(code)
}

async function main() {
  try {
    const response = await fetch(BASE_URL)
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
  } catch (error) {
    fail(`dev server not reachable at ${BASE_URL} (${error.message}). Start it with "npm run dev" first.`)
  }

  mkdirSync(OUT_DIR, { recursive: true })

  const outDirForBrowser = OUT_DIR.replace(/\\/g, '/')
  const source = `async page => (${runChecks.toString()})(page)`
    .replace("'__OUT_DIR__/'", JSON.stringify(`${outDirForBrowser}/`))
    .replace("'__BASE_URL__'", JSON.stringify(BASE_URL))
    .replace("'__EXACT_WAITS__'", JSON.stringify(process.env.VERIFY_UI_EXACT_WAITS === '1' ? 'yes' : 'no'))

  const scriptFile = join(tmpdir(), `verify-ui-${process.pid}.js`)
  writeFileSync(scriptFile, source)

  console.log(`verify:ui: checking ${BASE_URL} at 1440, 1280 and 390px (takes a few minutes)…`)

  let raw = ''
  let errorText = ''
  try {
    const opened = playwrightCli(['open', quote(BASE_URL)])
    if (opened.status !== 0) {
      fail(`could not open a browser with playwright-cli. Is it installed (npm install -g @playwright/cli@latest)?\n${opened.stderr || opened.stdout}`)
    }

    const ran = playwrightCli(['--raw', 'run-code', `--filename=${quote(scriptFile)}`])

    raw = ran.stdout.trim()
    // When the run dies without a report, the reason is usually on stderr (or in the exit status)
    errorText = `exit status ${ran.status}${ran.signal ? `, signal ${ran.signal}` : ''}${ran.stderr ? `\n${ran.stderr.trim()}` : ''}`
  } finally {
    playwrightCli(['close'])
    rmSync(scriptFile, { force: true })
  }

  let report
  try {
    // --raw prints the returned string as a JSON string literal.
    report = JSON.parse(raw)
    if (typeof report === 'string') {
      report = JSON.parse(report)
    }
  } catch {
    fail(`playwright-cli did not return a report:\n${raw.slice(0, 2000)}\n${errorText.slice(0, 2000)}`, 1)
  }

  writeFileSync(join(OUT_DIR, 'report.json'), JSON.stringify(report, null, 2))

  // The time since the previous check is charged to the area of the check that ended it, and so is the
  // part of it that was fixed waits (a close approximation: the steps before a check belong to it)
  const byArea = new Map()
  let previous = { t: 0, s: 0 }
  for (const result of report.results) {
    const area = byArea.get(result.area) ?? { passed: 0, total: 0, ms: 0, waited: 0 }
    area.total += 1
    area.passed += result.pass ? 1 : 0
    area.ms += (result.t ?? previous.t) - previous.t
    area.waited += (result.s ?? previous.s) - previous.s
    previous = { t: result.t ?? previous.t, s: result.s ?? previous.s }
    byArea.set(result.area, area)
  }

  console.log('')
  for (const [area, { passed, total }] of [...byArea].sort(([a], [b]) => a.localeCompare(b))) {
    console.log(`  ${passed === total ? 'ok  ' : 'FAIL'}  ${area.padEnd(14)} ${passed}/${total}`)
  }

  // Where the time went: the slowest areas, with how much of each was fixed waits
  const timings = [...byArea].map(([area, { ms, waited }]) => ({ area, seconds: Math.round(ms / 100) / 10, waitedSeconds: Math.round(waited / 100) / 10 })).sort((a, b) => b.seconds - a.seconds)
  const lastResult = report.results[report.results.length - 1]
  writeFileSync(join(OUT_DIR, 'timings.json'), JSON.stringify({ totalSeconds: Math.round((lastResult?.t ?? 0) / 100) / 10, fixedWaitSeconds: Math.round((lastResult?.s ?? 0) / 100) / 10, areas: timings }, null, 2))
  console.log(`\n  Time: ${Math.round((lastResult?.t ?? 0) / 1000)} s in all, ${Math.round((lastResult?.s ?? 0) / 1000)} s of it fixed waits. Slowest areas: ${timings.slice(0, 8).map((x) => `${x.area} ${x.seconds}s (${x.waitedSeconds}s waits)`).join(', ')} (all in verify-ui-output/timings.json)`)

  if (report.failed.length > 0) {
    console.log('\nFailed checks:')
    for (const result of report.failed) {
      console.log(`  [${result.width}] ${result.area}: ${result.name}`)
      if (result.detail) {
        console.log(`      ${result.detail}`)
      }
    }
  }

  if (report.errors.length > 0) {
    console.log('\nBrowser console errors/warnings:')
    for (const error of report.errors) {
      console.log(`  ${error}`)
    }
  }

  const passed = report.total - report.failed.length
  console.log(`\n${passed}/${report.total} checks passed, ${report.errors.length} console errors.`)
  console.log(`Screenshots and report.json: ${OUT_DIR}`)

  process.exit(report.failed.length === 0 && report.errors.length === 0 ? 0 : 1)
}

main().catch((error) => fail(error.stack ?? String(error)))
