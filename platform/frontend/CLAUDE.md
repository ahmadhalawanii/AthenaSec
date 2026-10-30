# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

AthenaSec frontend: a high-fidelity, front-end-only prototype of a SOC/security operations console (React 19 + TypeScript + Vite + react-router-dom v7). There is no backend integration yet. There is no backend directory, and nothing in the app calls `fetch`. All data is mocked in `src/data/` and held in component state, so it resets on reload.

## Commands

```sh
npm run dev       # Vite dev server with HMR
npm run build     # tsc -b (type-check) then vite build
npm run lint      # eslint .
npm run preview   # serve the production build
npm run verify:ui # browser checks against the running dev server (see below)
```

The dev server runs at http://localhost:5173.

There is no unit-test framework. `npm run build` is the type-check gate, and `npm run verify:ui` is the UI regression check. `tsconfig.app.json` enables `noUnusedLocals` and `noUnusedParameters`, so unused imports or variables fail the build.

## Editing files

Modify project files only with the Edit or Write tools. Never write to project files from shell commands or scripts (node -e, python -c, PowerShell, sed, redirects, etc.).

## Architecture

**Auth and routing all live in `src/App.tsx`.** Login is simulated:
- `/login` checks credentials against `DEMO_ACCOUNTS` in `src/data/loginData.ts` (`analyst@athenasec.com` / `analyst123`, `admin@athenasec.com` / `admin123`).
- A successful login sets `pendingUser` and routes to `/mfa`. Any MFA "verify" promotes that user to `currentUser`, which is saved to localStorage under `AUTH_STORAGE_KEY`.
- On load, `readStoredUser()` validates the stored user and clears it if it's malformed.
- `/app/*` renders `AppLayout` (TopBar + Sidebar + `<main>`) with nested routes.
- Logout goes through the shared `ConfirmModal`, using `LOGOUT_CONFIRMATION`.

**Role-based access.** There are two roles, `Analyst` and `Administrator`, and each has its own page set:
- Analyst: alerts, cases, incident
- Administrator: configuration, detection-rules, response-policies, integrations, user-management, audit-logs, system-health, settings
- Both: dashboard and profile. `/app/dashboard` renders `AdminDashboardPage` or `AnalystDashboardPage` depending on role.

To add a page, update all of these together:
1. The route in `App.tsx`, wrapped in the role check that redirects to `/app/dashboard`.
2. The `analystPages` / `adminPages` lists in `src/data/appData.ts`. The notifications use these to link only to pages the role can open.
3. The nav entries in `src/components/Sidebar.tsx`.

**Per-feature file triad.** Each feature is split across three files with matching names:
- `src/pages/XPage.tsx`: the component, which holds its own `useState`/`useMemo` for filtering, search and view state. Records that other parts of the app show (the dashboards, global search, sidebar badges, top bar, audit log) live in shared state instead: `SocStateProvider` / `useSocState()` for the analyst side and `AdminStateProvider` / `useAdminState()` for the admin side, both mounted in `AppLayout`. Every admin change through `useAdminState()` also records an audit event with old → new values.
- `src/data/xData.ts`: seed records and static copy.
- `src/types/xTypes.ts`: the record types.

Keep new mock data and types in this layout instead of inlining them in pages. Shared app-level types (`Role`, `AuthenticatedUser`, `DemoAccount`) are in `src/types/appTypes.ts`.

**Page markup conventions.** Each page's root is `<section className="page active" data-page="<route-slug>">`. Modals and drawers render through `createPortal` to `document.body` so they aren't clipped by the scrolling main area.

## Styling

Styling is plain global CSS (no CSS modules, Tailwind or CSS-in-JS). All four stylesheets are imported in `src/main.tsx`, and the import order matters:
- `athenasec.css`: the main design system (layout classes such as `.screen`, `.body`, `.main`, `.page`, plus badges like `danger`/`warn`/`ok`/`blue`, tables and buttons).
- `react-stability.css`: overrides that stop layout jumps when React re-renders tables during filter, sort or search, e.g. `scrollbar-gutter`, and turning off the page animations inherited from the original static prototype.
- `integrations-table-fix.css` and `user-management-table-fix.css`: page-specific fixes scoped with `.page[data-page="..."]` selectors.

Page-specific overrides should follow the same `data-page` scoping pattern.

## Verifying visual changes

Run the UI check after any visual or behavioural change:

```sh
npm run dev          # terminal 1: the check needs the dev server running
npm run verify:ui    # terminal 2: takes a few minutes
```

- **Prerequisite:** the `playwright-cli` command on PATH (`npm install -g @playwright/cli@latest`). The script uses its own browser session (`-s=verify-ui`), so it won't disturb a browser you already have open.
- **What it covers:** both demo roles, every page they can see, at 1440px, 1280px and 390px. It checks navigation, the sidebar drawer and the sticky mobile header, status accuracy, tables (pinned actions, clipping, scroll cue), the User Management "⋯" row menu (keyboard, focus return, disabled own-account actions), dialogs (Escape, focus trap, focus return), labels, focus rings, global search, copy (no developer wording), status colours, button variants, derived dashboard stats, the self-hosted font and the severity chart.
- **Output:** a pass count per area, every failed check with its detail, and any browser console errors or warnings. Screenshots and a full `report.json` go to `verify-ui-output/` (gitignored). Look at the screenshots as well: the numbers have missed visual problems before.
- **Exit code:** 0 when every check passes and the console is clean, 1 on any failure, 2 if setup fails (dev server not running, `playwright-cli` missing).
- **Options:** `VERIFY_UI_BASE_URL` (default `http://localhost:5173`) and `VERIFY_UI_OUT_DIR`.
- **Adding checks:** edit `runChecks()` in `scripts/verify-ui.js` and call `check(width, area, name, pass, detail)`. `runChecks` is serialised and run inside `playwright-cli run-code`, so it must stay self-contained (no imports, no references outside the function).

For a quick look at a single page, the `playwright-cli` skill also works directly. Most pages are behind the login, so sign in with a demo account for the role that can see the page.
