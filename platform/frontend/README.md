# Frontend: the AthenaSec console

React 19 · TypeScript · Vite · react-router-dom.

The web console analysts and admins use.

## Live mode and demo mode

When the page loads it asks the backend who is signed in:

- **Backend running:** live mode. Sign-in uses real accounts with two-factor codes, and the pages show the backend's alerts, cases, approvals, users, audit trail and service health.
- **Backend not running:** demo mode. The login page shows the demo accounts and the pages use the sample data in `src/data/`.

In development, `npm run dev` forwards every `/api` request to the backend at http://localhost:8000 (see `vite.config.ts`), so the session cookie works. To point it elsewhere, set `ATHENASEC_BACKEND_URL` before starting. Set `VITE_DATA_MODE=demo` to force demo mode even with a backend running.

In live mode every page reads from and saves to the backend, and every change is audited there:

| Page | What is live |
| --- | --- |
| Alerts, Cases | Close/reopen, "Assign to me", ticking a case's recommended actions |
| Incident Response | The actions the backend actually ran, with approval, result, verification and rollback |
| Approvals | Pending requests and the approve/reject decision |
| Response Policies | The whitelist and blacklist the agent enforces |
| User Management | Create, edit, suspend/reactivate, delete, reset password, reset two-factor. A new account or a reset shows the one-time sign-in details (temporary password and/or a QR code for the authenticator app). Someone signing in with a temporary password must choose their own before the console opens. |
| Configuration | System values; the correlation window is used by alert correlation |
| Settings, Profile | Saved per account; Profile also has Change password and your real sign-in activity |
| System Health, Service Panel | The backend's real health checks (Refresh / Check run them again) |
| Audit Logs | The backend's tamper-evident audit trail |

A change the backend refuses is put back on screen and the reason shown at the bottom right.

What live mode cannot show, because the backend does not have it: the VM's processor, memory and disk figures (the desktop Service Panel on the VM shows them), and notification delivery (the choices are saved; sending them is not connected). Demo-only tools (the audit tamper demo, the approval-flow demo controls) are hidden in live mode.

## Run it

```
npm install
npm run dev         http://localhost:5173
npm run build       type-check and production build
npm run lint
```

Demo mode logins: `analyst@athenasec.com` / `analyst123`, `admin@athenasec.com` / `admin123`, code `123456`.

## Folders

| Folder | What it is |
| --- | --- |
| `src/App.tsx` | Routing, sign-in, and choosing live or demo mode. |
| `src/api/` | Talking to the backend: `client.ts` (requests, session, CSRF), `apiTypes.ts` (backend shapes), `adapters.ts` (backend records to page records). |
| `src/components/LiveDataProvider.tsx` | Loads alerts, cases, users, audit and health from the backend every 30 seconds. |
| `src/components/LiveApprovals.tsx` | The Approvals page in live mode: real requests, approve or reject. |
| `src/pages/` | One file per page: dashboards, alerts, cases, approvals, response policies, audit logs, users, settings. |
| `src/components/` | Shared building blocks: layout (sidebar, top bar), badges, tables, dialogs, and the state providers. |
| `src/data/` | Sample data for demo mode. |
| `src/hooks/` | Shared React hooks and contexts. |
| `src/types/` | TypeScript types. |
| `src/utils/` | Small helper functions. |
| `src/styles/` | CSS. |
| `public/` | Static files served as-is. |
| `scripts/` | Browser checks (`npm run verify:ui`, `verify:policy`, `verify:panel`). Needs the dev server running. |
| `design/` | The agent action policy PDF and its open gaps, and `website-logic.md`, which explains how the pages and data fit together. |
| `src/styles/athenasec.css` | The whole look: purple and charcoal colour tokens at the top, then layout and components. Change colours here. |
| `CLAUDE.md` | Notes for Claude Code when working in this folder. |
