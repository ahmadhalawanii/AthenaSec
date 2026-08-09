# AthenaSec Website Logic

## Purpose

This document explains how the current AthenaSec React frontend works, how its files and pages are connected, where its data comes from, and which behaviors are real versus simulated.

The current application is a high-fidelity frontend prototype. It does not currently communicate with a backend, database, external security platform, or fake API server.

## 1. Current architecture

```text
Browser
  |
  v
index.html
  |
  v
src/main.tsx
  |
  v
src/App.tsx
  |-- LoginPage -> MfaPage -> authenticated application
  |
  `-- AppLayout
        |-- TopBar
        |-- Sidebar
        `-- selected page component
```

The application uses:

- Vite to run and build the frontend.
- React to render components and update the interface.
- TypeScript for types and compile-time checks.
- React state for temporary page data and user interactions.
- `localStorage` only for the authenticated demo user and selected page.
- CSS files for the complete visual design and targeted layout fixes.

It does not use:

- A backend server.
- A database.
- REST or GraphQL endpoints.
- `fetch` or Axios.
- A mock API server such as MSW, JSON Server, or MirageJS.
- WebSockets.
- React Router.
- A shared application state library.

## 2. Application startup

### `src/main.tsx`

`main.tsx` is the frontend entry point.

It performs these actions:

1. Imports React and `createRoot`.
2. Imports the four CSS files in override order.
3. Imports `App.tsx`.
4. Finds the HTML element with the ID `root`.
5. Throws an error if the root element does not exist.
6. Renders `<App />` inside React `StrictMode`.

CSS import order:

```text
athenasec.css
  -> react-stability.css
  -> integrations-table-fix.css
  -> user-management-table-fix.css
```

Later stylesheets can override earlier rules. The final two files specifically correct action-column clipping in their respective tables.

## 3. Root application controller

### `src/App.tsx`

`App.tsx` is the main controller. It owns authentication, the active role, the selected application page, persistence, and top-level rendering.

### Main state

| State | Purpose |
|---|---|
| `currentUser` | The currently authenticated demo user, or `null` |
| `appView` | Selects `login`, `mfa`, or `app` |
| `currentPage` | Selects the page rendered inside the application layout |
| `pendingUser` | Holds a matched demo account while MFA is pending |

### Demo accounts

The analyst and administrator credentials are declared directly in `App.tsx`. Login searches this in-memory array. No request leaves the browser.

### Startup restoration

When React starts, `readStoredUser()` reads `athenasec-authenticated-user` from `localStorage`. It parses the JSON and verifies that the value has a string email, string name, and one of the two recognized roles.

Invalid stored data is deleted. A valid stored user causes the application to open directly in the authenticated view.

`readStoredPage()` reads `athenasec-current-page`. It checks the page against the current role's allowlist. An invalid or unauthorized page falls back to `dashboard`.

### Authentication flow

```text
LoginPage submits email and password
  |
  v
App.handleLogin()
  |
  |-- credentials do not match -> return false -> login error
  |
  `-- credentials match
        |-- store account in pendingUser
        `-- change appView to mfa
                |
                v
          MfaPage checks 123456
                |
                v
          App.handleMfaVerify()
                |-- create currentUser
                |-- clear pendingUser
                |-- select dashboard
                |-- change appView to app
                `-- write user and page to localStorage
```

The MFA check is performed inside `MfaPage`; `App.handleMfaVerify()` trusts that callback. This is suitable only for a demonstration.

### Logout

`logout()` clears the user, pending user, and active page state. It returns the view to login and removes both AthenaSec keys from `localStorage`.

### Role access

`App.tsx` contains separate analyst and administrator page allowlists. Every call to `navigate(page)` checks the requested page against the current role. Unauthorized or unknown page IDs are changed to `dashboard`.

This protects navigation inside the prototype, but it is not real security. Browser-side role checks can be modified by a user. A production backend must authorize every request and action.

### Page selection

There are no browser routes. `renderCurrentPage()` uses a `switch` on `currentPage` and returns the corresponding page component. Consequently:

- The URL does not change between pages.
- Browser Back and Forward do not navigate between AthenaSec pages.
- A page cannot be bookmarked directly.
- Every page component is imported into the main application bundle.

## 4. Shared application layout

### `src/components/AppLayout.tsx`

`AppLayout` receives the role, user name, current page, navigation callback, logout callback, and currently selected page as `children`.

It creates the common authenticated screen:

```text
Application label
Screen container
  |-- TopBar
  `-- Body
       |-- Sidebar
       `-- Main content
            `-- current page component
```

### `src/components/Sidebar.tsx`

The sidebar uses the role to choose its navigation buttons.

Analyst navigation:

- Dashboard
- Alerts
- Case Management
- Incident Response
- Profile
- Logout

Administrator navigation:

- Dashboard
- Configuration
- Detection Rules
- Response Policies
- Integrations
- User Management
- Audit Logs
- System Health
- Settings
- Profile
- Logout

The current page receives the `active` CSS class. Clicking a page calls the navigation callback owned by `App.tsx`; the sidebar does not render pages itself.

### `src/components/TopBar.tsx`

The top bar contains:

- A logo button that navigates to the dashboard.
- A static system-online indicator.
- A global-search input that is currently visual only.
- A notification dropdown with hard-coded notification text.
- A user dropdown for Profile, administrator Settings, and Logout.

Only the dropdown open/closed state is stored in `TopBar`. Notifications are not fetched, and the global search is not connected to page datasets.

## 5. Authentication pages

### `LoginPage.tsx`

The login page stores email, password, and error text in local component state. Submitting calls the `onSignIn` function supplied by `App.tsx`. The Remember Me and forgot-password controls do not implement real account functionality.

### `MfaPage.tsx`

The MFA page stores six input digits in an array. It filters input to digits, advances focus, supports moving backward, joins the digits, and accepts the hard-coded code `123456`. Resend displays a browser alert; it does not send a message.

## 6. Analyst pages

### `AnalystDashboardPage.tsx`

The dashboard contains a hard-coded alert array plus static summary and chart values. Search and severity filters derive `filteredAlerts` with `useMemo`. Selecting an alert opens its details. Severity cards update the local severity filter.

### `AlertsPage.tsx`

`initialAlerts` is declared in the source file and copied into React state. The page supports attack-type filtering, risk-band filtering, risk sorting, a detail drawer, and local status toggling.

Changing an alert status updates only that page's in-memory `alerts` state. It does not update the analyst dashboard's separate alert array and is lost if the page component is unmounted or the browser reloads.

### `CasesPage.tsx`

`initialCases` includes each case's overview, evidence, recommended actions, MITRE mapping, and timeline. Search, severity, and status filters produce a derived visible list. The page can open a case drawer and toggle a case between Open and Closed.

Changes exist only in this component's state and are not written to storage or shared with another page.

### `IncidentResponsePage.tsx`

The page contains hard-coded response-execution records and timelines. Search, action, result, and approval filters select visible records. Clicking an execution opens its detail drawer. These records are display-only and do not execute security actions.

## 7. Administrator pages

### `AdminDashboardPage.tsx`

The page displays hard-coded integration states, recent administrative activity, metrics, and system summaries. Its action cards call the `onNavigate` callback to open the relevant administrator page. Dashboard values are not calculated from the other page components.

### `ConfigurationPage.tsx`

The page keeps two copies of configuration data:

- Saved configuration.
- Editable form configuration.

`hasUnsavedChanges` compares the two. Save validates numeric and retention-related fields before replacing the saved copy. Cancel restores the last saved copy, while Restore Defaults loads predefined values. All saved values remain only for the lifetime of the mounted component.

### `DetectionRulesPage.tsx`

`initialRules` is the page's starting dataset. The component owns filters, modal mode, selected rule, form values, validation errors, and feedback messages.

It simulates:

- Adding a rule.
- Editing a rule.
- Viewing details.
- Enabling or disabling a rule.
- Deleting a rule.
- Filtering and searching.

Add operations generate an ID in browser code. Nothing is sent to a rule engine or backend.

### `ResponsePoliciesPage.tsx`

This page follows the same local CRUD pattern as Detection Rules. It stores policy records, filters, modal state, the selected policy, and an editable form. It parses an action list, validates fields, and simulates add, edit, view, enable/disable, and delete operations.

The policies do not trigger real response actions.

### `IntegrationsPage.tsx`

`initialIntegrations` is hard-coded. The page supports searching, status filtering, a details panel, connect/disconnect toggling, individual sync simulation, and testing all connections.

Timers are used to imitate asynchronous work. They update the local status, last-sync text, and page messages after a delay. No connection is made to Wazuh, OpenSearch, TheHive, Suricata, Ollama, MISP, or another service.

### `UserManagementPage.tsx`

`initialUsers` supplies the local user list. The page simulates adding, editing, viewing, suspending/reactivating, password resetting, and deleting users. It also provides search, role filtering, status filtering, form validation, modal state, and user feedback.

These users are separate from the demo accounts in `App.tsx`. Adding or editing a user here does not create login credentials and cannot change the active session.

### `AuditLogsPage.tsx`

Audit entries are hard-coded in `auditLogs`. The page filters by search text, category, result, and user, and opens a detail drawer. Export creates a CSV file from the currently visible browser data.

The export is a real client-side file operation, but the audit records themselves are not generated by application actions and are not stored by a server.

### `SystemHealthPage.tsx`

Metrics, services, and health events start from hard-coded arrays. Helper functions translate numeric values and statuses into labels and CSS classes. Search and status filters derive the visible service list.

Refresh, check-service, and check-all operations use timers and generated frontend values to simulate health checks. They do not contact real services.

### `SettingsPage.tsx`

The page maintains saved settings and an editable form. It detects drafts, validates dependencies between settings, saves locally, cancels changes, restores defaults, and coordinates notification and MFA toggles.

The theme and language values do not currently reconfigure the application globally. Settings are not persisted after the component is destroyed or the browser reloads.

### `ProfilePage.tsx`

`App.tsx` passes the active user's name, email, and role into this page. The page constructs saved and editable profile values, detects changes, validates the form, saves locally, cancels changes, or restores the original values.

Editing the profile does not update `App.tsx`, the top-bar name, the stored authenticated user, or User Management. The changes are isolated to the Profile component.

## 8. State and data ownership

The application has two different state scopes.

### Application-level state

Owned by `App.tsx`:

- Authenticated demo user.
- Pending MFA user.
- Authentication screen.
- Current page.

Only the authenticated user and current page are persisted to `localStorage`.

### Page-level state

Owned separately by each page:

- Tables and records.
- Filters and searches.
- Selected details.
- Modal or drawer visibility.
- Editable forms.
- Simulated status changes.
- Feedback messages.

Page data is not centralized. Similar objects on different pages are separate copies. For example, changing an alert on `AlertsPage` does not update an alert shown on `AnalystDashboardPage`, a case, an audit entry, or a dashboard statistic.

## 9. Modal and drawer logic

Several pages use `createPortal(..., document.body)` to render overlays outside the normal layout hierarchy. This prevents drawers and modals from being clipped by parent containers.

The usual pattern is:

1. Store the selected record or modal mode in state.
2. Render the portal only when that state is set.
3. Close when the backdrop is clicked.
4. Stop click propagation inside the dialog.
5. Close using an explicit close button.

The pattern is repeated per page rather than implemented as shared Modal and Drawer components.

## 10. Styling logic

### `athenasec.css`

This is the main design system and layout file. It defines the dark theme, authentication screens, shell, top bar, sidebar, grids, cards, tables, pills, charts, forms, dropdowns, modals, drawers, responsive rules, and animations.

### `react-stability.css`

This overrides animations and layout behavior that caused rows or pages to jump when React filtering or state changes triggered rerenders.

### `integrations-table-fix.css`

This gives the Integrations table enough width and correct overflow/action-column behavior so its buttons remain visible.

### `user-management-table-fix.css`

This applies the corresponding correction to the User Management table.

## 11. What is real and what is simulated

| Feature | Current implementation |
|---|---|
| React rendering | Real |
| Form validation | Real browser-side logic |
| Search, filters, and sorting | Real, over local arrays |
| Drawers and modals | Real UI behavior |
| CSV export | Real client-side file generation |
| Page restoration | Real `localStorage` behavior |
| Login | Hard-coded browser comparison |
| MFA | Hard-coded browser comparison |
| Role authorization | Browser-only allowlist |
| Alerts and cases | Hard-coded mock records |
| CRUD actions | In-memory simulation |
| Integration sync | Timer-based simulation |
| System health | Timer/value simulation |
| Notifications | Hard-coded display content |
| Global search | Visual control only |
| Database persistence | Not implemented |
| API communication | Not implemented |
| External integrations | Not implemented |

## 12. Why some page files are large

The page files are large mainly because each one combines several responsibilities:

- Type definitions.
- Large hard-coded datasets.
- Filtering and mutation logic.
- Form state and validation.
- Modal and drawer state.
- Full table and detail markup.
- Feedback messages and simulated operations.

The lack of a database contributes indirectly, but a database alone would not make the files small. The immediate cause is that mock records and many UI responsibilities are embedded in the same component files.

An API would remove large data literals from the frontend, but the components should also be split into reusable modules. A cleaner structure would separate:

```text
features/alerts/
  |-- api.ts
  |-- types.ts
  |-- AlertTable.tsx
  |-- AlertFilters.tsx
  |-- AlertDrawer.tsx
  `-- AlertsPage.tsx
```

The same pattern can be used for cases, rules, policies, integrations, users, audit logs, and system health.

## 13. Recommended future data flow

```text
Page component
  |
  v
API/query module
  |
  v
AthenaSec backend
  |-- authentication and authorization
  |-- validation and business logic
  |-- audit generation
  |-- integration adapters
  |
  +-- PostgreSQL for users, cases, policies, settings
  +-- OpenSearch for alerts and telemetry
  +-- Redis for cache, jobs, and rate limits
  `-- Wazuh/TheHive/Suricata/Ollama/MISP integrations
```

During backend development, a fake API layer can be introduced before real services exist. For example, MSW can intercept requests in development while keeping page code written against the final API contract. That would be different from the current implementation because pages would call API modules instead of importing hard-coded arrays directly.

## 14. Important current limitations

- Refresh persistence proves only that a browser value exists; it does not prove a valid server session.
- Users can alter `localStorage` and browser JavaScript.
- Page-level changes generally disappear when the page unmounts or reloads.
- Duplicate datasets can become inconsistent across pages.
- Dashboard totals are not derived from page records.
- User Management is not connected to authentication.
- Profile edits are not connected back to the application user.
- Settings do not affect the whole application.
- Simulated integration and health operations do not verify external systems.
- There are no loading, network-error, retry, caching, or server-conflict states because there is no network data layer.

## 15. Summary

The site is linked correctly as a React frontend prototype: `main.tsx` starts `App.tsx`; `App.tsx` controls authentication and page selection; `AppLayout` connects the shared top bar and sidebar; and each page owns its own interactive logic and mock records.

The current system uses hard-coded mock data and local React simulations. It is not already using a fake API system. The next architectural step should be to define API contracts, add an API/query layer, and then connect that layer either to a development mock server or to the real backend.
