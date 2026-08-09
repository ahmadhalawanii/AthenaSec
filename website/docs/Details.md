# AthenaSec Code Details

This project is a static high-fidelity prototype for an AthenaSec security operations console. It is made from three main files:

- `index.html` contains every visible screen, form, table, button, demo row, and page section.
- `css/styles.css` contains the visual design, layout, cards, tables, forms, animations, modals, and responsive rules.
- `js/app.js` contains all interactive behavior: login, MFA, role access, navigation, filtering, global search, modals, and demo actions.

There is no backend in this prototype. All users, alerts, incidents, rules, integrations, and settings are demo data stored directly in the HTML or JavaScript. The app behaves like a multi-page SOC console, but it is really one HTML page where JavaScript hides and shows sections.

## Overall Flow

When `index.html` opens, the browser loads the CSS file first and then runs `js/app.js` at the bottom of the body.

The user starts on the login screen. After a valid demo email and password, the app moves to the MFA screen. After the demo MFA code is entered, the authenticated app shell appears.

Demo accounts:

- Analyst: `analyst@athenasec.com` / `analyst123`
- Administrator: `admin@athenasec.com` / `admin123`
- MFA code: `123456`

The logged-in role controls which pages are visible. Analysts see operational SOC pages. Administrators also see management and configuration pages.

## `index.html`

`index.html` is the main structure of the whole prototype. It contains the authentication views, the app frame, the navigation, the sidebar, all content pages, and the modal root.

### Document Setup

- `<!DOCTYPE html>` enables modern browser rendering.
- `<html lang="en">` marks the page language as English.
- The `<head>` defines character encoding, mobile viewport scaling, the page title, and the stylesheet link.
- `<link rel="stylesheet" href="css/styles.css">` loads all styling.
- `<script src="js/app.js"></script>` loads the behavior after the HTML has been created.

### Authentication Area

The authentication views are wrapped inside `#authViews`. This wrapper contains `#loginView` and `#mfaView`.

`#loginView` is the first screen. It has a left hero panel with AthenaSec branding and a right form panel. The login form includes email, password, Remember Me, Forgot Password, and Sign In controls.

Important login elements:

- `loginForm`: JavaScript listens for submit events here.
- `loginEmail`: email input.
- `loginPassword`: password input.
- `rememberMe`: controls whether the email is stored in `localStorage`.
- `loginError`: hidden error box shown when credentials are wrong.
- `data-action="forgot-password"`: opens a demo modal.

`#mfaView` starts hidden with the `hidden` class. It appears after correct login credentials. It contains six one-character MFA inputs and a submit button.

Important MFA elements:

- `mfaForm`: JavaScript listens for submit events here.
- `mfaError`: hidden error box shown when the MFA code is wrong.
- `data-mfa-digit`: marks each digit input so JavaScript can collect the full code and auto-focus the next box.
- `data-action="resend-code"`: opens a modal saying to keep using `123456`.

### Main App Shell

The authenticated app is inside `#appShell`. It starts hidden and becomes visible only after MFA succeeds.

The shell contains the workspace label, `.screen` app frame, `.topbar`, `.sidebar`, `#mainContent`, and `#modal-root`.

### Navigation, Search, and Menus

The top bar includes the AthenaSec logo, major navigation buttons, global search, notification dropdown, and user dropdown.

Navigation buttons use `data-page-link`, for example `data-page-link="dashboard"`. JavaScript reads this value and activates the matching page section.

Some navigation items use `data-admin-only`. JavaScript hides these from Analysts and shows them for Administrators.

The search input is `#globalSearch`. Its results are shown in `#searchResults`. Searchable pages and records are marked with `data-search-page` and `data-search-record`. JavaScript builds search results from those marked elements.

The notification dropdown and user dropdown start hidden. The user menu contains Profile, Settings for admins, and Logout. Logout uses `data-action="logout"`, which opens a confirmation modal before ending the session.

### Sidebar

The sidebar contains page links for the app. It repeats many top navigation destinations and includes extra pages such as Alert Details, AI Analysis, Response Activity, Endpoints, Detection Rules, Integrations, Audit Logs, Settings, Profile, and Logout.

The sidebar title changes by role: Analysts see `Analyst`, while Administrators see `Security Management`.

### Page System

Every application page is a `<section class="page">` inside `#mainContent`.

Only one page is visible at a time. CSS hides `.page` by default and shows `.page.active`. JavaScript moves the `active` class when navigation happens.

Each page has a `data-page` ID, such as `dashboard`, `alerts`, or `system-health`. Navigation links point to these IDs using `data-page-link`.

### Dashboard Page

The Dashboard page is active by default. It contains two role-specific dashboard views: `data-role-view="Analyst"` and `data-role-view="Administrator"`.

The Analyst dashboard shows SOC status, alert counts, critical alerts, open incidents, AI actions, an alert severity chart, endpoint status, and recent alert filtering.

The Administrator dashboard shows management-focused stats and shortcut cards for Configuration, Detection Rules, and System Health.

Dashboard alert rows use `data-dashboard-alert` and `data-severity`. JavaScript uses those attributes to filter recent alerts by text and severity.

### Alerts Page

The Alerts page contains an advanced alert table.

Important controls:

- `attackFilter`: filters by attack type.
- `riskFilter`: filters by risk band.
- `riskSort`: sorts by risk score.
- `visibleAlertCount`: displays how many rows are visible.
- `alertsTableBody`: contains alert rows.

Each alert row has attributes such as `data-alert-id`, `data-attack`, `data-risk`, and `data-risk-band`. JavaScript uses these to filter, sort, and open alert details.

The View buttons use `data-action="view-alert"` and `data-alert-id`. Clicking one selects that alert and opens Alert Details.

### Alert Details Page

The Alert Details page contains multiple panels, one per alert, marked with `data-alert-detail`. JavaScript shows only the selected alert's panel and hides the others.

The main `ALT-001` panel includes alert summary, threat intelligence, AI summary, policy decision, executed actions, and a timeline. It also has buttons for creating a case, closing the alert, viewing logs, and opening the timeline.

### AI Analysis Page

The AI Analysis page contains panels marked with `data-ai-alert`. These are synchronized with the selected alert.

The main AI panel explains the AI summary, threat classification, reasoning, policy used, suggested actions, executed actions, MITRE ATT&CK mapping, and threat intelligence references.

### Incidents Page

The Incidents page provides incident management. It includes incident stats, filters, a queue table, an incident overview panel, a note textarea, and a current notes list.

Important elements:

- `incidentSearch`: text filter.
- `incidentSeverity`: severity filter.
- `incidentStatus`: status filter.
- `incidentRows`: incident table body.
- `incidentOverview`: area filled dynamically when an incident is selected.
- `incidentNote`: note textarea.
- `incidentNotes`: notes list.

Incident rows use `data-incident-id`, `data-severity`, and `data-status`.

### Other Analyst Pages

Response Activity shows response actions such as blocking IPs, creating cases, isolating endpoints, and capturing telemetry. Rows are searchable because they use `data-search-record`.

Endpoints lists hosts, IPs, operating systems, statuses, isolation state, and last seen time. Buttons allow the user to view endpoint details, isolate an endpoint, or reconnect it.

Profile is available to both roles. JavaScript fills the account details, role, display name, and phone fields from the current logged-in user. Saving updates the current user object and refreshes the profile display.

### Admin Pages

The admin-only pages use `data-admin-only` and are protected by JavaScript access checks.

- Configuration: editable-looking settings cards. Save marks config as `Saved`; Cancel opens a discarded-changes modal.
- Detection Rules: rule search, status filtering, Add Rule, Edit, Enable/Disable, and Delete actions.
- Response Policies: AI response policy cards with `IF` conditions and `THEN` actions.
- Integrations: connected services such as Wazuh, OpenSearch, TheHive, Cortex, Suricata, Ollama, LangGraph, and Zeek. Sync changes status to Connected and last sync to `Just now`.
- User Management: Add User, Edit User, Disable/Enable User, and Reset Password actions.
- Audit Logs: searchable audit trail with visual pagination controls.
- System Health: CPU, memory, storage, network, service, endpoint, alert, and case metrics.
- Settings: theme, language, notifications, session timeout, and MFA controls.

## `css/styles.css`

The CSS file creates the full visual system for the prototype.

### Global Styles

The universal selector resets margins and padding and uses `box-sizing: border-box`. The body uses a dark navy background, light text, and the Inter/Segoe UI/Arial font stack.

### Layout

Important layout classes:

- `.section`: full-screen outer section.
- `.screen`: rounded app frame with border and shadow.
- `.topbar`: horizontal navigation.
- `.body`: sidebar plus main content layout.
- `.sidebar`: left navigation.
- `.main`: scrollable content area with subtle radial background.

### Navigation

`.logo`, `.nav`, `.side-item`, and `.active` style the top and side navigation. The AthenaSec logo square is generated with `.logo:before`, so it does not need an image.

### Cards, Tables, Buttons, and Forms

Reusable grid classes include `.grid`, `.stats`, `.two`, `.three`, and `.four`.

Reusable panels include `.card` and `.stat`. They use dark gradients, borders, rounded corners, shadows, and hover lift effects.

Tables are full width with uppercase muted headers, light body text, subtle row borders, and hover backgrounds. `.data-row` rows animate in with the `rowIn` keyframes.

`.pill` creates compact status badges. Variants include `.pill.ok`, `.pill.warn`, `.pill.danger`, `.pill.blue`, and `.pill.muted`.

`.btn` is the base button style. Variants include `.primary`, `.danger`, `.ghost`, and `.small`.

Inputs and selects use `.field-input`, `.select-input`, and `.textarea-input`. Focus states add a blue border and glow.

### Charts, Search, Dropdowns, and Modals

The dashboard chart uses `.chart` and `.bar`. System health progress bars use `.metric` and `.metric span`.

Search and dropdowns use `.search-wrap`, `.search-input`, `.search-results`, `.search-result`, `.dropdown-wrap`, `.dropdown`, and `.drop-item`.

Modals use `.modal-backdrop`, `.modal`, `.modal-body`, and `.modal-actions`.

### Visibility and Responsiveness

`.hidden` hides elements. `.page` is hidden by default, and `.page.active` is visible. `.is-highlighted` briefly highlights search destinations.

Below `1180px`, large grids collapse and spacing tightens. Below `820px`, the interface becomes mobile-friendly: the body scrolls, login becomes one column, the sidebar becomes a two-column grid, the topbar wraps, grids become one column, and search becomes full width.

## `js/app.js`

The JavaScript file makes the static HTML interactive.

### Demo Data and State

`DEMO_ACCOUNTS` stores the Analyst and Administrator demo users. `MFA_CODE` stores the static MFA code. `ADMIN_PAGES` lists page IDs that require the Administrator role.

The `state` object tracks `currentUser`, `pendingUser`, `currentPage`, `selectedAlert`, and `selectedIncident`.

### Helper Functions

`$` and `$$` are shortcuts for selecting DOM elements.

Other helpers include `show`, `hide`, `isAdmin`, `canAccess`, `escapeHtml`, `pillClass`, and `pillHtml`.

### Initialization

`init()` runs when the script loads. It restores remembered email, binds form events, binds input events, binds click events, applies initial alert filters, selects incident `INC-006`, and shows alert detail `ALT-001`.

### Login and MFA

The login form checks the entered email and password against `DEMO_ACCOUNTS`. If valid, it stores the user in `state.pendingUser`, handles Remember Me, hides login, and shows MFA.

The MFA form joins the six digit boxes and compares them to `MFA_CODE`. If correct, it moves the user into `state.currentUser`, hides authentication screens, shows the app shell, applies role access, and opens the dashboard.

### Input and Click Binding

`bindInputs()` connects all filters, searches, and MFA digit boxes.

`bindClicks()` uses event delegation from the document. It checks clicks for `data-page-link` and `data-action`, so dynamically added rows still work.

### Role Access and Navigation

`applyRoleAccess()` shows or hides admin-only elements, switches the dashboard role view, updates labels, updates the user chip, and fills the profile page.

`navigate(page)` checks access, stores the current page, activates the matching `.page`, updates active nav links, hides search results, closes dropdowns, and refreshes alert or AI panels when needed.

### Alert and AI Panels

`showAlertDetail(alertId, shouldNavigate)` stores the selected alert, shows the matching alert detail panel, updates the AI panel, and optionally navigates to Alert Details.

`showAiPanel(alertId)` shows the matching AI panel and hides the others.

### Filters and Search

`applyAlertFilters()` filters and sorts the Alerts table. `filterDashboardAlerts()`, `filterIncidents()`, `filterRules()`, and `filterAuditLogs()` filter their own tables.

`updateGlobalSearch()` reads the top search box, gathers searchable records, shows up to ten results, and wires each result to navigate to its page.

`searchableRecords()` gathers all elements marked with `data-search-page` and `data-search-record`, while respecting admin access.

### Demo Actions

JavaScript simulates prototype actions:

- Select and update incidents.
- Add incident notes.
- Close alerts.
- Isolate or reconnect endpoints.
- Save configuration.
- Add, toggle, or delete detection rules.
- Sync integrations.
- Add or disable users.
- Save profile details.

These actions update the visible page but do not persist to a backend.

### Modals and Logout

`modal(title, body)` creates a simple OK modal. `confirmModal(title, body, onConfirm)` creates a Cancel/Confirm modal and runs the callback only when Confirm is clicked.

`logout()` clears the current user, hides the app shell, shows the authentication wrapper, returns to the login view, hides MFA, and clears any open modal.

## How Everything Works Together

The project uses a simple pattern:

- HTML declares the content and behavior hooks.
- CSS controls layout, styling, visibility, animation, and responsiveness.
- JavaScript listens for user actions and changes classes, text, attributes, and generated HTML.

The most important hooks are `data-page`, `data-page-link`, `data-action`, `data-admin-only`, `data-search-page`, `data-search-record`, `data-alert-id`, `data-alert-detail`, and `data-ai-alert`.

## Current Limitations

Because this is a front-end-only prototype:

- Login uses hard-coded demo accounts.
- MFA uses the hard-coded `123456` code.
- Data is not saved to a backend.
- Added users and rules disappear after refresh.
- Edit, refresh, reset, sync, and save actions are mostly simulated through visible UI changes and modals.
- Audit pagination is visual only.

## Summary

`index.html` defines all screens and demo content. `css/styles.css` creates the polished dark SOC interface. `js/app.js` turns the static page into an interactive single-page prototype with authentication, MFA, role-based access, navigation, filters, search, modals, and demo management actions.
