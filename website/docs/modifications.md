# AthenaSec Website Review and Implementation Guide

## Purpose of this document

This document explains how the current AthenaSec website prototype is structured, what is already implemented, what is missing, and how it should be converted into a functional and secure web application.

It is written for human readers such as:

- Students
- Developers
- Project supervisors
- System analysts
- Cybersecurity team members
- Frontend and backend developers

It is not written as an AI prompt. It can later be converted into a prompt or implementation specification if required.

---

# 1. Project files reviewed

The following uploaded files were reviewed:

| File | Purpose |
|---|---|
| `index(1).html` | Contains the complete website layout, pages, forms, tables, cards, dashboards, and placeholder data |
| `styles(1).css` | Contains the website design, colors, responsive layout, forms, cards, tables, charts, modals, and animations |
| `app(1).js` | Contains login behavior, MFA behavior, page navigation, filters, search, role-based visibility, and simulated actions |
| `Details(1).md` | Contains documentation explaining how the prototype is intended to work |

The current HTML expects the following folder structure:

```text
project/
├── index.html
├── css/
│   └── styles.css
└── js/
    └── app.js
```

The uploaded files currently have different names:

```text
index(1).html
styles(1).css
app(1).js
Details(1).md
```

Before running the project, either rename and move the files into the expected folders or update the links inside the HTML file.

Example:

```html
<link rel="stylesheet" href="styles(1).css">
<script src="app(1).js"></script>
```

For a proper project, the recommended structure is still:

```text
project/
├── index.html
├── css/
│   └── styles.css
└── js/
    └── app.js
```

---

# 2. Current project status

## 2.1 What the project currently is

The website is currently a static, high-fidelity prototype for a Security Operations Center dashboard.

It looks and behaves like a real application, but it is not connected to a backend or database.

The current system works like this:

```text
HTML
  ↓
Contains all pages, forms, cards, tables, and demo values

CSS
  ↓
Controls colors, layout, responsive behavior, and animations

JavaScript
  ↓
Shows and hides pages, checks demo login details, filters tables,
opens modals, and changes values temporarily
```

The website is technically one large HTML page.

JavaScript displays different page sections by adding or removing CSS classes.

It does not use real browser routes such as:

```text
/dashboard
/alerts
/cases
/settings
```

Instead, it changes which HTML section is visible.

---

## 2.2 What is already implemented

The prototype already contains:

- Login screen
- MFA screen
- Analyst workspace
- Administrator workspace
- Dashboard
- Alert list
- Alert analysis drawer
- Case management
- Incident response activity
- Configuration page
- Detection rule management
- Response policies
- Integrations
- User management
- Audit logs
- System health
- Settings
- User profile
- Search
- Dropdown menus
- Filters
- Responsive design rules
- Role-based page visibility
- Demo actions and confirmation modals

---

## 2.3 What is not implemented

The following major components are missing:

- Backend server
- Database
- Real API
- Real user authentication
- Real MFA
- Secure user sessions
- Real alert data
- Real endpoint data
- Real chart data
- Real case storage
- Persistent settings
- Real integrations
- Proper server-side authorization
- Security logging
- Real-time alert updates
- Deployment configuration

---

# 3. Current website structure

## 3.1 Authentication area

The authentication section contains:

```text
Authentication
├── Login
└── Multi-Factor Authentication
```

Important HTML sections include:

```text
#authViews
#loginView
#mfaView
```

The login form currently asks for:

- Email address
- Password
- Remember Me
- Forgot Password

The MFA form contains six input boxes for a six-digit code.

---

## 3.2 Main application shell

After login, the website shows:

```text
#appShell
├── Top navigation bar
├── Sidebar
└── Main page content
```

The top navigation contains:

- AthenaSec logo
- System status
- Global search
- Notification menu
- User menu

The sidebar changes according to the user role.

---

## 3.3 Analyst pages

Analyst users currently have access to:

- Dashboard
- Alerts
- Case Management
- Incident Response
- Profile
- Logout

The analyst dashboard focuses on:

- Alert totals
- Critical alerts
- Open cases
- AI actions
- Recent alerts
- Alert severity
- Endpoint status

---

## 3.4 Administrator pages

Administrator users currently have access to:

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

The administrator dashboard focuses on:

- Integration status
- Detection rules
- Response policies
- Audit storage
- System health
- Administrative activity

---

# 4. Current design style

The current design uses a professional dark cybersecurity theme.

## Main design characteristics

- Dark navy background
- Dark slate cards
- Blue and cyan highlights
- Rounded cards
- Rounded buttons
- Status badges
- Fixed desktop sidebar
- Top navigation bar
- Dashboard statistic cards
- Tables with hover effects
- Animated system status
- Simulated charts
- Modal windows
- Slide-out alert drawer

This design is suitable for a Security Operations Center application.

The website does not require a complete visual redesign.

The main task should be to improve consistency, responsiveness, usability, and maintainability.

---

# 5. Design elements to keep

The following existing design elements should be kept:

- Dark AthenaSec theme
- Blue and cyan accent colors
- Sidebar navigation
- Top global search
- Status indicators
- Severity pills
- Statistic cards
- Alert analysis drawer
- System status widget
- Role-specific dashboards
- Responsive tables
- Card-based dashboard layout
- Confirmation modals
- Clean login layout

These elements already match the purpose of the project.

---

# 6. Design elements to improve

## 6.1 Card styling

The current cards use very large corner rounding and strong hover movement.

Recommended changes:

- Reduce card border radius from approximately 24 pixels to 12–16 pixels
- Reduce hover movement
- Reduce heavy shadows
- Keep cards visually separated without making them appear floating

This will make the system look more like an enterprise application.

---

## 6.2 Inline styling

The HTML contains many inline styles such as:

```html
style="margin-top:18px"
```

These should be moved into reusable CSS classes.

Example:

```css
.section-gap {
  margin-top: 18px;
}
```

Then use:

```html
<div class="card section-gap">
```

This makes the design easier to maintain.

---

## 6.3 Mobile navigation

The current mobile design turns the sidebar into a grid.

A better approach is:

- Hide the desktop sidebar
- Add a menu button in the top bar
- Open the sidebar as a slide-in drawer
- Allow the user to close it by clicking outside or pressing Escape

---

## 6.4 Mobile tables

Large SOC tables are difficult to read on mobile.

Use one of the following:

### Option 1: Horizontal scrolling

Keep the table but allow horizontal scrolling.

### Option 2: Mobile cards

Each row becomes a card:

```text
Alert: ALT-001
Severity: Critical
Endpoint: endpoint-01
Risk: 92
Status: Open

[View Alert]
```

For important operational pages, mobile cards are often easier to read.

---

## 6.5 Real chart components

The current charts use manually assigned CSS heights and percentages.

Example:

```html
style="height:88%"
```

This must be replaced with a proper chart library that reads numeric data.

Recommended chart library:

- Recharts for React
- Chart.js as an alternative
- Apache ECharts for advanced dashboards

---

# 7. Recommended responsive layout

## 7.1 Desktop

Recommended desktop layout:

```text
┌───────────────────────────────────────────────────────────────┐
│ Logo | System Status | Search              Alerts | User Menu │
├───────────────┬───────────────────────────────────────────────┤
│ Sidebar       │ Page title and actions                        │
│               │                                               │
│ Dashboard     │ Statistics                                    │
│ Alerts        │ Charts                                        │
│ Cases         │ Tables                                        │
│ Response      │ Details                                       │
│ Admin Pages   │ Forms                                         │
└───────────────┴───────────────────────────────────────────────┘
```

Suggested sizes:

- Sidebar width: 240–260 pixels
- Top bar height: 64–72 pixels
- Main page padding: 24–32 pixels
- Card gaps: 16–20 pixels
- Maximum content width: approximately 1,600 pixels

---

## 7.2 Tablet

On tablets:

- Collapse the sidebar into icon-only mode or a drawer
- Change four-column cards into two columns
- Allow tables to scroll
- Move page buttons under the title
- Keep global search available
- Reduce card padding

---

## 7.3 Mobile

On mobile:

- Use one-column layouts
- Use a menu drawer
- Use full-screen alert detail drawers
- Reduce large headings
- Use mobile-friendly buttons
- Avoid fixed `100vh`
- Use `100dvh` when full height is required
- Use card-based rows for important tables

---

# 8. Page-by-page design plan

# 8.1 Login page

## Keep

- AthenaSec branding
- Split desktop layout
- Email and password form
- MFA step
- Clean dark design

## Add

- Password visibility button
- Loading state
- Account lockout message
- Password reset workflow
- Accessible error messages
- Generic authentication failure messages
- Real MFA
- Security notice
- Session timeout notice

## Remove from production

- Demo account text
- Demo passwords
- Demo MFA code

---

# 8.2 Analyst dashboard

The analyst dashboard should display the current operational security situation.

## Recommended cards

- Total alerts
- Critical alerts
- High-severity alerts
- Open cases
- Automated actions
- Endpoints online
- Endpoints isolated
- Mean time to acknowledge
- Mean time to respond

## Recommended charts

- Alerts over time
- Alerts by severity
- Alerts by attack type
- Alerts by endpoint
- MITRE ATT&CK techniques
- Response actions over time

## Recommended tables

- Recent critical alerts
- Recently assigned cases
- Failed response actions
- Offline endpoints

## Recommended controls

- Time range selector
- Refresh button
- Auto-refresh setting
- Severity filter
- Endpoint filter
- Data freshness timestamp

---

# 8.3 Administrator dashboard

The administrator dashboard should focus on system management.

## Recommended cards

- Connected integrations
- Active users
- Enabled detection rules
- Enabled response policies
- Failed integrations
- Services online
- Audit events stored
- Storage usage

## Recommended sections

- Integration health
- Service health
- Administrative activity
- System resource usage
- Recent configuration changes
- Security warnings

---

# 8.4 Alerts page

The current Alerts page is a strong starting point.

## Recommended columns

- Alert ID
- Timestamp
- Severity
- Status
- Source IP
- Destination IP
- Endpoint
- Detection rule
- MITRE technique
- Risk score
- Assigned analyst
- Action

## Recommended features

- Server-side pagination
- Search
- Severity filter
- Status filter
- Attack type filter
- Date range
- Risk range
- Column sorting
- Saved views
- Bulk assignment
- Bulk close
- Export
- Row selection
- Real detail drawer

Example URL:

```text
/alerts?severity=critical&status=open&page=2
```

The URL may store filters, but the backend must still check permissions.

---

# 8.5 Alert details

Keep the slide-out drawer design.

Recommended tabs:

```text
Overview
Evidence
AI Analysis
Timeline
Response
Related Cases
```

The drawer should load data from API endpoints instead of reading table cells.

Recommended API requests:

```http
GET /api/v1/alerts/{alert_id}
GET /api/v1/alerts/{alert_id}/events
GET /api/v1/alerts/{alert_id}/analysis
GET /api/v1/alerts/{alert_id}/responses
```

---

# 8.6 Case management

Recommended case information:

- Case ID
- Title
- Severity
- Priority
- Status
- Owner
- Created date
- Last update
- Related alerts
- Evidence
- Notes
- Tasks
- Timeline
- Response actions
- TheHive reference
- Closure reason
- Audit history

Recommended statuses:

```text
New
Triage
Investigating
Contained
Resolved
Closed
```

---

# 8.7 Incident response activity

This page should act as a permanent history of security actions.

Each response action should include:

- Execution ID
- Triggering alert
- Policy
- Action
- Target
- Initiator
- Approval type
- Start time
- End time
- Result
- Failure reason
- Rollback status
- Evidence

Completed response records should not be edited.

Corrections should create new audit entries.

---

# 8.8 Detection rules

Recommended fields:

- Rule name
- Rule type
- Data source
- Query or condition
- MITRE ATT&CK mapping
- Severity
- Status
- Version
- Author
- Last modified
- Last triggered
- Number of alerts generated

Recommended actions:

- Create
- Edit
- Validate
- Test
- Enable
- Disable
- Publish
- Roll back
- Delete draft
- View change history

---

# 8.9 Response policies

Recommended policy structure:

```text
WHEN
  severity = Critical
  AND confidence >= 0.90
  AND asset criticality is not Tier 1

THEN
  isolate endpoint
  create case
  notify SOC

APPROVAL
  automatic
  analyst approval
  administrator approval
```

Every policy execution should save:

- Policy ID
- Policy version
- Conditions received
- Decision result
- Selected actions
- Approval result
- Execution result
- Failure reason

---

# 8.10 Integrations

Recommended integration information:

- Name
- Type
- Connection state
- Last successful sync
- Last failed sync
- Data latency
- API health
- Credential expiry
- Last error
- Events received
- Status

Recommended actions:

- Test connection
- Sync now
- Disable
- Enable
- Update settings
- Rotate credentials
- View logs

Integration credentials must never be sent back to the frontend.

---

# 8.11 User management

Recommended user fields:

- Name
- Email
- Role
- Status
- MFA state
- Last login
- Failed login count
- Session count
- Created date

Recommended actions:

- Invite user
- Change role
- Disable account
- Enable account
- Reset password
- Reset MFA
- End sessions
- View login activity
- Remove user

All permission changes must be checked by the backend.

---

# 8.12 Audit logs

Audit logs should be permanent and server-controlled.

Recommended filters:

- Date range
- User
- Action
- Object type
- Result
- Source IP
- Request ID

Recommended audit fields:

- Timestamp
- Actor
- Action
- Target
- Result
- Source IP
- Request ID
- Details

Do not store:

- Plaintext passwords
- Access tokens
- API secrets
- MFA secrets

---

# 8.13 System health

Recommended sections:

- FastAPI service health
- PostgreSQL health
- OpenSearch health
- Wazuh health
- TheHive health
- Ollama health
- Redis health
- Event ingestion rate
- Processing delay
- Queue backlog
- Error rate
- CPU usage
- Memory usage
- Storage usage
- Active endpoints
- Offline endpoints
- Last backup

Use line charts for values over time.

---

# 8.14 Settings and profile

Separate settings into three areas.

## Personal settings

- Name
- Phone
- Time zone
- Theme
- Language
- Notifications

## Security settings

- Password
- MFA
- Active sessions
- Login history
- Recovery codes

## Organization settings

- Data retention
- Alert routing
- Session timeout
- Integration defaults
- Response approval rules
- Notification defaults

Organization settings must only be available to authorized administrators.

---

# 9. Real data implementation

## 9.1 Recommended data flow

```text
Wazuh / Suricata / TheHive / OpenSearch / Ollama
                         ↓
             Data ingestion and processing
                         ↓
              Backend service and workers
                         ↓
          PostgreSQL / OpenSearch / Redis
                         ↓
               REST API and WebSockets
                         ↓
                  React frontend
                         ↓
             Dashboard, tables, and charts
```

---

# 9.2 Data source responsibilities

| Information | Source | Storage |
|---|---|---|
| Raw alerts | Wazuh or OpenSearch | OpenSearch |
| Network alerts | Suricata | OpenSearch |
| Users | AthenaSec backend | PostgreSQL |
| Roles and permissions | AthenaSec backend | PostgreSQL |
| Cases | AthenaSec and/or TheHive | PostgreSQL |
| Case notes | AthenaSec backend | PostgreSQL |
| Detection rule metadata | AthenaSec backend | PostgreSQL |
| Response policies | AthenaSec backend | PostgreSQL |
| Response actions | AthenaSec backend | PostgreSQL |
| Audit logs | Backend services | PostgreSQL or OpenSearch |
| System metrics | Prometheus exporters | Prometheus |
| Cached dashboard values | Processing service | Redis |
| Secrets | Secret manager | Vault or equivalent |

---

# 9.3 Dashboard API

Recommended endpoint:

```http
GET /api/v1/dashboard/summary?range=24h
```

Example response:

```json
{
  "range": "24h",
  "generatedAt": "2026-08-01T06:00:00Z",
  "totalAlerts": 1532,
  "criticalAlerts": 18,
  "openCases": 7,
  "automatedActions": 31
}
```

Recommended update frequency:

- Every 15–60 seconds
- Refresh after important WebSocket events
- Allow manual refresh

---

# 9.4 Alert severity chart API

Recommended endpoint:

```http
GET /api/v1/analytics/alerts-by-severity?range=24h&interval=1h
```

Example response:

```json
{
  "series": [
    {
      "timestamp": "2026-08-01T05:00:00Z",
      "critical": 2,
      "high": 8,
      "medium": 21,
      "low": 16
    }
  ]
}
```

The frontend should convert these values into a chart.

---

# 9.5 Endpoint status API

Recommended endpoint:

```http
GET /api/v1/endpoints/status-summary
```

Recommended status logic:

```text
Active
  The latest heartbeat was received within the normal interval

Warning
  The latest heartbeat is delayed

Offline
  No heartbeat has been received within the offline threshold

Isolated
  The endpoint currently has an active isolation record
```

The backend should calculate the authoritative status.

---

# 9.6 Alerts API

Recommended request:

```http
GET /api/v1/alerts
    ?severity=critical
    &status=open
    &search=ssh
    &sort=-risk_score
    &page=1
    &page_size=25
```

Example response:

```json
{
  "items": [
    {
      "id": "93a50f37-0765-48e4-84db-2d5765b445a3",
      "displayId": "ALT-001842",
      "timestamp": "2026-08-01T05:51:00Z",
      "severity": "critical",
      "status": "open",
      "attackType": "SSH Brute Force",
      "endpoint": {
        "id": "9e7e72f8-0c59-4ee0-a11d-48658c0d821d",
        "hostname": "endpoint-01"
      },
      "riskScore": 92
    }
  ],
  "page": 1,
  "pageSize": 25,
  "total": 418
}
```

Filtering and pagination should occur on the backend.

Do not download all alerts and filter them only in the browser.

---

# 9.7 Case API

Recommended endpoints:

```http
GET    /api/v1/cases
POST   /api/v1/cases
GET    /api/v1/cases/{case_id}
PATCH  /api/v1/cases/{case_id}
POST   /api/v1/cases/{case_id}/notes
POST   /api/v1/cases/{case_id}/assign
POST   /api/v1/cases/{case_id}/close
GET    /api/v1/cases/{case_id}/timeline
```

---

# 9.8 Detection rule API

Recommended endpoints:

```http
GET    /api/v1/detection-rules
POST   /api/v1/detection-rules
GET    /api/v1/detection-rules/{rule_id}
PATCH  /api/v1/detection-rules/{rule_id}
POST   /api/v1/detection-rules/{rule_id}/validate
POST   /api/v1/detection-rules/{rule_id}/publish
POST   /api/v1/detection-rules/{rule_id}/disable
```

---

# 9.9 Response policy API

Recommended endpoints:

```http
GET    /api/v1/response-policies
POST   /api/v1/response-policies
PATCH  /api/v1/response-policies/{policy_id}
POST   /api/v1/response-policies/{policy_id}/validate
POST   /api/v1/response-policies/{policy_id}/activate
GET    /api/v1/response-policies/{policy_id}/versions
```

---

# 9.10 Real-time updates

Use WebSockets for:

- Critical alerts
- Alert status changes
- Case assignment
- Response execution progress
- Integration health changes
- System warnings

Example event:

```json
{
  "type": "alert.created",
  "timestamp": "2026-08-01T05:55:12Z",
  "data": {
    "alertId": "93a50f37-0765-48e4-84db-2d5765b445a3",
    "severity": "critical",
    "riskScore": 96
  }
}
```

Not every page needs WebSockets.

Normal API requests are sufficient for:

- Settings
- User lists
- Detection rule lists
- Audit searches
- Profile settings

---

# 10. Recommended database structure

## Main PostgreSQL tables

```text
users
roles
permissions
user_roles
sessions
mfa_credentials

cases
case_alerts
case_notes
case_tasks
case_status_history

detection_rules
detection_rule_versions

response_policies
response_policy_versions
response_executions
response_execution_steps

integrations
integration_health_events

endpoints
endpoint_isolation_events

audit_logs
notifications
```

---

## Example users table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    status VARCHAR(30) NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## Example cases table

```sql
CREATE TABLE cases (
    id UUID PRIMARY KEY,
    display_id VARCHAR(30) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL,
    owner_id UUID REFERENCES users(id),
    created_by UUID REFERENCES users(id),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    version INTEGER NOT NULL DEFAULT 1
);
```

---

## Example audit table

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    actor_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    object_type VARCHAR(80) NOT NULL,
    object_id UUID,
    result VARCHAR(30) NOT NULL,
    source_ip INET,
    request_id UUID NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

# 11. Security review

## 11.1 Current security limitations

| Current implementation | Security problem |
|---|---|
| Passwords are stored in JavaScript | Anyone can inspect them |
| MFA code is stored in JavaScript | It is not real MFA |
| Session is stored in localStorage | It can be modified or stolen through XSS |
| Role checks only occur in the browser | Users can bypass interface restrictions |
| Data is hardcoded | There is no trusted server state |
| Actions are simulated | No server validation occurs |
| No backend exists | No server-side authorization exists |
| No rate limiting exists | Login and API abuse are unrestricted |
| No audit enforcement exists | Actions cannot be trusted |
| No secret storage exists | Integration credentials cannot be protected |

---

# 11.2 HTTPS and TLS

## Threat prevented

- Network interception
- Session theft
- Modified traffic
- Password interception

## Where to implement

- Reverse proxy
- Hosting infrastructure
- Domain configuration

## Method

- HTTPS only
- TLS 1.2 or TLS 1.3
- Trusted certificate
- HTTP to HTTPS redirection
- HSTS

---

# 11.3 Password hashing

## Threat prevented

- Password disclosure after database theft

## Where to implement

- Backend authentication service

## Method

Use Argon2id.

Do not store plaintext passwords.

Do not use simple SHA-256 alone for passwords.

---

# 11.4 Authentication and MFA

## Threat prevented

- Unauthorized login
- Password-only compromise
- Credential reuse

## Where to implement

- Backend or identity provider

## Method

- Real login endpoint
- Secure password verification
- TOTP or WebAuthn
- Recovery codes
- Login auditing
- Session revocation

---

# 11.5 Role-based access control

## Threat prevented

- Analysts accessing administrator functions
- Users changing roles
- Unauthorized configuration changes

## Where to implement

- Backend API

## Method

Each API endpoint must check the required permission.

Example permissions:

```text
alerts.read
alerts.close
cases.read
cases.create
cases.assign
rules.manage
policies.manage
users.manage
audit.read
settings.manage
```

The frontend may hide buttons, but the backend must make the final decision.

---

# 11.6 Object-level authorization

Users may try to change an ID:

```text
/api/v1/cases/100
```

to:

```text
/api/v1/cases/101
```

The server must check whether the authenticated user can access case 101.

The correct process is:

1. Authenticate the requester
2. Validate the ID
3. Load the requested object
4. Check access to that object
5. Check the requested action
6. Log the action
7. Return only allowed data

Do not rely on hiding URLs.

Do not rely only on UUIDs.

Do not rely on JavaScript checks.

---

# 11.7 UUIDs

UUIDs are recommended for internal object identifiers.

Example:

```text
93a50f37-0765-48e4-84db-2d5765b445a3
```

They make guessing IDs more difficult.

They do not replace authorization.

A user who obtains a valid UUID must still pass the backend permission check.

---

# 11.8 Signed URLs

Use signed URLs for temporary file downloads.

Example:

```text
/report-download?expires=...&signature=...
```

The signature should include:

- File ID
- User or organization scope
- Expiration
- Allowed operation

Do not use signed URLs as a replacement for normal API authorization.

---

# 11.9 SQL injection protection

## Threat prevented

- Unauthorized database queries
- Data theft
- Data modification
- Database destruction

## Where to implement

- Backend database layer

## Method

Use:

- SQLAlchemy
- Parameterized queries
- Typed request schemas
- Allowlisted sorting fields
- Least-privilege database accounts

Correct:

```python
stmt = select(Alert).where(Alert.severity == requested_severity)
```

Incorrect:

```python
query = f"SELECT * FROM alerts WHERE severity = '{user_input}'"
```

---

# 11.10 Cross-site scripting protection

## Threat prevented

- Malicious scripts
- Session theft
- Data theft
- Interface modification

## Where to implement

- Frontend
- Backend
- Reverse proxy

## Method

- Render text as text
- Avoid raw HTML
- Sanitize approved rich text
- Use Content Security Policy
- Avoid inline JavaScript
- Validate analyst notes
- Escape displayed values

React automatically escapes normal string output, but dangerous raw HTML must still be avoided.

---

# 11.11 CSRF protection

## Threat prevented

- Another website forcing an authenticated user to perform an action

## Where to implement

- Backend and frontend

## Method

When cookie authentication is used:

- Use SameSite cookies
- Use CSRF tokens
- Validate Origin
- Validate Referer where appropriate
- Do not change data using GET requests

---

# 11.12 Input validation

## Threat prevented

- Invalid data
- Injection
- Unexpected values
- Broken application state

## Where to implement

- Backend
- Frontend for user experience

## Method

Use Pydantic schemas on the backend.

Example:

```python
class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    severity: Literal["low", "medium", "high", "critical"]
```

Frontend validation is useful, but backend validation is mandatory.

---

# 11.13 Rate limiting and brute-force protection

## Threat prevented

- Login guessing
- API flooding
- Password spraying
- Resource exhaustion

## Where to implement

- API gateway
- Reverse proxy
- Backend
- Redis

## Method

Examples:

```text
Login:
5 failed attempts per account in 15 minutes

API:
Limit based on endpoint and role

Password reset:
Very low rate per account and IP
```

Use delays or temporary account locks after repeated failures.

---

# 11.14 Secure error handling

## Threat prevented

- Internal information leakage
- Database information exposure
- Stack trace exposure

## Where to implement

- Backend

## Method

Return generic messages:

```json
{
  "detail": "Unable to process request"
}
```

Store full technical details in protected server logs.

---

# 11.15 Logging and monitoring

Log:

- Login attempts
- MFA failures
- User changes
- Role changes
- Policy changes
- Detection rule changes
- Case changes
- Alert closures
- Response actions
- Integration changes
- Permission failures
- Suspicious API usage

Do not log:

- Plaintext passwords
- Tokens
- MFA secrets
- API secrets
- Database passwords

---

# 11.16 Secret management

Store secrets outside source code.

Secrets include:

- Database password
- JWT keys
- Wazuh credentials
- OpenSearch credentials
- TheHive API key
- Email password
- Integration tokens

Use:

- HashiCorp Vault
- Cloud secret manager
- Docker secrets
- Kubernetes secrets with proper protection

A local `.env` file may be used during development, but it must not be committed to Git.

---

# 11.17 File upload security

If evidence or rule files are uploaded:

1. Limit file size
2. Validate file type
3. Validate file signature
4. Rename the file on the server
5. Store it outside the web root
6. Scan for malware
7. Reject executable files unless required
8. Protect downloads with authorization
9. Log uploads and downloads
10. Detect archive bombs

---

# 11.18 CORS

Only allow approved frontend origins.

Example:

```text
https://athenasec.example.com
```

Do not use:

```text
Access-Control-Allow-Origin: *
```

for an authenticated application.

---

# 11.19 Secure HTTP headers

Recommended headers:

```text
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
Cross-Origin-Opener-Policy
```

Use CSP `frame-ancestors` or equivalent protection against clickjacking.

---

# 12. React explanation

React is a JavaScript library for building user interfaces.

It builds the interface using reusable components.

Example component:

```tsx
function SeverityPill({ severity }: { severity: string }) {
  return (
    <span className={`pill pill-${severity}`}>
      {severity}
    </span>
  );
}
```

This component can be reused in:

- Dashboard
- Alert table
- Case page
- Alert drawer
- Audit page

---

## 12.1 React state

State is information remembered by a component.

Example:

```tsx
const [severity, setSeverity] = useState("all");
```

This can store the selected severity filter.

---

## 12.2 React routing

React normally uses React Router.

Example:

```tsx
<Routes>
  <Route path="/dashboard" element={<DashboardPage />} />
  <Route path="/alerts" element={<AlertsPage />} />
  <Route path="/cases/:caseId" element={<CasePage />} />
</Routes>
```

---

## 12.3 React backend communication

React can use:

- `fetch`
- Axios
- TanStack Query

TanStack Query is recommended for:

- Loading data
- Caching
- Refreshing
- Retrying
- Error handling
- Pagination

---

## 12.4 React advantages

- Large ecosystem
- Strong TypeScript support
- Suitable for large dashboards
- Many table libraries
- Many chart libraries
- Strong testing tools
- Widely used
- Good scalability

---

## 12.5 React disadvantages

- Requires several supporting libraries
- Project structure must be planned
- State can become complicated
- Developers must understand hooks
- Poorly structured React code can become difficult to maintain

---

# 13. Vue explanation

Vue is a progressive JavaScript framework.

It can be used for:

- One section of an existing website
- A complete single-page application
- Reusable user interface components

Example Vue component:

```vue
<script setup lang="ts">
defineProps<{
  severity: string
}>()
</script>

<template>
  <span :class="`pill pill-${severity}`">
    {{ severity }}
  </span>
</template>
```

---

## 13.1 Vue state

Vue uses reactive values.

For larger applications, Pinia is commonly used for shared state.

---

## 13.2 Vue routing

Vue Router is used for routes such as:

```text
/dashboard
/alerts
/cases/:caseId
```

---

## 13.3 Vue backend communication

Vue can use:

- `fetch`
- Axios
- Vue Query

---

## 13.4 Vue advantages

- Easier initial learning
- HTML-style templates
- Clear official ecosystem
- Good documentation
- Suitable for gradual integration
- Fast development
- Good dashboard support

---

## 13.5 Vue disadvantages

- Smaller ecosystem than React
- Smaller hiring market
- Some enterprise libraries prioritize React
- Fewer examples for some specialized systems

---

# 14. React and Vue comparison

| Area | React | Vue |
|---|---|---|
| Type | UI library | Progressive framework |
| Learning difficulty | Moderate | Easier |
| Templates | JSX or TSX | HTML-style templates |
| Project structure | Flexible | More guided |
| State | Hooks and external libraries | Reactive values and Pinia |
| Routing | React Router | Vue Router |
| Performance | Strong | Strong |
| Community | Larger | Large |
| Libraries | Very extensive | Extensive |
| Scalability | Excellent | Excellent |
| Dashboard suitability | Excellent | Excellent |
| Gradual integration | Good | Excellent |
| AthenaSec suitability | Recommended | Good alternative |

---

# 15. Recommended frontend choice

Use React with TypeScript.

Reasons:

1. AthenaSec contains many complex tables.
2. It requires filters, forms, charts, drawers, and role-based pages.
3. React has a large ecosystem.
4. TanStack Table is suitable for alerts and cases.
5. TanStack Query is suitable for API data.
6. TypeScript improves data safety.
7. React is suitable for long-term growth.
8. Testing support is strong.

Vue is still a valid option when the team strongly prefers Vue or requires the easiest gradual integration.

---

# 16. Integration approaches

# 16.1 Approach A: Gradual integration

React or Vue components can be inserted into selected parts of the current HTML.

Example HTML:

```html
<div id="alert-chart-root"></div>
```

Example React entry:

```tsx
import { createRoot } from "react-dom/client";
import { AlertSeverityChart } from "./components/AlertSeverityChart";

const root = document.getElementById("alert-chart-root");

if (root) {
  createRoot(root).render(<AlertSeverityChart />);
}
```

Good components to convert first:

- Dashboard charts
- Statistic cards
- Global search
- Alerts table
- Alert drawer
- Notifications

## Advantages

- Existing website remains usable
- Lower initial risk
- Parts can be converted separately

## Disadvantages

- React and old JavaScript may conflict
- Two state systems exist
- Manual navigation remains
- Authentication remains difficult to modernize
- Technical debt remains longer

---

# 16.2 Approach B: Full frontend conversion

Each current page becomes a React route.

Each repeated design element becomes a reusable component.

Recommended conversion process:

1. Keep the current prototype as a visual reference
2. Create a new React project
3. Reuse colors and selected CSS
4. Build the application shell
5. Convert one page at a time
6. Connect mock APIs
7. Connect real APIs
8. Remove old manual DOM JavaScript

This is the recommended final approach.

---

# 17. Recommended React project structure

```text
athenasec/
├── frontend/
│   ├── public/
│   │   └── assets/
│   ├── src/
│   │   ├── app/
│   │   │   ├── App.tsx
│   │   │   ├── router.tsx
│   │   │   └── providers.tsx
│   │   ├── components/
│   │   │   ├── charts/
│   │   │   ├── data-table/
│   │   │   ├── feedback/
│   │   │   ├── forms/
│   │   │   ├── layout/
│   │   │   └── navigation/
│   │   ├── features/
│   │   │   ├── alerts/
│   │   │   ├── audit/
│   │   │   ├── auth/
│   │   │   ├── cases/
│   │   │   ├── dashboard/
│   │   │   ├── detection-rules/
│   │   │   ├── integrations/
│   │   │   ├── response-policies/
│   │   │   ├── system-health/
│   │   │   └── users/
│   │   ├── hooks/
│   │   ├── lib/
│   │   │   ├── api.ts
│   │   │   ├── auth.ts
│   │   │   ├── permissions.ts
│   │   │   └── websocket.ts
│   │   ├── styles/
│   │   │   ├── tokens.css
│   │   │   ├── globals.css
│   │   │   └── components.css
│   │   ├── types/
│   │   └── main.tsx
│   ├── .env.example
│   ├── package.json
│   └── vite.config.ts
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── integrations/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── workers/
│   │   └── main.py
│   ├── migrations/
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
│
├── infrastructure/
│   ├── nginx/
│   ├── docker/
│   ├── monitoring/
│   └── compose.yaml
└── README.md
```

---

# 18. Installation instructions

## 18.1 Create the React frontend

```bash
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
```

Install packages:

```bash
npm install react-router-dom
npm install @tanstack/react-query
npm install @tanstack/react-table
npm install axios
npm install zod
npm install react-hook-form
npm install @hookform/resolvers
npm install zustand
npm install recharts
npm install date-fns
```

Install testing tools:

```bash
npm install -D vitest
npm install -D @testing-library/react
npm install -D @testing-library/jest-dom
npm install -D @testing-library/user-event
npm install -D playwright
```

Run the frontend:

```bash
npm run dev
```

Build the frontend:

```bash
npm run build
```

---

## 18.2 Create the FastAPI backend

Create the virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install packages:

```bash
pip install fastapi
pip install "uvicorn[standard]"
pip install sqlalchemy
pip install asyncpg
pip install alembic
pip install pydantic-settings
pip install argon2-cffi
pip install pyjwt
pip install redis
pip install httpx
pip install websockets
```

Run the backend:

```bash
uvicorn app.main:app --reload
```

---

# 19. Environment variables

## Frontend

```env
VITE_API_BASE_URL=https://api.athenasec.internal
VITE_WS_BASE_URL=wss://api.athenasec.internal
VITE_APP_ENV=production
```

Frontend variables are visible to the browser.

Do not store secrets in frontend variables.

---

## Backend

```env
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://...
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private_key
WAZUH_API_URL=https://...
WAZUH_USERNAME=...
WAZUH_PASSWORD=...
OPENSEARCH_URL=https://...
THEHIVE_API_URL=https://...
THEHIVE_API_KEY=...
```

Production secrets should come from a secret manager.

---

# 20. Existing file reuse plan

| Current item | Reuse | Required treatment |
|---|---|---|
| Dark color palette | Yes | Convert to CSS variables |
| Card design | Yes | Reduce radius and shadow |
| Buttons | Yes | Convert to reusable React components |
| Status pills | Yes | Convert to status components |
| Sidebar design | Yes | Rebuild as responsive component |
| Top bar | Yes | Rebuild with accessible menus |
| Table design | Partially | Keep appearance, replace logic |
| CSS bar chart | No | Replace with Recharts |
| CSS donut chart | Mostly no | Replace with real data components |
| Login design | Yes | Connect to backend |
| Hardcoded users | No | Remove |
| Hardcoded MFA | No | Remove |
| localStorage session | No | Replace with secure session |
| Manual navigation | No | Replace with React Router |
| DOM filtering | No | Replace with React and backend filtering |
| HTML string drawer | No | Replace with React component |
| Inline CSS | No | Move to stylesheets |
| Hardcoded rows | No | Replace with API data |
| Details documentation | Partially | Update to match final architecture |

---

# 21. Recommended technology stack

| Layer | Technology | Reason |
|---|---|---|
| Frontend | React and TypeScript | Strong dashboard ecosystem |
| Build tool | Vite | Fast development and production build |
| Styling | Existing CSS converted to design tokens and modules | Preserves current design |
| Routing | React Router | Proper page routes |
| API state | TanStack Query | Caching and refetching |
| UI state | Zustand or React Context | Shared interface state |
| Forms | React Hook Form and Zod | Typed validation |
| Tables | TanStack Table | Filtering, sorting, pagination |
| Charts | Recharts | Responsive dashboard charts |
| Backend | FastAPI | Suitable for Python and AI integrations |
| ORM | SQLAlchemy | Secure and maintainable database queries |
| Database | PostgreSQL | Users, cases, policies, and settings |
| Alert search | OpenSearch | Telemetry and alert searching |
| Cache | Redis | Caching and rate limiting |
| Background processing | Celery or Dramatiq | Integration and processing jobs |
| Real-time | WebSockets | Live alerts and response progress |
| Metrics | Prometheus and Grafana | System monitoring |
| Reverse proxy | Nginx or Traefik | HTTPS and routing |
| Deployment | Docker Compose | Suitable for a lab deployment |
| Testing | Pytest, Vitest, Playwright | Backend, frontend, and full-system testing |
| Security testing | Semgrep, Bandit, npm audit, pip-audit, OWASP ZAP | Security checks |
| CI/CD | GitHub Actions | Automated testing and deployment |
| Threat intellengce indicator | misp | lets organizations collect, store, correlate, and share cybersecurity threat data and indicators of compromise |

---

# 22. Implementation roadmap

# Phase 1: Review and preparation

## Tasks

- Correct file names and paths
- Validate HTML structure
- Document all pages and fields
- Compare documentation with current code
- Confirm user roles
- Define API requirements
- Define data ownership
- Create Git repository structure

## Expected output

- Valid prototype
- Page inventory
- Role and permission matrix
- API specification draft
- Data dictionary
- Architecture document

## Dependencies

- Access to Wazuh
- Access to OpenSearch
- Access to TheHive
- Confirmed scope
- Confirmed user roles

## Risks

- Code and documentation may describe different versions
- Integration APIs may not be available
- Case ownership may be unclear

---

# Phase 2: Design improvements

## Tasks

- Create design tokens
- Fix page markup
- Remove inline styling
- Improve desktop layout
- Add tablet layout
- Add mobile navigation
- Standardize cards and forms
- Design loading states
- Design empty states
- Design errors
- Improve accessibility

## Expected output

- Responsive design system
- Page layout specifications
- Component list
- Approved visual design

## Dependencies

- Page inventory
- Required metrics
- Role definitions

## Risks

- Excessive redesign
- Mobile table complexity
- Inconsistent page behavior

---

# Phase 3: Frontend development

## Tasks

- Create React TypeScript project
- Build application shell
- Add routing
- Build role-aware navigation
- Convert login
- Convert MFA
- Build shared components
- Convert dashboard
- Convert alerts
- Convert alert drawer
- Add mock API data

## Expected output

- Functional React application
- Responsive pages
- Reusable components
- Mock API integration

## Dependencies

- Design system
- API response formats
- Page designs

## Risks

- Copying the existing HTML without restructuring
- Mixing old JavaScript with React
- Creating duplicated state

---

# Phase 4: Backend and database

## Tasks

- Create FastAPI project
- Configure PostgreSQL
- Create migrations
- Create users
- Create roles
- Create permissions
- Create cases
- Create rules
- Create policies
- Add OpenSearch connection
- Add audit middleware
- Add API documentation

## Expected output

- Working backend
- Database schema
- Versioned API
- Initial integration adapters

## Dependencies

- Final data model
- Authentication design
- Integration credentials

## Risks

- Duplicated data
- Changing integration schemas
- TheHive synchronization conflicts

---

# Phase 5: Real-data integration

## Tasks

- Connect Wazuh
- Connect OpenSearch
- Normalize alert data
- Calculate dashboard statistics
- Connect endpoint data
- Connect case creation
- Store response history
- Add WebSocket events
- Add background synchronization

## Expected output

- Real dashboard
- Real alerts
- Real endpoint status
- Real cases
- Live notifications

## Dependencies

- Backend
- Database
- Integration environments

## Risks

- High event volume
- Duplicate events
- Delayed events
- Timestamp inconsistencies
- Integration outages

---

# Phase 6: Authentication and security

## Tasks

- Remove demo accounts
- Remove demo MFA
- Add password hashing
- Add MFA
- Add secure sessions
- Add backend RBAC
- Add object authorization
- Add CSRF protection
- Add rate limiting
- Configure CORS
- Configure CSP
- Add security headers
- Add secret management
- Add audit logging

## Expected output

- Secure authentication
- Enforced permissions
- Security documentation
- Threat model

## Dependencies

- User database
- Role matrix
- Domain configuration

## Risks

- Relying on frontend permissions
- Incorrect cookies
- Broad CORS
- Missing object checks

---

# Phase 7: Testing

## Tasks

- Unit tests
- API integration tests
- Database tests
- Authorization tests
- Responsive tests
- Accessibility tests
- WebSocket tests
- Dependency scans
- Static analysis
- OWASP ZAP testing
- Backup testing
- Recovery testing

## Expected output

- Test reports
- Security reports
- Permission test matrix
- Release candidate

## Dependencies

- Stable frontend
- Stable backend
- Staging environment

## Risks

- Testing only successful cases
- Missing authorization tests
- Unrealistic test data
- Insufficient telemetry volume testing

---

# Phase 8: Deployment

## Tasks

- Build frontend
- Build backend Docker image
- Configure reverse proxy
- Configure HTTPS
- Configure private networks
- Configure backups
- Configure logging
- Configure monitoring
- Configure CI/CD
- Deploy staging
- Deploy lab production
- Verify deployment
- Create rollback procedure

## Expected output

- Deployed AthenaSec system
- Operations guide
- Backup procedure
- Monitoring dashboards
- Rollback process

## Dependencies

- Hosting
- DNS
- Certificates
- Secret manager
- Backup storage

## Risks

- Publicly exposed database
- Publicly exposed OpenSearch
- Missing backups
- Incorrect TLS
- Missing rollback image

---

# 23. Priority checklist

## First actions

- [ ] Correct the HTML, CSS, and JavaScript file paths
- [ ] Validate the HTML structure
- [ ] Repair the dashboard nesting
- [ ] Compare `Details(1).md` with the current code
- [ ] Remove or label non-functional actions
- [ ] Implement or remove audit pagination
- [ ] Confirm whether Endpoints and AI Analysis pages are required
- [ ] Define analyst permissions
- [ ] Define administrator permissions

## Architecture actions

- [ ] Select React with TypeScript
- [ ] Select FastAPI
- [ ] Define PostgreSQL data
- [ ] Define OpenSearch data
- [ ] Define TheHive case ownership
- [ ] Create API specification
- [ ] Define WebSocket events
- [ ] Define normalized alert format

## First development actions

- [ ] Build React application shell
- [ ] Convert login and MFA
- [ ] Build analyst dashboard
- [ ] Build alerts table
- [ ] Build alert detail drawer
- [ ] Build case management
- [ ] Connect Wazuh and OpenSearch

## Security actions

- [ ] Remove hardcoded credentials
- [ ] Remove hardcoded MFA
- [ ] Remove localStorage authentication
- [ ] Add backend authentication
- [ ] Add server-side RBAC
- [ ] Add object-level authorization
- [ ] Use parameterized database queries
- [ ] Add brute-force protection
- [ ] Add rate limiting
- [ ] Add HTTPS
- [ ] Add secure cookies
- [ ] Add CSRF protection
- [ ] Configure CORS
- [ ] Configure CSP
- [ ] Add secure headers
- [ ] Protect secrets
- [ ] Add audit logging
- [ ] Add security testing

---

# 24. Final recommendation

The current AthenaSec prototype should be treated as a visual and interaction reference.

The design is already suitable for a cybersecurity dashboard and should not be completely replaced.

The main work is to replace the prototype behavior with:

- React components
- Proper routes
- FastAPI backend endpoints
- PostgreSQL storage
- OpenSearch alert retrieval
- Secure authentication
- Server-side permissions
- Real charts
- Persistent cases and settings
- Real integration data
- WebSocket updates
- Logging and monitoring

The safest development method is to preserve the current visual identity while rebuilding the internal application structure one feature at a time.
