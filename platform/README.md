# AthenaSec

AI-assisted security operations platform for small organisations. Wazuh detects, the AthenaSec agent investigates and proposes a response, an analyst approves risky actions, and Cortex carries them out.

## What is where

```
AthenaSec/
├── backend/          The AI agent and its API (Python, FastAPI, LangGraph). Start here for agent logic.
├── frontend/         The web console analysts and admins use (React, TypeScript, Vite).
└── infrastructure/   Everything that runs on the Ubuntu VM: installer, MISP, Cortex, Ollama, service panel.
```

Each folder has its own README that explains what is inside it.

## How the parts connect

```
Wazuh alert ──► backend (agent investigates, scores risk, checks policy)
                   │
                   ├── MISP ............ threat intelligence lookups
                   ├── Ollama .......... local language model for analysis
                   ├── Cortex .......... carries out approved actions (block IP, isolate host)
                   └── PostgreSQL ...... users, sessions, approvals, audit trail
                   │
frontend ◄─────────┘  analysts review alerts, approve actions; admins set the response policy
```

The website connects to the backend when it is running. If the backend is not running, the website switches to **demo mode** and shows sample data instead (the login page says so).

## Run it

You need Python 3.14, Node 22 or newer, and PostgreSQL 16 (or Docker to run it).

### 1. Database

With Docker, one command:

```
docker run -d --name athenasec-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=athenasec -p 5432:5432 postgres:16
```

Or install PostgreSQL and create a database called `athenasec`.

### 2. Backend settings

```
cd backend
copy .env.example .env          (Windows)   or   cp .env.example .env   (Linux)
```

Open `backend/.env` and set:

- `ATHENASEC_DATABASE_URL`: matches the database from step 1. The Docker command above gives `postgresql://postgres:postgres@localhost:5432/athenasec`.
- `ATHENASEC_TOTP_MASTER_KEY`: run `python -c "import secrets; print(secrets.token_hex(32))"` and paste the result.

### 3. Backend

```
cd backend
python -m venv .venv
.venv\Scripts\activate          (Windows)   or   source .venv/bin/activate   (Linux)
pip install -r requirements.txt
alembic upgrade head            creates the tables
python -m pytest -q             expected: 1463 passed, 9 skipped
uvicorn app.main:create_app --factory --reload
```

The API runs on http://localhost:8000.

### 4. Create your account (once)

In a second terminal, in `backend/` with the venv active:

```
python -m app.services.auth.web_auth create USR-001 you@example.com "Your Name" --role Administrator --approver
```

It asks for a password (14+ characters), then prints an `otpauth://` link. Add it to an authenticator app (Microsoft Authenticator, Google Authenticator, Authy): choose "enter a setup key" and use the `secret=` part of the link. Keep that link private.

Use `--role Analyst` for analyst accounts. `--approver` lets the account approve or reject actions.

### 5. Website

```
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and sign in with your email, password and the 6-digit code from your authenticator app.

On Windows PowerShell, use `npm.cmd` instead of `npm` if you get "running scripts is disabled".

**Demo mode:** if the backend is not running, sign in with `analyst@athenasec.com` / `analyst123` or `admin@athenasec.com` / `admin123`, and code `123456`.

**Infrastructure:** see `infrastructure/README.md`.

## Where to find a feature

| I want to change... | Look in |
| --- | --- |
| How the agent investigates an alert | `backend/app/graph/` |
| Risk scores | `backend/app/services/risk/` |
| Allowed and blocked actions (response policy) | `backend/app/services/policy/` |
| Approving or rejecting actions | `backend/app/services/approvals/` |
| Running, verifying or undoing an action | `backend/app/services/execution/`, `backend/app/services/cortex/` |
| Timed blocks expiring | `backend/app/services/containment/` |
| API routes | `backend/app/main.py` |
| Data shapes (records, requests, responses) | `backend/app/schemas.py` |
| The ML classifier and its training | `backend/app/ml/`, `backend/training/` |
| A page in the console | `frontend/src/pages/` |
| How the website talks to the backend | `frontend/src/api/` |
| Sample data for demo mode | `frontend/src/data/` |
| Installing Wazuh, MISP, Cortex on the VM | `infrastructure/installer/` |
