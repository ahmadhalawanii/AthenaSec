# AthenaSec — Server Runbook

How to run AthenaSec on the team Ubuntu server (`athenasec`, Tailscale IP `100.92.246.34`).
Every command is copy-paste. Run server commands as the user **ahmed** in the Ubuntu terminal (Remote Desktop or `ssh ahmed@100.92.246.34`).

---

## 0. What lives where

| Thing | Location / address |
|---|---|
| Project folder | `/home/ahmed/AthenaSec` |
| Backend settings (secrets, never share or commit) | `/home/ahmed/AthenaSec/backend/.env` (chmod 600) |
| Backup of the settings | `/home/ahmed/.athenasec.env.backup` |
| Wazuh CA certificate copy | `/home/ahmed/AthenaSec/backend/certs/wazuh-root-ca.pem` |
| Python environment | `/home/ahmed/athvenv` (Python 3.14, made with `uv`) |
| Database | PostgreSQL, database + role `athenasec` |
| Website | http://100.92.246.34:5180 (service `athenasec-web`) |
| Backend API | http://127.0.0.1:8000 — server only (service `athenasec-backend`) |
| AI model | Ollama service on the server, model `qwen3:4b` |
| Wazuh forwarder | `/var/ossec/integrations/custom-athenasec` + `<integration>` block in `/var/ossec/etc/ossec.conf` |
| Daniel's secrets | `/etc/athenasec/secrets/` (root only) |

**Do not touch:** `/opt/semi_main` and port 5173 (teammate's site), `/opt/athenasec` (Daniel), the `postgres` superuser password, or Daniel's Wazuh / MISP / Cortex config without asking him.

---

## 1. Everyday commands

```bash
# Are both services running?
systemctl is-active athenasec-backend athenasec-web

# Restart after changing .env or code
sudo systemctl restart athenasec-backend athenasec-web

# Live logs (Ctrl+C to stop watching)
journalctl -u athenasec-backend -f
journalctl -u athenasec-web -f

# Last 50 backend log lines
journalctl -u athenasec-backend -n 50 --no-pager

# Stop / start
sudo systemctl stop athenasec-web athenasec-backend
sudo systemctl start athenasec-backend athenasec-web

# Is the AI model up?
systemctl is-active ollama && ollama list
```

---

## 2. Update the server with a new zip

**On your Windows laptop** (Command Prompt, connected to Tailscale):

```bat
scp "%USERPROFILE%\Downloads\AthenaSec-organized.zip" ahmed@100.92.246.34:~/
```

**On the server** (this keeps `.env` and the certificates; the old folder is kept as a dated backup):

```bash
sudo systemctl stop athenasec-web athenasec-backend
cd ~
cp ~/AthenaSec/backend/.env ~/.athenasec.env.backup
rm -rf ~/athenasec-certs-backup && cp -r ~/AthenaSec/backend/certs ~/athenasec-certs-backup
mv ~/AthenaSec ~/AthenaSec-old-$(date +%Y%m%d-%H%M)
unzip -q ~/AthenaSec-organized.zip -d ~
chmod -R u+w ~/AthenaSec
cp ~/.athenasec.env.backup ~/AthenaSec/backend/.env && chmod 600 ~/AthenaSec/backend/.env
cp -r ~/athenasec-certs-backup ~/AthenaSec/backend/certs

# Backend packages + database changes
cd ~/AthenaSec/backend
uv pip install --python ~/athvenv/bin/python -r requirements.txt
~/athvenv/bin/alembic upgrade head

# Website build
cd ~/AthenaSec/frontend
npm ci
npm run build

sudo systemctl start athenasec-backend athenasec-web
sleep 3; systemctl is-active athenasec-backend athenasec-web
```

Both lines should say `active`. Then open http://100.92.246.34:5180 and sign in.

If the zip changed `backend/integrations/custom-athenasec.py`, reinstall the Wazuh forwarder (section 5, step 1).

When the new version works, delete the old copy: `rm -rf ~/AthenaSec-old-*`

**Roll back:** `sudo systemctl stop athenasec-web athenasec-backend && mv ~/AthenaSec ~/AthenaSec-broken && mv ~/AthenaSec-old-<date> ~/AthenaSec && sudo systemctl start athenasec-backend athenasec-web`

---

## 3. First-time install on a new server

Only needed on a machine that has never run AthenaSec.

### 3.1 Packages

```bash
sudo apt update
sudo apt install -y postgresql unzip curl qrencode
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.bashrc
```

### 3.2 Code + Python environment

```bash
unzip -q ~/AthenaSec-organized.zip -d ~ && chmod -R u+w ~/AthenaSec
uv venv ~/athvenv --python 3.14
uv pip install --python ~/athvenv/bin/python -r ~/AthenaSec/backend/requirements.txt
```

### 3.3 Database (own role — leave the `postgres` password alone)

```bash
DBPW="$(openssl rand -hex 16)"
sudo -u postgres psql -c "CREATE ROLE athenasec LOGIN PASSWORD '$DBPW';"
sudo -u postgres createdb -O athenasec athenasec
```

### 3.4 Settings file

```bash
cd ~/AthenaSec/backend
cp .env.example .env && chmod 600 .env
sed -i "s|^ATHENASEC_DATABASE_URL=.*|ATHENASEC_DATABASE_URL=postgresql://athenasec:$DBPW@localhost:5432/athenasec|" .env
sed -i "s|^ATHENASEC_TOTP_MASTER_KEY=.*|ATHENASEC_TOTP_MASTER_KEY=$(openssl rand -hex 32)|" .env
sed -i "s|^ATHENASEC_WAZUH_INGEST_KEY=.*|ATHENASEC_WAZUH_INGEST_KEY=$(openssl rand -hex 32)|" .env
sed -i "s|^ATHENASEC_CORS_ORIGINS=.*|ATHENASEC_CORS_ORIGINS=http://100.92.246.34:5180|" .env
sed -i "s|^ATHENASEC_ML_MODEL_PATH=.*|ATHENASEC_ML_MODEL_PATH=models/athenasec-classifier-v3.pkl|" .env
unset DBPW
cp .env ~/.athenasec.env.backup && chmod 600 ~/.athenasec.env.backup
```

Keep `ATHENASEC_TOTP_MASTER_KEY` forever — changing it breaks every authenticator app.

### 3.5 Database tables

```bash
cd ~/AthenaSec/backend && ~/athvenv/bin/alembic upgrade head
```

### 3.6 First administrator account

```bash
cd ~/AthenaSec/backend
~/athvenv/bin/python -m app.services.auth.web_auth create USR-ADMIN ahmed@athenasec.local "Ahmed" --role Administrator --approver
```

It asks for a password (14+ characters) and prints an `otpauth://...` link. Show it as a QR code and scan it with an authenticator app (paste the link between the quotes):

```bash
qrencode -t ansiutf8 'otpauth://...'
```

Then `clear` the terminal. Never share that link or QR — it is the 2FA secret. Other accounts are created in the website: **Users → Add user**.

### 3.7 AI model (Ollama)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b
```

### 3.8 Website build + services

```bash
cd ~/AthenaSec/frontend && npm ci && npm run build
sudo cp ~/AthenaSec/infrastructure/athenasec-services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now athenasec-backend athenasec-web
systemctl is-active athenasec-backend athenasec-web
```

The service files assume user `ahmed` and `/home/ahmed`. For another account, edit `User=` and the paths in both files first.

---

## 4. Wazuh indexer (evidence the agent reads)

Needs a **read-only** indexer login from Daniel, saved as
`/etc/athenasec/secrets/wazuh/indexer-reader-credential` (line 1 username, line 2 password).
Use `127.0.0.1`, not `localhost` or `192.168.x.x` — the indexer certificate only covers `127.0.0.1`.

```bash
mkdir -p ~/AthenaSec/backend/certs
sudo install -o ahmed -g ahmed -m 644 /etc/wazuh-indexer/certs/root-ca.pem ~/AthenaSec/backend/certs/wazuh-root-ca.pem

sudo -v
F=/etc/athenasec/secrets/wazuh/indexer-reader-credential

# Test the login — expect "status" : "green" or "yellow"
curl -s --cacert ~/AthenaSec/backend/certs/wazuh-root-ca.pem -u "$(sudo sed -n 1p $F):$(sudo sed -n 2p $F)" "https://127.0.0.1:9200/_cluster/health?pretty"

# Write the settings (password never shown) and restart
cd ~/AthenaSec/backend
cp .env ~/.athenasec.env.before-indexer
sed -i '/^ATHENASEC_EVIDENCE_PROVIDER=/d;/^WAZUH_INDEXER_/d;/^WAZUH_VERIFY_SSL=/d' .env
{
echo "ATHENASEC_EVIDENCE_PROVIDER=wazuh"
echo "WAZUH_INDEXER_URL=https://127.0.0.1:9200"
echo "WAZUH_INDEXER_USERNAME=$(sudo sed -n 1p $F)"
echo "WAZUH_INDEXER_PASSWORD=$(sudo sed -n 2p $F)"
echo "WAZUH_INDEXER_CA_BUNDLE=$HOME/AthenaSec/backend/certs/wazuh-root-ca.pem"
echo "WAZUH_VERIFY_SSL=true"
} >> .env
chmod 600 .env
cp .env ~/.athenasec.env.backup
sudo systemctl restart athenasec-backend
```

Check **System Health** on the website. If the backend log says `CERTIFICATE_VERIFY_FAILED`, add `WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT=true` to `.env` and restart.

Undo: `cp ~/.athenasec.env.before-indexer ~/AthenaSec/backend/.env && sudo systemctl restart athenasec-backend`

---

## 5. Wazuh → AthenaSec alert forwarding

Wazuh sends every alert of level 7+ to the backend. Already installed on the team server; repeat only on a new server or when the forwarder script changes.

**Step 1 — install the script**

```bash
sudo install -o root -g wazuh -m 750 ~/AthenaSec/backend/integrations/custom-athenasec.py /var/ossec/integrations/custom-athenasec
```

**Step 2 — add the block to Wazuh (first time only, agree with Daniel)**

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.before-athenasec
KEY="$(grep '^ATHENASEC_WAZUH_INGEST_KEY=' ~/AthenaSec/backend/.env | cut -d= -f2-)"
sudo tee -a /var/ossec/etc/ossec.conf >/dev/null <<EOF
<ossec_config>
  <integration>
    <name>custom-athenasec</name>
    <hook_url>http://127.0.0.1:8000/api/v1/integrations/wazuh/alerts</hook_url>
    <api_key>$KEY</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
unset KEY
sudo systemctl restart wazuh-manager
```

**Check it:** `sudo tail -n 20 /var/ossec/logs/integrations.log` — a forwarded alert shows HTTP 200 and appears on the **Alerts** page.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `athenasec-backend` is `failed` | `journalctl -u athenasec-backend -n 50 --no-pager` and read the last error |
| Log says `.env` missing / database login failed | `cp ~/.athenasec.env.backup ~/AthenaSec/backend/.env && chmod 600 ~/AthenaSec/backend/.env` then restart |
| Website shows the **demo** login (demo accounts listed) | Backend is down — start it, then refresh |
| `Permission denied` editing/deleting project files | `chmod -R u+w ~/AthenaSec` |
| Wazuh forwarder gets 503 | Ollama is down: `sudo systemctl restart ollama`, then `ollama list` |
| Forwarder times out | Model is slow on first call; raise `TIMEOUT_SECONDS` in `/var/ossec/integrations/custom-athenasec` (e.g. 180) |
| Indexer `Unauthorized` | Wrong login — get a read-only indexer user from Daniel (section 4) |
| Indexer certificate error | URL must be `https://127.0.0.1:9200`; CA path must be the copy in `backend/certs` |
| Authenticator code rejected | Phone clock must be automatic; wait for the next code. Admin can **Reset 2FA** on the Users page |
| Forgot admin password | Another admin uses **Reset password** on the Users page |
| Port 5180 already in use | `sudo ss -ltnp | grep 5180` to see what holds it |

---

## 7. Safety rules

- Never paste `.env`, passwords, API keys, `otpauth://` links or QR codes into chat, GitHub or screenshots.
- `.env` is not in the zip or in Git — keep `~/.athenasec.env.backup` up to date after every change.
- `AUTONOMOUS_RESPONSE_ENABLED` stays `false`; Cortex actions need an analyst's approval.
