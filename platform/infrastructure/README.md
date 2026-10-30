# Infrastructure

What runs on the Ubuntu VM alongside the backend. On the VM these are deployed under `/opt/athenasec/`, and the installer expects the folder names below to stay the same.

| Folder | What it is |
| --- | --- |
| `installer/` | Bash installer. `install.sh` runs `modules/base.sh`, `wazuh.sh`, `cortex.sh`, `misp.sh`, then `integrations.sh` to check they talk to each other. `configs/secrets.conf` lists where secrets live (no actual secrets). |
| `misp-docker/` | MISP threat intelligence platform, run with Docker Compose. Copy `template.env` to `.env` first. |
| `strangebee-docker/prod1-cortex/` | Cortex (StrangeBee) with nginx, run with Docker Compose. Copy `dot.env.template` to `.env` first. Scripts for certificates, backup and restore are in `scripts/`. |
| `ollama/` | `start.sh` starts the local Ollama language model server on port 11434. |
| `service-panel/` | Desktop panel (GTK) to start, stop and check every AthenaSec service on the VM. See its README for install steps. |
