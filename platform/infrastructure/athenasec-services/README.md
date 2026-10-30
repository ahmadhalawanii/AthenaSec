# AthenaSec services (Ubuntu server)

Run AthenaSec without open terminals: systemd starts both at boot and restarts them after a crash.
Both run as the user `ahmed` from `/home/ahmed/AthenaSec` (change `User=` and the paths for another account).

| Service | What | Port |
| --- | --- | --- |
| `athenasec-backend` | FastAPI backend, reads `backend/.env` | 127.0.0.1:8000 (server only) |
| `athenasec-web` | The built website (`npm run build` first); forwards `/api` to the backend | 0.0.0.0:5180 |

Install:

```bash
cd ~/AthenaSec/frontend && npm run build
sudo cp ~/AthenaSec/infrastructure/athenasec-services/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now athenasec-backend athenasec-web
```

Everyday:

```bash
systemctl status athenasec-backend athenasec-web
journalctl -u athenasec-backend -f
sudo systemctl restart athenasec-backend athenasec-web
```

Remove: `sudo systemctl disable --now athenasec-backend athenasec-web`, delete the two files from `/etc/systemd/system/`, then `sudo systemctl daemon-reload`.
