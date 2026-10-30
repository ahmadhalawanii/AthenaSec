# AthenaSec Service Panel v3 — 30 September 2026

Adds a startup mock admin login, sign out, machine CPU/RAM usage, and MISP login-page availability fallback with diagnostic details. Includes the previously proposed Ubuntu 24.04 AppArmor/VirtualBox compatibility changes.

## Install or upgrade on the Ubuntu VM

Close the currently running panel first. Save the archive in `/home/s91/Downloads`, then run as `s91`:

```bash
cd ~/Downloads
tar -xzf athenasec-service-panel-v3.tar.gz
cd ~/Downloads/athenasec-service-panel-v3
python3 -m unittest discover -s tests -v
sudo python3 install-panel.py
athenasec-service-panel
```

The first two commands apply to the archive download. If this folder was recreated from the guide, run the last three commands inside that reconstructed folder instead.

Dependencies, if not already installed:

```bash
sudo apt update
sudo apt install python3 python3-gi gir1.2-gtk-4.0 gir1.2-webkit-6.0 apparmor
```

The installer installs only the panel, launcher, desktop entry, and its application-specific AppArmor profile. It backs up the previous panel to `/opt/athenasec/service-panel-v3-backup.<random>` and prints the exact rollback command. Close the panel before rollback too. It refuses a different existing panel AppArmor profile or an explicitly disabled profile. It does not alter global sysctls, Docker group membership, Compose files, service configuration, or secrets. Application files are root-owned; run the desktop panel without sudo.

## Sign in

- Email: `admin@athenasec.com`
- Password: `admin123`

These are the user-supplied mock website credentials, duplicated in `service-panel/auth.py`. Email comparison ignores surrounding spaces and case; password comparison is exact. No website API, cookie sharing, database, production authorization, or automatic MISP/Cortex/Wazuh login is implemented. Anyone with access to the code can read the demo password. Replace this local mock with real server-side authentication before relying on it for access control.

Every fresh application process opens the login window. Launching the command while the application is already open raises its current window. Sign out destroys the panel and returns to a blank login; the next successful login creates new ephemeral WebKit sessions. The embedded services still require their own credentials.

## Device usage

The sidebar shows machine-wide CPU percentage and RAM percentage plus used/total GiB, refreshed approximately every two seconds. On this installation, “device” means the Ubuntu VM, not the physical host. CPU needs two samples and initially displays Sampling. RAM uses `(MemTotal - MemAvailable) / MemTotal`; reclaimable cache is not counted as unavailable RAM. All readings are from `/proc`, with no new Python dependency.

## MISP Unknown

The old check only understood an unauthenticated heartbeat at `https://127.0.0.1:9445/users/heartbeat`. Redirects, authentication, a different response format, and network/TLS failures could all produce Unknown.

v3 sends the configured MISP Host header while connecting only to loopback. If the heartbeat responds but cannot be confirmed, it separately requests `/users/login`; it does not follow arbitrary redirects. HTTP 200 plus a completed `UserLoginForm` containing `UserEmail`, `UserPassword`, and MISP branding produces **Available — web availability only**. Generic HTML, proxy errors, and explicit failed health responses are not marked available. This does not prove that every MISP container, worker, module, database, or Redis instance is healthy.

If still Unknown, run without sudo from this extracted folder:

```bash
python3 diagnose-misp.py
```

Send the two printed lines. No passwords, cookies, API keys, response bodies, Docker access, or runtime secrets are requested. A refused loopback connection needs port/binding investigation; a redirected login needs proxy/base-URL investigation. The probe does not access the private LAN from the development workspace.

## Validation and limits

58 tests passed in the development environment, including five installer tests confined to temporary directories with AppArmor calls mocked. Those five tests skip when the suite is run as a normal user; do not run tests with sudo just to avoid the skips. GTK controller tests use stand-ins and are not rendering tests. Live `/proc` sampling and Python syntax checks passed. This workspace has no GTK/WebKit, graphical desktop, AppArmor parser, or access to your VM; real GUI rendering, embedded service navigation, actual policy attachment, and your MISP response remain to be validated there.

The updated `docs/service_panel_internal.md` in the release contains the historical v2 guide and a dated v3 chapter with all current sources, explanations, tests, and self-contained reconstruction steps.
