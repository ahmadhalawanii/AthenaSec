# AthenaSec

## Scripts_V1

These are the initial scripts for installing and configuring the tools.

---

## Main Script

`install.sh` calls the modules required to install and configure the tools.

---

## Modules

### `base.sh`

Updates package libraries, installs basic dependencies such as `curl`, `wget`, `unzip`, and `zip`, and creates the directories used by AthenaSec.

---

### `wazuh.sh`

Installs and configures Wazuh.

---

### `misp.sh`

Installs and configures MISP.

---

### `cortex.sh`

Installs and configures Cortex.

---

### `integrations.sh`

Checks the integrations between AthenaSec and the installed tools.
