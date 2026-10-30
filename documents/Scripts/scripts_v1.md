# AthenaSec Installer Scripts — v1 Overview

> **Purpose:** A simple public overview of the AthenaSec installer scripts and what each script is responsible for.  
> This document intentionally avoids passwords, API keys, private infrastructure details, machine-specific addresses, and other sensitive deployment information.

---

## What the Installer Does

AthenaSec uses a modular installer to prepare the services required by the platform.

The installer runs the setup in this order:

```text
Base system
→ Wazuh
→ Cortex
→ MISP
→ Integration checks
```

Each part has its own script so installation, testing, and future maintenance can be handled independently.

---

## `install.sh`

### Main function

`install.sh` is the main entry point for the AthenaSec installer.

It runs the setup modules in the correct order and stops if one of them fails.

Simplified flow:

```text
install.sh
  ├─ base.sh
  ├─ wazuh.sh
  ├─ cortex.sh
  ├─ misp.sh
  └─ integrations.sh
```

This keeps the installation process predictable and makes it easier to identify which component needs attention if an installation does not complete.

---

## `base.sh`

### Main function

Prepares the operating system before the security services are installed.

Typical responsibilities include:

- Updating package information
- Installing required system packages
- Preparing Docker and related dependencies
- Making sure commands required by later modules are available

This module provides the common environment used by the rest of the installer.

---

## `wazuh.sh`

### Main function

Installs and prepares Wazuh for use with AthenaSec.

Wazuh is used for security monitoring, endpoint visibility, detection, and alerting.

The script is responsible for tasks such as:

- Installing or detecting the Wazuh deployment
- Starting required Wazuh services
- Preparing API access for AthenaSec
- Handling fresh-install and existing-install scenarios
- Saving generated runtime credentials securely outside the project source

AthenaSec uses service credentials for API communication instead of embedding credentials directly into the source code.

---

## `cortex.sh`

### Main function

Installs and prepares Cortex.

Cortex provides analysis capabilities that AthenaSec can use when investigating security data.

The script handles tasks such as:

- Preparing Cortex configuration
- Starting the Cortex Docker services
- Initializing the Cortex environment
- Preparing API access for AthenaSec
- Storing generated runtime credentials securely

The installer uses configuration templates so deployment-specific values can be generated during installation instead of being permanently stored in the repository.

---

## `misp.sh`

### Main function

Installs and prepares MISP.

MISP provides threat-intelligence storage and sharing capabilities that AthenaSec can access through its API.

The script handles:

- Preparing MISP runtime configuration
- Building the bundled MISP container images
- Starting the database and cache services
- Starting MISP modules
- Starting the MISP core service
- Starting supporting services
- Waiting for required containers to become healthy
- Verifying that the MISP web/API service is reachable

The installer builds the bundled MISP source so deployments are not dependent on an unpredictable floating container version.

---

## `integrations.sh`

### Main function

Checks whether AthenaSec can actually communicate with the installed services.

A service being installed or a container being marked as running does not automatically mean the API is usable.

This script verifies the real integration paths:

```text
AthenaSec → Wazuh
AthenaSec → Cortex
AthenaSec → MISP
```

Typical checks include:

- Authenticating with the service
- Confirming that an API response is received
- Confirming that the AthenaSec service identity has access
- Waiting for an application to finish initialization when required

This final validation helps prevent an installation from being reported as successful when one of the APIs is not actually ready.

---

## `secrets.sh`

### Main function

Provides helper functions for securely handling runtime secrets.

The installer source does not contain real deployment passwords or API keys.

Instead, generated credentials are stored outside the normal project source tree with restricted permissions.

This helps keep the repository safe to share without including credentials from a deployed environment.

---

## `secrets.conf`

### Main function

Defines the locations and identifiers used by the installer when working with runtime secrets.

It contains configuration for the installer itself, not the real secret values generated for a deployment.

---

## Why the Installer Is Split Into Modules

Keeping each service in a separate script provides several advantages:

- Easier debugging
- Easier testing
- Clearer responsibilities
- Safer future updates
- Individual services can be improved without rewriting the entire installer
- Integration checks can remain separate from installation logic

For example, a MISP startup issue can be investigated in `misp.sh` without changing Wazuh or Cortex installation logic.

---

## Security Approach

The current installer follows several basic security rules:

- Real passwords and API keys are not stored in the repository.
- Machine/service credentials are kept separate from normal administrator accounts.
- Generated runtime secrets are stored outside the project source.
- API integrations are tested using real authenticated requests.
- Installation success is not based only on whether a process or container exists.
- Runtime configuration is generated from templates where possible.
- Fresh installations should not depend on state from a previous deployment.

---

## Current v1 Scope

The installer currently focuses on preparing and connecting the core services required by AthenaSec:

```text
Wazuh   → monitoring and detection
Cortex  → security analysis
MISP    → threat intelligence
```

AthenaSec then acts as the layer that communicates with those services through their APIs.

Future versions can extend this architecture with additional automation, response workflows, dashboard features, and other integrations without changing the basic modular installer design.

---

## Summary

The AthenaSec installer is designed around one main idea:

```text
install each service independently
→ verify each service is ready
→ verify AthenaSec can authenticate to it
→ only then treat the deployment as complete
```

This keeps the installation process understandable, testable, and easier to maintain as AthenaSec grows.
