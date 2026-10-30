#!/usr/bin/env bash

set -euo pipefail

INSTALLER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "================================"
echo "       AthenaSec Installer"
echo "================================"

echo
echo "[AthenaSec] Running base setup..."
"$INSTALLER_DIR/modules/base.sh"

echo
echo "================================"
echo "   AthenaSec Wazuh Installer"
echo "================================"

echo
echo "[AthenaSec] Installing/configuring Wazuh..."
"$INSTALLER_DIR/modules/wazuh.sh"

echo
echo "================================"
echo "   AthenaSec Cortex Installer"
echo "================================"

echo
echo "[AthenaSec] Installing/configuring Cortex..."
"$INSTALLER_DIR/modules/cortex.sh"

echo
echo "================================"
echo "    AthenaSec Misp Installer"
echo "================================"

echo
echo "[AthenaSec] Installing/configuring MISP..."
"$INSTALLER_DIR/modules/misp.sh"

echo
echo "================================"
echo "AthenaSec Integrations Installer"
echo "================================"

echo
echo "[AthenaSec] Configuring integrations..."
"$INSTALLER_DIR/modules/integrations.sh"

echo
echo "================================"
echo " AthenaSec installation complete"
echo "================================"
