#!/usr/bin/env bash
# Installs pinned security tool binaries into ~/.local/bin (no sudo needed).
set -euo pipefail
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

NUCLEI=3.11.1; GITLEAKS=8.30.1; TRIVY=0.76.1

fetch() { echo "-> $1"; curl -fsSL -o "$2" "$1"; }

fetch "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI}/nuclei_${NUCLEI}_linux_amd64.zip" nuclei.zip
python3 -c "import zipfile;zipfile.ZipFile('nuclei.zip').extract('nuclei','.')"
install -m 755 nuclei "$BIN/nuclei"

fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS}/gitleaks_${GITLEAKS}_linux_x64.tar.gz" gitleaks.tgz
tar -xzf gitleaks.tgz gitleaks && install -m 755 gitleaks "$BIN/gitleaks"

fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY}/trivy_${TRIVY}_Linux-64bit.tar.gz" trivy.tgz
tar -xzf trivy.tgz trivy && install -m 755 trivy "$BIN/trivy"

"$BIN/nuclei" -version 2>&1 | tail -1
"$BIN/gitleaks" version
"$BIN/trivy" --version | head -1
