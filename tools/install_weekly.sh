#!/usr/bin/env bash
# Install the weekly read-only security scan as a systemd user timer in WSL (no sudo).
set -euo pipefail
SA="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
U="$HOME/.config/systemd/user"
mkdir -p "$U"
cat > "$U/security-weekly.service" <<EOF
[Unit]
Description=Weekly read-only security scan (gitleaks + trivy over config/scope.yaml)

[Service]
Type=oneshot
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/bin/bash "$SA/tools/weekly_scan.sh"
EOF
cat > "$U/security-weekly.timer" <<'EOF'
[Unit]
Description=Run the security scan every Sunday at 03:30

[Timer]
OnCalendar=Sun *-*-* 03:30:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now security-weekly.timer
systemctl --user list-timers security-weekly.timer --no-pager
