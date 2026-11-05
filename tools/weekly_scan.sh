#!/usr/bin/env bash
# Weekly read-only scan of everything in config/scope.yaml (repos, backups, deployed):
# gitleaks (history + files, --redact) and trivy (vuln, misconfig). Secret stores are never scanned.
# Results: runs/<date>-weekly/. Pushes a one-line summary through an ntfy config ($NTFY_CONFIG) if present.
# Installed as a systemd user timer by tools/install_weekly.sh. Follows config/AGENT_RULES.md 1-8.
set -uo pipefail
SA="${SA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"   # the repo this script lives in
BIN="$HOME/.local/bin"
RUN="$SA/runs/$(date +%F)-weekly"
mkdir -p "$RUN/raw"
log() { echo "$(date -Iseconds) [weekly] $*" >> "$RUN/commands.log"; }
CFG="$SA/tools/gitleaks.toml"

# scope.yaml -> WSL paths (repos, backups, deployed). Windows "C:\x" -> /mnt/c/x; \\wsl.localhost\<distro>\x -> /x
mapfile -t TARGETS < <(python3 -I - "$SA/config/scope.yaml" <<'PY'
import re, sys
section, out = None, []
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"^([a-z_]+):", line)
    if m:
        section = m.group(1)
        continue
    m = re.match(r"^\s+-\s+(.+?)\s*(#.*)?$", line)
    if not m or section not in ("repos", "backups", "deployed"):
        continue
    p = m.group(1).strip()
    if p.lower().startswith("\\\\wsl.localhost\\"):
        p = "/" + "/".join(p.split("\\")[4:])
    elif re.match(r"^[A-Za-z]:\\", p):
        p = "/mnt/" + p[0].lower() + "/" + p[3:].replace("\\", "/")
    out.append(f"{section}\t{p}")
print("\n".join(out))
PY
)

leaks=0; vulns=0; missing=0; n=0
for row in "${TARGETS[@]}"; do
  sec="${row%%$'\t'*}"; p="${row#*$'\t'}"
  # backups hold many repos: scan each child folder separately
  if [[ "$sec" == backups && -d "$p" ]] && ! git -C "$p" rev-parse --git-dir >/dev/null 2>&1; then
    kids=("$p"/*/)
  else
    kids=("$p")
  fi
  for t in "${kids[@]}"; do
    t="${t%/}"
    name="$(echo "${t#/}" | tr '/ ' '__' | cut -c1-120)"
    if [[ ! -d "$t" ]]; then log "SKIP missing $t"; missing=$((missing+1)); continue; fi
    n=$((n+1))
    if git -C "$t" rev-parse --git-dir >/dev/null 2>&1; then
      "$BIN/gitleaks" git --redact --no-banner -c "$CFG" -f json -r "$RUN/raw/gl_git_$name.json" "$t" >/dev/null 2>&1
      log "gitleaks git $t -> exit $?"
    fi
    "$BIN/gitleaks" dir --redact --no-banner -c "$CFG" -f json -r "$RUN/raw/gl_dir_$name.json" "$t" >/dev/null 2>&1
    log "gitleaks dir $t -> exit $?"
    "$BIN/trivy" fs -q --scanners vuln,misconfig --skip-dirs "**/node_modules" --skip-dirs "**/.venv" \
      --format json -o "$RUN/raw/trivy_$name.json" "$t" >/dev/null 2>&1
    log "trivy fs $t -> exit $?"
  done
done

python3 -I - "$RUN" > "$RUN/weekly.summary.md" <<'PY'
import json, pathlib, sys, collections
run = pathlib.Path(sys.argv[1]); raw = run / "raw"
leaks = collections.Counter(); sev = collections.Counter(); per = collections.Counter()
for f in raw.glob("gl_*.json"):
    try: data = json.loads(f.read_text() or "[]")
    except ValueError: data = []
    for d in data:
        leaks[(f.stem.split("_", 2)[2], d.get("File", "?"), d.get("RuleID", "?"))] += 1
for f in raw.glob("trivy_*.json"):
    try: data = json.loads(f.read_text() or "{}")
    except ValueError: continue
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            sev[v.get("Severity", "?")] += 1; per[f.stem[6:]] += 1
print(f"# Weekly scan {run.name}\n")
print(f"- gitleaks findings (redacted, unique file+rule): **{len(leaks)}**")
print(f"- dependency vulns: **{sum(sev.values())}** ({', '.join(f'{k} {v}' for k, v in sev.most_common())})\n")
print("## Secrets (file : rule)\n")
for (t, f, r) in sorted(leaks): print(f"- `{t}` {f} : {r}")
print("\n## Vulns per target\n")
for t, c in per.most_common(): print(f"- `{t}`: {c}")
PY
log "summary written"

# Optional push via Gatekeeper's ntfy config (same hub ntfy). Never fatal.
NT="${NTFY_CONFIG:-$HOME/.gatekeeper/ntfy.json}"   # on WSL with Gatekeeper on Windows: /mnt/c/Users/<you>/.gatekeeper/ntfy.json
if [[ -f "$NT" ]]; then
  python3 -I - "$NT" "$RUN/weekly.summary.md" <<'PY' || true
import json, sys, urllib.request
c = json.load(open(sys.argv[1])); lines = open(sys.argv[2]).read().splitlines()
msg = " / ".join(l.strip("- ").replace("**", "") for l in lines[2:4])
h = {"Content-Type": "application/json"}
if c.get("token"): h["Authorization"] = "Bearer " + c["token"]
body = {"topic": c["topic"], "title": "Weekly security scan", "message": msg, "priority": 2, "tags": ["shield"]}
urllib.request.urlopen(urllib.request.Request(c["url"], json.dumps(body).encode(), h), timeout=10)
PY
  log "ntfy summary push attempted"
fi
echo "$RUN/weekly.summary.md"
