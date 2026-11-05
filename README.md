# security-agents

A personal security toolkit for a developer machine that runs AI coding agents. It has two parts:

1. **Security agents.** A rulebook and a scope file let Claude Code, or any capable agent, audit your own
   machine **read-only**: secrets in your repos and their history, vulnerable dependencies, exposed ports, risky
   agent code, and MCP configs. Findings land in a consistent format, and a weekly timer re-runs the scanners.
2. **Gatekeeper.** A small always-on service (Windows-first) that:
   - checks new files in Downloads, Desktop and synced folders, and quarantines risky ones;
   - asks you before Claude Code runs risky commands;
   - warns Claude when a web page or file contains prompt injection;
   - pushes alerts to your phone, with one-tap Release / Keep blocked buttons;
   - alerts you whenever someone edits the security rules themselves.

```
          ┌──────────── security agents (on demand + weekly) ─────────────┐
 config/scope.yaml ──► gitleaks · trivy · nuclei (allow-listed hosts only) ──► runs/<date>/*.jsonl + summary.md
 config/AGENT_RULES.md   + code-review playbooks (agent / trading / MCP)        (read and report only)

          ┌──────────── Gatekeeper (always on) ──────────────────────────────────────────────────┐
 new file ─► facts (MOTW, signature, macros, LNK, PDF) + YARA + gitleaks ─► clean │ notice │ quarantine ─► push
 Claude tool call ─► PreToolUse hook: typosquats, pipe-to-shell, writes to ~/.claude … ─► ask (never "allow")
 tool result ──────► PostToolUse hook: prompt-injection patterns ─► warning added to Claude's context
 scope.yaml / AGENT_RULES.md / GATEKEEPER_RULES.md changed ─► critical push (counts only, no content)
```

> Not a replacement for your OS antivirus. Gatekeeper adds context Windows Defender doesn't have: where a file
> came from, what your AI agent is about to run, and which text is trying to give it instructions.

## Part 1: security agents

### Setup

```bash
git clone https://github.com/<owner>/public-security-agents.git security-agents
cd security-agents
cp config/scope.example.yaml config/scope.yaml     # then list YOUR repos, hosts and files (git-ignored)
bash tools/install.sh                              # gitleaks, trivy, nuclei into ~/.local/bin (Linux/WSL, no sudo)
```

On Windows, run `tools/` inside WSL. Paths in `scope.yaml` can be Windows (`C:\...`) or
`\\wsl.localhost\<distro>\...`; the scripts translate both.

### Run an audit

Open Claude Code in this folder and ask, for example:

> Run the security agents: follow `config/AGENT_RULES.md`, scope is `config/scope.yaml`.
> Do a baseline: secrets (files + history), dependency CVEs, host exposure, and a code review of the agentic repos.

The rules keep the run safe:
- read and report only;
- scope enforced, and nuclei only against your own hosts with safe flags;
- secrets redacted to 4 characters;
- every command logged;
- findings written as JSON Lines plus a short summary in `runs/<date>-<name>/`.

Fixes are proposals; you approve them explicitly.

Optional review playbooks are Claude Code skills (for example from ECC): `agent-security-hardening`,
`llm-trading-agent-security` and `mcp-dependency-review`. Rule 9 says when to use each one.

### Weekly scan

```bash
bash tools/install_weekly.sh         # systemd user timer: Sundays 03:30, gitleaks + trivy over scope.yaml
```

Results go to `runs/<date>-weekly/weekly.summary.md`. With `NTFY_CONFIG` set to an ntfy JSON file, the scan
also pushes a one-line summary.

## Part 2: Gatekeeper

### Install (Windows, no admin)

```powershell
cd gatekeeper
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python ..\tools\fetch_yara.py          # optional: YARA Forge rules, hash-verified
.venv\Scripts\python -m gatekeeper.install_windows --ntfy-config C:\path\to\ntfy.json
.venv\Scripts\python -m gatekeeper.install_hooks deploy   # Claude Code hooks (add --wsl-distro NAME for WSL)
```

- **`install_windows`** registers a hidden per-user scheduled task, `Gatekeeper`, that runs
  `python -m gatekeeper serve` from a snapshot of the committed code in `~\.gatekeeper\service`. Re-run it after
  you change the code.
- **`install_hooks deploy`** adds Gatekeeper's PreToolUse and PostToolUse hooks to `~/.claude/settings.json`.
  It backs the file up first and leaves your other hooks alone.
- **`ntfy.json`** is `{"url": "https://ntfy.sh", "topic": "<long random topic>", "token": "<optional>"}`. On
  public ntfy.sh, anyone who knows the topic can read it, so use a long random name. Pushes never contain
  file contents.

### Configure (`~/.gatekeeper/config.toml`, optional)

```toml
watch_roots = ["C:/Users/you/Downloads", "C:/Users/you/Desktop", "C:/Users/you/Sync"]
code_tree_roots = ["C:/Users/you/projects"]   # source files here only trip on scanner hits
tz = "America/Chicago"                         # quiet hours 23:00-08:00 in this zone (critical pushes skip them)
endpoint_binds = ["127.0.0.1", "100.64.0.10"]  # add your Tailscale IP so phone buttons work
guarded_files = ["C:/Users/you/security-agents/config/scope.yaml",
                 "C:/Users/you/security-agents/config/AGENT_RULES.md",
                 "C:/Users/you/security-agents/gatekeeper/GATEKEEPER_RULES.md"]
```

### How it decides

- **Never `allow`.** Hooks only add `ask`, or a warning. On any error or timeout they fail closed to `ask`.
- **Quarantine moves, never deletes.** Files go to `~\.gatekeeper\quarantine\<date>\<id>`, hash-checked on
  release.
- **Phone buttons carry a per-file, single-use, 7-day token**, never the endpoint key. The endpoint listens only
  on loopback and the tailnet (`100.64.0.0/10`), never on a wildcard address.
- **Scanners:**
  - Mark-of-the-Web origin
  - Authenticode signatures
  - Office macros (oletools)
  - PDF actions
  - LNK targets
  - extension vs content mismatch
  - YARA (if installed)
  - gitleaks for text files (on PATH, or `GATEKEEPER_GITLEAKS`, or `GATEKEEPER_GITLEAKS_WSL="<distro>:<path>"`)
  - typosquat checks against the top 5,000 PyPI/npm names

Gatekeeper's own limits are in [`gatekeeper/GATEKEEPER_RULES.md`](gatekeeper/GATEKEEPER_RULES.md).

### Tests

```powershell
cd gatekeeper
.venv\Scripts\python -m pytest -q
```

The tests use temp folders, fixtures and a local test endpoint. The gitleaks test is skipped when gitleaks
isn't installed. `tests/e2e/README.md` is a manual end-to-end checklist for a real machine.

## Layout

```
config/AGENT_RULES.md          rules every agent run follows
config/scope.example.yaml      template for your scope.yaml (git-ignored)
tools/                         scanner installer, weekly scan + timer, YARA fetcher, gitleaks config
gatekeeper/gatekeeper/         watcher, verdicts, quarantine, hooks, endpoint, guard, notify
gatekeeper/gatekeeper/data/    top PyPI/npm names (sources + hashes in SOURCES.md), YARA release pin
gatekeeper/tests/              pytest suite (+ e2e checklist)
runs/                          your audit output (git-ignored)
```

## License

MIT, see [LICENSE](LICENSE). The top PyPI/npm name lists are derived from public upstream rankings. Their
sources and hashes are in `gatekeeper/gatekeeper/data/SOURCES.md`. YARA Forge rules are not included.
