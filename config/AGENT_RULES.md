# Rules for every security agent (non-negotiable)

These rules apply to every agent run (for example a Claude Code session told "run the security agents"). An agent
that can't follow a rule stops and says why.

1. **Read and report only.** Never change settings, install, uninstall, patch, kill processes, delete files,
   commit, push, or alter any repo or system state. Propose fixes in writing only. The owner applies fixes, or
   approves them explicitly in the session, and that approval is noted in `commands.log`.
2. **Scope is `config/scope.yaml`.** Never touch a host, IP, or path that isn't listed there, and never edit
   it. The owner edits it. Gatekeeper's guard pushes an alert to the owner's phone on every change.
3. **Nuclei limits:** run it only against `network_allowlist` hosts, and always pass
   `-rl 150 -c 25 -etags dos,fuzz,intrusive,bruteforce,brute-force -disable-update-check -silent -ni`.
   `-ni` means no interactsh, so nothing is sent to external servers. Never use `-code`, `-ai`, `-dast`,
   `-headless`, `-allow-local-file-access`, `-interactsh-url`, or custom or unreviewed templates.
4. **Never print a secret in full.** Use `gitleaks --redact`. In notes, show at most the first 4 characters of
   a secret, plus file:line and the rule. For `secret_stores`, check permissions and key *names* only.
5. **Log every command** you run, one line each, to `runs/<RUN>/commands.log`.
6. **Tools:** gitleaks, trivy and nuclei, installed by `tools/install.sh` into `~/.local/bin`. On Windows, run
   them inside WSL. Windows paths map to `/mnt/c/...`, and in this repo a `\\wsl.localhost\<distro>\...` path
   means that distro's own filesystem.
7. **Findings** go to `runs/<RUN>/<agent>.jsonl` as JSON Lines, one object per finding:
   `{"agent","id","title","severity":"critical|high|medium|low|info","asset","evidence","recommendation","confidence":"high|medium|low"}`.
   Also write a short `runs/<RUN>/<agent>.summary.md` saying what was checked, what was skipped, and why.
   Once a finding is fixed, add a `"status"` field instead of deleting the line.
8. **No guessing.** If a check fails or a tool errors, record it as skipped with the reason. Never fabricate
   results.
9. **Review playbooks.** These are optional Claude Code skills (for example from
   [ECC](https://github.com/affaan-m/everything-claude-code)). Load the matching skill before a code review and
   apply it read-only; rules 1–8 still apply. Tag each finding with the playbook in its `id`, for example
   `"code-agentsec-007"`.
   - **`agent-security-hardening`:** for any repo where a model's output becomes file, shell, network,
     email or memory actions. Map each `source -> validator -> side effect` boundary. Report every side effect
     that has no deterministic check in code; a prompt-only rule counts as no check. Run the skill's
     "Verification Gate" as a *read* of the code and tests only. Never execute the attacks.
   - **`llm-trading-agent-security`:** for trading bots. For broker-based stock bots, translate the skill's
     terms:
     - wallet → which API keys and account (paper or live) they reach
     - spend limits → risk settings enforced in code
     - simulate before send → order validation and buying-power checks
     - circuit breaker → kill switches and drawdown halts

     Also check three things: fetched text (filings, news) is data, never instructions; agents can veto but can
     never raise size; every decision is logged.
   - **`mcp-dependency-review`:** for MCP config files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) in
     scoped repos, plus any machine-wide Claude config the owner lists under `files:`. This is a static read
     only; never run the server commands. Flag `@latest`, bare package names and version ranges.
10. **Upstream watch list.** List here the packages you depend on whose ownership or publishing changed and is
    still unverified. On every run, read the scoped repos' lockfiles (static read, no installs):
    - Report as `high` any locked version that differs from the reviewed one.
    - Report as `info` what you can see about the owner without installing anything: the GitHub org or user,
      its creation date, recent committers, and whether the registry's project URLs still match.

    Example entry:
    - **`<package>`** in `<repo>`. Reviewed: `<package> X.Y.Z` (date). Why it's watched: `<one line>`.
      Mark it resolved only after the owner confirms.
