# Rules for the gatekeeper
Separate from `AGENT_RULES.md`. The gatekeeper may only: read files under watched roots; move files into/out of
quarantine; write its own state/logs; send pushes; return `ask`/`deny`/context from hooks. It never deletes user files,
never changes system settings, never edits Claude permission allow-lists, never sends file contents anywhere except the
capped triage call. Secrets are never logged (gitleaks `--redact`, first 4 chars max).
