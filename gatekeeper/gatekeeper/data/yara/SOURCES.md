# YARA rule set (not bundled)

The rules are a separate project with per-rule licenses, so this repo only pins the release.
`python tools/fetch_yara.py` downloads it, checks both hashes below, and installs
`~/.gatekeeper/yara-rules-core.yar`, where `scanners.py` looks (override: `GATEKEEPER_YARA_RULES`).
Without it, YARA checks report a `yara_unavailable` notice.

- Origin: YARA Forge "core" rule set, release tag `20261103`
- URL: https://github.com/YARAHQ/yara-forge/releases/download/20261103/yara-forge-rules-core.zip
- SHA-256 of the zip: BE0D5A49D2A8CD37713F5A8C4E5A3C4235061242BC12240E18C69934FA47BB59
- Extracted file: `packages/core/yara-rules-core.yar`
- SHA-256 of yara-rules-core.yar: 4F5CCA2CFCE626518A0EB0D5AF26749F73B79A6BF92F8630B1772DC2B5F4C5A2
- Downloaded 2026-11-03. Compiles whole under yara-python 4.5.4 (no rules excluded).
- Update only by choosing a new release tag and re-recording the hashes here.
