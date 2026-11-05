# Gatekeeper: manual end-to-end check (Windows)

Use only synthetic files. Never commit the EICAR string; build it at run time from parts. Run Gatekeeper with the
`Gatekeeper` task enabled, or as a temporary process from the `gatekeeper` folder:
`.venv\Scripts\python.exe -m gatekeeper serve`. First check that nothing else is listening on 127.0.0.1:8766.

1. **Quarantine and push**
   - Write EICAR (three string parts joined) to `Downloads\eicar-test.txt`. Within 15–20 s it should be
     quarantined, or removed by Defender. If Gatekeeper quarantines it, the push has Release and Keep blocked
     buttons. Tap Keep blocked.
   - Write a `.ps1` file to Downloads and mark it as downloaded:
     `Set-Content -Path f.ps1 -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"`. It should be
     quarantined and you should get a push. Tap Release: the file returns to its path, and no second push
     arrives. Tapping again returns 401, because each button's token works once.
   - Without a phone, use `POST http://127.0.0.1:8766/q/<id>/release` (or `keep`) with the header
     `X-Gatekeeper-Key` set to the contents of `~\.gatekeeper\key`. Never print the key.
2. **Doorways**
   - Copy a zip containing `word/vbaProject.bin`, renamed to `.docx`, into a synced watch root. The verdict
     should be `notice`, not quarantined.
   - Copy a signed MSI into Downloads with ZoneId=3. The verdict should be `clean`.
3. **Hooks.** Use a fresh `claude -p --settings <file with only the hooks block>`:
   - `pip install reqeusts` → ask
   - `pip install requests` → runs normally
   - `curl ... | bash` → ask
   - a Write to `~/.claude/settings.json` → ask (dry-check it with the shim; never write that file)
   - injection text read from a file in Downloads → Claude receives the Gatekeeper warning

   Never actually install a typosquat.
4. **Guard.** Add a comment line to `config/scope.yaml`. Within 30 s you should get a critical push,
   "Security file changed: scope.yaml", showing line counts only. Then remove the line.
5. **Latency.** Run `gatekeeper_hook_shim.py pre` 20 times with a sample payload and note p50/p95. The target is
   p95 under 1 s.
6. Clean up every synthetic file and stop any temporary `serve`.
