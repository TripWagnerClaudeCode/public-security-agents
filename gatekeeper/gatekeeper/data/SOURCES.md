# Data sources

## top_pypi.txt
- Top 5,000 PyPI projects by 30-day downloads (lowercased, one per line, rank order).
- Origin: https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json (upstream last_update 2026-11-01 06:41:05), fetched 2026-11-03.
- SHA-256 of upstream JSON: 3e958a64ebe1de0b6a4ab4c6b465d481f350fd1dfa926c639add36eb34dabc1e
- SHA-256 of top_pypi.txt: f9967c26b5041e30e2a0b68faebd6ee2e67163de2c2e08f6ffd0074ebad2657f

## top_npm.txt
- First 5,000 entries of the npm "high impact" package ranking (rank order).
- Origin: https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js (wooorm/npm-high-impact, 17,337 names), fetched 2026-11-03.
- SHA-256 of upstream top.js: bbc16e783283f23d38559a1322d93af27b8a7a884b1fa9c5a1dd84e810684f0c
- SHA-256 of top_npm.txt: eedf7747a1a7fb5cc34ad778154c880d7b8683fc14f7ea7678624ee2b5c172bd

## Ecosystem coverage
- pypi, npm, crates, go: registry checks (+ OSV for pypi/npm/crates/go).
- winget, choco, scoop: only the "installed from a URL/git/path" rule; no registry checks.
- Typosquat check only for pypi and npm (the ecosystems with top lists).
