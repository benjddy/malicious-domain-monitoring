# Malicious Domain Monitoring — CLAUDE.md

## Project Overview

Python tooling that monitors for malicious domains targeting MetaMask users. It queries
URLScan.io saved searches, filters results against the MetaMask phishing blacklist
(eth-phishing-detect), and maintains rolling lists of domains that still need to be blocked.

## Structure

```
malicious-domain-monitoring/
├── get_domains.py                    # Single script that processes all feeds
├── config.json                       # Feed definitions, URLs, paths
├── key_phishing_domains/
│   ├── kp_still_need_blocked.txt     # Rolling 30-day list of unblocked domains
│   └── key_phishing_domains_archive/ # Per-run snapshots
├── pbdomains/
│   ├── pb_still_need_blocked.txt     # Rolling 30-day list of unblocked domains
│   └── pbdomains_archive/            # Per-run snapshots
├── skip_apex_domains.txt             # Apex domains to exclude from both pipelines
└── ROADMAP.md
```

## How It Works

1. Queries URLScan.io API (paginated) using a saved search query
2. Fetches the current MetaMask blacklist from GitHub (eth-phishing-detect/src/config.json)
3. Filters out: already-blacklisted domains, apex-matched domains, skip-listed domains, IPs
4. Saves a timestamped archive file for the run
5. Rebuilds `still_need_blocked.txt` from the last 30 days of archives, re-filtering
   against the current blacklist each time

## Environment Variables

- `URLSCAN_API_KEY` — required for URLScan API access

## How to Run

```bash
python get_domains.py
```

Processes all feeds defined in `config.json`. To add a new feed, add an entry to the
`feeds` object in `config.json` with the URLScan search UUID and output paths.

## Roadmap (current priorities)

1. ~~**Consolidate scripts**~~ — done
2. ~~**Remove manual pb flow**~~ — done
3. ~~**Extract hardcoded config**~~ — done
4. ~~**Add a README**~~ — done
