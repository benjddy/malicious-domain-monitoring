# Malicious Domain Monitoring — CLAUDE.md

## Project Overview

Python tooling that monitors for malicious domains targeting MetaMask users. It queries
URLScan.io saved searches, filters results against the MetaMask phishing blacklist
(eth-phishing-detect), and maintains rolling lists of domains that still need to be blocked.

## Structure

```
malicious-domain-monitoring/
├── key_phishing_domains/
│   ├── get_key_phishing_domains.py   # Main script for key phishing feed
│   ├── kp_still_need_blocked.txt     # Rolling 30-day list of unblocked domains
│   └── key_phishing_domains_archive/ # Per-run snapshots
├── pbdomains/
│   ├── get_pb_domains.py             # Main script for pb feed (identical logic)
│   ├── pb_still_need_blocked.txt     # Rolling 30-day list of unblocked domains
│   ├── pbdomains_archive/            # Per-run snapshots
│   ├── manual_pb.csv                 # Manual domain list (to be deleted)
│   └── pb_manual_csv.py              # Manual CSV processor (to be deleted)
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

## Roadmap (current priorities)

1. **Consolidate scripts** — merge `get_key_phishing_domains.py` and `get_pb_domains.py`
   into one configurable script; the two are identical except for the URLScan search query
   UUID and output paths
2. **Remove manual pb flow** — delete `manual_pb.csv` and `pb_manual_csv.py`
3. **Extract hardcoded config** — URLScan query UUIDs, file paths, and the GitHub URL
   should live in a shared config file or `.env`, not inline in the scripts
4. **Add a README** — setup instructions, env vars, how to run
