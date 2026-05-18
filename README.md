# Malicious Domain Monitoring

Monitors for malicious domains targeting MetaMask users. Queries URLScan.io saved searches, filters results against the [MetaMask phishing blacklist](https://github.com/MetaMask/eth-phishing-detect), and maintains rolling lists of domains that still need to be blocked.

## How It Works

A GitHub Actions workflow runs automatically twice a day (8am and 8pm UTC). Each run:

1. Queries the URLScan API (paginated, last 48 hours) for each configured feed
2. Fetches the current MetaMask blacklist from GitHub
3. Filters out already-blacklisted domains, apex-matched domains, skip-listed domains, and IPs
4. Saves a timestamped archive file for the run
5. Rebuilds `still_need_blocked.txt` from the last 30 days of archives, re-filtering against the current blacklist
6. Commits and pushes the updated results back to this repo

## Setup

Add your URLScan API key as a repository secret named `URLSCAN_API_KEY` (Settings → Secrets and variables → Actions). The workflow reads it from there automatically.

## Output

Each feed produces:

- **Archive files** — timestamped snapshots per run (e.g. `kpdomains_2026-05-14_1023.txt`)
- **`still_need_blocked.txt`** — rolling 30-day list of domains not yet on the MetaMask blacklist

## Adding a New Feed

Add an entry to the `feeds` object in `config.json`:

```json
{
  "my_feed": {
    "search_uuid": "your-urlscan-saved-search-uuid",
    "archive_dir": "my_feed/archive",
    "archive_prefix": "my_feed",
    "still_need_blocked_file": "my_feed/still_need_blocked.txt"
  }
}
```

## Configuration

| File | Purpose |
|------|---------|
| `config.json` | Feed definitions, URLs, retention settings |
| `skip_apex_domains.txt` | Apex domains to exclude from all feeds |

## Running Manually

```bash
pip install requests
export URLSCAN_API_KEY=your_key_here
python get_domains.py
```
