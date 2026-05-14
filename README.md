# Malicious Domain Monitoring

Monitors for malicious domains targeting MetaMask users. Queries URLScan.io saved searches, filters results against the [MetaMask phishing blacklist](https://github.com/MetaMask/eth-phishing-detect), and maintains rolling lists of domains that still need to be blocked.

## Setup

1. Install dependencies:

   ```bash
   pip install requests
   ```

2. Set your URLScan API key:

   ```bash
   export URLSCAN_API_KEY=your_key_here
   ```

## Usage

```bash
python get_domains.py
```

This processes all feeds defined in `config.json`. Each feed:

1. Queries the URLScan API (paginated, last 48 hours)
2. Fetches the current MetaMask blacklist from GitHub
3. Filters out already-blacklisted domains, apex-matched domains, skip-listed domains, and IPs
4. Saves a timestamped archive file for the run
5. Rebuilds `still_need_blocked.txt` from the last 30 days of archives, re-filtering against the current blacklist

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

## Output

Each feed produces:

- **Archive files** — timestamped snapshots per run (e.g. `kpdomains_2026-05-14_1023.txt`)
- **`still_need_blocked.txt`** — rolling 30-day list of domains not yet on the MetaMask blacklist
