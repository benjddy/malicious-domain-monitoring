import json
import requests
import os
import ipaddress
from datetime import datetime

# --- CONFIG ---
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/'
SEARCH_QUERY = 'meta:searchhit.search.8834ad57-24f0-4932-9ca3-731e814c7b21 AND date:>now-48h'
SKIP_LIST_FILE = 'skip_apex_domains.txt'
ARCHIVE_DIR = 'pbdomains/pbdomains_archive'
PB_STILL_NEED_BLOCKED = 'pbdomains/pb_still_need_blocked.txt'

# --- Helper: Check if string is an IP address ---
def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

# --- Helper: Check if domain matches skip list ---
def should_skip(domain, skip_list):
    for skip in skip_list:
        if domain == skip or domain.endswith('.' + skip):
            return True
    return False

# --- Load skip list ---
skip_domains = set()
if os.path.exists(SKIP_LIST_FILE):
    with open(SKIP_LIST_FILE, 'r') as f:
        for line in f:
            entry = line.strip().lower()
            if entry and not entry.startswith('#'):
                skip_domains.add(entry)
    print(f"Loaded {len(skip_domains)} domains from skip list: {skip_domains}")
else:
    print(f"WARNING: Skip list not found at {SKIP_LIST_FILE}")

# --- Step 1: Get ALL domains from URLScan API (with pagination) ---
headers = {'API-Key': URLSCAN_API_KEY}
urlscan_results = []
search_after = None

while True:
    params = {
        'q': SEARCH_QUERY,
        'size': 100
    }
    if search_after:
        params['search_after'] = search_after

    response = requests.get(URLSCAN_SEARCH_URL, headers=headers, params=params)
    data = response.json()
    results = data.get('results', [])

    if not results:
        break

    urlscan_results.extend(results)

    last_sort = results[-1].get('sort')
    if last_sort:
        search_after = ','.join(str(s) for s in last_sort)
    else:
        break

    print(f"Fetched {len(urlscan_results)} results so far...")

print(f"Total results from URLScan: {len(urlscan_results)}")

# --- Step 2: Get blacklist from MetaMask GitHub ---
response = requests.get(
    GITHUB_RAW_URL,
    headers={'Cache-Control': 'no-cache'}
)
config = response.json()
json_domains = set(config['blacklist'])

print(f"Fetched {len(json_domains)} domains from MetaMask blacklist")

# --- Step 3: Extract domains and filter ---
urlscan_domains = set()
filtered_blacklist = set()
filtered_apex = set()
filtered_skip = set()
filtered_ips = set()

for result in urlscan_results:
    task = result.get('task', {})
    domain = task.get('domain', '').strip().lower()
    apex_domain = task.get('apexDomain', '').strip().lower()

    if not domain:
        continue

    if is_ip_address(domain):
        filtered_ips.add(domain)
        continue

    if domain in json_domains:
        filtered_blacklist.add(domain)
        continue

    if apex_domain in json_domains and domain != apex_domain:
        filtered_apex.add(domain)
        continue

    if should_skip(domain, skip_domains):
        filtered_skip.add(domain)
        continue

    urlscan_domains.add(domain)

# --- Step 4: Save archive file (new domains for this run only) ---
today = datetime.now().strftime('%Y-%m-%d_%H%M')
output_file = f'{ARCHIVE_DIR}/pbdomains_{today}.txt'
os.makedirs(ARCHIVE_DIR, exist_ok=True)

with open(output_file, 'w') as f:
    for domain in sorted(urlscan_domains):
        f.write(domain + '\n')

print("-" * 50)
print(f"ARCHIVE RESULTS:")
print(f"Total results from URLScan: {len(urlscan_results)}")
print(f"Total in MetaMask blacklist: {len(json_domains)}")
print(f"IP addresses skipped: {len(filtered_ips)}")
print(f"Already in blacklist (exact match): {len(filtered_blacklist)}")
print(f"Subdomains filtered (apex already blocked): {len(filtered_apex)}")
print(f"Domains filtered (manual skip list): {len(filtered_skip)}")
print(f"New domains NOT in blacklist: {len(urlscan_domains)}")
print(f"Saved to {output_file}")

# ==============================================================
# Step 5: Build "still need blocked" list from ALL archived files
# ==============================================================
print("")
print("=" * 50)
print("BUILDING PB-STILL-NEED-BLOCKED LIST...")
print("=" * 50)

all_archived_domains = set()

for filename in os.listdir(ARCHIVE_DIR):
    if filename.endswith('.txt') and filename != '.gitkeep':
        filepath = os.path.join(ARCHIVE_DIR, filename)
        with open(filepath, 'r') as f:
            for line in f:
                domain = line.strip().lower()
                if domain:
                    all_archived_domains.add(domain)

print(f"Total unique domains across all archive files: {len(all_archived_domains)}")

# Filter out domains that have since been added to the blacklist
pb_still_need_blocked = set()
for domain in all_archived_domains:
    # Skip if now in blacklist
    if domain in json_domains:
        continue

    # Skip IPs
    if is_ip_address(domain):
        continue

    # Skip if on manual skip list
    if should_skip(domain, skip_domains):
        continue

    # Skip if apex domain is already in blacklist
    parts = domain.split('.')
    apex_found = False
    for i in range(len(parts) - 1):
        potential_apex = '.'.join(parts[i:])
        if potential_apex in json_domains and potential_apex != domain:
            apex_found = True
            break
    if apex_found:
        continue

    pb_still_need_blocked.add(domain)
# Overwrite the still_need_blocked file (not archived, always current)
with open(PB_STILL_NEED_BLOCKED, 'w') as f:
    for domain in sorted(pb_still_need_blocked):
        f.write(domain + '\n')

print(f"Domains still needing to be blocked: {len(pb_still_need_blocked)}")
print(f"Saved to {PB_STILL_NEED_BLOCKED}")
