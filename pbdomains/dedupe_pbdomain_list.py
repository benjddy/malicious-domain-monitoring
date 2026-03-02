import json
import requests
import os
import ipaddress
from datetime import datetime

# --- CONFIG ---
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/'
SEARCH_QUERY = 'meta:searchhit.search.48499f70-6417-4cce-8d55-daa7b731061c'
SKIP_LIST_FILE = 'skip_apex_domains.txt'

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
    print(f"Current working directory: {os.getcwd()}")
    print(f"Files in current directory: {os.listdir('.')}")

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

    # Skip IP addresses
    if is_ip_address(domain):
        filtered_ips.add(domain)
        continue

    # Skip if exact domain is already in blacklist
    if domain in json_domains:
        filtered_blacklist.add(domain)
        continue

    # Skip if apex domain is already in blacklist (subdomain covered)
    if apex_domain in json_domains and domain != apex_domain:
        filtered_apex.add(domain)
        continue

    # Skip if domain matches our manual skip list (endswith check)
    if should_skip(domain, skip_domains):
        filtered_skip.add(domain)
        continue

    urlscan_domains.add(domain)

# --- Step 4: Output ---
today = datetime.now().strftime('%Y-%m-%d_%H%M')
output_file = f'pbdomains/pbdomains_archive/pbdomains_{today}.txt'
os.makedirs('pbdomains/pbdomains_archive', exist_ok=True)

with open(output_file, 'w') as f:
    for domain in sorted(urlscan_domains):
        f.write(domain + '\n')

print("-" * 50)
print(f"Total results from URLScan: {len(urlscan_results)}")
print(f"Total in MetaMask blacklist: {len(json_domains)}")
print(f"IP addresses skipped: {len(filtered_ips)}")
print(f"Already in blacklist (exact match): {len(filtered_blacklist)}")
print(f"Subdomains filtered (apex already blocked): {len(filtered_apex)}")
print(f"Domains filtered (manual skip list): {len(filtered_skip)}")
if filtered_skip:
    print(f"Skip list matches: {sorted(filtered_skip)}")
print(f"New domains NOT in blacklist: {len(urlscan_domains)}")
print(f"Saved to {output_file}")
