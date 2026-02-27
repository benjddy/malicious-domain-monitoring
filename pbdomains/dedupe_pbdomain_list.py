import json
import requests
import os
from datetime import datetime

# --- CONFIG ---
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/'
SEARCH_QUERY = 'meta:searchhit.search.8834ad57-24f0-4932-9ca3-731e814c7b21'
SKIP_LIST_FILE = 'pbdomains/skip_apex_domains.txt'

# --- Load skip list ---
skip_domains = set()
if os.path.exists(SKIP_LIST_FILE):
    with open(SKIP_LIST_FILE, 'r') as f:
        for line in f:
            domain = line.strip().lower()
            if domain and not domain.startswith('#'):
                skip_domains.add(domain)

print(f"Loaded {len(skip_domains)} apex domains to skip")

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
filtered_apex = set()
filtered_skip = set()

for result in urlscan_results:
    task = result.get('task', {})
    domain = task.get('domain', '').strip().lower()
    apex_domain = task.get('apexDomain', '').strip().lower()

    if not domain:
        continue

    # Skip if exact domain is already in blacklist
    if domain in json_domains:
        continue

    # Skip if apex domain is already in blacklist (subdomain covered)
    if apex_domain in json_domains and domain != apex_domain:
        filtered_apex.add(domain)
        continue

    # Skip if apex domain is in our manual skip list
    if apex_domain in skip_domains:
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
print(f"Subdomains filtered (apex already blocked): {len(filtered_apex)}")
print(f"Domains filtered (manual skip list): {len(filtered_skip)}")
print(f"New domains NOT in blacklist: {len(urlscan_domains)}")
print(f"Saved to {output_file}")
