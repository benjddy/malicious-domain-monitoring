import json
import requests
import os
from datetime import datetime

# --- CONFIG ---
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/'
SEARCH_QUERY = 'meta:searchhit.search.8834ad57-24f0-4932-9ca3-731e814c7b21'

# --- Step 1: Get ALL domains from URLScan API (with pagination) ---
headers = {'API-Key': URLSCAN_API_KEY}
urlscan_domains = set()
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

    for result in results:
        domain = result.get('task', {}).get('domain', '').strip().lower()
        if domain:
            urlscan_domains.add(domain)

    # Get the sort value from the last result for pagination
    last_sort = results[-1].get('sort')
    if last_sort:
        search_after = ','.join(str(s) for s in last_sort)
    else:
        break

    print(f"Fetched {len(urlscan_domains)} unique domains so far...")

print(f"Total unique domains from URLScan: {len(urlscan_domains)}")

# --- Step 2: Get blacklist from MetaMask GitHub ---
response = requests.get(GITHUB_RAW_URL)
config = response.json()
json_domains = set(config['blacklist'])

print(f"Fetched {len(json_domains)} domains from MetaMask blacklist")

# --- Step 3: Compare ---
unique_to_urlscan = urlscan_domains - json_domains

# --- Step 4: Output ---
today = datetime.now().strftime('%Y-%m-%d_%H%M')
output_file = f'pbdomains/pbdomains_archive/pbdomains_{today}.txt'
os.makedirs('pbdomains/pbdomains_archive', exist_ok=True)

with open(output_file, 'w') as f:
    for domain in sorted(unique_to_urlscan):
        f.write(domain + '\n')

print("-" * 50)
print(f"Total from URLScan: {len(urlscan_domains)}")
print(f"Total in MetaMask blacklist: {len(json_domains)}")
print(f"New domains NOT in blacklist: {len(unique_to_urlscan)}")
print(f"Saved to {output_file}")
