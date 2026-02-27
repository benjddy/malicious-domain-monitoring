import json
import requests
import os
from datetime import datetime

# --- CONFIG ---
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/refs/heads/main/src/config.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search?datasource=scans&q=meta:searchhit.search.8834ad57-24f0-4932-9ca3-731e814c7b21'

# --- Step 1: Get domains from URLScan API ---
headers = {'API-Key': URLSCAN_API_KEY}
response = requests.get(URLSCAN_SEARCH_URL, headers=headers, params={'size': 10000})
urlscan_data = response.json()

csv_domains = set()
for result in urlscan_data.get('results', []):
    domain = result.get('task', {}).get('domain', '').strip().lower()
    if domain:
        csv_domains.add(domain)

print(f"Fetched {len(csv_domains)} domains from URLScan")

# --- Step 2: Get blacklist from MetaMask GitHub ---
response = requests.get(GITHUB_RAW_URL)
config = response.json()
json_domains = set(config['blacklist'])

print(f"Fetched {len(json_domains)} domains from MetaMask blacklist")

# --- Step 3: Compare ---
unique_to_urlscan = csv_domains - json_domains

# --- Step 4: Output ---
today = datetime.now().strftime('%Y-%m-%d_%H%M')
output_file = f'pbdomains-archive/pbdomains_{today}.txt'
os.makedirs('pbdomains-archive', exist_ok=True)

with open(output_file, 'w') as f:
    for domain in sorted(unique_to_urlscan):
        f.write(domain + '\n')

print("-" * 50)
print(f"Total from URLScan: {len(csv_domains)}")
print(f"Total in MetaMask blacklist: {len(json_domains)}")
print(f"New domains NOT in blacklist: {len(unique_to_urlscan)}")
print(f"Saved to {output_file}")
