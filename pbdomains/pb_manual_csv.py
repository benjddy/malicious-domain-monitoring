print("Script started...")
import json
import csv
import os
import sys
import ipaddress
import requests
from datetime import datetime

# --- CONFIG ---
GITHUB_RAW_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json'
SKIP_LIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'skip_apex_domains.txt')
ARCHIVE_DIR = os.path.join(os.path.dirname(__file__), 'pbdomains_archive')

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

# --- Get CSV filename from user ---
if len(sys.argv) > 1:
    csv_file = sys.argv[1]
else:
    csv_file = input("Enter the CSV filename (e.g. domains.csv): ").strip()

if not os.path.exists(csv_file):
    print(f"ERROR: File '{csv_file}' not found!")
    print(f"Make sure the file is in: {os.getcwd()}")
    sys.exit(1)

# --- Load skip list ---
skip_domains = set()
if os.path.exists(SKIP_LIST_FILE):
    with open(SKIP_LIST_FILE, 'r') as f:
        for line in f:
            entry = line.strip().lower()
            if entry and not entry.startswith('#'):
                skip_domains.add(entry)
    print(f"Loaded {len(skip_domains)} domains from skip list")
else:
    print(f"WARNING: Skip list not found at {SKIP_LIST_FILE}")

# --- Detect CSV column name ---
with open(csv_file, 'r') as f:
    reader = csv.DictReader(f)
    columns = reader.fieldnames
    print(f"CSV columns found: {columns}")

    domain_column = None
    for col in columns:
        if col.strip().lower() in ['domain', 'task domain', 'hostname', 'url']:
            domain_column = col
            break

    if not domain_column:
        print(f"\nCouldn't auto-detect domain column.")
        print(f"Available columns: {columns}")
        domain_column = input("Enter the column name that contains domains: ").strip()

    print(f"Using column: '{domain_column}'")

# --- Load domains from CSV ---
csv_domains = set()
with open(csv_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        domain = row[domain_column].strip().lower()
        if domain:
            csv_domains.add(domain)

print(f"Loaded {len(csv_domains)} domains from CSV")

# --- Get blacklist from MetaMask GitHub ---
print("Fetching latest MetaMask blacklist...")
response = requests.get(
    GITHUB_RAW_URL,
    headers={'Cache-Control': 'no-cache'}
)
config = response.json()
json_domains = set(config['blacklist'])
print(f"Fetched {len(json_domains)} domains from MetaMask blacklist")

# --- Compare and filter (same checks as automated script) ---
unique_domains = set()
filtered_blacklist = set()
filtered_apex = set()
filtered_skip = set()
filtered_ips = set()

for domain in csv_domains:
    # Skip IP addresses
    if is_ip_address(domain):
        filtered_ips.add(domain)
        continue

    # Skip if exact domain is already in blacklist
    if domain in json_domains:
        filtered_blacklist.add(domain)
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
        filtered_apex.add(domain)
        continue

    # Skip if domain matches manual skip list
    if should_skip(domain, skip_domains):
        filtered_skip.add(domain)
        continue

    unique_domains.add(domain)

# --- Save results to archive folder ---
today = datetime.now().strftime('%Y-%m-%d_%H%M')
os.makedirs(ARCHIVE_DIR, exist_ok=True)
output_file = os.path.join(ARCHIVE_DIR, f'pb_manual_{today}.txt')

with open(output_file, 'w') as f:
    for domain in sorted(unique_domains):
        f.write(domain + '\n')

# --- Print summary ---
print("-" * 50)
print(f"Total domains in CSV: {len(csv_domains)}")
print(f"Total in MetaMask blacklist: {len(json_domains)}")
print(f"IP addresses skipped: {len(filtered_ips)}")
print(f"Already in blacklist (exact match): {len(filtered_blacklist)}")
print(f"Subdomains filtered (apex already blocked): {len(filtered_apex)}")
print(f"Domains filtered (skip list): {len(filtered_skip)}")
print(f"New domains NOT in blacklist: {len(unique_domains)}")
print("-" * 50)
print(f"Results saved to {output_file}")