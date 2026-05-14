import json
import requests
import os
import ipaddress
from datetime import datetime, timedelta


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def should_skip(domain, skip_list):
    for skip in skip_list:
        if domain == skip or domain.endswith('.' + skip):
            return True
    return False


def load_skip_list(path):
    skip_domains = set()
    if os.path.exists(path):
        with open(path, 'r') as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    skip_domains.add(line)
    return skip_domains


def fetch_urlscan_results(api_key, search_url, search_uuid):
    query = f'meta:searchhit.search.{search_uuid} AND date:>now-48h'
    results = []
    search_after = None

    while True:
        params = {'q': query, 'size': 100}
        if search_after:
            params['search_after'] = search_after

        headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json'
        }

        response = requests.get(search_url, params=params, headers=headers)
        data = response.json()
        batch = data.get('results', [])

        if not batch:
            break

        results.extend(batch)

        last_sort = batch[-1].get('sort')
        if last_sort:
            search_after = ','.join(str(s) for s in last_sort)
        else:
            break

        print(f"  Fetched {len(results)} results so far...")

    return results


def fetch_blacklist(github_url):
    response = requests.get(github_url, headers={'Cache-Control': 'no-cache'})
    config = response.json()
    return set(config['blacklist'])


def filter_domains(urlscan_results, blacklist, skip_domains):
    new_domains = set()
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

        if domain.startswith("www."):
            domain = domain[4:]

        if is_ip_address(domain):
            filtered_ips.add(domain)
            continue

        if domain in blacklist:
            filtered_blacklist.add(domain)
            continue

        if apex_domain in blacklist and domain != apex_domain:
            filtered_apex.add(domain)
            continue

        if should_skip(domain, skip_domains):
            filtered_skip.add(domain)
            continue

        new_domains.add(domain)

    return new_domains, filtered_blacklist, filtered_apex, filtered_skip, filtered_ips


def save_archive(domains, archive_dir, prefix):
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M')
    output_file = f'{archive_dir}/{prefix}_{timestamp}.txt'

    with open(output_file, 'w') as f:
        for domain in sorted(domains):
            f.write(domain + '\n')

    return output_file


def build_still_need_blocked(archive_dir, prefix, retention_days, blacklist, skip_domains):
    still_need_blocked = set()
    cutoff_date = datetime.now() - timedelta(days=retention_days)

    for filename in sorted(os.listdir(archive_dir)):
        if not filename.endswith('.txt'):
            continue

        try:
            date_str = filename.replace(f'{prefix}_', '').replace('.txt', '')
            file_date = datetime.strptime(date_str, '%Y-%m-%d_%H%M')
        except ValueError:
            continue
        if file_date < cutoff_date:
            continue

        filepath = os.path.join(archive_dir, filename)
        with open(filepath, 'r') as f:
            for line in f:
                domain = line.strip().lower()
                if not domain:
                    continue
                if domain.startswith("www."):
                    domain = domain[4:]
                if is_ip_address(domain):
                    continue
                if domain in blacklist:
                    continue
                if should_skip(domain, skip_domains):
                    continue

                parts = domain.split('.')
                apex_found = False
                for i in range(len(parts) - 1):
                    potential_apex = '.'.join(parts[i:])
                    if potential_apex in blacklist and potential_apex != domain:
                        apex_found = True
                        break
                if apex_found:
                    continue

                still_need_blocked.add(domain)

    return still_need_blocked


def run_feed(feed_name, feed_config, api_key, search_url, blacklist, skip_domains, retention_days):
    print(f"\n{'='*60}")
    print(f"Processing feed: {feed_name}")
    print(f"{'='*60}")

    results = fetch_urlscan_results(api_key, search_url, feed_config['search_uuid'])
    print(f"Total results from URLScan: {len(results)}")

    new_domains, f_blacklist, f_apex, f_skip, f_ips = filter_domains(results, blacklist, skip_domains)

    output_file = save_archive(new_domains, feed_config['archive_dir'], feed_config['archive_prefix'])

    print(f"\nSaved {len(new_domains)} new domains to {output_file}")
    print(f"Filtered out: {len(f_blacklist)} already in blacklist, "
          f"{len(f_apex)} apex matched, {len(f_skip)} skipped, "
          f"{len(f_ips)} IPs")

    still_need_blocked = build_still_need_blocked(
        feed_config['archive_dir'],
        feed_config['archive_prefix'],
        retention_days,
        blacklist,
        skip_domains
    )

    with open(feed_config['still_need_blocked_file'], 'w') as f:
        for domain in sorted(still_need_blocked):
            f.write(domain + '\n')

    print(f"Domains still needing to be blocked: {len(still_need_blocked)}")
    print(f"Saved to {feed_config['still_need_blocked_file']}")


def main():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)

    api_key = os.environ.get('URLSCAN_API_KEY')
    if not api_key:
        print("Error: URLSCAN_API_KEY environment variable not set")
        return

    skip_domains = load_skip_list(config['skip_list_file'])
    print(f"Loaded {len(skip_domains)} skip domains")

    blacklist = fetch_blacklist(config['github_blacklist_url'])
    print(f"Fetched {len(blacklist)} domains from MetaMask blacklist")

    for feed_name, feed_config in config['feeds'].items():
        run_feed(
            feed_name,
            feed_config,
            api_key,
            config['urlscan_search_url'],
            blacklist,
            skip_domains,
            config['archive_retention_days']
        )


if __name__ == '__main__':
    main()
