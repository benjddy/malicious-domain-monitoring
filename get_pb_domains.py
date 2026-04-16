import requests
import re

def get_pb_domains():
    # Sample code to get PB domains
    response = requests.get('https://example.com')
    return response.text.splitlines()


def remove_www_prefix(domain):
    if domain.startswith('www.'):  
        return domain[4:]  
    return domain


def main():
    domains = get_pb_domains()
    filtered_domains = []
    for domain in domains:
        domain = remove_www_prefix(domain)  # Remove www prefix
        if is_malicious(domain):
            filtered_domains.append(domain)
    print(filtered_domains)

if __name__ == '__main__':
    main()