# Functionality to Remove www. Subdomains

def remove_www_subdomain(domain):
    if domain.startswith('www.'):  
        return domain[4:]  
    return domain

# Example usage
# print(remove_www_subdomain('www.example.com'))  # Output: example.com
# print(remove_www_subdomain('example.com'))  # Output: example.com