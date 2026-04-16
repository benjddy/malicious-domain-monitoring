# pb_manual_csv.py

import csv
import re
import sys


def remove_www_prefix(url):
    """Helper function to remove 'www.' prefix from a URL if present."""
    if url.startswith('www.'):  
        return url[4:]
    return url


def read_csv_file(file_path):
    """Reads a CSV file and processes URLs in it."""
    with open(file_path, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            for url in row:
                filtered_url = filter_url(url)
                print(filtered_url)


def filter_url(url):
    """Filters the URL to remove 'www.' prefix and returns the filtered URL."""
    return remove_www_prefix(url)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python pb_manual_csv.py <file_path>')
        sys.exit(1)

    file_path = sys.argv[1]
    read_csv_file(file_path)