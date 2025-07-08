import re
from bs4 import BeautifulSoup

def count_hyperlinks(html_content):
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    return len(soup.find_all('a', href=True))

def has_ip_in_url(html_content):
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', href):
            return 1
    return 0

def has_script_tags(html_content):
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    return 1 if soup.find_all('script') else 0