

from bs4 import BeautifulSoup
from docx import Document


def extract_text_and_html(path):
    ext = path.split('.')[-1].lower()
    if ext == 'html':
        with open(path, encoding='utf-8', errors='ignore') as f:
            html_content = f.read()
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text(), html_content
    elif ext == 'docx':
        return "\n".join(p.text for p in Document(path).paragraphs),""
    return "",""

