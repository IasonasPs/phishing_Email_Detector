from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from docx import Document
import os, joblib, re, unicodedata
import warnings
import scipy.sparse as sp # Import for combining features in prediction


warnings.filterwarnings("ignore") 

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

model = joblib.load('New_Model/phishing_model_with_new_features.pkl')
vectorizer = joblib.load('New_Model/vectorizer_with_new_features.pkl')

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

def sanitize_text(text):
    return unicodedata.normalize("NFKD", text).encode("utf-8", "ignore").decode("utf-8", "ignore")

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

def phishing_cues(txt):
    cues = []
    if re.search(r'\burgent\b|\bimmediately\b|\basap\b|\balert\b', txt, re.I):
        cues.append("⚠️ Urgency language detected")
    if re.search(r'\bclick here\b|\bverify\b|\breset.*password\b|\bconfirm .*account\b', txt, re.I):
        cues.append("🔗 Suspicious action request")
    if re.search(r'\bdear (customer|user|valued customer)\b', txt, re.I):
        cues.append("👤 Generic greeting found")
    if re.search(r'\blogin\b|\bpassword\b|\bcredit card\b|\bbank account\b', txt, re.I):
        cues.append("🔐 Sensitive information request")
    return cues

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST' and request.files['file'].filename:from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from docx import Document
import os, joblib, re, unicodedata
import warnings
import scipy.sparse as sp # Import for combining features in prediction
import numpy as np # Import for creating dense arrays for numerical features

warnings.filterwarnings("ignore")

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # Configure Flask to use the upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load the pre-trained model and vectorizer
# Ensure these files are in a directory named 'New_Model' relative to your app.py
try:
    model = joblib.load('New_Model/phishing_model_with_new_features.pkl')
    vectorizer = joblib.load('New_Model/vectorizer_with_new_features.pkl')
except FileNotFoundError:
    print("Error: Model or vectorizer files not found.")
    print("Please ensure 'phishing_model_with_new_features.pkl' and 'vectorizer_with_new_features.pkl' are in the 'New_Model' directory.")
    # Exit or handle the error appropriately, e.g., by not starting the app
    exit()


def extract_text_and_html(path):
    """
    Extracts text content and raw HTML content from a given file path.
    Supports .html and .docx files.
    """
    ext = path.split('.')[-1].lower()
    if ext == 'html':
        with open(path, encoding='utf-8', errors='ignore') as f:
            html_content = f.read()
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text(), html_content
    elif ext == 'docx':
        # For docx, we only extract text, no HTML content
        return "\n".join(p.text for p in Document(path).paragraphs), ""
    return "", "" # Return empty strings if file type is not supported

def sanitize_text(text):
    """
    Sanitizes text by normalizing Unicode characters and encoding/decoding
    to remove non-ASCII characters.
    """
    return unicodedata.normalize("NFKD", text).encode("utf-8", "ignore").decode("utf-8", "ignore")

def count_hyperlinks(html_content):
    """
    Counts the number of hyperlinks (<a> tags with href attribute) in HTML content.
    """
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    return len(soup.find_all('a', href=True))

def has_ip_in_url(html_content):
    """
    Checks if any hyperlink in the HTML content contains an IP address in its URL.
    Returns 1 if found, 0 otherwise.
    """
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # Regex to find a typical IPv4 address pattern
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', href):
            return 1
    return 0

def has_script_tags(html_content):
    if not html_content:
        return 0
    soup = BeautifulSoup(html_content, 'html.parser')
    return 1 if soup.find_all('script') else 0

def phishing_cues(txt):
    cues = []
    # Urgency language
    if re.search(r'\burgent\b|\bimmediately\b|\basap\b|\balert\b', txt, re.I):
        cues.append("⚠️ Urgency language detected")
    # Suspicious action requests
    if re.search(r'\bclick here\b|\bverify\b|\breset.*password\b|\bconfirm .*account\b', txt, re.I):
        cues.append("🔗 Suspicious action request")
    # Generic greetings
    if re.search(r'\bdear (customer|user|valued customer)\b', txt, re.I):
        cues.append("👤 Generic greeting found")
    # Sensitive information requests
    if re.search(r'\blogin\b|\bpassword\b|\bcredit card\b|\bbank account\b', txt, re.I):
        cues.append("🔐 Sensitive information request")
    return cues

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    result = None
    displayed_cues = None
    is_phishing = False

    if request.method == 'POST':
        # Check if a file was actually uploaded

        file = request.files['file']
        path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        file.save(path)

        raw_text, html_content = extract_text_and_html(path)
        text = sanitize_text(raw_text)

        text_features = vectorizer.transform([text])

        num_hyperlinks = count_hyperlinks(html_content)
        ip_in_url_flag = has_ip_in_url(html_content)
        script_tags_flag = has_script_tags(html_content)

        numerical_features = np.array([[num_hyperlinks, ip_in_url_flag, script_tags_flag]])
        numerical_features_sparse = sp.csr_matrix(numerical_features)
        combined_features = sp.hstack([text_features, numerical_features_sparse])

        model_pred = model.predict(combined_features)[0]

        cues = phishing_cues(text)

        # Modified logic: Only flag as phishing if model predicts 1 AND some cues are found
        is_phishing = (model_pred == 1) and (len(cues) > 0)

        result = "⚠️ Phishing Detected!" if is_phishing else "✅ Safe Document."
        displayed_cues = cues if cues else ["✅ No obvious phishing cues detected in text."]

        if html_content:
            displayed_cues.append(f"🔗 Links Count: {num_hyperlinks}")
            displayed_cues.append(f"🌐 IP in URL: {'Yes' if ip_in_url_flag else 'No'}")
            displayed_cues.append(f"📄 Script Tags: {'Yes' if script_tags_flag else 'No'}")
        else:
            displayed_cues.append("ℹ️ No HTML content to analyze for links/scripts.")

        os.remove(path)

    return render_template(
        'upload.html',
        result=result,
        cues=displayed_cues,
        is_phishing=is_phishing
    )



if __name__ == '__main__':
    app.run(debug=True)

