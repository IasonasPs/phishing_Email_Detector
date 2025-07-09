from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from docx import Document
import os, joblib, re, unicodedata
import warnings
import scipy.sparse as sp # Import for combining features in prediction
import numpy as np # Import for creating dense arrays for numerical features
from werkzeug.utils import secure_filename
# Assuming these are available in app_Utilities and logs_creating
from app_Utilities.extract_text_and_html import extract_text_and_html
from app_Utilities.sanitize_text import sanitize_text
from app_Utilities.new_features_Functions import count_hyperlinks, has_ip_in_url, has_script_tags
from logs_creating import log_phishing_data_to_csv

warnings.filterwarnings("ignore")

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Mock model and vectorizer for demonstration purposes
# In a real application, these would be loaded from actual .pkl files
class MockVectorizer:
    def transform(self, text_list):
        # Returns a sparse matrix, similar to TfidfVectorizer output
        return sp.csr_matrix([[len(text_list[0])]]) # Simple mock: length of text

class MockModel:
    def predict(self, features):
        # Simple mock prediction: always predicts 0 (safe)
        # unless features indicate something specific for testing
        if features.shape[1] > 1 and features[0, 1] > 0: # Check for numerical features, e.g., hyperlinks
            return np.array([1]) # Mock: predict phishing if hyperlinks exist
        return np.array([0])

# Ensure model and vectorizer paths exist or mock them
# For this example, we will use mock objects since the actual .pkl files are not provided.
mPath, vPath = 'model/phishing_model.pkl', 'model/vectorizer.pkl'
newM_Path, newV_Path = 'New_Model_with_new_features/phishing_model_with_new_features.pkl', 'New_Model_with_new_features/vectorizer_with_new_features.pkl'

# region Control variable to switch between old and new model paths
control = False # Set to True to use old model paths (which will still be mocked here)
if control:
    modelPath = mPath
    vectorizerPath = vPath
else:
    modelPath = newM_Path
    vectorizerPath = newV_Path

# Load or mock the model and vectorizer
try:
    model = joblib.load(modelPath)
    vectorizer = joblib.load(vectorizerPath)
except FileNotFoundError:
    print("Model or vectorizer files not found. Using mock objects for demonstration.")
    model = MockModel()
    vectorizer = MockVectorizer()
# endregion --- --- --- --- --- --- --- ---

def phishing_cues(txt):
    cues = []
    score = 0

 
    cue_patterns = {
        "⚠️ Urgency language detected": r'\b(urgent|immediately|asap|alert|action required|expire|deadline|final warning|act now)\b',
        "🔗 Suspicious action request": r'\b(click here|verify|reset.*password|confirm.*account|update your information|download attachment|view invoice|login to your account|access now)\b',
        "👤 Generic greeting found": r'\b(dear (customer|user|valued customer|member)|undisclosed recipients|attention:)\b',
        "🔐 Sensitive information request": r'\b(login|password|credit card|bank account|social security|pin|security code|date of birth|username|account number)\b',
        "💰 Financial request/issue": r'\b(invoice due|payment failed|refund|transaction alert|billing issue|wire transfer|money order|unpaid balance|payment required)\b',
        "🚨 Account issue/suspension": r'\b(account suspended|unusual activity|account locked|security alert|compromised account|account disabled|unauthorized access)\b',
        "🎭 Spoofing indicators (e.g., misspellings, odd sender)": r'\b(from a trusted source|official notification|security update|misspelled|kindly|verify your identity)\b', 
        "🚫 Threatening tone": r'\b(will be closed|legal action|penalty|suspend your account|block your access|terminate your account|failure to comply)\b',
        "🎁 Deceptive/Baiting language": r'\b(congratulations|prize|gift|lucky winner|exclusive offer|you have won|claim your reward|free money)\b',
        "🏢 Authoritative/Official tone": r'\b(compliance|mandatory|official communication|government agency|court order|regulatory notice)\b'
    }

    # Assign base scores for each type of cue
    cue_scores = {
        "⚠️ Urgency language detected": 2,
        "🔗 Suspicious action request": 3,
        "👤 Generic greeting found": 1,
        "🔐 Sensitive information request": 5,
        " Financial request/issue": 4,
        " Account issue/suspension": 4,
        " Spoofing indicators (e.g., misspellings, odd sender)": 3,
        " Threatening tone": 5,
        " Deceptive/Baiting language": 3,
        " Authoritative/Official tone": 2
    }

    tone_counts = {
        "urgent": 0, "threatening": 0, "deceptive": 0, "authoritative": 0
    }

    for cue_description, pattern in cue_patterns.items():
        if re.search(pattern, txt, re.I):
            cues.append(cue_description)
            current_cue_score = cue_scores.get(cue_description, 0)
            score += current_cue_score

            if "Urgency" in cue_description:
                tone_counts["urgent"] += 1
            if "Threatening" in cue_description:
                tone_counts["threatening"] += 1
            if "Deceptive" in cue_description:
                tone_counts["deceptive"] += 1
            if "Authoritative" in cue_description:
                tone_counts["authoritative"] += 1

    overall_tone = "Neutral"
    if tone_counts["threatening"] > 0 or (tone_counts["urgent"] > 1 and tone_counts["threatening"] == 0):
        overall_tone = "Highly Urgent/Threatening"
    elif tone_counts["deceptive"] > 0:
        overall_tone = "Deceptive/Baiting"
    elif tone_counts["authoritative"] > 0:
        overall_tone = "Authoritative/Official"
    elif tone_counts["urgent"] > 0:
        overall_tone = "Urgent"

    if overall_tone != "Neutral":
        cues.append(f"🗣️ Detected Tone: {overall_tone}")

    risk_level = "Low"
    if score >= 10:
        risk_level = "High"
    elif score >= 5: 
        risk_level = "Medium"

    cues.append(f" Phishing Score: {score} (Risk: {risk_level})")

    return cues, score, risk_level

@app.route('/', methods=['GET', 'POST']) # flask route decorator
def upload_file():
    result = None
    displayed_cues = None
    is_phishing = False
    phishing_score = 0
    phishing_risk_level = "Low"

    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', result="No file part")
        file = request.files['file']
        if file.filename == '':
            return render_template('upload.html', result="No selected file")

        path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))

        datetime = request.form.get('datetime', None)
        filename = request.form.get('filename', None)
        file.save(path)

        print(f"File saved to {path}")
        raw_text, html_content = extract_text_and_html(path)
        text = sanitize_text(raw_text)

        text_features = vectorizer.transform([text])

        # New features extraction
        num_hyperlinks = count_hyperlinks(html_content)
        ip_in_url_flag = has_ip_in_url(html_content)
        script_tags_flag = has_script_tags(html_content)

        # region --- --- ---
        if control: # old model
            combined_features = text_features
        else:      # new model
            numerical_features = np.array([[num_hyperlinks, ip_in_url_flag, script_tags_flag]])
            numerical_features_sparse = sp.csr_matrix(numerical_features)
            combined_features = sp.hstack([text_features, numerical_features_sparse])
        # endregion --- --- ---

        model_pred = model.predict(combined_features)[0]
        # Call the enhanced phishing_cues function
        cues, phishing_score, phishing_risk_level = phishing_cues(text)

        # Modified logic: Flag as phishing if model predicts 1 OR risk level is Medium/High
        is_phishing = (model_pred == 1) or (phishing_risk_level in ["High", "Medium"])

        result = "⚠️ Phishing Detected!" if is_phishing else "✅ Safe Document."
        # If no cues are found by the pattern matching, provide a default message
        displayed_cues = cues if cues else ["✅ No obvious phishing cues detected in text."]

        # Append HTML-based cues
        if html_content:
            displayed_cues.append(f"🔗 Links Count: {num_hyperlinks}")
            displayed_cues.append(f"🌐 IP in URL: {'Yes' if ip_in_url_flag else 'No'}")
            displayed_cues.append(f"📄 Script Tags: {'Yes' if script_tags_flag else 'No'}")
        else:
            displayed_cues.append("ℹ️ No HTML content to analyze for links/scripts.")

        os.remove(path)

        # Log the phishing detection data
        log_phishing_data_to_csv(
            email_filename=filename if filename else secure_filename(file.filename),
            detection_datetime=datetime if datetime else "N/A",
            is_phishing=is_phishing,
            cues=', '.join(displayed_cues)
        )


    return render_template(
        'upload.html',
        result=result,
        cues=displayed_cues,
        is_phishing=is_phishing,
        phishing_score=phishing_score,
        phishing_risk_level=phishing_risk_level
    )

if __name__ == '__main__':
    app.run(debug=True)
