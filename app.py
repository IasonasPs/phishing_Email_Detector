from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from docx import Document
import os, joblib, re, unicodedata
import warnings
import scipy.sparse as sp # Import for combining features in prediction
import numpy as np # Import for creating dense arrays for numerical features
from werkzeug.utils import secure_filename
from app_Utilities.extract_text_and_html import extract_text_and_html
from app_Utilities.sanitize_text import   sanitize_text
from app_Utilities.new_features_Functions import count_hyperlinks, has_ip_in_url, has_script_tags
from logs_creating import log_phishing_data_to_csv



warnings.filterwarnings("ignore") 

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

mPath, vPath = 'model/phishing_model.pkl', 'model/vectorizer.pkl'
newM_Path, newV_Path = 'New_Model_with_new_features/phishing_model_with_new_features.pkl', 'New_Model_with_new_features/vectorizer_with_new_features.pkl'

# region Control variable to switch between old and new model paths
control = False
if control:
    modelPath = mPath
    vectorizerPath = vPath
else:
    modelPath = newM_Path
    vectorizerPath = newV_Path     

model = joblib.load(modelPath)
vectorizer = joblib.load(vectorizerPath)
# endregion --- --- --- --- --- --- --- ---

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

@app.route('/', methods=['GET', 'POST']) # flask route decorator
def upload_file():
    result = None
    displayed_cues = None
    is_phishing = False

    if request.method == 'POST':

        file = request.files['file']
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
        else:       # new model
            numerical_features = np.array([[num_hyperlinks, ip_in_url_flag, script_tags_flag]])
            numerical_features_sparse = sp.csr_matrix(numerical_features)
            combined_features = sp.hstack([text_features, numerical_features_sparse])   
        # endregion --- --- ---    
        
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
        is_phishing=is_phishing
    )

if __name__ == '__main__':
    app.run(debug=True)

