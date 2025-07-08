import os
import re
import pandas as pd
import unicodedata
import scipy.sparse as sp
import joblib
from bs4 import BeautifulSoup
from docx import Document
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression # Or your preferred model
from sklearn.metrics import classification_report, accuracy_score
from sklearn.feature_extraction.text import CountVectorizer
from app_Utilities.sanitize_text import sanitize_text
from train_and_evaluate_new_Model_with_new_features import count_links, has_ip_in_url, has_script_tags

def extract_text(file_path):
    ext = file_path.split('.')[-1].lower()
    if ext == 'html':
        with open(file_path, encoding='utf-8', errors='ignore') as f:
            return BeautifulSoup(f, 'html.parser').get_text(), f.read() # Return full HTML for new features
    elif ext == 'docx':
        return "\n".join(p.text for p in Document(file_path).paragraphs), "" # No HTML for docx
    return "", ""

def train_new_model(dataset_path='dataset', model_output_path='New_Model_With_Count_Vectorizer', vectorizer_output_path='New_Model_With_Count_Vectorizer'):
 
    data = []
    labels = [] # Labels: 0 for legitimate, 1 for phishing

    #region --- Load Data ---
    #  legitimate emails
    legit_path = os.path.join(dataset_path, 'legitimate')
    for filename in os.listdir(legit_path):
        file_path = os.path.join(legit_path, filename)
        if os.path.isfile(file_path):
            text_content, html_content = extract_text(file_path)
            data.append({
                'text': sanitize_text(text_content),
                'html': html_content,
                'label': 0 # Legitimate
            })
            labels.append(0)

    #   phishing emails
    phishing_path = os.path.join(dataset_path, 'phishing')
    for filename in os.listdir(phishing_path):
        file_path = os.path.join(phishing_path, filename)
        if os.path.isfile(file_path):
            text_content, html_content = extract_text(file_path)
            data.append({
                'text': sanitize_text(text_content),
                'html': html_content,
                'label': 1 # for phishing
            })
            labels.append(1)

    df = pd.DataFrame(data)

    print(f"Loaded {len(df)} emails.")
    print(f"Phishing emails: {df[df['label'] == 1].shape[0]}")
    print(f"Legitimate emails: {df[df['label'] == 0].shape[0]}")
    # endregion --- --- --- --- --- --- --- --- --- ---
    
    # ---New Feature Engineering ---
    print("Engineering new features...")
    df['num_links'] = df['html'].apply(count_links)
    df['has_ip_in_url'] = df['html'].apply(has_ip_in_url)
    df['has_script_tags'] = df['html'].apply(has_script_tags)

    X = df['text']
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Performing Count Vectorization...")    
    vectorizer = CountVectorizer(max_features=5000, stop_words='english')
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    X_train_engineered_features = sp.csc_matrix(df.loc[X_train.index, ['num_links', 'has_ip_in_url', 'has_script_tags']].values)
    X_test_engineered_features = sp.csc_matrix(df.loc[X_test.index, ['num_links', 'has_ip_in_url', 'has_script_tags']].values)

    X_train_combined = sp.hstack([X_train_tfidf, X_train_engineered_features])
    X_test_combined = sp.hstack([X_test_tfidf, X_test_engineered_features])


    # --- Train the Model ---
    print("Training the model...")
    model = LogisticRegression(max_iter=1000) # You can try other classifiers like RandomForestClassifier, SVM
    model.fit(X_train_combined, y_train)

    # --- Evaluate the Model ---
    print("\nEvaluating the model...")
    y_pred = model.predict(X_test_combined)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    print(f"Model Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(report)

    # --- Save Model and Vectorizer ---
    os.makedirs(model_output_path, exist_ok=True)
    joblib.dump(model, os.path.join(model_output_path, 'phishing_model_with_Count_Vectorizer.pkl'))
    joblib.dump(vectorizer, os.path.join(vectorizer_output_path, 'vectorizer_with_Count_Vectorizer.pkl'))
    print(f"New model saved to {os.path.join(model_output_path, 'phishing_model_with_Count_Vectorizer.pkl')}")
    print(f"New vectorizer saved to {os.path.join(vectorizer_output_path, 'vectorizer_Count_Vectorizer.pkl')}")

if __name__ == '__main__':
    train_new_model(dataset_path='dataset')