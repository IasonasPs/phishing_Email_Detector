import os
import csv
from datetime import datetime 

def log_phishing_data_to_csv(email_filename, detection_datetime, is_phishing, cues):
    print("Logging phishing data to CSV...")
    print(f"Email Filename: {email_filename}")
    print(f"Detection Datetime: {detection_datetime}")
    print(f"Is Phishing: {is_phishing}")
    print(f"Cues: {cues}")
    
    
    
    log_folder = 'logs'
    log_file_name = 'phishing_detection_log.csv'
    log_file_path = os.path.join(log_folder, log_file_name)

    try:
        os.makedirs(log_folder, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory '{log_folder}': {e}")
        return 

    file_exists = os.path.exists(log_file_path)

    try:
        with open(log_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            if not file_exists:
                writer.writerow(['Email Filename', 'Detection Datetime', 'Is Phishing', 'Cues'])
                print(f"Created new CSV file '{log_file_name}' with header.")

            writer.writerow([email_filename, detection_datetime, is_phishing, cues])
            print(f"Logged data to '{log_file_name}'.")
    except IOError as e:
        print(f"Error writing to CSV file '{log_file_path}': {e}")

