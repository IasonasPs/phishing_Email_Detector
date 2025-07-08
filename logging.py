import logging
import os

def logging(filename,datetime,is_phishing,cues):

    # Create a logger
    logger = logging.getLogger('phishing_email_detector')
    logger.setLevel(logging.DEBUG)

    # Create a file handler
    log_file = 'phishing_email_detector.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create a formatter and set it for both handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger