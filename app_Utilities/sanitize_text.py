import unicodedata


def sanitize_text(text):
    return unicodedata.normalize("NFKD", text).encode("utf-8", "ignore").decode("utf-8", "ignore")