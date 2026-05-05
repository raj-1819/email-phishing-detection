# src/preprocess.py
import re
import pandas as pd
from sklearn.model_selection import train_test_split

def clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    # remove URLs
    text = re.sub(r'http\S+|www\.\S+', ' ', text)
    # remove email addresses
    text = re.sub(r'\S+@\S+', ' ', text)
    # remove non-alphanumeric characters (keep spaces)
    text = re.sub(r'[^A-Za-z0-9\s]', ' ', text)
    text = text.lower()
    # collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def load_and_prepare(path: str, text_column='text', label_column='label', sample_frac=None):
    df = pd.read_csv(path)
    # Ensure expected columns: try common names if not found
    if text_column not in df.columns:
        # try possible alternatives
        for alt in ['content','message','body','email','text_body','email_body']:
            if alt in df.columns:
                text_column = alt
                break
    if label_column not in df.columns:
        for alt in ['label','class','target','is_phish','phish']:
            if alt in df.columns:
                label_column = alt
                break
    df = df[[text_column, label_column]].dropna()
    df['text_clean'] = df[text_column].apply(clean_text)
    # standardize labels: phishing=1, legit=0
    df[label_column] = df[label_column].map(lambda v: 1 if str(v).lower() in ['phish','phishing','1','true','yes'] else 0)
    if sample_frac:
        df = df.sample(frac=sample_frac, random_state=42)
    X = df['text_clean'].values
    y = df[label_column].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    return X_train, X_test, y_train, y_test
