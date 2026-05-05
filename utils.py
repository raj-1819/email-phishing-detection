# utils.py
import re
from bs4 import BeautifulSoup
import tldextract

url_regex = re.compile(r'(https?://\S+)|(\bwww\.\S+\b)', re.IGNORECASE)

def extract_urls(text):
    return url_regex.findall(text)

def extract_url_strings(text):
    matches = url_regex.findall(text)
    # matches are tuples from the regex; pick non-empty
    urls = [m[0] or m[1] for m in matches]
    return urls

def clean_text(text):
    # remove HTML tags, lower, strip punctuation except URLs (we'll extract URLs separately)
    if not isinstance(text, str): text = str(text)
    soup = BeautifulSoup(text, "html.parser")
    text = soup.get_text(" ")
    text = text.lower()
    # remove excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def url_features(urls):
    # simple URL features: count, avg length, has IP, subdomain depth, suspicious TLDs
    import numpy as np
    if not urls:
        return {
            "url_count":0,
            "avg_url_len":0,
            "has_ip":0,
            "subdomain_depth":0,
            "suspicious_tld":0
        }
    lengths = [len(u) for u in urls]
    extracts = [tldextract.extract(u) for u in urls]
    subdepths = [len(e.subdomain.split('.')) if e.subdomain else 0 for e in extracts]
    suspicious_tlds = ['tk','ml','ga','cf','gq']  # common suspicious short TLDs (example)
    return {
        "url_count": len(urls),
        "avg_url_len": np.mean(lengths),
        "has_ip": int(any(re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', u) for u in urls)),
        "subdomain_depth": int(max(subdepths)),
        "suspicious_tld": int(any(e.suffix in suspicious_tlds for e in extracts))
    }
