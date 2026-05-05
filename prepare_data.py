# prepare_data.py
import pandas as pd
import os
from utils import clean_text, extract_url_strings, url_features

def prepare(infile, outfile="data/processed.csv"):
    df = pd.read_csv(infile)
    # assume text column is named 'text' (if different, adjust)
    if 'text' not in df.columns:
        # try common column names
        for c in df.columns:
            if 'body' in c.lower() or 'message' in c.lower():
                df = df.rename(columns={c:'text'})
                break
    df['text_clean'] = df['text'].fillna('').apply(clean_text)
    df['urls'] = df['text'].fillna('').apply(extract_url_strings)
    feats = df['urls'].apply(url_features).apply(pd.Series)
    df = pd.concat([df, feats], axis=1)
    df.to_csv(outfile, index=False)
    print(f"Processed data saved to {outfile}")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    import sys
    if len(sys.argv) < 2:
        print("Usage: python prepare_data.py data/your.csv")
    else:
        prepare(sys.argv[1])
