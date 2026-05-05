# quick_test_data.py
import os
import pandas as pd

os.makedirs("data", exist_ok=True)

rows = [
    {"text":"Dear user, your account will be suspended. Click http://fake-login.example.com to verify", "label":"phishing"},
    {"text":"Team update: the meeting is moved to 3pm today. See calendar invite.", "label":"legit"},
    {"text":"Your invoice attached. Download from http://malicious.example/download", "label":"phishing"},
    {"text":"Hello Raj, can you share the quarterly report? Thanks.", "label":"legit"},
    {"text":"Important: confirm your payment details at https://secure-pay.example.verify-account.com", "label":"phishing"}
]

df = pd.DataFrame(rows)
df.to_csv("data/quick_sample.csv", index=False)
print("Quick sample saved to data/quick_sample.csv")
