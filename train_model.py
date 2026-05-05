import sys
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

def train(data_path):
    # Load data
    df = pd.read_csv(data_path)
    
    # Check columns
    if 'text' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must contain 'text' and 'label' columns.")
    
    # Check class distribution
    class_counts = df['label'].value_counts()
    print("Class distribution:\n", class_counts)
    
    X_text = df['text'].values
    y = df['label'].values
    
    # Determine test_size and stratification
    min_class_count = class_counts.min()
    if min_class_count < 2:
        print("Warning: Very few samples in at least one class. Stratified split not possible.")
        stratify_param = None
        test_size = 0.3 if len(df) > 1 else 0.5
    else:
        stratify_param = y
        test_size = 0.3
    
    # Split dataset
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=test_size, random_state=42, stratify=stratify_param
    )
    
    # Vectorize text
    vectorizer = TfidfVectorizer()
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_test_vec = vectorizer.transform(X_test_text)
    
    # Train classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vec, y_train)
    
    # Evaluate model
    y_pred = clf.predict(X_test_vec)
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

if __name__ == "__main__":
    train(sys.argv[1])
