# src/train.py
"""
Train phishing detection models, and save RandomForest + TF-IDF for monitor.py
"""

import argparse
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from preprocess import load_and_prepare
from utils import ensure_dirs, plot_confusion_matrix

def evaluate_model(name, model, X_test, y_test, report_dir):
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm_path = os.path.join(report_dir, f"cmatrix_{name}.png")
    plot_confusion_matrix(y_test, y_pred, out=cm_path)
    report = classification_report(y_test, y_pred, target_names=['Legit', 'Phish'], zero_division=0)
    return {
        'model': name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'report': report,
        'cm_path': cm_path
    }

def main(dataset_path, sample_frac=None):
    ensure_dirs()
    report_dir = 'reports'
    os.makedirs(report_dir, exist_ok=True)

    # Load full dataset stats
    df = pd.read_csv(dataset_path)
    if sample_frac:
        df = df.sample(frac=sample_frac, random_state=42)

    total_samples = len(df)
    total_legit = int((df.iloc[:, 1].map(
        lambda v: 1 if str(v).lower() in ['phish','phishing','1','true','yes'] else 0
    ) == 0).sum())
    total_phish = total_samples - total_legit

    print("\n=== Phishing Detection Models Training ===")
    print(f"Total Samples: {total_samples} | Legit: {total_legit} | Phishing: {total_phish}\n")

    # ---------------------------------------------------------------------
    #  MAIN MODEL FOR CAPSTONE PROJECT: Random Forest + TF-IDF
    # ---------------------------------------------------------------------
    print("[INFO] Training RandomForest for monitor.py...")

    X_train, X_test, y_train, y_test = load_and_prepare(dataset_path, sample_frac=sample_frac)

    tfidf_monitor = TfidfVectorizer(max_features=30000, ngram_range=(1,2))
    X_train_tfidf = tfidf_monitor.fit_transform(X_train)
    X_test_tfidf = tfidf_monitor.transform(X_test)

    rf_model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train_tfidf, y_train)

    y_pred = rf_model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred)
    print(f"[INFO] RandomForest Accuracy: {acc:.4f}")

    os.makedirs('models', exist_ok=True)

    # --- SAVE USING CORRECT CAPSTONE NAMES ---
    joblib.dump(rf_model, "models/random_forest.joblib")
    joblib.dump(tfidf_monitor, "models/tfidf_vectorizer.joblib")

    print("[INFO] Saved RandomForest model (models/random_forest.joblib)")
    print("[INFO] Saved TF-IDF vectorizer (models/tfidf_vectorizer.joblib)")

    # ---------------------------------------------------------------------
    #  OPTIONAL MODELS FOR COMPARISON (LogReg, NB, SVC, Boost, KNN)
    # ---------------------------------------------------------------------
    models = {
        'Logistic Regression': LogisticRegression(max_iter=2000, solver='lbfgs'),
        'Multinomial NB': MultinomialNB(),
        'Linear SVC': LinearSVC(max_iter=5000, dual=False),
        'Gradient Boost': GradientBoostingClassifier(n_estimators=200, random_state=42),
        'KNN': KNeighborsClassifier(n_neighbors=5)
    }

    for name, model in models.items():
        X_train, X_test, y_train, y_test = load_and_prepare(dataset_path, sample_frac=sample_frac)
        tfidf = TfidfVectorizer(max_features=30000, ngram_range=(1,2))
        X_train_tfidf = tfidf.fit_transform(X_train)
        X_test_tfidf = tfidf.transform(X_test)

        print(f"→ Training {name} ...", end=" ")
        model.fit(X_train_tfidf, y_train)

        res = evaluate_model(name, model, X_test_tfidf, y_test, report_dir)
        joblib.dump(model, f"models/{name.replace(' ','_')}.joblib")

        print("✅ Done")
        print(f"  Accuracy: {res['accuracy']:.4f} | Precision: {res['precision']:.4f} "
              f"| Recall: {res['recall']:.4f} | F1: {res['f1']:.4f}\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train phishing detection models")
    parser.add_argument('--data', required=True, help='Path to phishing dataset CSV')
    parser.add_argument('--sample_frac', type=float, default=1.0,
                        help='Fraction of dataset to use (default = 1.0)')
    args = parser.parse_args()
    main(args.data, sample_frac=args.sample_frac)
