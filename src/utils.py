# src/utils.py
import os
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

def ensure_dirs():
    for d in ['models', 'reports']:
        if not os.path.exists(d):
            os.makedirs(d)

def save_model(model, tfidf, model_path='models/phish_detector.joblib', tfidf_path='models/tfidf.joblib'):
    joblib.dump(model, model_path)
    joblib.dump(tfidf, tfidf_path)

def write_html_report(metrics_text: str, cm_path: str, html_path='reports/phishing_report.html'):
    html = f"""
    <html>
    <head><title>Phishing Detection Report</title></head>
    <body>
      <h1>Phishing Detection Report</h1>
      <h2>Metrics</h2>
      <pre>{metrics_text}</pre>
      <h2>Confusion Matrix</h2>
      <img src="{os.path.basename(cm_path)}" alt="confusion matrix">
    </body>
    </html>
    """
    # copy cm image into reports folder if not already there
    import shutil
    reports_dir = os.path.dirname(html_path)
    if reports_dir == '':
        reports_dir = '.'
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    dest_cm = os.path.join(reports_dir, os.path.basename(cm_path))
    if os.path.abspath(cm_path) != os.path.abspath(dest_cm):
        shutil.copy(cm_path, dest_cm)
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

def plot_confusion_matrix(y_true, y_pred, out='reports/cmatrix.png'):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(5,4))
    plt.imshow(cm, interpolation='nearest')
    plt.title('Confusion matrix')
    plt.colorbar()
    ticks = [0,1]
    plt.xticks(ticks, ['Legit','Phish'])
    plt.yticks(ticks, ['Legit','Phish'])
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], 'd'),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    return out

def metrics_summary(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    report = classification_report(y_true, y_pred, target_names=['legit','phish'], zero_division=0)
    text = f"Accuracy: {acc:.4f}\\nPrecision: {prec:.4f}\\nRecall: {rec:.4f}\\nF1: {f1:.4f}\\n\\n{report}"
    return text
