"""
monitor.py
Enterprise-style Email Security Monitor (Capstone Version)

Features:
- Uses Gmail IMAP + App Password from config.ini
- Loads RandomForest + TF-IDF (capstone model)
- Monitors INBOX + Spam + Promotions + Social in real time
- PyQt5 GUI dashboard (antivirus style)
- System tray icon: green (normal) / red (phishing detected)
- Close window -> monitoring continues in tray
- Pause / Resume / Open Dashboard / Open Reports / Exit from tray
- OCR on images (if pytesseract installed) for image-based phishing
- Threat report dialog on row double-click (sender, domain, geo, risk factors, URLs, SPF/DKIM hint)
- Logs to logs/scan_log.csv  (ROOT/logs, not src/logs)
- Daily HTML report in reports/YYYY-MM-DD_report.html on exit
"""

import os
import sys
import time
import re
import csv
import imaplib
import email
import traceback
import configparser
import signal
from datetime import datetime, date
from email.header import decode_header, make_header
from email.utils import parseaddr

import joblib
import requests
from PyQt5 import QtCore, QtGui, QtWidgets

# Color output
from colorama import init as colorama_init, Fore, Style
colorama_init(autoreset=True)

# Optional OCR imports
try:
    import pytesseract
    from PIL import Image
    import io
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False


# -------------------------------------------------------
# PATHS & CONFIG
# -------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # ...\phishing_project\src
ROOT_DIR = os.path.dirname(BASE_DIR)                           # ...\phishing_project

CONFIG_PATH = os.path.join(ROOT_DIR, "config.ini")

# >>> Logs now in ROOT\logs <<<
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOGS_DIR, "scan_log.csv")

REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

GREEN_ICON_PATH = os.path.join(ROOT_DIR, "icon_green.ico")
RED_ICON_PATH = os.path.join(ROOT_DIR, "icon_red.ico")

# -------------------------------------------------------
# LOAD CONFIG
# -------------------------------------------------------
config = configparser.ConfigParser()
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"config.ini not found at: {CONFIG_PATH}")
config.read(CONFIG_PATH)

EMAIL_USER = config.get("EMAIL", "USERNAME")
EMAIL_PASS = config.get("EMAIL", "APP_PASSWORD", fallback="").strip()
IMAP_SERVER = config.get("EMAIL", "IMAP_SERVER", fallback="imap.gmail.com")
IMAP_PORT = config.getint("EMAIL", "IMAP_PORT", fallback=993)
FOLDERS = [f.strip() for f in config.get("EMAIL", "FOLDERS", fallback="INBOX").split(",") if f.strip()]
POLL_INTERVAL = config.getint("EMAIL", "POLL_INTERVAL", fallback=5)

MODEL_PATH = os.path.join(BASE_DIR, config.get("MODEL", "RANDOM_FOREST"))
VECTORIZER_PATH = os.path.join(BASE_DIR, config.get("MODEL", "TFIDF"))

if not EMAIL_USER or not EMAIL_PASS:
    raise ValueError("USERNAME or APP_PASSWORD missing in [EMAIL] section of config.ini")


# -------------------------------------------------------
# LOAD MODEL
# -------------------------------------------------------
print("[INFO] Loading RandomForest model + TF-IDF...")
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
print("[INFO] Model Loaded.\n")


# -------------------------------------------------------
# HELPERS
# -------------------------------------------------------
def decode_str(s: str) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"http\S+", " url ", text)
    text = re.sub(r"<.*?>", " ", text)
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_body_and_ocr(msg):
    parts = []
    ocr_texts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()

            try:
                if ctype == "text/plain":
                    txt = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    parts.append(txt)
                elif ctype == "text/html":
                    html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    txt = re.sub("<[^<]+?>", "", html)
                    parts.append(txt)
                elif OCR_AVAILABLE and ("image/" in ctype) and ("attachment" in disp or "inline" in disp):
                    raw = part.get_payload(decode=True)
                    if raw:
                        try:
                            img = Image.open(io.BytesIO(raw))
                            text = pytesseract.image_to_string(img)
                            if text.strip():
                                ocr_texts.append(text)
                        except Exception:
                            pass
            except Exception:
                continue
    else:
        try:
            txt = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
            parts.append(txt)
        except Exception:
            pass

    combined = "\n".join(parts)
    if ocr_texts:
        combined += "\n" + "\n".join(ocr_texts)

    cleaned = clean_text(combined)
    return cleaned, combined  # cleaned for model, raw_text for report


def classify_email(text: str):
    X = vectorizer.transform([text])
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0][pred]
    label = "LEGIT" if int(pred) == 1 else "PHISHING"

    # Balanced: avoid noisy PHISHING if model not confident
    if label == "PHISHING" and prob < 0.80:
        label = "LEGIT"

    return label, float(prob)


def extract_urls(raw_text: str):
    urls = re.findall(r'https?://[^\s"\'<>]+', raw_text)
    return list(dict.fromkeys(urls))  # dedupe, preserve order


def append_log(row):
    header_needed = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if header_needed:
            writer.writerow(["timestamp", "folder", "from", "subject", "label", "probability"])
        writer.writerow(row)


def get_auth_results(headers: str):
    """
    Simple SPF/DKIM/DMARC parsing from Authentication-Results.
    """
    auth_line = ""
    for line in headers.splitlines():
        if line.lower().startswith("authentication-results:"):
            auth_line += line + " "
        elif auth_line and (line.startswith(" ") or line.startswith("\t")):
            auth_line += line + " "
        elif auth_line:
            break

    auth_line = auth_line.lower()
    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"

    if "spf=pass" in auth_line:
        spf = "pass"
    elif "spf=fail" in auth_line or "spf=softfail" in auth_line:
        spf = "fail"

    if "dkim=pass" in auth_line:
        dkim = "pass"
    elif "dkim=fail" in auth_line:
        dkim = "fail"

    if "dmarc=pass" in auth_line:
        dmarc = "pass"
    elif "dmarc=fail" in auth_line:
        dmarc = "fail"

    return spf, dkim, dmarc


def extract_sender_domain(sender: str):
    _, addr = parseaddr(sender)
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return ""


def extract_ip_from_headers(headers: str):
    # Very simple IP regex
    ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', headers)
    if not ips:
        return None
    # Heuristic: last IP often closest to source
    return ips[-1]


def geo_lookup(ip: str):
    if not ip:
        return None
    try:
        url = f"https://ipapi.co/{ip}/json/"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "asn": data.get("asn"),
                "org": data.get("org"),
            }
    except Exception:
        pass
    return {"ip": ip}


def risk_factors_for_email(subject: str, raw_text: str, urls, label: str, prob: float,
                           spf: str, dkim: str, dmarc: str):
    factors = []
    subj_l = (subject or "").lower()
    body_l = raw_text.lower()

    urgent_words = ["urgent", "immediate action", "verify", "suspended", "locked", "password", "login"]
    if any(w in subj_l for w in urgent_words):
        factors.append("Subject contains urgent/pressure wording")

    if any(w in body_l for w in urgent_words):
        factors.append("Body contains urgent/pressure wording")

    if urls:
        factors.append(f"Contains {len(urls)} URL(s)")
        suspicious_tlds = [".ru", ".cn", ".tk", ".biz"]
        for u in urls:
            if any(tld in u.lower() for tld in suspicious_tlds):
                factors.append("URL uses suspicious TLD (e.g., .ru, .cn, .tk, .biz)")
                break

        # URL path hints
        for u in urls:
            lower = u.lower()
            if "/login" in lower or "/verify" in lower or "/update" in lower or "account" in lower:
                factors.append("URL path suggests authentication or verification page")
                break

    if spf == "fail" or dkim == "fail" or dmarc == "fail":
        factors.append("Email authentication (SPF/DKIM/DMARC) reported as FAIL")

    if label == "PHISHING":
        if prob >= 0.9:
            factors.append("Model extremely confident this is phishing")
        elif prob >= 0.8:
            factors.append("Model strongly indicates phishing")
        else:
            factors.append("Model indicates phishing with moderate confidence")
    else:
        if prob >= 0.9:
            factors.append("Model extremely confident this is legitimate content")
        else:
            factors.append("Model indicates likely legitimate content")

    if not factors:
        factors.append("No strong risk indicators found by heuristic rules")

    return factors


def print_console_result(result: dict, reasons: list):
    """
    Pretty color output in CMD, matching your screenshot:
    - Info + separators + From/Subject  -> cyan
    - Prediction LEGIT                  -> green
    - Prediction PHISHING               -> red
    - [REASONS] and bullets             -> magenta
    """
    folder = result.get("folder", "INBOX")
    label = result.get("label", "LEGIT")
    prob = result.get("prob", 0.0)
    sender = result.get("from", "")
    subject = result.get("subject", "")

    sep = "=" * 60

    # Info line
    print(Fore.CYAN + f"[INFO] {folder}: found 1 new unseen email(s)." + Style.RESET_ALL)
    print(Fore.CYAN + sep + Style.RESET_ALL)

    print(Fore.CYAN + f"From: {sender}" + Style.RESET_ALL)
    print(Fore.CYAN + f"Subject: {subject}" + Style.RESET_ALL)

    if label == "PHISHING":
        print(Fore.RED + f"Prediction: PHISHING ({prob:.2f})" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"Prediction: LEGIT ({prob:.2f})" + Style.RESET_ALL)

    print(Fore.MAGENTA + "[REASONS]" + Style.RESET_ALL)
    for r in reasons:
        print(Fore.MAGENTA + f" - {r}" + Style.RESET_ALL)

    print(Fore.CYAN + sep + Style.RESET_ALL)
    print()  # blank line


# -------------------------------------------------------
# BACKGROUND MONITOR THREAD
# -------------------------------------------------------
class EmailMonitorThread(QtCore.QThread):
    new_result = QtCore.pyqtSignal(dict)       # summary info
    status = QtCore.pyqtSignal(str)
    phishing_alert = QtCore.pyqtSignal(dict)   # fired only for PHISHING

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop_flag = False
        self._paused = False
        self.seen = set()  # (folder, uid)

    def stop(self):
        self._stop_flag = True

    def pause(self):
        self._paused = True
        self.status.emit("Monitoring paused.")

    def resume(self):
        self._paused = False
        self.status.emit("Monitoring resumed.")

    def run(self):
        self.status.emit("Connecting to Gmail via IMAP...")
        imap = None

        while not self._stop_flag:
            if self._paused:
                time.sleep(1)
                continue

            try:
                if imap is None:
                    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                    imap.login(EMAIL_USER, EMAIL_PASS)
                    self.status.emit("Connected. Monitoring mailboxes...")

                for folder in FOLDERS:
                    if self._stop_flag or self._paused:
                        break

                    status, _ = imap.select(folder)
                    if status != "OK":
                        continue

                    status, data = imap.search(None, "UNSEEN")
                    if status != "OK":
                        continue

                    ids = data[0].split()
                    for uid in ids:
                        if self._stop_flag or self._paused:
                            break

                        key = (folder, uid)
                        if key in self.seen:
                            continue
                        self.seen.add(key)

                        status, msg_data = imap.fetch(uid, "(RFC822)")
                        if status != "OK":
                            continue

                        raw_bytes = msg_data[0][1]
                        msg = email.message_from_bytes(raw_bytes)

                        sender = decode_str(msg.get("From", ""))
                        subject = decode_str(msg.get("Subject", ""))
                        headers_str = "".join(f"{k}: {v}\n" for k, v in msg.items())

                        cleaned_text, raw_text = extract_body_and_ocr(msg)
                        if not cleaned_text.strip() and not raw_text.strip():
                            continue

                        label, prob = classify_email(cleaned_text)
                        urls = extract_urls(raw_text)
                        spf, dkim, dmarc = get_auth_results(headers_str)
                        sender_domain = extract_sender_domain(sender)
                        ip = extract_ip_from_headers(headers_str)

                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        result = {
                            "time": ts,
                            "folder": folder,
                            "from": sender,
                            "subject": subject,
                            "label": label,
                            "prob": prob,
                            "urls": urls,
                            "raw_text": raw_text,
                            "headers": headers_str,
                            "sender_domain": sender_domain,
                            "ip": ip,
                            "spf": spf,
                            "dkim": dkim,
                            "dmarc": dmarc,
                        }

                        # Risk factors for console + dialog
                        reasons = risk_factors_for_email(
                            subject, raw_text, urls, label, prob, spf, dkim, dmarc
                        )
                        result["reasons"] = reasons

                        # Log row
                        append_log([ts, folder, sender, subject, label, prob])

                        # Console output with colors
                        print_console_result(result, reasons)

                        # GUI updates
                        self.new_result.emit(result)

                        if label == "PHISHING":
                            self.phishing_alert.emit(result)

                for _ in range(POLL_INTERVAL):
                    if self._stop_flag:
                        break
                    time.sleep(1)

            except imaplib.IMAP4.error as e:
                self.status.emit(f"IMAP error: {e}. Reconnecting in 10s...")
                if imap:
                    try:
                        imap.logout()
                    except Exception:
                        pass
                imap = None
                time.sleep(10)
            except Exception as e:
                self.status.emit(f"Error: {e}. See console.")
                traceback.print_exc()
                time.sleep(5)

        if imap:
            try:
                imap.logout()
            except Exception:
                pass
        self.status.emit("Monitor stopped.")


# -------------------------------------------------------
# THREAT REPORT DIALOG
# -------------------------------------------------------
class ThreatReportDialog(QtWidgets.QDialog):
    def __init__(self, result: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Email Threat Report")
        self.resize(700, 500)

        layout = QtWidgets.QVBoxLayout(self)

        # Basic metadata
        meta = QtWidgets.QTextEdit()
        meta.setReadOnly(True)

        geo = geo_lookup(result.get("ip"))
        spf = result.get("spf", "unknown")
        dkim = result.get("dkim", "unknown")
        dmarc = result.get("dmarc", "unknown")

        factors = result.get("reasons") or risk_factors_for_email(
            result.get("subject", ""),
            result.get("raw_text", ""),
            result.get("urls", []),
            result.get("label", ""),
            result.get("prob", 0.0),
            spf, dkim, dmarc
        )

        lines = []
        lines.append(f"Time: {result.get('time')}")
        lines.append(f"Folder: {result.get('folder')}")
        lines.append(f"Sender: {result.get('from')}")
        lines.append(f"Sender Domain: {result.get('sender_domain')}")
        lines.append(f"Classification: {result.get('label')} (prob={result.get('prob'):.4f})")
        lines.append("")
        lines.append("Authentication:")
        lines.append(f"  SPF: {spf}")
        lines.append(f"  DKIM: {dkim}")
        lines.append(f"  DMARC: {dmarc}")
        lines.append("")
        if geo:
            lines.append("Sender Geo (best effort from IP):")
            lines.append(f"  IP: {geo.get('ip')}")
            if geo.get("city") or geo.get("country"):
                lines.append(f"  Location: {geo.get('city')}, {geo.get('country')}")
            if geo.get("org"):
                lines.append(f"  Org/ISP: {geo.get('org')}")
            lines.append("")
        if result.get("urls"):
            lines.append("URLs found in email:")
            for u in result["urls"]:
                lines.append(f"  - {u}")
            lines.append("")

        lines.append("Risk Analysis:")
        for f in factors:
            lines.append(f"  - {f}")

        meta.setPlainText("\n".join(lines))

        layout.addWidget(QtWidgets.QLabel("Summary & Risk Analysis:"))
        layout.addWidget(meta)

        # Raw text preview
        raw_box = QtWidgets.QTextEdit()
        raw_box.setReadOnly(True)
        raw_box.setPlainText(result.get("raw_text") or "(no body extracted)")
        layout.addWidget(QtWidgets.QLabel("Email Body (cleaned for analysis):"))
        layout.addWidget(raw_box)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)


# -------------------------------------------------------
# DASHBOARD WINDOW
# -------------------------------------------------------
class DashboardWindow(QtWidgets.QMainWindow):
    def __init__(self, tray_icon):
        super().__init__()
        self.tray_icon = tray_icon

        self.setWindowTitle("Email Security Monitor")
        self.resize(1000, 600)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        # Top stats panel
        stats_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(stats_layout)

        self.lbl_total = self._make_stat_label("Total Scanned", "0")
        self.lbl_phish = self._make_stat_label("Phishing Detected", "0")
        self.lbl_legit = self._make_stat_label("Legit Emails", "0")
        self.lbl_status = QtWidgets.QLabel("Status: Initializing...")
        self.lbl_status.setStyleSheet("font-size: 13px;")

        stats_layout.addWidget(self.lbl_total["box"])
        stats_layout.addWidget(self.lbl_phish["box"])
        stats_layout.addWidget(self.lbl_legit["box"])
        layout.addWidget(self.lbl_status)

        # Table
        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Folder", "From", "Subject", "Label"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

        self.footer = QtWidgets.QLabel("Monitoring: " + ", ".join(FOLDERS))
        self.footer.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.footer)

        # Counters
        self.total_scanned = 0
        self.total_phish = 0
        self.total_legit = 0

        # Store results for report dialog
        self.results = []  # newest first

        # Double-click -> open report
        self.table.cellDoubleClicked.connect(self.on_row_double_clicked)

    def _make_stat_label(self, title, value):
        box = QtWidgets.QGroupBox(title)
        v = QtWidgets.QVBoxLayout(box)
        lbl = QtWidgets.QLabel(value)
        lbl.setAlignment(QtCore.Qt.AlignCenter)
        lbl.setStyleSheet("font-size: 22px; font-weight: bold;")
        v.addWidget(lbl)
        return {"box": box, "label": lbl}

    def update_status(self, msg: str):
        self.lbl_status.setText("Status: " + msg)

    def add_result(self, result: dict):
        self.results.insert(0, result)  # newest first

        self.total_scanned += 1
        if result["label"] == "PHISHING":
            self.total_phish += 1
        else:
            self.total_legit += 1

        self.lbl_total["label"].setText(str(self.total_scanned))
        self.lbl_phish["label"].setText(str(self.total_phish))
        self.lbl_legit["label"].setText(str(self.total_legit))

        row = 0
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(result["time"]))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(result["folder"]))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(result["from"]))
        self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(result["subject"]))
        lbl_item = QtWidgets.QTableWidgetItem(result["label"])
        self.table.setItem(row, 4, lbl_item)

        # Color coding
        if result["label"] == "PHISHING":
            for col in range(5):
                self.table.item(row, col).setBackground(QtGui.QColor("#ffcccc"))
            lbl_item.setForeground(QtGui.QBrush(QtGui.QColor("red")))
        else:
            for col in range(5):
                self.table.item(row, col).setBackground(QtGui.QColor("#e6ffe6"))
            lbl_item.setForeground(QtGui.QBrush(QtGui.QColor("green")))

    def on_row_double_clicked(self, row, column):
        if 0 <= row < len(self.results):
            result = self.results[row]
            dlg = ThreatReportDialog(result, self)
            dlg.exec_()

    def closeEvent(self, event):
        # Hide window instead of quitting app -> tray continues
        event.ignore()
        self.hide()


# -------------------------------------------------------
# SYSTEM TRAY ICON
# -------------------------------------------------------
class TrayIcon(QtWidgets.QSystemTrayIcon):
    def __init__(self, app, monitor_thread_getter, parent=None):
        # Select default icon
        if os.path.exists(GREEN_ICON_PATH):
            icon = QtGui.QIcon(GREEN_ICON_PATH)
        else:
            icon = app.style().standardIcon(QtWidgets.QStyle.SP_MediaPlay)

        super().__init__(icon, parent)
        self.app = app
        self.monitor_thread_getter = monitor_thread_getter

        self.green_icon = QtGui.QIcon(GREEN_ICON_PATH) if os.path.exists(GREEN_ICON_PATH) else icon
        self.red_icon = QtGui.QIcon(RED_ICON_PATH) if os.path.exists(RED_ICON_PATH) else app.style().standardIcon(
            QtWidgets.QStyle.SP_MessageBoxCritical
        )

        # Last phishing email for quick report on click
        self.last_phish_result = None

        # Context menu
        menu = QtWidgets.QMenu()
        self.action_show = menu.addAction("Open Dashboard")
        self.action_pause = menu.addAction("Pause Monitoring")
        self.action_resume = menu.addAction("Resume Monitoring")
        self.action_reports = menu.addAction("Open Reports Folder")
        self.action_exit = menu.addAction("Stop Monitoring & Exit")
        self.setContextMenu(menu)

        self.action_show.triggered.connect(self.on_show)
        self.action_pause.triggered.connect(self.on_pause)
        self.action_resume.triggered.connect(self.on_resume)
        self.action_reports.triggered.connect(self.on_open_reports)
        self.action_exit.triggered.connect(self.on_exit)

        self.activated.connect(self.on_activated)
        self.setToolTip("Email Security Monitor")

    def on_show(self):
        for widget in self.app.topLevelWidgets():
            if isinstance(widget, DashboardWindow):
                widget.showNormal()
                widget.raise_()
                widget.activateWindow()
                break

    def on_pause(self):
        monitor = self.monitor_thread_getter()
        if monitor:
            monitor.pause()

    def on_resume(self):
        monitor = self.monitor_thread_getter()
        if monitor:
            monitor.resume()

    def on_open_reports(self):
        if os.path.exists(REPORTS_DIR):
            os.startfile(REPORTS_DIR)

    def on_exit(self):
        self.app.quit()

    def on_activated(self, reason):
        # Single click on tray icon: if we have a last phishing result, open its report
        if reason == QtWidgets.QSystemTrayIcon.Trigger and self.last_phish_result:
            dlg = ThreatReportDialog(self.last_phish_result, None)
            dlg.exec_()
        elif reason == QtWidgets.QSystemTrayIcon.DoubleClick:
            self.on_show()

    def set_safe(self):
        self.setIcon(self.green_icon)
        self.setToolTip("Email Security Monitor – Monitoring (Safe)")

    def set_alert(self):
        self.setIcon(self.red_icon)
        self.setToolTip("Email Security Monitor – PHISHING DETECTED!")

    def notify_phishing(self, result: dict):
        self.last_phish_result = result
        title = "PHISHING EMAIL DETECTED"
        msg = f"From: {result['from']}\nSubject: {result['subject']}"
        self.showMessage(title, msg, QtWidgets.QSystemTrayIcon.Critical, 10000)


# -------------------------------------------------------
# DAILY HTML REPORT
# -------------------------------------------------------
def generate_daily_report():
    today_str = date.today().isoformat()
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                # Skip malformed older rows
                if "timestamp" not in r or "label" not in r:
                    continue
                if not r["timestamp"].startswith(today_str):
                    continue
                rows.append(r)

    if not rows:
        return

    total = len(rows)
    phish = sum(1 for r in rows if r["label"] == "PHISHING")
    legit = total - phish

    html_path = os.path.join(REPORTS_DIR, f"{today_str}_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Email Security Report</title></head><body>")
        f.write(f"<h1>Email Security Report - {today_str}</h1>")
        f.write("<h2>Summary</h2>")
        f.write(f"<p>Total scanned: {total}</p>")
        f.write(f"<p>Phishing detected: {phish}</p>")
        f.write(f"<p>Legit emails: {legit}</p>")
        f.write("<h2>Details</h2>")
        f.write("<table border='1' cellpadding='4' cellspacing='0'>")
        f.write("<tr><th>Time</th><th>Folder</th><th>From</th><th>Subject</th><th>Label</th><th>Probability</th></tr>")
        for r in rows:
            color = "#ffcccc" if r["label"] == "PHISHING" else "#e6ffe6"
            prob_val = r.get("probability", "")
            try:
                prob_val = f"{float(prob_val):.4f}"
            except Exception:
                pass
            f.write(
                f"<tr style='background:{color}'><td>{r['timestamp']}</td><td>{r['folder']}</td>"
                f"<td>{r['from']}</td><td>{r['subject']}</td><td>{r['label']}</td><td>{prob_val}</td></tr>"
            )
        f.write("</table></body></html>")


# -------------------------------------------------------
# MAIN APP
# -------------------------------------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)

    monitor_thread_holder = {"thread": None}

    def get_monitor_thread():
        return monitor_thread_holder["thread"]

    tray = TrayIcon(app, get_monitor_thread)
    tray.show()
    tray.set_safe()

    window = DashboardWindow(tray)

    monitor_thread = EmailMonitorThread()
    monitor_thread_holder["thread"] = monitor_thread
    monitor_thread.new_result.connect(window.add_result)
    monitor_thread.status.connect(window.update_status)

    def handle_phish(result):
        tray.set_alert()
        tray.notify_phishing(result)

    monitor_thread.phishing_alert.connect(handle_phish)

    def on_about_to_quit():
        # Graceful shutdown
        monitor_thread.stop()
        monitor_thread.wait(3000)
        generate_daily_report()

    app.aboutToQuit.connect(on_about_to_quit)

    monitor_thread.start()
    window.update_status("Connecting...")

    # Handle Ctrl+C cleanly (no big traceback)
    try:
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        print("\n[INFO] Ctrl+C received, shutting down...")
        app.quit()
        on_about_to_quit()


if __name__ == "__main__":
    main()
