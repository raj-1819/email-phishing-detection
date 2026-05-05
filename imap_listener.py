# src/imap_listener.py
# Lightweight IMAP new-mail poller. Use IMAP IDLE alternatives (imapclient supports IDLE)
from imapclient import IMAPClient
import email
import time

HOST = 'imap.gmail.com'
USERNAME = 'your.email@gmail.com'
APP_PASSWORD = 'APP_PASSWORD_HERE'  # store securely or via environment vars!

def fetch_new():
    with IMAPClient(HOST, ssl=True) as client:
        client.login(USERNAME, APP_PASSWORD)
        client.select_folder('INBOX')
        # search for UNSEEN
        messages = client.search(['UNSEEN'])
        result = []
        if messages:
            response = client.fetch(messages, ['BODY[]','ENVELOPE'])
            for msgid, data in response.items():
                raw = data[b'BODY[]']
                em = email.message_from_bytes(raw)
                subject = str(em.get('Subject',''))
                sender = str(em.get('From',''))
                # get body (simple)
                body = ""
                if em.is_multipart():
                    for part in em.walk():
                        ctype = part.get_content_type()
                        if ctype == 'text/plain' and part.get_payload(decode=True):
                            body += part.get_payload(decode=True).decode(errors='ignore')
                else:
                    body = em.get_payload(decode=True).decode(errors='ignore')
                result.append({'msgid': msgid, 'subject': subject, 'from': sender, 'body': body, 'raw': raw.decode(errors='ignore')})
        return result

if __name__ == "__main__":
    new = fetch_new()
    print("Found:", len(new))
