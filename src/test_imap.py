import imapclient
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

email_conf = config['EMAIL']
USERNAME = email_conf.get('USERNAME')
APP_PASSWORD = email_conf.get('APP_PASSWORD')
IMAP_SERVER = email_conf.get('IMAP_SERVER')
IMAP_PORT = email_conf.getint('IMAP_PORT')

print("Connecting to Gmail IMAP...")
client = imapclient.IMAPClient(IMAP_SERVER, port=IMAP_PORT, ssl=True)
client.login(USERNAME, APP_PASSWORD)
print("✅ Logged in successfully!")

folders = client.list_folders()
print("Available folders:")
for f in folders:
    print(" -", f[-1])
client.logout()
