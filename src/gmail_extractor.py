import os
import re
import pandas as pd
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import base64
import email
from email import policy
from email.parser import BytesParser
import spacy
import json

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailExtractor:
    def __init__(self, company_name_extractor):
        self.company_name_extractor = company_name_extractor
        self.service = self.authenticate_gmail()
        self.label = self.read_label_from_config()

    def authenticate_gmail(self):
        creds = None
        if os.path.exists('token.json'):
            creds = service_account.Credentials.from_authorized_user_file('token.json', SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        return build('gmail', 'v1', credentials=creds)

    def read_label_from_config(self):
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
        return config.get('label', 'INBOX')

    def read_emails(self, user_id='me', label_ids=[]):
        try:
            response = self.service.users().messages().list(userId=user_id, labelIds=label_ids).execute()
            messages = []
            if 'messages' in response:
                messages.extend(response['messages'])
            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.service.users().messages().list(userId=user_id, labelIds=label_ids, pageToken=page_token).execute()
                messages.extend(response['messages'])
            return messages
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None

    def extract_email_data(self, message_id):
        try:
            message = self.service.users().messages().get(userId='me', id=message_id, format='raw').execute()
            msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
            mime_msg = BytesParser(policy=policy.default).parsebytes(msg_str)
            sender = mime_msg['From']
            subject = mime_msg['Subject']
            date = mime_msg['Date']
            body = mime_msg.get_body(preferencelist=('plain')).get_content()
            return sender, subject, date, body
        except HttpError as error:
            print(f'An error occurred: {error}')
            return None, None, None, None

    def save_to_excel(self, data, filename='emails.xlsx'):
        df = pd.DataFrame(data, columns=['Sender', 'Company Name', 'Short Description', 'Date'])
        df.to_excel(filename, index=False)

    def run(self):
        messages = self.read_emails(label_ids=[self.label])
        if not messages:
            print('No messages found.')
            return
        email_data = []
        for message in messages:
            sender, subject, date, body = self.extract_email_data(message['id'])
            if sender and subject and date:
                company_name = self.company_name_extractor.determine_company_name(sender, subject, body)
                short_description = subject if subject else body[:50]
                email_data.append([sender, company_name, short_description, date])
        self.save_to_excel(email_data)

class CompanyNameExtractor:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")

    def determine_company_name(self, sender, subject, body):
        domain_pattern = re.compile(r'@([a-zA-Z0-9.-]+)')
        domain_match = domain_pattern.search(sender)
        if domain_match:
            domain = domain_match.group(1)
            company_name = domain.split('.')[0]
            return company_name

        doc = self.nlp(subject + " " + body)
        for ent in doc.ents:
            if ent.label_ == "ORG":
                return ent.text

        return 'Unknown'

def main():
    company_name_extractor = CompanyNameExtractor()
    gmail_extractor = GmailExtractor(company_name_extractor)
    gmail_extractor.run()

if __name__ == '__main__':
    main()
