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

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
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

def read_emails(service, user_id='me', label_ids=[]):
    try:
        response = service.users().messages().list(userId=user_id, labelIds=label_ids).execute()
        messages = []
        if 'messages' in response:
            messages.extend(response['messages'])
        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId=user_id, labelIds=label_ids, pageToken=page_token).execute()
            messages.extend(response['messages'])
        return messages
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def extract_email_data(service, message_id):
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
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

def determine_company_name(sender, subject, body):
    domain_pattern = re.compile(r'@([a-zA-Z0-9.-]+)')
    domain_match = domain_pattern.search(sender)
    if domain_match:
        domain = domain_match.group(1)
        company_name = domain.split('.')[0]
        return company_name
    return 'Unknown'

def save_to_excel(data, filename='emails.xlsx'):
    df = pd.DataFrame(data, columns=['Sender', 'Company Name', 'Short Description', 'Date'])
    df.to_excel(filename, index=False)

def main():
    service = authenticate_gmail()
    label_ids = ['INBOX']  # Change this to the desired label ID
    messages = read_emails(service, label_ids=label_ids)
    if not messages:
        print('No messages found.')
        return
    email_data = []
    for message in messages:
        sender, subject, date, body = extract_email_data(service, message['id'])
        if sender and subject and date:
            company_name = determine_company_name(sender, subject, body)
            short_description = subject if subject else body[:50]
            email_data.append([sender, company_name, short_description, date])
    save_to_excel(email_data)

if __name__ == '__main__':
    main()
