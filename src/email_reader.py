import base64
import email
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email import policy
from email.parser import BytesParser

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
