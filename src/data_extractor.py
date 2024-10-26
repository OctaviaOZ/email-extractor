import base64
import email
from email import policy
from email.parser import BytesParser
from googleapiclient.errors import HttpError

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
