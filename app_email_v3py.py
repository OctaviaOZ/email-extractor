import os
import pickle
import re
import csv
import yaml
import logging
import base64
import ssl
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from datetime import datetime
import dateutil.parser
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError
import time
from typing import Dict, List, Tuple, Optional, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from YAML
def load_config(config_file='config.yaml') -> Dict[str, Any]:
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

CONFIG = load_config()

# Set up logging
logging.basicConfig(
    filename=CONFIG['log_file'],
    level=CONFIG['log_level'],
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def create_http_session():
    """Create a session with retry strategy."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# Retry decorator for API calls
def retry_on_error(func):
    def wrapper(*args, **kwargs):
        for attempt in range(2):  # Reduced from CONFIG['max_retries'] to 2
            try:
                return func(*args, **kwargs)
            except (HttpError, socket.error, ssl.SSLError, requests.exceptions.RequestException) as e:
                if attempt == 1:  # Last attempt
                    logger.error(f"Function {func.__name__} failed after 2 attempts: {e}")
                    raise
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in 1 second.")
                time.sleep(1)  # Reduced from CONFIG['retry_delay'] to 1 second
    return wrapper

# Authenticate Gmail API
def authenticate_gmail():
    creds = None
    if os.path.exists(CONFIG['token_file']):
        try:
            with open(CONFIG['token_file'], 'rb') as token:
                creds = pickle.load(token)
        except Exception as e:
            logger.error(f"Error loading token file: {e}")
            os.remove(CONFIG['token_file'])

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                logger.warning("Token refresh failed. Removing token file and re-authenticating.")
                os.remove(CONFIG['token_file'])
                return authenticate_gmail()
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CONFIG['credentials_file'], SCOPES)
                creds = flow.run_local_server(port=0)
                with open(CONFIG['token_file'], 'wb') as token:
                    pickle.dump(creds, token)
            except Exception as e:
                logger.error(f"Error during authentication: {e}")
                raise

    try:
        return build('gmail', 'v1', credentials=creds, cache_discovery=False)
    except Exception as e:
        logger.error(f"Error building Gmail service: {e}")
        raise

@retry_on_error
def list_labels(service) -> List[Dict[str, Any]]:
    """List all labels in the user's mailbox."""
    response = service.users().labels().list(userId='me').execute()
    return response.get('labels', [])

def get_label_id(service, label_name: str) -> Optional[str]:
    """Get the ID of a label by its name."""
    labels = list_labels(service)
    return next((label['id'] for label in labels if label['name'] == label_name), None)

@retry_on_error
def list_messages(service, user_id='me', label_ids=[], query='') -> List[Dict[str, Any]]:
    """List all messages matching the criteria."""
    messages = []
    request = service.users().messages().list(userId=user_id, labelIds=label_ids, q=query)
    while request is not None:
        response = request.execute()
        messages.extend(response.get('messages', []))
        request = service.users().messages().list_next(request, response)
    return messages

def decode_base64(data: str) -> str:
    """Decode base64 data with padding."""
    try:
        return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4)).decode('utf-8')
    except Exception as e:
        logger.error(f"Error decoding base64 data: {e}")
        return ""

def extract_email_parts(email: str) -> Tuple[str, str, str]:
    """Extract name, email address, and domain from email string."""
    match = re.match(r'^(.*?)\s*<(.+)>$', email)
    if match:
        name, email_address = match.groups()
    else:
        name, email_address = '', email
    domain = email_address.split('@')[-1]
    return name.strip(), email_address, domain

def parse_date(date_str: str) -> Tuple[str, str, str, str]:
    """Parse date string into components."""
    try:
        dt = dateutil.parser.parse(date_str)
        return dt.strftime('%Y-%m-%d'), str(dt.year), str(dt.month), str(dt.day)
    except Exception as e:
        logger.warning(f"Could not parse date '{date_str}': {e}")
        return '', '', '', ''

def get_company_name(domain: str, user_name: str, subject: str) -> str:
    """Get company name based on domain and subject."""
    if domain in CONFIG['special_domains']:
        return user_name
    elif domain in CONFIG['subject_domains']:
        return subject.split()[-1]
    else:
        return domain.split('.')[0]

def extract_email_body(message: Dict[str, Any]) -> Tuple[str, str]:
    """Extract plain text and HTML body from email message."""
    if 'payload' not in message:
        return "", ""

    payload = message['payload']
    plain_text = ""
    html_text = ""

    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                plain_text = decode_base64(part['body'].get('data', ''))
            elif part['mimeType'] == 'text/html':
                html_text = decode_base64(part['body'].get('data', ''))
    elif 'body' in payload and 'data' in payload['body']:
        if payload['mimeType'] == 'text/plain':
            plain_text = decode_base64(payload['body']['data'])
        elif payload['mimeType'] == 'text/html':
            html_text = decode_base64(payload['body']['data'])

    return plain_text, html_text

def extract_links(html_content: str) -> List[str]:
    """Extract links from HTML content."""
    if not html_content:
        return []
    
    soup = BeautifulSoup(html_content, 'html.parser')
    return [a.get('href') for a in soup.find_all('a', href=True)]

def analyze_content(plain_text: str, html_text: str) -> Dict[str, Any]:
    """Analyze email content for relevant information."""
    analysis = {
        'word_count': 0,
        'has_application_link': False,
        'has_attachment': False,
        'links': [],
        'keywords': []
    }

    # Combine text for analysis
    text = plain_text + " " + BeautifulSoup(html_text, 'html.parser').get_text()
    
    # Word count
    analysis['word_count'] = len(text.split())
    
    # Extract links
    analysis['links'] = extract_links(html_text)
    
    # Check for application-related keywords
    application_keywords = CONFIG['content_analysis']['application_keywords']
    found_keywords = [word for word in application_keywords if word.lower() in text.lower()]
    analysis['keywords'] = found_keywords
    
    # Check for application links
    application_domains = CONFIG['content_analysis']['application_domains']
    analysis['has_application_link'] = any(domain in ' '.join(analysis['links']).lower() for domain in application_domains)
    
    return analysis

@retry_on_error
def get_message_details(service, message_id: str) -> Tuple[Optional[str], Optional[str], Optional[str], Dict[str, Any]]:
    """Get detailed message information including body and analysis."""
    try:
        # Add a small delay between requests to avoid rate limiting
        time.sleep(0.1)
        
        # Add timeout to the request
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute(timeout=30)  # 30 second timeout
        
        headers = {header['name']: header['value'] for header in message['payload']['headers']}
        
        # Extract basic headers
        sender = headers.get('From')
        date = headers.get('Date')
        subject = headers.get('Subject')
        
        # Extract and analyze body
        plain_text, html_text = extract_email_body(message)
        content_analysis = analyze_content(plain_text, html_text)
        
        return sender, date, subject, content_analysis
    except Exception as e:
        logger.error(f"Error getting message details for message {message_id}: {e}")
        return None, None, None, {}

def prepare_csv_data(messages: List[Dict[str, Any]], service) -> List[List[Any]]:
    """Prepare data for CSV export with enhanced analysis."""
    csv_data = []
    total_messages = len(messages)
    
    logger.info(f"Processing {total_messages} messages...")
    
    # Process messages in smaller batches to avoid overwhelming the API
    batch_size = 5  # Reduced from 10 to 5
    for i in range(0, total_messages, batch_size):
        batch = messages[i:i + batch_size]
        logger.info(f"Processing batch {i//batch_size + 1} of {(total_messages + batch_size - 1)//batch_size}")
        try:
            with ThreadPoolExecutor(max_workers=min(batch_size, CONFIG.get('max_workers', 4))) as executor:
                futures = []
                for msg in batch:
                    futures.append(executor.submit(get_message_details, service, msg['id']))
                
                for future in futures:
                    try:
                        sender, date, subject, analysis = future.result(timeout=60)  # 60 second timeout per message
                        if sender:
                            sender_name, email_address, domain = extract_email_parts(sender)
                            if domain not in CONFIG['skip_domains']:
                                formatted_date, year, month, day = parse_date(date)
                                user_name = email_address.split('@')[0]
                                company_name = get_company_name(domain, user_name, subject)
                                
                                # Enhanced CSV row with analysis
                                row = [
                                    year, month, day, formatted_date,
                                    domain, sender_name, subject,
                                    user_name, company_name,
                                    analysis['word_count'],
                                    analysis['has_application_link'],
                                    len(analysis['links']),
                                    ','.join(analysis['keywords'])
                                ]
                                csv_data.append(row)
                    except Exception as e:
                        logger.error(f"Error processing message in batch: {e}")
            logger.info(f"Finished batch {i//batch_size + 1}")
        except Exception as e:
            logger.error(f"Error in batch {i//batch_size + 1}: {e}")
        # Add a delay between batches
        time.sleep(0.5)  # Reduced from 1 to 0.5 seconds
    logger.info(f"All batches processed. Total rows: {len(csv_data)}")
    return csv_data

def generate_csv(data: List[List[Any]], filename: str) -> None:
    """Generate CSV file with enhanced columns."""
    logger.info(f"Generating CSV file: {filename}")
    enhanced_columns = CONFIG['csv_columns'] + [
        'Word Count',
        'Has Application Link',
        'Link Count',
        'Keywords'
    ]
    
    with open(filename, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(enhanced_columns)
        writer.writerows(data)
    logger.info(f"CSV file '{filename}' generated successfully with {len(data)} rows.")

def main():
    """Main execution function with enhanced error handling and performance."""
    try:
        logger.info("Starting email processing...")
        service = authenticate_gmail()
        
        logger.info(f"Looking for label: {CONFIG['label_name']}")
        label_id = get_label_id(service, CONFIG['label_name'])

        if not label_id:
            logger.error(f'Label "{CONFIG["label_name"]}" not found.')
            return

        query = f"after:{CONFIG['start_date']}"
        logger.info(f"Fetching messages with query: {query}")
        messages = list_messages(service, label_ids=[label_id], query=query)
        
        if not messages:
            logger.warning("No messages found matching the criteria.")
            return

        logger.info(f"Found {len(messages)} messages to process")
        # Process only the first message for testing
        messages = messages[:1]
        logger.info("Processing only the first message for testing.")
        csv_data = prepare_csv_data(messages, service)

        output_dir = CONFIG['output_directory'] or os.getcwd()
        output_file = os.path.join(output_dir, CONFIG['output_filename'])
        generate_csv(csv_data, output_file)
        
        logger.info(f"CSV file '{output_file}' generated successfully with {len(csv_data)} entries.")
        
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}")
        raise

if __name__ == "__main__":
    main()