from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle
import os
import base64
from email.mime.text import MIMEText
import json
import time
from config import SCOPES, CREDENTIALS_FILE, TOKEN_FILE, AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, AZURE_URL
from ai_scorer import AIScorer
import logging
from datetime import datetime, timedelta
from flask import session
from user_manager import UserManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a single instance of UserManager
user_manager = UserManager()

class GmailHandler:
    def __init__(self):
        self.creds = None
        self.service = None
        self.last_history_id = None
        self.ai_scorer = AIScorer(AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT)
        self.setup_credentials()

    def setup_credentials(self):
        """Set up Gmail API credentials"""
        try:
            # Clear any existing credentials
            self.creds = None
            self.service = None
            
            # Create new flow with forced prompt
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, 
                SCOPES,
                redirect_uri=f'{AZURE_URL}/oauth2callback'
            )
            
            # Use redirect flow instead of local server
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )
            
            return authorization_url
            
        except Exception as e:
            logger.error(f"Error setting up credentials: {str(e)}", exc_info=True)
            raise

    def setup_push_notifications(self):
        """Set up Gmail API push notifications"""
        try:
            # Replace YOUR_PUBLIC_URL with the ngrok URL you got
            webhook_url = 'https://your-ngrok-url.ngrok.io/webhook'  
            
            request = {
                'labelIds': ['INBOX'],
                'topicName': 'projects/emailflow-453902/topics/gmail-notifications',
                'labelFilterAction': 'include'
            }
            
            self.service.users().watch(userId='me', body=request).execute()
            print("Push notifications set up successfully!")
        except Exception as e:
            print(f"Error setting up push notifications: {str(e)}")

    def get_email_data(self, message_id):
        max_retries = 3
        retry_delay = 1  # seconds
        
        for attempt in range(max_retries):
            try:
                message = self.service.users().messages().get(
                    userId='me', id=message_id, format='full').execute()
                
                headers = message['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
                
                email_data = {
                    'message_id': message_id,
                    'subject': subject,
                    'sender': sender,
                    'date': date,
                    'snippet': message.get('snippet', ''),
                    'importance': self.ai_scorer.score_email({
                        'sender': sender,
                        'subject': subject,
                        'snippet': message.get('snippet', '')
                    })
                }
                return email_data
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1}/{max_retries} failed for email {message_id}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    # Try to refresh credentials
                    if 'invalid credentials' in str(e).lower():
                        self.setup_credentials()
                else:
                    return None

    def get_unread_emails(self):
        results = self.service.users().messages().list(
            userId='me', labelIds=['UNREAD']).execute()
        messages = results.get('messages', [])
        return messages

    def get_history(self):
        """Get changes since last check"""
        try:
            if not self.last_history_id:
                # Get the current history ID if we don't have one
                profile = self.service.users().getProfile(userId='me').execute()
                self.last_history_id = profile['historyId']
                return []

            results = self.service.users().history().list(
                userId='me',
                startHistoryId=self.last_history_id
            ).execute()

            changes = results.get('history', [])
            if changes:
                self.last_history_id = results['historyId']
            
            return changes
        except Exception as e:
            print(f"Error getting history: {str(e)}")
            return []

    def check_new_emails(self):
        """Check for new emails using history"""
        changes = self.get_history()
        new_messages = []
        
        for change in changes:
            if 'messagesAdded' in change:
                for message in change['messagesAdded']:
                    msg_data = self.get_email_data(message['message']['id'])
                    if msg_data:
                        new_messages.append(msg_data)
        
        return new_messages

    def get_user_email(self):
        """Get the email of the authenticated user"""
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            return profile['emailAddress']
        except Exception as e:
            print(f"Error getting user email: {str(e)}")
            return None 

    def get_filtered_unread_emails(self, timeframe):
        """Get unread emails within timeframe and process them one by one"""
        try:
            # Calculate time threshold based on filter
            now = datetime.now()
            if timeframe == 'hour':
                threshold = now - timedelta(hours=1)
            elif timeframe == 'day':
                threshold = now - timedelta(days=1)
            elif timeframe == 'week':
                threshold = now - timedelta(weeks=1)
            elif timeframe == 'month':
                threshold = now - timedelta(days=30)
            
            # Get unread emails
            results = self.service.users().messages().list(
                userId='me',
                labelIds=['UNREAD'],
                q=f'after:{threshold.strftime("%Y/%m/%d")}'
            ).execute()
            
            messages = results.get('messages', [])
            
            # Process each message one at a time
            for message in messages:
                # Get email details
                email_data = self.get_email_data(message['id'])
                if email_data:
                    # Yield each processed email immediately
                    yield email_data
                
        except Exception as e:
            logger.error(f"Error getting filtered unread emails: {str(e)}")
            yield None 

    def get_unread_count(self, timeframe):
        """Get total count of unread emails within timeframe"""
        try:
            now = datetime.now()
            if timeframe == 'hour':
                threshold = now - timedelta(hours=1)
            elif timeframe == 'day':
                threshold = now - timedelta(days=1)
            elif timeframe == 'week':
                threshold = now - timedelta(weeks=1)
            elif timeframe == 'month':
                threshold = now - timedelta(days=30)
            
            results = self.service.users().messages().list(
                userId='me',
                labelIds=['UNREAD'],
                q=f'after:{threshold.strftime("%Y/%m/%d")}'
            ).execute()
            
            return len(results.get('messages', []))
        except Exception as e:
            logger.error(f"Error getting unread count: {str(e)}")
            return 0 

    def mark_as_read(self, message_id):
        """Mark a message as read by removing UNREAD label"""
        try:
            # Create a new service instance for this request
            service = build('gmail', 'v1', credentials=self.creds)
            
            service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'removeLabelIds': ['UNREAD']
                }
            ).execute()
            
            logger.info(f"Marked message {message_id} as read")
            
            # Close the service connection
            if hasattr(service, '_http'):
                service._http.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error marking message as read: {str(e)}")
            return False
        finally:
            # Ensure we clean up any remaining connections
            if 'service' in locals() and hasattr(service, '_http'):
                service._http.close() 