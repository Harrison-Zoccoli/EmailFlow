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
from config import SCOPES, CREDENTIALS_FILE, TOKEN_FILE, AZURE_URL
from ai_scorer import AIScorer
import logging
from datetime import datetime, timedelta
from flask import session
from user_manager import UserManager
import google_auth_oauthlib.flow
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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
        
        # Use environment variables instead of hardcoded keys
        self.ai_scorer = AIScorer(
            os.getenv('AZURE_OPENAI_KEY'),
            os.getenv('AZURE_OPENAI_ENDPOINT')
        )
        print(f"Created AIScorer with deployment: {os.getenv('AZURE_OPENAI_DEPLOYMENT')}")

    def setup_credentials(self):
        """Set up Gmail API credentials"""
        try:
            # Clear any existing credentials
            self.creds = None
            self.service = None
            
            # Create new flow with forced prompt for desktop client
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, 
                SCOPES,
                redirect_uri='http://localhost:8090'  # Must match OAuth client configuration
            )
            
            # Use local server flow for desktop client
            self.creds = flow.run_local_server(
                port=8090,
                authorization_prompt_message='Please select a Google account',
                success_message='Authentication successful! You can close this window.',
                open_browser=True
            )
            
            self.service = build('gmail', 'v1', credentials=self.creds)
            
            # Check if user exists in database
            email = self.get_user_email()
            logger.info(f"Checking if user {email} exists in database")
            
            # Important: Return "new_user" status without re-authenticating
            if not user_manager.user_exists(email):
                logger.info(f"User {email} is new, returning new_user status")
                return "new_user"
            
            logger.info(f"User {email} exists, authentication successful")
            return None
            
        except Exception as e:
            logger.error(f"Error setting up credentials: {str(e)}")
            return str(e)

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

    def get_unread_emails(self, time_filter='week'):
        """Get unread emails from Gmail API directly"""
        try:
            # Create a new service instance for this request
            service = build('gmail', 'v1', credentials=self.creds)
            
            # Calculate the time range based on the filter
            now = datetime.now()
            if time_filter == 'hour':
                time_ago = now - timedelta(hours=1)
            elif time_filter == 'day':
                time_ago = now - timedelta(days=1)
            elif time_filter == 'week':
                time_ago = now - timedelta(weeks=1)
            elif time_filter == 'month':
                time_ago = now - timedelta(days=30)
            else:
                time_ago = now - timedelta(weeks=1)  # Default to week
            
            # Format the date for Gmail query
            date_str = time_ago.strftime('%Y/%m/%d')
            
            # Query for unread emails after the specified date
            query = f'is:unread after:{date_str}'
            
            # Get the messages
            results = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=50  # Limit to 50 emails
            ).execute()
            
            messages = results.get('messages', [])
            
            if not messages:
                return []
            
            # Process each message to get details
            unread_emails = []
            for message in messages:
                msg = service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                
                # Extract headers
                headers = {header['name']: header['value'] for header in msg['payload']['headers']}
                
                # Create email object
                email_data = {
                    'id': message['id'],
                    'sender': headers.get('From', 'Unknown Sender'),
                    'subject': headers.get('Subject', '(No Subject)'),
                    'date': headers.get('Date', 'Unknown Date'),
                    'snippet': msg.get('snippet', '')
                }
                
                unread_emails.append(email_data)
            
            return unread_emails
            
        except Exception as e:
            logger.error(f"Error getting unread emails: {str(e)}")
            return []

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
        """Get user's email address"""
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            email = profile['emailAddress']
            logger.info(f"Retrieved email: {email}")
            return email
        except Exception as e:
            logger.error(f"Error getting user email: {str(e)}")
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

    def check_for_new_emails(self):
        """Check for new emails since last check"""
        try:
            print("\n==== CHECKING FOR NEW EMAILS ====")
            
            # Create a new service instance
            service = build('gmail', 'v1', credentials=self.creds)
            
            # Get current history ID
            profile = service.users().getProfile(userId='me').execute()
            current_history_id = profile.get('historyId')
            
            print(f"Current history ID: {current_history_id}")
            print(f"Last history ID: {self.last_history_id}")
            
            # If this is our first check, just store the history ID and return
            if not self.last_history_id:
                print("First check - storing history ID for future reference")
                self.last_history_id = current_history_id
                return False
            
            # Get only messages that arrived since last check
            print(f"Checking for messages since history ID: {self.last_history_id}")
            history_results = service.users().history().list(
                userId='me',
                startHistoryId=self.last_history_id,
                historyTypes=['messageAdded']
            ).execute()
            
            print(f"History results: {json.dumps(history_results, indent=2)}")
            
            # Extract only new message IDs
            message_ids = []
            if 'history' in history_results:
                for history in history_results['history']:
                    for message_added in history.get('messagesAdded', []):
                        msg = message_added.get('message', {})
                        # Only include INBOX messages
                        if 'INBOX' in msg.get('labelIds', []):
                            message_ids.append(msg['id'])
            
            print(f"Found {len(message_ids)} new messages since last check")
            print(f"Message IDs: {message_ids}")
            
            # Process each new message
            for message_id in message_ids:
                print(f"Processing message: {message_id}")
                self.process_message(message_id)
            
            # Update the last history ID
            self.last_history_id = current_history_id
            
            print("==== FINISHED CHECKING FOR NEW EMAILS ====\n")
            return len(message_ids) > 0
            
        except Exception as e:
            print(f"Error checking for new emails: {str(e)}")
            return False

    def get_latest_history_id(self):
        """Get the latest history ID for the user's mailbox"""
        try:
            # Create a new service instance for this request
            service = build('gmail', 'v1', credentials=self.creds)
            
            # Get the profile which includes the historyId
            profile = service.users().getProfile(userId='me').execute()
            
            # Close the service connection
            if hasattr(service, '_http'):
                service._http.close()
            
            return profile.get('historyId')
            
        except Exception as e:
            logger.error(f"Error getting latest history ID: {str(e)}")
            return None
        finally:
            # Ensure we clean up any remaining connections
            if 'service' in locals() and hasattr(service, '_http'):
                service._http.close()

    def get_history_since_last_id(self):
        """Get history since the last recorded history ID"""
        if not self.last_history_id:
            logger.error("No last history ID available")
            return None
        
        try:
            # Create a new service instance for this request
            service = build('gmail', 'v1', credentials=self.creds)
            
            # Get history with the last history ID
            history = service.users().history().list(
                userId='me',
                startHistoryId=self.last_history_id,
                historyTypes=['messageAdded']
            ).execute()
            
            # Close the service connection
            if hasattr(service, '_http'):
                service._http.close()
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting history since last ID: {str(e)}")
            return None
        finally:
            # Ensure we clean up any remaining connections
            if 'service' in locals() and hasattr(service, '_http'):
                service._http.close()

    def extract_new_message_ids(self, history_results):
        """Extract new message IDs from history results"""
        if not history_results or 'history' not in history_results:
            return []
        
        message_ids = set()
        
        # Extract message IDs from history
        for item in history_results.get('history', []):
            for message_added in item.get('messagesAdded', []):
                message = message_added.get('message', {})
                
                # Only include messages that are not in TRASH and are UNREAD
                labels = message.get('labelIds', [])
                if 'TRASH' not in labels and 'UNREAD' in labels:
                    message_ids.add(message.get('id'))
        
        return list(message_ids) 

    def process_message(self, message_id):
        """Process a single message by ID"""
        try:
            print(f"\n==== PROCESSING NEW EMAIL: {message_id} ====")
            
            # Create a new service instance for this request
            service = build('gmail', 'v1', credentials=self.creds)
            
            # Get the message
            message = service.users().messages().get(userId='me', id=message_id).execute()
            
            # Extract message details
            headers = {header['name']: header['value'] for header in message['payload']['headers']}
            
            # Get sender, subject, and date
            sender = headers.get('From', 'Unknown Sender')
            subject = headers.get('Subject', '(No Subject)')
            date = headers.get('Date', 'Unknown Date')
            
            # Get snippet (preview of message body)
            snippet = message.get('snippet', '')
            
            print(f"Email details:")
            print(f"  From: {sender}")
            print(f"  Subject: {subject}")
            print(f"  Date: {date}")
            print(f"  Snippet: {snippet[:100]}...")
            
            # Score the email importance
            print(f"Scoring email with AI...")
            importance = self.ai_scorer.score_email({
                'sender': sender,
                'subject': subject,
                'snippet': snippet
            })
            print(f"AI Score: {importance['score']}/10")
            print(f"Explanation: {importance['explanation']}")
            
            # Create email object
            email_data = {
                'id': message_id,
                'sender': sender,
                'subject': subject,
                'date': date,
                'snippet': snippet,
                'importance': importance
            }
            
            # Import the global email_storage directly from app.py
            import app
            app.email_storage.add_email(email_data)
            print(f"Email added to storage. Total emails: {len(app.email_storage.get_all_emails())}")
            
            print(f"==== EMAIL PROCESSING COMPLETE ====\n")
            return True
            
        except Exception as e:
            logger.error(f"Error processing message {message_id}: {str(e)}")
            print(f"ERROR processing message {message_id}: {str(e)}")
            return False
        finally:
            # Ensure we clean up any remaining connections
            if 'service' in locals() and hasattr(service, '_http'):
                service._http.close() 