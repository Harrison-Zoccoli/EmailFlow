from flask import Flask, jsonify, render_template, redirect, url_for, session, request
from gmail_handler import GmailHandler
from email_storage import EmailStorage
from user_manager import UserManager
import json
import time
import threading
from flask_socketio import SocketIO, emit
from functools import wraps
import logging
import requests
import google_auth_oauthlib
from dotenv import load_dotenv
import os
from config import SCOPES, CREDENTIALS_FILE, AZURE_URL
from datetime import datetime
from sms_handler import SMSHandler
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import sys
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for sessions

# Initialize with explicit configuration for WebSocket
socketio = SocketIO(app, 
                   cors_allowed_origins="*",  # Allow connections from any origin
                   async_mode='threading',    # Use threading mode
                   logger=True,               # Enable SocketIO logging
                   engineio_logger=True)      # Enable Engine.IO logging

# Initialize handlers
email_storage = EmailStorage()
gmail_handler = None
sms_handler = SMSHandler()  # Initialize with default key for testing
email_thread = None
user_manager = UserManager()

# Configure more detailed logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # Log to console
        logging.FileHandler('emailflow.log')  # Also log to file
    ]
)
logger = logging.getLogger(__name__)

# Add a startup message
logger.info("=" * 50)
logger.info("EmailFlow Server Starting")
logger.info("=" * 50)

# Add at the start of app.py
print("Loading environment variables...")
load_dotenv()
print(f"AZURE_OPENAI_DEPLOYMENT: {os.getenv('AZURE_OPENAI_DEPLOYMENT')}")
print(f"AZURE_OPENAI_ENDPOINT: {os.getenv('AZURE_OPENAI_ENDPOINT')}")
print(f"AZURE_OPENAI_KEY (first 10 chars): {os.getenv('AZURE_OPENAI_KEY')[:10]}...")

def log_exception(exc_type, exc_value, exc_traceback):
    """Log exception with traceback"""
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

# Set the excepthook to catch and log unhandled exceptions
sys.excepthook = log_exception

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def login():
    return render_template('login.html', 
                         current_user=session.get('user_email'),
                         error=session.get('error'))

@app.route('/google_login')
def google_login():
    """Start the Google OAuth flow for desktop client"""
    try:
        logger.info("Starting Google login process")
        
        # Create a new GmailHandler instance for this login
        global gmail_handler
        gmail_handler = GmailHandler()
        
        # Run the desktop client flow - explicitly call it here
        result = gmail_handler.setup_credentials()
        logger.info(f"Authentication result: {result}")
        
        # Get user email after authentication
        user_email = gmail_handler.get_user_email()
        if not user_email:
            logger.error("Failed to get user email after authentication")
            session['error'] = "Failed to get user email"
            return redirect(url_for('login'))
            
        session['user_email'] = user_email
        logger.info(f"User authenticated with email: {user_email}")
        
        # Check if user exists in database
        if result == "new_user" or not user_manager.user_exists(user_email):
            # New user, redirect to profile completion
            logger.info(f"New user {user_email}, redirecting to complete_profile")
            
            # Create a new user in the database
            user_manager.create_user(user_email)
            
            return redirect(url_for('complete_profile'))
        else:
            # Existing user, redirect to monitor
            logger.info(f"Existing user {user_email}, redirecting to monitor")
            return redirect(url_for('monitor'))
            
    except Exception as e:
        logger.error(f"Error in Google login: {str(e)}")
        session['error'] = str(e)
        return redirect(url_for('login'))

@app.route('/google_login_callback')
def google_login_callback():
    global gmail_handler, email_thread
    
    # Existing code for handling the OAuth callback...
    
    # Start the email checking thread if not already running
    if email_thread is None or not email_thread.is_alive():
        email_thread = threading.Thread(target=check_new_emails, daemon=True)
        email_thread.start()
        logger.info("Started background email checking thread")
    
    # Rest of the existing code...

@app.route('/logout')
def logout():
    global gmail_handler, email_thread
    
    try:
        if gmail_handler and gmail_handler.creds:
            # Revoke access completely
            requests.post('https://accounts.google.com/o/oauth2/revoke',
                params={'token': gmail_handler.creds.token},
                headers={'content-type': 'application/x-www-form-urlencoded'})
            
            # Clear credentials
            gmail_handler.creds = None
            gmail_handler.service = None
        
        # Stop and clear email thread
        email_thread = None
        
        # Clear all session data
        session.clear()
        
        # Clear stored emails
        email_storage.clear_emails()
        
        # Clear Firebase tokens
        if 'user_email' in session:
            user_manager.update_user(session['user_email'], {'gmail_token': None})
        
        # Redirect with cache-busting headers
        response = redirect(url_for('login'))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/monitor')
@login_required
def monitor():
    """Monitor page - show all emails"""
    try:
        # Get all emails from storage
        emails = email_storage.get_all_emails()
        
        print("\n==== MONITOR PAGE LOAD ====")
        print(f"Total emails in storage: {len(emails)}")
        print(f"Email storage object ID: {id(email_storage)}")
        
        # Print each email
        for i, email in enumerate(emails):
            print(f"  {i+1}. ID: {email.get('id', 'No ID')}")
            print(f"     Subject: {email.get('subject', 'No subject')}")
            print(f"     From: {email.get('sender', 'Unknown')}")
        
        return render_template('monitor.html', emails=emails)
    except Exception as e:
        logger.error(f"Error in monitor route: {str(e)}")
        return render_template('monitor.html', emails=[])

@app.route('/emails')
@login_required
def get_emails():
    """Get all stored emails"""
    try:
        emails = email_storage.get_all_emails()
        print(f"Returning {len(emails)} emails from storage")
        for i, email in enumerate(emails):
            print(f"  {i+1}. {email.get('subject', 'No subject')} from {email.get('sender', 'Unknown')}")
        return jsonify(emails)
    except Exception as e:
        logger.error(f"Error in get_emails: {str(e)}")
        return jsonify([])

@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    data = request.json
    user_email = session.get('user_email')
    user_manager.update_user(user_email, data)
    return jsonify({'status': 'success'})

@app.route('/get_user')
@login_required
def get_user():
    user_email = session.get('user_email')
    user_data = user_manager.get_user(user_email)
    return jsonify(user_data)

@app.route('/signup')
@login_required
def signup():
    return render_template('signup.html', email=session.get('user_email'))

@app.route('/complete_signup', methods=['POST'])
@login_required
def complete_signup():
    global email_thread
    email = session.get('user_email')
    name = request.form.get('name')
    phone = request.form.get('phone')
    
    user_manager.create_user(email, {
        'email': email,
        'name': name,
        'phonenumber': phone
    })
    
    # Start email checking thread if not already running
    if email_thread is None or not email_thread.is_alive():
        email_thread = threading.Thread(target=check_new_emails, daemon=True)
        email_thread.start()
        logger.info("Started background email checking thread after signup")
    
    return redirect(url_for('monitor'))

def check_new_emails():
    """Background thread that continuously checks for new emails"""
    while True:
        try:
            if gmail_handler is not None:
                logger.info("Checking for new emails...")
                
                # Check for new emails
                new_emails_found = gmail_handler.check_for_new_emails()
                
                if new_emails_found:
                    logger.info(f"Found new emails during background check")
                    # The process_message method in gmail_handler will handle 
                    # sending SMS for high priority emails
                
                # Sleep for 30 seconds before checking again
                time.sleep(30)
            else:
                # If gmail_handler is not initialized, wait longer before retrying
                logger.warning("Gmail handler not initialized, waiting...")
                time.sleep(60)
                
        except Exception as e:
            logger.error(f"Error in background email check: {str(e)}", exc_info=True)
            # If there's an error, wait before retrying
            time.sleep(60)

@app.route('/debug')
@login_required
def debug():
    return jsonify({
        'user_email': session.get('user_email'),
        'gmail_handler_exists': gmail_handler is not None,
        'email_thread_running': email_thread is not None,
        'stored_emails': len(email_storage.get_all_emails()),
        'firebase_user': user_manager.get_user(session.get('user_email'))
    })

@app.route('/unread')
@login_required
def unread():
    """Unread emails page"""
    return render_template('unread.html')

@app.route('/get_unread_emails')
@login_required
def get_unread_emails_ajax():
    """Get unread emails from Gmail API directly"""
    try:
        time_filter = request.args.get('time_filter', 'week')
        
        if gmail_handler:
            # This calls Gmail API directly to get unread emails
            unread_emails = gmail_handler.get_unread_emails(time_filter)
            return jsonify({
                'status': 'success',
                'emails': unread_emails
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'Gmail handler not initialized'
            })
    except Exception as e:
        logger.error(f"Error getting unread emails: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        })

@app.route('/unread_emails/<filter>')
@login_required
def get_unread_emails(filter):
    try:
        total = gmail_handler.get_unread_count(filter)
        logger.info(f"Found {total} unread emails for filter: {filter}")
        processed = 0
        errors = 0
        
        def generate():
            nonlocal processed, errors
            
            for email in gmail_handler.get_filtered_unread_emails(filter):
                if email:
                    processed += 1
                    logger.info(f"Processed email {processed}/{total}")
                    yield json.dumps({
                        'type': 'email',
                        'data': email,
                        'progress': {
                            'processed': processed,
                            'total': total,
                            'errors': errors
                        }
                    }) + '\n'
                else:
                    errors += 1
                    logger.warning(f"Failed to process email {processed + errors}/{total}")
                    yield json.dumps({
                        'type': 'error',
                        'progress': {
                            'processed': processed,
                            'total': total,
                            'errors': errors
                        }
                    }) + '\n'
                    
        return app.response_class(generate(), mimetype='text/event-stream')
    except Exception as e:
        logger.error(f"Error streaming emails: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/mark_as_read/<message_id>', methods=['POST'])
@login_required
def mark_message_as_read(message_id):
    try:
        if gmail_handler.mark_as_read(message_id):
            return jsonify({'status': 'success'})
        else:
            return jsonify({'error': 'Failed to mark message as read'}), 500
    except Exception as e:
        logger.error(f"Error in mark_as_read route: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_emails')
@login_required
def check_emails():
    """Manually check for new emails"""
    try:
        if gmail_handler:
            # Get the latest emails
            gmail_handler.check_for_new_emails()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'error': 'Gmail handler not initialized'})
    except Exception as e:
        logger.error(f"Error checking emails: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/debug_emails')
@login_required
def debug_emails():
    """Debug endpoint to check what emails are in storage"""
    try:
        emails = email_storage.get_emails()
        return jsonify({
            'count': len(emails),
            'emails': emails
        })
    except Exception as e:
        logger.error(f"Error in debug_emails: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug_process_email/<message_id>')
@login_required
def debug_process_email(message_id):
    """Debug endpoint to manually process a specific email"""
    try:
        if gmail_handler:
            result = gmail_handler.process_message(message_id)
            return jsonify({
                'status': 'success' if result else 'error',
                'message': f"Processed email {message_id}",
                'emails_in_storage': len(email_storage.get_all_emails())
            })
        else:
            return jsonify({'status': 'error', 'error': 'Gmail handler not initialized'})
    except Exception as e:
        logger.error(f"Error in debug_process_email: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_test_email_and_redirect')
@login_required
def add_test_email_and_redirect():
    """Add a test email to the storage and redirect to monitor page"""
    try:
        # Create a test email
        test_email = {
            'id': f'test-{int(time.time())}',
            'sender': 'test@example.com',
            'subject': f'Test Email {int(time.time())}',
            'date': time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime()),
            'snippet': 'This is a test email to verify the UI display functionality.',
            'importance': {
                'score': 5,
                'explanation': 'This is a test email with medium priority.'
            },
            'stored_at': datetime.now().isoformat()
        }
        
        # Add to storage
        email_storage.add_email(test_email)
        
        # Print to console
        print(f"\n==== ADDED TEST EMAIL ====")
        print(f"Email details:")
        print(f"  From: {test_email['sender']}")
        print(f"  Subject: {test_email['subject']}")
        print(f"  Date: {test_email['date']}")
        print(f"  Snippet: {test_email['snippet']}")
        print(f"  Priority: {test_email['importance']['score']}/10")
        print(f"Total emails in storage: {len(email_storage.get_all_emails())}")
        
        # Redirect to monitor page
        return redirect(url_for('monitor'))
    except Exception as e:
        logger.error(f"Error adding test email: {str(e)}")
        return redirect(url_for('monitor'))

@app.route('/refresh_emails')
@login_required
def refresh_emails():
    """Check for new emails and redirect to monitor page"""
    try:
        if gmail_handler:
            # Get the latest emails
            gmail_handler.check_for_new_emails()
            
            # Print current emails in storage
            emails = email_storage.get_all_emails()
            print(f"After refresh: {len(emails)} emails in storage")
            
        return redirect(url_for('monitor'))
    except Exception as e:
        logger.error(f"Error refreshing emails: {str(e)}")
        return redirect(url_for('monitor'))

@app.route('/refresh_emails_ajax')
@login_required
def refresh_emails_ajax():
    """Check for new emails and return JSON response"""
    try:
        # Get current email count
        current_count = len(email_storage.get_all_emails())
        
        # Check for new emails if Gmail handler is initialized
        if gmail_handler:
            new_emails_found = gmail_handler.check_for_new_emails()
            
            # Get updated count
            new_count = len(email_storage.get_all_emails())
            
            return jsonify({
                'status': 'success',
                'email_count': new_count,
                'new_emails': new_count - current_count,
                'found_new': new_emails_found
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'Gmail handler not initialized',
                'email_count': current_count
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'email_count': len(email_storage.get_all_emails())
        })

@app.route('/debug_dump_emails')
@login_required
def debug_dump_emails():
    """Debug endpoint to dump all email storage contents"""
    try:
        emails = email_storage.get_all_emails()
        
        # Print to console
        print("\n==== DEBUG DUMP EMAILS ====")
        print(f"Total emails in storage: {len(emails)}")
        print(f"Email storage object ID: {id(email_storage)}")
        
        # Return as JSON
        return jsonify({
            'count': len(emails),
            'storage_id': id(email_storage),
            'emails': emails
        })
    except Exception as e:
        logger.error(f"Error in debug_dump_emails: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_email_thread_status')
@login_required
def check_email_thread_status():
    """Check if the email thread is running"""
    if email_thread is not None and email_thread.is_alive():
        return jsonify({
            'status': 'running',
            'last_check': time.time()
        })
    else:
        return jsonify({
            'status': 'stopped',
            'error': 'Email checking thread is not running'
        })

def initialize_background_email_checker():
    """Initialize and start the background email checker for all users"""
    logger.info("=" * 50)
    logger.info("Initializing background email checker...")
    logger.info("=" * 50)
    
    try:
        # Start the background thread
        email_checker_thread = threading.Thread(target=check_emails_for_all_users, daemon=True)
        email_checker_thread.start()
        logger.info("Background email checker thread started with ID: %s", email_checker_thread.ident)
        
        return email_checker_thread
    except Exception as e:
        logger.error(f"Failed to start background email checker: {str(e)}", exc_info=True)
        return None

def check_emails_for_all_users():
    """Background thread that checks emails for all users"""
    # Wait 10 seconds before starting to ensure server is fully initialized
    logger.info("Background email checker waiting 10 seconds before starting...")
    time.sleep(10)
    
    logger.info("Background email checker active and running")
    
    check_count = 0
    while True:
        check_count += 1
        try:
            # Get all users from the database
            users = user_manager.get_all_users()
            
            # Filter out invalid users
            valid_users = []
            for user in users:
                # Only consider users with an email, name, phone number, and Gmail token
                if (user.get('email') and 
                    user.get('name') and 
                    user.get('phonenumber') and 
                    user.get('gmail_token')):
                    valid_users.append(user)
            
            logger.info("=" * 30)
            logger.info(f"Check #{check_count}: Found {len(users)} total users, {len(valid_users)} valid users")
            
            for user in valid_users:
                try:
                    email = user.get('email')
                    logger.info(f"Processing user: {email}")
                    
                    # Create credentials from stored token
                    creds = create_credentials_from_token(user.get('gmail_token'))
                    
                    # If credentials are expired and can't be refreshed, skip this user
                    if not creds or not creds.valid:
                        logger.warning(f"Invalid credentials for user {email}, skipping")
                        continue
                    
                    logger.info(f"Successfully created credentials for user {email}")
                    
                    # Create a temporary Gmail handler for this user
                    temp_gmail_handler = GmailHandler()
                    temp_gmail_handler.creds = creds
                    temp_gmail_handler.service = build('gmail', 'v1', credentials=creds)
                    
                    # Check for new emails
                    logger.info(f"Checking emails for user {email}")
                    new_emails_found = temp_gmail_handler.check_for_new_emails()
                    
                    if new_emails_found:
                        logger.info(f"Found new emails for user {email}")
                    else:
                        logger.info(f"No new emails found for user {email}")
                    
                    # If credentials were refreshed, update the stored token
                    if creds and creds.valid and hasattr(creds, 'refresh_token') and creds.refresh_token:
                        token_data = {
                            'token': creds.token,
                            'refresh_token': creds.refresh_token,
                            'token_uri': creds.token_uri,
                            'client_id': creds.client_id,
                            'client_secret': creds.client_secret,
                            'scopes': creds.scopes
                        }
                        user_manager.update_user(email, {'gmail_token': token_data})
                        logger.info(f"Updated token for user {email}")
                    
                except Exception as e:
                    logger.error(f"Error checking emails for user {user.get('email')}: {str(e)}", exc_info=True)
            
            logger.info(f"Check #{check_count} complete. Sleeping for 10 seconds...")
            logger.info("=" * 30)
            # Sleep for 10 seconds before checking again
            time.sleep(10)
            
        except Exception as e:
            logger.error(f"Error in background email checker: {str(e)}", exc_info=True)
            # If there's an error, wait before retrying
            logger.info("Waiting 30 seconds before retrying after error...")
            time.sleep(30)

def create_credentials_from_token(token_data):
    """Create credentials object from stored token data"""
    try:
        if not token_data:
            return None
            
        creds = Credentials(
            token=token_data.get('token'),
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_data.get('token_uri'),
            client_id=token_data.get('client_id'),
            client_secret=token_data.get('client_secret'),
            scopes=token_data.get('scopes')
        )
        
        # If token is expired, try to refresh it
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            
        return creds
    except Exception as e:
        logger.error(f"Error creating credentials from token: {str(e)}")
        return None

# Start the background email checker when the app starts
logger.info("Starting background email checker on server startup")
email_checker_thread = initialize_background_email_checker()

if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    try:
        socketio.run(app, debug=True, port=5000, host='0.0.0.0', allow_unsafe_werkzeug=True)
    finally:
        # Make sure the thread is properly terminated when the app exits
        if email_checker_thread and email_checker_thread.is_alive():
            logger.info("Shutting down background email checker...") 