from flask import Flask, jsonify, render_template, redirect, url_for, session, request, Response
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
from datetime import datetime, timedelta
from sms_handler import SMSHandler
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import sys
from googleapiclient.discovery import build
from firebase_admin import firestore as admin_firestore
from ai_scorer import AIScorer
from firebase_config import db as firestore_db
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

# Add this line to allow OAuth over HTTP (for development only)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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
    """Start the Google OAuth flow"""
    logger.info("Starting Google login process")
    
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES)
    
    # Set the redirect URI
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    
    # Generate URL for request to Google's OAuth 2.0 server
    authorization_url, state = flow.authorization_url(
        # Enable offline access so we can refresh an access token without
        # re-prompting the user for permission
        access_type='offline',
        # Enable incremental authorization
        include_granted_scopes='true')
    
    # Store the state in the session for later validation
    session['state'] = state
    
    # Redirect the user to Google's OAuth 2.0 server
    return redirect(authorization_url)

@app.route('/google_auth_callback')
def google_auth_callback():
    """Handle the OAuth 2.0 callback from Google"""
    # Specify the state when creating the flow in the callback
    state = session.get('state')
    
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
        state=state)
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    
    # Use the authorization server's response to fetch the OAuth 2.0 tokens
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    # Store credentials in the session
    credentials = flow.credentials
    
    # Get user email from Gmail API - FIX THIS PART
    try:
        # Create Gmail service directly
        service = build('gmail', 'v1', credentials=credentials)
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile['emailAddress']
        
        # Store user email in session
        if user_email:
            session['user_email'] = user_email
            print(f"Successfully retrieved and stored user email: {user_email}")
        else:
            print("Warning: Could not get user email from Gmail API")
            return redirect(url_for('login', error="Could not retrieve your email address. Please try again."))
        
        # Check if user exists in database
        logger.info(f"Checking if user {user_email} exists in database")
        user_exists = user_manager.user_exists(user_email)
        
        # Store token in database
        token_data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Store token in database
        user_manager.update_user(user_email, {'gmail_token': token_data})
        
        # If user doesn't exist, redirect to complete signup
        if not user_exists:
            logger.info(f"New user {user_email}, redirecting to complete signup")
            return redirect(url_for('complete_signup'))
        else:
            logger.info(f"Existing user {user_email}, redirecting to monitor")
            return redirect(url_for('monitor'))
            
    except Exception as e:
        logger.error(f"Error in Google auth callback: {str(e)}")
        return redirect(url_for('login', error="Authentication error. Please try again."))

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

@app.route('/complete_signup')
@login_required
def complete_signup():
    """Complete the signup process for new users"""
    # Use the existing signup.html template instead of the missing complete_signup.html
    return render_template('signup.html', email=session.get('user_email'))

@app.route('/complete_signup', methods=['POST'])
@login_required
def process_signup():
    """Process the signup form submission"""
    try:
        # Get email from session, not from form
        user_email = session.get('user_email')
        name = request.form.get('name')
        phone = request.form.get('phone')
        
        logger.info(f"Processing signup for {user_email} with name {name} and phone {phone}")
        
        if not user_email or not name or not phone:
            logger.error(f"Missing required fields in signup: email={user_email}, name={name}, phone={phone}")
            return redirect(url_for('signup'))
        
        # Update user data in the database
        user_data = {
            'name': name,
            'phonenumber': phone,
            'email': user_email,
            'created_at': admin_firestore.SERVER_TIMESTAMP
        }
        
        # Create or update the user
        user_manager.create_user(user_email, user_data)
        logger.info(f"User profile completed for {user_email}")
        
        # Redirect to the monitor page
        return redirect(url_for('monitor'))
        
    except Exception as e:
        logger.error(f"Error processing signup: {str(e)}")
        return redirect(url_for('signup'))

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

@app.route('/unread_emails/<timeframe>')
@login_required
def get_unread_emails(timeframe):
    """Stream unread emails to the client"""
    # Get user info BEFORE starting the generator
    user_email = session.get('user_email')
    user_data = user_manager.get_user(user_email)
    
    if not user_data or 'gmail_token' not in user_data:
        return jsonify({
            'type': 'error', 
            'message': 'No Gmail token found. Please re-authenticate.',
            'progress': {'processed': 0, 'total': 0}
        })
    
    # Prepare credentials outside the generator
    token_data = user_data.get('gmail_token')
    
    # Set up cutoff time based on filter
    if timeframe == 'hour':
        cutoff_time = datetime.now() - timedelta(hours=1)
    elif timeframe == 'day':
        cutoff_time = datetime.now() - timedelta(days=1)
    elif timeframe == 'month':
        cutoff_time = datetime.now() - timedelta(days=30)
    else:  # Default to week
        cutoff_time = datetime.now() - timedelta(days=7)
    
    # Create a profile reference if it exists
    user_profile = None
    ai_settings = user_data.get('ai_settings', {})
    selected_model = ai_settings.get('selected_model', 'standard')
    
    if selected_model == 'enhanced':
        profile = ai_settings.get('profile', {})
        if profile.get('training_status') == 'completed':
            user_profile = profile.get('profile_text')
    
    # Now define generator without Flask context dependencies
    def generate():
        try:
            # Create credentials from stored token
            creds = Credentials(
                token=token_data.get('token'),
                refresh_token=token_data.get('refresh_token'),
                token_uri=token_data.get('token_uri'),
                client_id=token_data.get('client_id'),
                client_secret=token_data.get('client_secret'),
                scopes=token_data.get('scopes')
            )
            
            # Set up Gmail handler
            local_handler = GmailHandler()
            local_handler.creds = creds
            local_handler.setup_service()
            
            # Get the total number of unread emails
            total_emails = local_handler.get_unread_count(timeframe)
            processed = 0
            
            # Process and yield emails one by one
            for email in local_handler.get_filtered_unread_emails(timeframe):
                if email:
                    # Store in email_storage for later use with ratings
                    email_storage.add_email(email)
                    
                    processed += 1
                    response_data = {
                        'type': 'email',
                        'data': email,
                        'progress': {'processed': processed, 'total': total_emails}
                    }
                    yield f"{json.dumps(response_data)}\n"
            
        except Exception as e:
            logger.error(f"Error streaming emails: {str(e)}")
            yield json.dumps({
                'type': 'error',
                'message': f"Error: {str(e)}",
                'progress': {'processed': 0, 'total': 0}
            }) + '\n'
            
    return Response(generate(), mimetype='application/x-json-stream')

@app.route('/mark_as_read/<message_id>', methods=['POST'])
@login_required
def mark_message_as_read(message_id):
    try:
        # Get the current user's email from session
        user_email = session.get('user_email')
        
        # Get user's credentials from database
        user_data = user_manager.get_user(user_email)
        
        if not user_data or 'gmail_token' not in user_data:
            logger.error(f"No token found for user {user_email}")
            return jsonify({'error': 'No Gmail token found. Please re-authenticate.'}), 401
        
        # Create a new handler for this request
        local_handler = GmailHandler()
        
        # Create credentials from stored token
        token_data = user_data.get('gmail_token')
        creds = Credentials(
            token=token_data.get('token'),
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_data.get('token_uri'),
            client_id=token_data.get('client_id'),
            client_secret=token_data.get('client_secret'),
            scopes=token_data.get('scopes')
        )
        
        # Setup handler with these credentials
        local_handler.creds = creds
        local_handler.setup_service()
        
        # Mark the message as read
        if local_handler.mark_as_read(message_id):
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

def check_emails_for_user(user_email, user_data, check_number):
    """Check emails for a specific user"""
    try:
        # Create credentials from stored token
        creds = create_credentials_from_token(user_data.get('gmail_token'))
        
        if not creds or not creds.valid:
            logger.error(f"Invalid credentials for user {user_email}")
            return False
            
        logger.info(f"Successfully created credentials for user {user_email}")
        
        # Create AI scorer
        ai_scorer = AIScorer(
            os.getenv('AZURE_OPENAI_KEY'),
            os.getenv('AZURE_OPENAI_ENDPOINT')
        )
        
        # Create Gmail handler with credentials
        try:
            # Get the user's selected model from Firebase
            user_settings = user_manager.get_user(user_email)
            selected_model = user_settings.get('ai_settings', {}).get('selected_model', 'standard')
            
            # Get user profile if enhanced model is selected
            user_profile = None
            if selected_model == 'enhanced':
                user_profile = user_settings.get('ai_settings', {}).get('profile', {}).get('profile_text', None)
                
            # Log which model is being used - make it more prominent
            print(f"\n{'=' * 40}")
            print(f"📧 USING {selected_model.upper()} MODEL FOR {user_email}")
            if selected_model == 'enhanced' and user_profile:
                print(f"✅ User profile is available and will be used for scoring")
            elif selected_model == 'enhanced' and not user_profile:
                print(f"⚠️ Enhanced model selected but no user profile found")
            print(f"{'=' * 40}\n")
            
            logger.info(f"Using {selected_model} model for user {user_email}")
            
            # Pass the selected model and user profile to the Gmail handler
            gmail_handler = GmailHandler(creds, ai_scorer, selected_model=selected_model, user_profile=user_profile)
        except TypeError:
            # If it doesn't accept the selected_model parameter, try the old way
            gmail_handler = GmailHandler()
            gmail_handler.creds = creds
            gmail_handler.ai_scorer = ai_scorer
            gmail_handler.service = build('gmail', 'v1', credentials=creds)
            
            # Try to set the selected model if the attribute exists
            if hasattr(gmail_handler, 'selected_model'):
                user_settings = user_manager.get_user(user_email)
                selected_model = user_settings.get('ai_settings', {}).get('selected_model', 'standard')
                gmail_handler.selected_model = selected_model
                
                # Try to set the user profile if the attribute exists
                if hasattr(gmail_handler, 'user_profile') and selected_model == 'enhanced':
                    user_profile = user_settings.get('ai_settings', {}).get('profile', {}).get('profile_text', None)
                    gmail_handler.user_profile = user_profile
                
                # Log which model is being used - make it more prominent
                print(f"\n{'=' * 40}")
                print(f"📧 USING {selected_model.upper()} MODEL FOR {user_email}")
                if selected_model == 'enhanced' and user_profile:
                    print(f"✅ User profile is available and will be used for scoring")
                elif selected_model == 'enhanced' and not user_profile:
                    print(f"⚠️ Enhanced model selected but no user profile found")
                print(f"{'=' * 40}\n")
                
                logger.info(f"Using {selected_model} model for user {user_email}")
        
        # Only log this once per check cycle instead of for each user
        if user_email == first_valid_user:
            logger.info(f"Check #{check_number}: Checking emails...")
        
        # Check for new emails
        new_emails = gmail_handler.check_for_new_emails()
        
        # Only log if there are new emails or if this is the first valid user
        if new_emails or user_email == first_valid_user:
            logger.info(f"User {user_email}: {'New emails found!' if new_emails else 'No new emails'}")
        
        # Update token in database if it was refreshed
        if creds.token != user_data.get('gmail_token', {}).get('token'):
            logger.info(f"Updated token for user {user_email}")
            user_manager.update_gmail_token(user_email, {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            })
        
        return True
    except Exception as e:
        logger.error(f"Error checking emails for user {user_email}: {str(e)}")
        return False

def background_email_checker():
    """Background thread to check emails for all users"""
    check_number = 0
    
    while True:
        try:
            check_number += 1
            logger.info("==============================")
            logger.info("Background email checker active and running")
            
            # Get all users from database
            all_users = user_manager.get_all_users()
            
            # Check if all_users is a list or dictionary and handle accordingly
            if isinstance(all_users, list):
                # If it's a list of user objects
                valid_users = [user.get('email') for user in all_users 
                              if user.get('gmail_token') and user.get('gmail_token').get('refresh_token')]
                
                # Create a dictionary for easier lookup
                users_dict = {user.get('email'): user for user in all_users if user.get('email')}
            else:
                # If it's already a dictionary with email keys
                valid_users = [email for email, data in all_users.items() 
                              if data.get('gmail_token') and data.get('gmail_token').get('refresh_token')]
                users_dict = all_users
            
            # Track the first valid user to use for minimal logging
            global first_valid_user
            first_valid_user = valid_users[0] if valid_users else None
            
            logger.info(f"Check #{check_number}: Found {len(all_users)} total users, {len(valid_users)} valid users")
            
            # Check emails for each valid user
            for user_email in valid_users:
                user_data = users_dict.get(user_email, {})
                check_emails_for_user(user_email, user_data, check_number)
            
            logger.info(f"Check #{check_number} complete. Sleeping for 20 seconds...")
            logger.info("==============================")
            
            # Sleep for 20 seconds before checking again (changed from 10)
            time.sleep(20)
            
        except Exception as e:
            logger.error(f"Error in background email checker: {str(e)}")
            logger.info("Background email checker will retry in 20 seconds...")
            time.sleep(20)  # Also changed here

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

# Global variable to track if the checker is already running
email_checker_running = False

# Start the background email checker when the app starts
logger.info("Starting background email checker on server startup")
# Initialize but don't start the thread yet
email_checker_thread = threading.Thread(target=background_email_checker)
email_checker_thread.daemon = True  # Make it a daemon thread

@app.route('/ai_settings', methods=['GET'])
@login_required
def ai_settings():
    user_email = session.get('user_email')
    user_data = user_manager.get_user(user_email)
    
    # Get AI settings or set defaults
    ai_settings = user_data.get('ai_settings', {
        'selected_model': 'standard',
        'profile': {
            'training_status': 'none'
        }
    })
    
    return render_template('ai_settings.html', 
                          current_user=user_email,
                          ai_settings=ai_settings)

@app.route('/update_ai_model', methods=['POST'])
@login_required
def update_ai_model():
    user_email = session.get('user_email')
    selected_model = request.form.get('model')
    
    # Update user's selected model in Firebase
    user_manager.update_user(user_email, {
        'ai_settings.selected_model': selected_model
    })
    
    return jsonify({'status': 'success'})

@app.route('/train_ai_model', methods=['POST'])
@login_required
def train_ai_model():
    user_email = session.get('user_email')
    
    # Update training status to in_progress
    user_manager.update_user(user_email, {
        'ai_settings.profile.training_status': 'in_progress',
        'ai_settings.profile.last_updated': admin_firestore.SERVER_TIMESTAMP
    })
    
    # Start training in background thread
    threading.Thread(target=train_user_model, args=(user_email,)).start()
    
    return jsonify({'status': 'success'})

@app.route('/check_training_status', methods=['GET'])
@login_required
def check_training_status():
    user_email = session.get('user_email')
    user_data = user_manager.get_user(user_email)
    
    ai_settings = user_data.get('ai_settings', {})
    profile = ai_settings.get('profile', {})
    
    return jsonify({
        'status': profile.get('training_status', 'none')
    })

def train_user_model(user_email):
    try:
        logger.info(f"Starting AI model training for user {user_email}")
        
        # Get user data and credentials
        user_data = user_manager.get_user(user_email)
        creds = create_credentials_from_token(user_data.get('gmail_token'))
        
        if not creds or not creds.valid:
            logger.error(f"Invalid credentials for user {user_email}")
            user_manager.update_user(user_email, {
                'ai_settings.profile.training_status': 'failed'
            })
            return
            
        # Create Gmail service
        service = build('gmail', 'v1', credentials=creds)
        
        # Get most recent emails first (no date filter)
        logger.info(f"Fetching recent emails for user {user_email}")
        results = service.users().messages().list(userId='me', maxResults=500).execute()
        messages = results.get('messages', [])
        
        if not messages:
            logger.warning(f"No emails found for user {user_email}")
            user_manager.update_user(user_email, {
                'ai_settings.profile.training_status': 'failed'
            })
            return
            
        logger.info(f"Found {len(messages)} emails for analysis")
        
        # Set a minimum threshold for training
        if len(messages) < 20:
            logger.warning(f"Insufficient emails for training: only {len(messages)} found")
            user_manager.update_user(user_email, {
                'ai_settings.profile.training_status': 'failed'
            })
            return
        
        # Process emails in batches
        batch_size = 50
        email_data = []

        for i in range(0, min(len(messages), 500), batch_size):  # Cap at 500 emails
            batch = messages[i:i+batch_size]
            
            for msg in batch:
                try:
                    # Get full message
                    message = service.users().messages().get(userId='me', id=msg['id']).execute()
                    
                    # Extract headers
                    headers = message.get('payload', {}).get('headers', [])
                    subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                    sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                    date = next((h['value'] for h in headers if h['name'].lower() == 'date'), '')
                    
                    # Get snippet
                    snippet = message.get('snippet', '')
                    
                    # Determine engagement level
                    labels = message.get('labelIds', [])
                    has_replied = 'SENT' in labels  # Approximation for replies
                    is_read = 'UNREAD' not in labels
                    
                    engagement = "high" if has_replied else ("medium" if is_read else "low")
                    
                    # Add to dataset
                    email_data.append({
                        'sender': sender,
                        'subject': subject,
                        'date': date,
                        'snippet': snippet,
                        'engagement': engagement
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing message {msg['id']}: {str(e)}")
            
            # Update progress
            progress = min(100, int((i + len(batch)) / min(len(messages), 500) * 100))
            logger.info(f"Processing progress: {progress}%")
        
        # Generate user profile using AI
        profile_text = generate_user_profile(email_data)
        
        if not profile_text:
            logger.error(f"Failed to generate profile for user {user_email}")
            user_manager.update_user(user_email, {
                'ai_settings.profile.training_status': 'failed'
            })
            return
            
        # Update user profile in Firebase
        user_manager.update_user(user_email, {
            'ai_settings.profile.profile_text': profile_text,
            'ai_settings.profile.training_status': 'completed',
            'ai_settings.profile.last_updated': admin_firestore.SERVER_TIMESTAMP,
            'ai_settings.selected_model': 'enhanced'  # Auto-switch to enhanced model
        })
        
        logger.info(f"Successfully completed AI model training for user {user_email} with {len(email_data)} emails")
        
    except Exception as e:
        logger.error(f"Error in train_user_model for {user_email}: {str(e)}", exc_info=True)
        user_manager.update_user(user_email, {
            'ai_settings.profile.training_status': 'failed'
        })

def generate_user_profile(email_data):
    try:
        # Initialize AI scorer
        ai_scorer = AIScorer(
            os.getenv('AZURE_OPENAI_KEY'),
            os.getenv('AZURE_OPENAI_ENDPOINT')
        )
        
        # Prepare data for the prompt
        high_engagement_emails = [e for e in email_data if e['engagement'] == 'high']
        medium_engagement_emails = [e for e in email_data if e['engagement'] == 'medium']
        
        # Sample emails for the prompt (prioritize high engagement)
        sample_size = min(50, len(email_data))
        samples = (
            high_engagement_emails[:int(sample_size * 0.6)] + 
            medium_engagement_emails[:int(sample_size * 0.3)] + 
            [e for e in email_data if e['engagement'] == 'low'][:int(sample_size * 0.1)]
        )
        
        # Create prompt for profile generation
        prompt = f"""
        Based on the following sample of {len(samples)} emails from a total dataset of {len(email_data)} emails, 
        create a medium-depth profile of the user. Focus on:

        1. Professional/academic status (student, professional, field of study)
        2. Key relationships and frequent contacts
        3. Important topics and interests
        4. Time-sensitive patterns or recurring events
        5. Types of emails that appear important to this user

        Note that emails marked as "high" engagement were replied to by the user,
        "medium" engagement emails were read but not replied to,
        and "low" engagement emails were not read.

        Sample emails:
        """
        
        # Add sample emails to prompt
        for i, email in enumerate(samples[:50]):  # Limit to 50 samples
            prompt += f"""
            Email {i+1}:
            - Sender: {email['sender']}
            - Subject: {email['subject']}
            - Date: {email['date']}
            - Content: {email['snippet']}
            - Engagement: {email['engagement']}
            """
        
        prompt += """
        Based on this information, provide a concise but informative profile of the user
        that could help determine which new emails would be important to them.
        Focus on patterns and preferences rather than specific details.
        """
        
        # Call Azure OpenAI
        response = ai_scorer.client.chat.completions.create(
            model=ai_scorer.deployment_name,
            messages=[
                {"role": "system", "content": "You are an expert at analyzing email patterns and creating user profiles."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000
        )
        
        profile_text = response.choices[0].message.content
        return profile_text
        
    except Exception as e:
        logger.error(f"Error generating user profile: {str(e)}", exc_info=True)
        return None

@app.route('/reset_training_status', methods=['POST'])
@login_required
def reset_training_status():
    user_email = session.get('user_email')
    
    # Reset training status to 'none'
    user_manager.update_user(user_email, {
        'ai_settings.profile.training_status': 'none'
    })
    
    return jsonify({'status': 'success'})

@app.route('/submit_rating', methods=['POST'])
def submit_rating():
    if 'user_email' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
        
    data = request.json
    message_id = data.get('message_id')
    user_rating = data.get('user_rating')
    
    if not message_id or not user_rating:
        return jsonify({'status': 'error', 'message': 'Missing required fields'})
    
    user_email = session['user_email']
    target_email = None
    
    # Try to find email in storage
    all_emails = email_storage.get_all_emails()
    for email in all_emails:
        if email.get('message_id') == message_id:
            target_email = email
            break
    
    # If not in storage, try to get it from Gmail API
    if not target_email and gmail_handler.is_authenticated():
        try:
            email_data = gmail_handler.get_email_data(message_id)
            if email_data:
                target_email = email_data
                email_storage.add_email(email_data)
        except Exception as e:
            logger.error(f"Error fetching email for rating: {str(e)}")
    
    if not target_email:
        return jsonify({'status': 'error', 'message': 'Email not found'})
    
    # Get the email, AI score, and user's new score
    email_data = target_email
    ai_score = target_email.get('importance', {}).get('score', 5)
    user_score = int(user_rating)
    
    # Get current user profile text
    user_data = user_manager.get_user(user_email)
    current_profile = user_data.get('ai_settings', {}).get('profile', {}).get('profile_text', '')
    
    # Update profile with the new rating information
    ai_scorer = AIScorer(
        os.getenv('AZURE_OPENAI_KEY'),
        os.getenv('AZURE_OPENAI_ENDPOINT')
    )
    
    updated_profile = ai_scorer.update_user_profile_with_rating(
        email_data, 
        ai_score, 
        user_score, 
        current_profile
    )
    
    # Save the updated profile
    user_manager.update_user(user_email, {
        'ai_settings': {
            'profile': {
                'profile_text': updated_profile,
                'training_status': 'completed'  # Ensure it's marked as completed
            },
            'selected_model': 'enhanced'  # Automatically select enhanced model
        }
    })
    
    # Extract AI score
    ai_score = target_email.get('importance', {}).get('score', 5)
    
    # Calculate difference
    difference = int(user_rating) - ai_score
    
    # Store rating in user data
    try:
        user_data = user_manager.get_user(user_email) or {}
        
        if 'rating_patterns' not in user_data:
            user_data['rating_patterns'] = {
                'total_ratings': 0,
                'avg_difference': 0,
                'ratings': []
            }
        
        patterns = user_data['rating_patterns']
        patterns['total_ratings'] += 1
        
        # Update average difference
        if patterns['total_ratings'] > 1:
            total_diff = (patterns['avg_difference'] * (patterns['total_ratings'] - 1)) + difference
            patterns['avg_difference'] = total_diff / patterns['total_ratings']
        else:
            patterns['avg_difference'] = difference
        
        # Add this specific rating
        patterns['ratings'].append({
            'message_id': message_id,
            'subject': target_email.get('subject', 'No Subject'),
            'ai_score': ai_score,
            'user_score': int(user_rating),
            'difference': difference,
            'timestamp': datetime.now().isoformat()
        })
        
        # Save updated user data
        user_manager.update_user(user_email, {'rating_patterns': patterns})
        
        return jsonify({
            'status': 'success', 
            'difference': difference,
            'ai_score': ai_score,
            'message': 'Rating saved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error saving rating: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Failed to save rating: {str(e)}'})

if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    
    # Print clickable links with high visibility
    print("\n")
    print("=" * 80)
    print("=" * 80)
    print("")
    print("  🌐  🌐  🌐  EmailFlow SERVER IS RUNNING  🌐  🌐  🌐")
    print("")
    print("  👉 CLICK THESE LINKS TO ACCESS THE APPLICATION:")
    print("")
    print("     Local:   http://127.0.0.1:5000")
    print("     Network: http://172.26.65.12:5000")
    print("")
    print("=" * 80)
    print("=" * 80)
    print("\n")
    
    # Start the background thread after printing the links
    # Only start if not already running
    if not email_checker_running:
        email_checker_thread.start()
        email_checker_running = True
    
    try:
        socketio.run(app, debug=True, port=5000, host='0.0.0.0', allow_unsafe_werkzeug=True)
    finally:
        # Make sure the thread is properly terminated when the app exits
        if email_checker_thread and email_checker_thread.is_alive():
            logger.info("Shutting down background email checker...") 