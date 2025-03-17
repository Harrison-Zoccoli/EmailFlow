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

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for sessions
socketio = SocketIO(app)
email_storage = EmailStorage()
gmail_handler = None
email_thread = None  # Add this to track the thread
user_manager = UserManager()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    global gmail_handler
    try:
        logger.info("Starting Google login process")
        gmail_handler = GmailHandler()
        user_email = gmail_handler.get_user_email()
        logger.info(f"User authenticated with email: {user_email}")
        session['user_email'] = user_email
        
        # Check if user exists in Firebase
        user_data = user_manager.get_user(user_email)
        logger.info(f"User data from Firebase: {user_data}")
        
        if user_data and user_data.get('name') and user_data.get('phonenumber'):
            logger.info("User has complete profile, redirecting to monitor")
            return redirect(url_for('monitor'))
        else:
            logger.info("User needs to complete profile, redirecting to signup")
            return redirect(url_for('signup'))
            
    except Exception as e:
        logger.error(f"Error during login: {str(e)}", exc_info=True)
        session['error'] = str(e)
        return redirect(url_for('login'))

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
    return render_template('monitor.html')

@app.route('/emails')
@login_required
def get_emails():
    return jsonify(email_storage.get_all_emails())

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
    
    # Start email checking thread after profile completion
    if email_thread is None:
        email_thread = threading.Thread(target=check_new_emails, daemon=True)
        email_thread.start()
    
    return redirect(url_for('monitor'))

def check_new_emails():
    while True:
        try:
            if gmail_handler is not None:
                logger.info("Checking for new emails...")
                new_messages = gmail_handler.check_new_emails()
                logger.info(f"Found {len(new_messages)} new messages")
                for msg in new_messages:
                    email_storage.add_email(msg)
                    socketio.emit('new_email', msg)
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error checking emails: {str(e)}", exc_info=True)
            time.sleep(10)

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
    return render_template('unread.html')

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

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000) 