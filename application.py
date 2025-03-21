from flask import Flask, request, jsonify
from flask import session
from datetime import datetime



#ignore this file its for testing

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello from Azure!'

@app.route('/submit_rating', methods=['POST'])
def submit_rating():
    if 'user_email' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
        
    data = request.json
    message_id = data.get('message_id')
    user_rating = data.get('user_rating')
    
    if not message_id or not user_rating:
        return jsonify({'status': 'error', 'message': 'Missing required fields'})
    
    # Get the email details
    user_email = session['user_email']
    
    # Placeholder for getting email data from Gmail API or your storage
    # This would need to be adapted based on how you're storing email information
    all_emails = email_storage.get_all_emails()
    target_email = None
    
    for email in all_emails:
        if email.get('message_id') == message_id:
            target_email = email
            break
    
    # If email not found in storage, try to fetch it
    if not target_email and gmail_handler.is_authenticated():
        # Attempt to get the email details from Gmail API
        email_detail = gmail_handler.get_message_detail(message_id)
        if email_detail:
            target_email = email_detail
    
    if not target_email:
        return jsonify({'status': 'error', 'message': 'Email not found'})
    
    # Extract or get AI score
    ai_score = target_email.get('importance', {}).get('score', 5)
    
    # Calculate difference
    difference = user_rating - ai_score
    
    # Store the rating in Firebase
    try:
        # Get existing user data
        user_data = user_manager.get_user(user_email) or {}
        
        # Initialize rating patterns if needed
        if 'rating_patterns' not in user_data:
            user_data['rating_patterns'] = {
                'total_ratings': 0,
                'avg_difference': 0,
                'ratings': []
            }
        
        patterns = user_data['rating_patterns']
        
        # Update statistics
        patterns['total_ratings'] += 1
        total_diff = (patterns['avg_difference'] * (patterns['total_ratings'] - 1)) + difference
        patterns['avg_difference'] = total_diff / patterns['total_ratings']
        
        # Add this rating
        patterns['ratings'].append({
            'message_id': message_id,
            'subject': target_email.get('subject', 'No Subject'),
            'ai_score': ai_score,
            'user_score': user_rating,
            'difference': difference,
            'timestamp': datetime.now().isoformat()
        })
        
        # Update user data in Firebase
        user_manager.update_user(user_email, {'rating_patterns': patterns})
        
        return jsonify({
            'status': 'success', 
            'difference': difference,
            'ai_score': ai_score,
            'message': 'Rating saved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error saving rating: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to save rating: {str(e)}'
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)