from firebase_admin import firestore
from firebase_config import db
import logging

logger = logging.getLogger(__name__)

class UserManager:
    def __init__(self):
        self.users_ref = db.collection('Users')

    def create_user(self, email, user_data=None):
        """Create or update user document"""
        if user_data is None:
            user_data = {
                'email': email,
                'name': '',
                'phonenumber': '',
                'created_at': firestore.SERVER_TIMESTAMP
            }
        else:
            user_data['created_at'] = firestore.SERVER_TIMESTAMP
        
        self.users_ref.document(email).set(user_data, merge=True)
        return user_data

    def get_user(self, email):
        """Get user data"""
        doc = self.users_ref.document(email).get()
        return doc.to_dict() if doc.exists else None

    def update_user(self, email, data):
        """Update user data in Firebase"""
        try:
            user_ref = self.users_ref.document(email)
            # If updating token, merge with existing data
            if 'gmail_token' in data:
                user_ref.set({'gmail_token': data['gmail_token']}, merge=True)
            else:
                user_ref.update(data)
        except Exception as e:
            print(f"Error updating user: {str(e)}")

    def user_exists(self, email):
        """Check if a user exists in the database with a complete profile"""
        try:
            # Get user data from Firestore
            doc = self.users_ref.document(email).get()
            
            if not doc.exists:
                logger.info(f"User {email} does not exist in database")
                return False
            
            user_data = doc.to_dict()
            
            # Check if user has a complete profile
            has_complete_profile = (
                user_data and 
                user_data.get('name') and 
                user_data.get('phonenumber')
            )
            
            logger.info(f"User {email} exists with complete profile: {has_complete_profile}")
            return has_complete_profile
            
        except Exception as e:
            logger.error(f"Error checking if user exists: {str(e)}")
            return False 

    def get_all_users(self):
        """Get all users from the database"""
        try:
            users = []
            docs = self.users_ref.stream()
            for doc in docs:
                user_data = doc.to_dict()
                users.append(user_data)
            return users
        except Exception as e:
            logger.error(f"Error getting all users: {str(e)}")
            return [] 