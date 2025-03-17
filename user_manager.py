from firebase_admin import firestore
from firebase_config import db

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