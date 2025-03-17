from datetime import datetime

class EmailStorage:
    def __init__(self):
        self.emails = []
    
    def add_email(self, email_data):
        email_data['stored_at'] = datetime.now().isoformat()
        self.emails.append(email_data)
    
    def get_all_emails(self):
        return self.emails

    def clear_emails(self):
        """Clear all stored emails"""
        self.emails = []