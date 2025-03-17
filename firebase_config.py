import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase Admin with your service account key
cred = credentials.Certificate('firebase-key.json')  # Update this path
firebase_admin.initialize_app(cred)

# Get Firestore client
db = firestore.client() 