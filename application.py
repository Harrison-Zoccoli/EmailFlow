# This is the entry point for Azure
from app import app, socketio

# Create the WSGI application object
application = app

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8000)