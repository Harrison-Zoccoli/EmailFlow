# This is the entry point for Azure
from app import app, socketio

if __name__ == '__main__':
    socketio.run(app) 