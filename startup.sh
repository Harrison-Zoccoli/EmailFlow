#!/bin/bash
cd /home/site/wwwroot
pip install --upgrade pip
pip install -r requirements.txt
gunicorn --bind=0.0.0.0 --timeout 600 --worker-class eventlet --log-level debug application:app 