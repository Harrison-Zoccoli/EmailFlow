#!/bin/bash
echo "Starting pip installation at $(date)" >> /home/LogFiles/pip_install.log

# Find the Python versions available
echo "Available Python installations:" >> /home/LogFiles/pip_install.log
find /opt/python -name python* -type f -executable | grep -v config >> /home/LogFiles/pip_install.log

# Try using Python 3.9 from the App Service environment which should have pip
PYTHON_PATH=/opt/python/3.9.21/bin/python
echo "Using Python at: $PYTHON_PATH" >> /home/LogFiles/pip_install.log

# Verify Python version
$PYTHON_PATH --version >> /home/LogFiles/pip_install.log 2>&1

# Check if pip is available with this Python
$PYTHON_PATH -m pip --version >> /home/LogFiles/pip_install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Pip not found, installing..." >> /home/LogFiles/pip_install.log
    curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    $PYTHON_PATH /tmp/get-pip.py >> /home/LogFiles/pip_install.log 2>&1
else
    echo "Pip is already installed" >> /home/LogFiles/pip_install.log
fi

# Install required packages using the correct Python
$PYTHON_PATH -m pip install -r requirements.txt >> /home/LogFiles/pip_install.log 2>&1

echo "Pip installation and package installation completed at $(date)" >> /home/LogFiles/pip_install.log 