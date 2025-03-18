import requests
import logging
import json
import traceback

# Set up logging
logger = logging.getLogger(__name__)

class SMSHandler:
    def __init__(self, api_key="0f698c04ac900cffdf542c69f375c5bde7bc0037z6UidsASMYaIRjzI5kwtY3f3m"):
        """Initialize SMS Handler with API key
        
        Args:
            api_key (str): TextBelt API key. Default is your purchased API key
        """
        self.api_key = api_key
        self.api_url = "https://textbelt.com/text"
        logger.info("SMS Handler initialized with API key")
    
    def send_notification(self, phone_number, message):
        """Send SMS notification using TextBelt API
        
        Args:
            phone_number (str): Recipient's phone number (e.g., "1234567890")
            message (str): Message content
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Attempting to send SMS to {phone_number}")
            logger.info(f"Message content: {message}")
            
            # Validate phone number format
            if not phone_number or not isinstance(phone_number, str):
                logger.error(f"Invalid phone number: {phone_number}")
                return False
                
            # Validate message
            if not message or not isinstance(message, str):
                logger.error(f"Invalid message: {message}")
                return False
            
            # Prepare the payload
            payload = {
                'phone': phone_number,
                'message': message,
                'key': self.api_key
            }
            
            logger.info(f"Sending request to TextBelt API: {self.api_url}")
            
            # Send the request
            response = requests.post(self.api_url, data=payload)
            
            # Log the raw response
            logger.info(f"TextBelt API response status code: {response.status_code}")
            logger.info(f"TextBelt API response content: {response.text}")
            
            # Parse the JSON response
            try:
                result = response.json()
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON response: {response.text}")
                return False
            
            # Log the result
            if result.get('success'):
                logger.info(f"SMS sent successfully to {phone_number}")
                logger.info(f"TextBelt response: {result}")
                logger.info(f"TextBelt textId: {result.get('textId')}")
                return True
            else:
                logger.error(f"Failed to send SMS: {result.get('error')}")
                logger.error(f"Full error response: {result}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error sending SMS: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending SMS: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def send_high_priority_email_alert(self, phone_number, sender, subject, importance_score):
        """Send notification about high priority email
        
        Args:
            phone_number (str): Recipient's phone number
            sender (str): Email sender
            subject (str): Email subject
            importance_score (int): Email importance score
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Preparing high priority email alert for {phone_number}")
            logger.info(f"Email details - From: {sender}, Subject: {subject}, Score: {importance_score}")
            
            # Sanitize sender information to avoid URL detection
            # Extract just the name if possible, or remove email address format
            sanitized_sender = sender
            if '<' in sender and '>' in sender:
                # Format is typically "Name <email@example.com>"
                sanitized_sender = sender.split('<')[0].strip()
            elif '@' in sender:
                # Just an email address without name
                sanitized_sender = sender.split('@')[0]  # Just use the username part
            
            logger.info(f"Sanitized sender: {sanitized_sender}")
            
            # Format the message without any potential URL-like content
            message = f"HIGH PRIORITY EMAIL: '{subject}' from {sanitized_sender}. Importance: {importance_score}/10"
            
            # Send the notification
            result = self.send_notification_with_fallback(phone_number, message)
            
            if result:
                logger.info(f"Successfully sent high priority email alert to {phone_number}")
            else:
                logger.error(f"Failed to send high priority email alert to {phone_number}")
                
            return result
            
        except Exception as e:
            logger.error(f"Error in send_high_priority_email_alert: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def send_notification_with_fallback(self, phone_number, message):
        """Send SMS with fallback to simpler message if first attempt fails
        
        Args:
            phone_number (str): Recipient's phone number
            message (str): Message content
            
        Returns:
            bool: True if successful, False otherwise
        """
        # First attempt with original message
        result = self.send_notification(phone_number, message)
        
        if result:
            return True
        
        # If failed, try with a simplified message
        logger.info("First SMS attempt failed, trying with simplified message")
        simplified_message = "You have received a high priority email. Please check your inbox."
        
        return self.send_notification(phone_number, simplified_message) 