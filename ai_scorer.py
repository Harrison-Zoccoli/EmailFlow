from openai import AzureOpenAI
import json
import os
#scores the emails
class AIScorer:
    def __init__(self, api_key, endpoint):
        print(f"Initializing AIScorer with deployment: {os.getenv('AZURE_OPENAI_DEPLOYMENT')}")
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-15-preview",
            azure_endpoint=endpoint
        )
        self.deployment_name = os.getenv('AZURE_OPENAI_DEPLOYMENT')

    def score_email_importance(self, email_data, selected_model='standard', user_profile=None):
        """Score email importance using AI"""
        try:
            # Base prompt for standard model
            prompt = f"""
            Please analyze this email and rate its importance on a scale of 1-10, where:
            1-3: Low importance (promotional, newsletters, etc.)
            4-6: Medium importance (regular updates, non-urgent requests)
            7-10: High importance (urgent, time-sensitive, from important contacts)
            
            Email details:
            From: {email_data.get('from', 'Unknown')}
            Subject: {email_data.get('subject', 'No Subject')}
            Date: {email_data.get('date', '')}
            Content: {email_data.get('snippet', '')}
            
            Provide your rating as a number followed by a brief explanation.
            """
            
            # Add user profile context for enhanced model
            if selected_model == 'enhanced' and user_profile:
                prompt += f"""
                
                User profile information:
                {user_profile}
                
                Based on both the email content AND the user's profile information above, 
                rate the importance of this email to THIS SPECIFIC USER.
                
                In your explanation, explicitly mention how aspects of the user's profile 
                influenced your rating (e.g., "Based on your profile, you typically...").
                """
            
            # Call the AI model
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are an expert at analyzing email importance."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150
            )
            
            # Extract the response text
            response_text = response.choices[0].message.content.strip()
            
            # Parse the response to get the score and explanation
            try:
                # Look for a number at the beginning of the response
                import re
                score_match = re.search(r'^(\d+(/\d+)?)', response_text)
                if score_match:
                    score_text = score_match.group(1)
                    if '/' in score_text:
                        score = int(score_text.split('/')[0])
                    else:
                        score = int(score_text)
                    
                    # Get the explanation (everything after the score)
                    explanation = response_text[score_match.end():].strip()
                    if explanation.startswith(':'):
                        explanation = explanation[1:].strip()
                    
                    return score, explanation
                else:
                    # If no score found at beginning, look for it in the text
                    score_match = re.search(r'(\d+)/10', response_text)
                    if score_match:
                        score = int(score_match.group(1))
                        return score, response_text
                    else:
                        # Default to middle score if no score found
                        return 5, response_text
            except Exception as e:
                print(f"❌ Error parsing AI response: {str(e)}")
                print(f"Response was: {response_text}")
                return 5, response_text
            
        except Exception as e:
            print(f"❌ API call failed with deployment: {self.deployment_name}")
            print(f"Error: {str(e)}")
            return 5, "Medium importance (default score, error occurred)"

    def score_email(self, email_data, user_profile=None):
        """Score email importance from 1-10 with optional user profile context"""
        print(f"⚠️ Using deployment: {self.deployment_name}")
        
        # Base prompt
        prompt = f"""
        Score this email's importance from 1-10 (10 being most important).
        Consider:
        - Sender: {email_data['sender']}
        - Subject: {email_data['subject']}
        - Content: {email_data['snippet']}

        Factors to consider:
        - Urgency of the matter
        - Sender's relationship (work, personal, automated)
        - Action required
        - Time sensitivity
        """
        
        # Add user profile context if available
        if user_profile:
            prompt += f"""
            
            User Profile Context:
            {user_profile}
            
            Use this profile information to personalize the importance score.
            Consider how this email relates to the user's status, relationships,
            interests, and patterns identified in their profile.
            """
        
        prompt += """
        Return only the numeric score and a brief explanation in JSON format like:
        {"score": 7, "explanation": "Urgent work matter requiring immediate attention"}
        """

        try:
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are an email importance analyzer. Score emails from 1-10."},
                    {"role": "user", "content": prompt}
                ]
            )
            print(f"✅ API call successful with deployment: {self.deployment_name}")
            result = json.loads(response.choices[0].message.content)
            return result
        except Exception as e:
            print(f"❌ API call failed with deployment: {self.deployment_name}")
            print(f"Error: {str(e)}")
            return {"score": 5, "explanation": "Error processing score"} 