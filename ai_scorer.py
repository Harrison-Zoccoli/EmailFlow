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

    def score_email_importance(self, email_data, selected_model='standard', user_profile=None, rating_patterns=None):
        """Score email importance using AI with rating adjustment"""
        try:
            # Base prompt for standard model
            prompt = f"""
            Please analyze this email and rate its importance on a scale of 1-10, where:
            1-3: Low importance (promotional, newsletters, etc.)
            4-6: Medium importance (regular updates, non-urgent requests)
            7-10: High importance (urgent, time-sensitive, from important contacts)
            
            Email:
            From: {email_data.get('sender', 'Unknown')}
            Subject: {email_data.get('subject', 'No Subject')}
            Content: {email_data.get('snippet', 'No content')}
            
            Provide your rating as a JSON object with 'score' (number 1-10) and 'explanation' (string).
            """
            
            # Enhanced model with user profile
            if selected_model == 'enhanced' and user_profile:
                prompt = f"""
                Based on this user's profile and preferences:
                
                {user_profile}
                
                Please analyze this email and rate its importance on a scale of 1-10, where:
                1-3: Low importance (promotional, newsletters, etc.)
                4-6: Medium importance (regular updates, non-urgent requests)
                7-10: High importance (urgent, time-sensitive, from important contacts)
                
                Email:
                From: {email_data.get('sender', 'Unknown')}
                Subject: {email_data.get('subject', 'No Subject')}
                Content: {email_data.get('snippet', 'No content')}
                
                Provide your rating as a JSON object with 'score' (number 1-10) and 'explanation' (string).
                """
            
            # Call the API
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
                    
                    # Get result from API
                    result = {"score": score, "explanation": explanation}
                    
                    # Apply rating pattern adjustment
                    if rating_patterns and 'avg_difference' in rating_patterns:
                        # Adjust score based on user's historical rating patterns
                        avg_difference = rating_patterns.get('avg_difference', 0)
                        adjusted_score = min(10, max(1, result['score'] + avg_difference))
                        
                        # Update explanation
                        result['original_score'] = result['score']
                        result['score'] = adjusted_score
                        result['explanation'] += f" (Score adjusted by {avg_difference} based on your rating history)"
                    
                    return result
                else:
                    # If no score found at beginning, look for it in the text
                    score_match = re.search(r'(\d+)/10', response_text)
                    if score_match:
                        score = int(score_match.group(1))
                        return {"score": score, "explanation": response_text}
                    else:
                        # Default to middle score if no score found
                        return {"score": 5, "explanation": response_text}
            except Exception as e:
                print(f"❌ Error parsing AI response: {str(e)}")
                print(f"Response was: {response_text}")
                return {"score": 5, "explanation": "Error processing score"}
            
        except Exception as e:
            print(f"❌ API call failed with deployment: {self.deployment_name}")
            print(f"Error: {str(e)}")
            return {"score": 5, "explanation": "Error processing score"}

    def score_email(self, email_data, user_profile=None, rating_patterns=None):
        """Score email importance from 1-10 with optional user profile and rating patterns"""
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
            
            # Add more robust JSON parsing with fallback
            content = response.choices[0].message.content.strip()
            try:
                # First try to parse as-is
                result = json.loads(content)
            except json.JSONDecodeError:
                # If that fails, try to extract JSON using regex
                import re
                json_match = re.search(r'({.*})', content, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group(1))
                    except:
                        # If regex extraction fails, create a default result
                        # but try to extract a score if possible
                        score_match = re.search(r'(\d+)(/10)?', content)
                        score = int(score_match.group(1)) if score_match else 5
                        result = {
                            "score": score,
                            "explanation": content
                        }
                else:
                    # Default if no JSON-like structure is found
                    result = {
                        "score": 5,
                        "explanation": content
                    }
            
            # Validate the structure of the result
            if not isinstance(result, dict) or 'score' not in result or 'explanation' not in result:
                # Create a valid result structure
                if isinstance(result, dict) and 'score' in result:
                    score = result['score']
                    explanation = result.get('explanation', 'No explanation provided')
                elif isinstance(result, int) or (isinstance(result, str) and result.isdigit()):
                    score = int(result)
                    explanation = 'Score derived from AI analysis'
                else:
                    score = 5
                    explanation = 'Invalid response format, using default score'
                
                result = {
                    "score": score,
                    "explanation": explanation
                }
            
            # At the end, apply rating adjustment if needed
            if rating_patterns and 'avg_difference' in rating_patterns:
                # Adjust score based on user's historical rating patterns
                avg_difference = rating_patterns.get('avg_difference', 0)
                adjusted_score = min(10, max(1, result['score'] + avg_difference))
                
                # Update explanation
                result['original_score'] = result['score']
                result['score'] = adjusted_score
                result['explanation'] += f" (Score adjusted by {avg_difference} based on rating history)"
            
            return result
            
        except Exception as e:
            print(f"❌ API call failed with deployment: {self.deployment_name}")
            print(f"Error: {str(e)}")
            return {"score": 5, "explanation": "Error processing score"} 

    def update_user_profile_with_rating(self, email_data, ai_score, user_score, current_profile):
        """Update user profile based on a new rating"""
        
        # Construct prompt for GPT to analyze the rating pattern
        prompt = f"""
        I'm going to show you:
        1. A user's current preference profile
        2. An email the user just rated
        3. How the AI scored it vs. how the user scored it
        
        Current User Profile:
        {current_profile if current_profile else "No profile exists yet. Create an initial profile based on this rating."}
        
        Email Information:
        - Sender: {email_data.get('sender', 'Unknown')}
        - Subject: {email_data.get('subject', 'No Subject')}
        - Content: {email_data.get('snippet', 'No content snippet available')}
        
        AI Score: {ai_score}/10
        User Score: {user_score}/10
        
        Based on this new rating information, update the user profile to better reflect their preferences.
        If this is their first rating, create a profile from scratch.
        If this contradicts previous patterns in the profile, update accordingly.
        If this reinforces existing patterns, strengthen those observations.
        
        Based on this information, provide a concise but informative profile of the user that could help determine which new emails would be important to them. Focus on patterns and preferences rather than specific details.
        """
        
        # Call the API to get an updated profile
        response = self.client.chat.completions.create(
            model=self.deployment_name,
            messages=[
                {"role": "system", "content": "You are an expert at analyzing user preferences and creating detailed profiles."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500
        )
        
        # Extract the updated profile
        updated_profile = response.choices[0].message.content.strip()
        
        return updated_profile 