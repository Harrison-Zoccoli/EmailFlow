from openai import AzureOpenAI
import json

class AIScorer:
    def __init__(self, api_key, endpoint, deployment_name):
        print(f"Initializing AIScorer with deployment: {deployment_name}")
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-15-preview",
            azure_endpoint=endpoint
        )
        self.deployment_name = deployment_name

    def score_email(self, email_data):
        """Score email importance from 1-10"""
        print(f"⚠️ Using deployment: {self.deployment_name}")
        
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

        Return only the numeric score and a brief explanation in JSON format like:
        {{"score": 7, "explanation": "Urgent work matter requiring immediate attention"}}
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