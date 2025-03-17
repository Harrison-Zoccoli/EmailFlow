from openai import AzureOpenAI
import json

class AIScorer:
    def __init__(self, api_key, endpoint, deployment_name):
        self.client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-15-preview",
            azure_endpoint=endpoint
        )
        self.deployment_name = deployment_name

    def score_email(self, email_data):
        """Score email importance from 1-10"""
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

        response = self.client.chat.completions.create(
            model=self.deployment_name,
            messages=[
                {"role": "system", "content": "You are an email importance analyzer. Score emails from 1-10."},
                {"role": "user", "content": prompt}
            ]
        )

        try:
            result = json.loads(response.choices[0].message.content)
            return result
        except:
            return {"score": 5, "explanation": "Error processing score"} 