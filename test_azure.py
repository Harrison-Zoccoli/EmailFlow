from openai import AzureOpenAI
import os

# Get values from .env file
api_key = "DoOzggQ4kLh4CmF8P5YFqEbCefnfYy9Qe1lBAw4jOcD3AyJjK8rLJQQJ99BCACYeBjFXJ3w3AAABACOGCYKL"
api_endpoint = "https://mailflow-openai.openai.azure.com/"
deployment = "emailflow-openai"  # Your deployment name

print(f"Attempting to connect to Azure OpenAI...")
print(f"Endpoint: {api_endpoint}")
print(f"Deployment: {deployment}")
print(f"Key (first 10 chars): {api_key[:10]}...")

try:
    # Create client with full debugging
    client = AzureOpenAI(
        api_key=api_key,
        api_version="2024-02-15-preview",
        azure_endpoint=api_endpoint
    )
    
    # Test basic completion
    response = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": "Say hello"}],
        max_tokens=10
    )
    
    print("\nSUCCESS! Response:")
    print(response.choices[0].message.content)
    
except Exception as e:
    print("\nERROR connecting to Azure OpenAI:")
    print(str(e))
    
    # Additional debugging suggestions
    if "401" in str(e):
        print("\nTroubleshooting 401 errors:")
        print("1. Verify your API key is correct")
        print("2. Check if deployment name exactly matches what's in Azure Portal")
        print("3. Ensure endpoint URL is correct and ends with a slash")
        print("4. Consider regenerating your API key in Azure Portal")
    
    elif "not found" in str(e).lower():
        print("\nDeployment not found. Check these:")
        print("1. Deployment name must match exactly (case sensitive)")
        print("2. Deployment may still be provisioning") 