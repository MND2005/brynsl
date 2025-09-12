# Migration Guide: From Gemini to Llama 4 Maverick via OpenRouter

## Changes Made

### 1. Dependencies Updated
- Replaced `google-generativeai>=0.8.0` with `openai>=1.0.0` in requirements.txt
- Added support for OpenRouter API client

### 2. Environment Variables Required
Create a `.env` file in your project root with the following variables:

```env
# Replace with your actual OpenRouter API key
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Optional: Your site details for OpenRouter rankings
SITE_URL=https://yoursite.com
SITE_NAME=Your App Name

# Keep all your existing Firebase and Mailtrap variables unchanged
FIREBASE_PROJECT_ID=your_existing_value
FIREBASE_PRIVATE_KEY_ID=your_existing_value
# ... (copy all other Firebase and Mailtrap variables from your current setup)
```

### 3. API Integration Changes
- Removed multiple Gemini API keys support
- Simplified to single OpenRouter API key for Llama 4 Maverick access
- Updated to use OpenRouter's specific headers (HTTP-Referer, X-Title)
- Uses direct requests.post() calls to properly include OpenRouter headers
- Model name set to "meta-llama/llama-4-maverick:free"
- Updated image processing to use base64 encoding for vision capabilities
- Modified prompt structure to work with OpenRouter's chat completions format

### 4. Model Features
- Supports both text and image inputs via OpenRouter
- Maintains multilingual support (Sinhala, English, etc.)
- Uses OpenRouter's chat completions API format
- Configurable model parameters (temperature, max_tokens)
- Free tier access to Llama 4 Maverick

## Next Steps

1. **Get OpenRouter API Key:**
   - Sign up at https://openrouter.ai/
   - Get your API key from the dashboard
   - Note: The free tier provides access to meta-llama/llama-4-maverick:free

2. **Install new dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   - Create a `.env` file based on `.env.example`
   - Add your OpenRouter API key
   - Optionally add your site URL and name for OpenRouter rankings

4. **Test the integration:**
   - Start your Flask application
   - Test both text and image-based questions
   - Verify multilingual responses work correctly

## Model Configuration Notes

- **Model Name**: "meta-llama/llama-4-maverick:free" (free tier)
- **Base URL**: "https://openrouter.ai/api/v1"
- **Temperature**: Set to 0.7 for balanced creativity
- **Max Tokens**: Set to 1500 - adjust based on your needs
- **Headers**: Includes OpenRouter-specific headers for site attribution

## OpenRouter Benefits

- **Free Access**: meta-llama/llama-4-maverick:free model available
- **Single API Key**: Simplified configuration compared to multiple Gemini keys
- **Vision Support**: Full support for image analysis
- **Reliability**: Managed infrastructure with good uptime
- **Rankings**: Optional site attribution for OpenRouter rankings

## Troubleshooting

If you encounter issues:
1. Verify your OpenRouter API key is correct and active
2. Check that you have sufficient credits/quota on OpenRouter
3. Ensure the model name "meta-llama/llama-4-maverick:free" is available
4. Review the logs for specific error messages from OpenRouter API
5. Check OpenRouter status page for any service issues

The migration maintains all existing functionality while switching to OpenRouter's Llama 4 Maverick backend with improved reliability and free tier access.