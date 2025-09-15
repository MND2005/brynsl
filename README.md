# Flask Application for Vercel Deployment

## Deployment to Vercel

This application is configured for deployment to Vercel. Follow these steps:

1. Create a new project on Vercel
2. Connect your GitHub repository
3. Set the following environment variables in your Vercel project settings:
   - `OPENROUTER_API_KEY` - Your OpenRouter API key
   - `FIREBASE_PROJECT_ID` - Your Firebase project ID
   - `FIREBASE_PRIVATE_KEY_ID` - Your Firebase private key ID
   - `FIREBASE_PRIVATE_KEY` - Your Firebase private key (with proper newline characters)
   - `FIREBASE_CLIENT_EMAIL` - Your Firebase client email
   - `FIREBASE_CLIENT_ID` - Your Firebase client ID
   - `FIREBASE_DATABASE_URL` - Your Firebase database URL
   - `FIREBASE_API_KEY` - Your Firebase API key
   - `MAILTRAP_API_TOKEN` - Your Mailtrap API token
   - `SITE_URL` - Your Vercel deployment URL (e.g., https://your-app.vercel.app)

4. Deploy the application

## Environment Variables

See [.env.example](.env.example) for a complete list of required environment variables.

## Requirements

- Python 3.9+
- All dependencies listed in [requirements.txt](requirements.txt)

## Local Development

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables (copy [.env.example](.env.example) to [.env](.env) and fill in values)

4. Run the application:
   ```bash
   python app.py
   ```