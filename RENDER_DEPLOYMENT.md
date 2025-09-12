# Render Deployment Guide

## Issue Fixed
- Removed unused `mailersend` import and dependency
- Your app uses Mailtrap API directly with `requests` library (which is correct)

## Environment Variables Required on Render

Add these environment variables in your Render dashboard:

### OpenRouter Configuration
```
OPENROUTER_API_KEY=your_openrouter_api_key_here
SITE_URL=https://your-render-app-url.onrender.com
SITE_NAME=BrynSL AI Assistant
```

### Firebase Configuration
```
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_PRIVATE_KEY_ID=your_firebase_private_key_id
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email
FIREBASE_CLIENT_ID=your_firebase_client_id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_X509_CERT_URL=your_firebase_client_cert_url
FIREBASE_DATABASE_URL=your_firebase_database_url
FIREBASE_API_KEY=your_firebase_api_key
```

### Mailtrap Configuration
```
MAILTRAP_API_TOKEN=your_mailtrap_api_token
MAILTRAP_API_URL=https://send.api.mailtrap.io/api/send
```

### Application Configuration
```
PORT=10000
```

## Render Configuration

### Build Command
```
pip install -r requirements.txt
```

### Start Command
```
python app.py
```

### Runtime
- Python 3.11.x

## Important Notes

1. **PORT Configuration**: Render assigns a port automatically, make sure your app.py uses the PORT environment variable:
   ```python
   if __name__ == '__main__':
       port = int(os.getenv("PORT", 5000))
       app.run(host='0.0.0.0', port=port, debug=False)  # Set debug=False for production
   ```

2. **FIREBASE_PRIVATE_KEY**: When setting this in Render, make sure to include the actual newlines. If you face issues, try replacing `\\n` with actual line breaks.

3. **HTTPS**: Render provides HTTPS by default, so your app will be secure.

4. **Site URL**: Update SITE_URL to your actual Render app URL once deployed.

## Deployment Steps

1. Push your updated code to GitHub
2. Connect your GitHub repo to Render
3. Set all environment variables in Render dashboard
4. Deploy!

Your app should now deploy successfully on Render!