# Vercel Deployment Guide

## Issue Fixed
The "sh: line 1: pip: command not found" error occurs because Vercel's Python environment doesn't always have pip in the PATH or available in the expected location.

## Solution Implemented

### 1. Created vercel.json
Configured the Vercel deployment with:
- Python 3.9 runtime
- Custom build command using our script
- Proper routing to our Flask app

### 2. Created vercel_build.sh
A robust build script that:
- Checks for Python and pip availability
- Uses environment variables for commands when available
- Upgrades pip before installing dependencies
- Installs all requirements from requirements.txt

### 3. Created wsgi.py
WSGI entry point for Vercel deployment that exposes the Flask app as `application`.

### 4. Updated app.py
Made sure the Flask app is properly exposed for Vercel deployment.

### 5. Added runtime.txt
Specifies Python 3.9 for the Vercel environment.

### 6. Created .env.example
Documents all required environment variables.

### 7. Created README.md
Provides deployment instructions for Vercel.

## Environment Variables Required on Vercel

Add these environment variables in your Vercel project settings:

### OpenRouter Configuration
```
OPENROUTER_API_KEY=your_openrouter_api_key_here
SITE_URL=https://your-vercel-app.vercel.app
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
SECRET_KEY=your_secret_key_here
```

## Vercel Configuration

### Build Command
```
bash vercel_build.sh
```

### Start Command
```
python wsgi.py
```

### Runtime
- Python 3.9

## Deployment Steps

1. Push your updated code to GitHub
2. Connect your GitHub repo to Vercel
3. Set all environment variables in Vercel dashboard
4. Deploy!

Your app should now deploy successfully on Vercel!