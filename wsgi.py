# WSGI entry point for Vercel deployment
from app import app

# Vercel expects the application to be available as `application`
application = app

if __name__ == "__main__":
    app.run()