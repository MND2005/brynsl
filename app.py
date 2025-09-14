from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort, make_response
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort
import firebase_admin
from firebase_admin import credentials, db, initialize_app
import requests
import datetime
from dotenv import load_dotenv
from openai import OpenAI
import os
import tempfile
from functools import wraps
import random
import smtplib
from email.message import EmailMessage
import logging
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.renderPDF import drawToFile
import io



load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.permanent_session_lifetime = datetime.timedelta(days=30)

firebase_cred = {
    "type": "service_account",
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),  # Handle newlines
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
}

cred = credentials.Certificate(firebase_cred)
firebase_admin.initialize_app(cred, {
    'databaseURL': os.getenv("FIREBASE_DATABASE_URL")
})

# Mailtrap API Configuration
MAILTRAP_API_TOKEN = os.getenv("MAILTRAP_API_TOKEN")
MAILTRAP_API_URL = os.getenv("MAILTRAP_API_URL")


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def is_admin(uid):
    """Check if user is admin"""
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()
    return user and user.get('is_admin', False)

def admin_required(f):
    """Decorator to ensure admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login'))
        
        if not is_admin(session['uid']):
            # Option 1: Redirect to login
            # return redirect(url_for('login'))
            
            # Option 2: Show 403 Forbidden
            abort(403, description="Admin access required")
            
        return f(*args, **kwargs)
    return decorated_function

def is_ceo(uid):
    """Check if user is ceo"""
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()
    return user and user.get('is_ceo', False)

def ceo_required(f):
    """Decorator to ensure ceo access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login'))
        
        if not is_admin(session['uid']):
            # Option 1: Redirect to login
            # return redirect(url_for('login'))
            
            # Option 2: Show 403 Forbidden
            abort(403, description="CEO access required")
            
        return f(*args, **kwargs)
    return decorated_function


# Configure Llama 4 Maverick via OpenRouter
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
SITE_URL = os.getenv("SITE_URL", "https://yoursite.com")  # Your site URL for OpenRouter rankings
SITE_NAME = os.getenv("SITE_NAME", "BrynSL AI Assistant")  # Your site name for OpenRouter rankings

# Debug: Check if API key is loaded
if not OPENROUTER_API_KEY:
    logger.error("OPENROUTER_API_KEY environment variable is not set!")
else:
    logger.info(f"OpenRouter API key loaded: {OPENROUTER_API_KEY[:10]}...{OPENROUTER_API_KEY[-4:]}")

# Initialize OpenAI client for OpenRouter
llama_client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1"
)

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")  # from Firebase > Project Settings > General

# Add this near your other Firebase initialization
notifications_ref = db.reference('notifications')
user_notifications_ref = db.reference('user_notifications')
ideas_ref = db.reference('ideas')

# Study Planner Database References
study_events_ref = db.reference('study_events')
study_sessions_ref = db.reference('study_sessions')
subjects_ref = db.reference('subjects')
study_progress_ref = db.reference('study_progress')

# Papers Database Reference
papers_ref = db.reference('papers')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/launch')
def launch():
    return render_template('launch.html')

@app.route('/userguide')
def userguide():
    return render_template('user_guide.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Check if this is an OTP verification request
        if 'otp' in request.form:
            return verify_otp(request)
        
        # Otherwise, handle new signup
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        day = request.form['birthday_day']
        month = request.form['birthday_month']
        year = request.form['birthday_year']
        phone = request.form['phone']
        education_level = request.form['education_level']

        # Validate data (same as before)
        try:
            birthday = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
            datetime.datetime.strptime(birthday, "%Y-%m-%d")
        except ValueError:
            return render_template('error.html', error="Invalid date.")

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_expiry = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")

        # Store in session (temporarily)
        session['temp_user'] = {
            "email": email,
            "password": password,
            "name": name,
            "birthday": birthday,
            "phone": phone,
            "education_level": education_level,
            "otp": otp,
            "otp_expiry": otp_expiry
        }

        # Send OTP via Mailtrap API
        try:
            headers = {
                "Authorization": f"Bearer {MAILTRAP_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "from": {"email": "hello@brynsl.com", "name": "BrynSL"},
                "to": [{"email": email}],
                "subject": "Your OTP Verification Code",
                "text": f"Hello {name},\n\nYour OTP is: {otp}\n\nExpires in 15 minutes.",
                "category": "OTP"
            }
            
            response = requests.post(MAILTRAP_API_URL, headers=headers, json=payload)
            
            if response.status_code != 200:
                session.pop('temp_user', None)
                return render_template('error.html', error="Failed to send OTP. Please try again.")
            
        except Exception as e:
            session.pop('temp_user', None)
            return render_template('error.html', error=f"Email service error: {str(e)}")

        return render_template('otp.html')  # Show OTP verification page

    return render_template('signup.html')  # Show signup form

def verify_otp(request):
    temp_user = session.get('temp_user')
    if not temp_user:
        return render_template('error.html', error="Session expired. Please sign up again.")
    
    # Check OTP expiry
    otp_expiry = datetime.datetime.strptime(temp_user['otp_expiry'], "%Y-%m-%d %H:%M:%S")
    if datetime.datetime.now() > otp_expiry:
        session.pop('temp_user', None)
        return render_template('otp.html', error="OTP has expired. Please request a new one.")
    
    if request.form['otp'] != temp_user['otp']:
        return render_template('otp.html', error="Invalid OTP. Try again.")
    
    # Proceed with Firebase signup
    try:
        # Create user in Firebase Authentication using REST API
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
        payload = {
            "email": temp_user['email'],
            "password": temp_user['password'],
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        data = response.json()

        if 'error' in data:
            session.pop('temp_user', None)
            return render_template('error.html', error=f"Signup failed: {data['error']['message']}")

        # User created successfully, store details in Realtime Database
        uid = data['localId']
        user_ref = db.reference(f'users/{uid}')
        user_ref.set({
            "email": temp_user['email'],
            "name": temp_user['name'],
            "birthday": temp_user['birthday'],
            "phone": temp_user['phone'],
            "education_level": temp_user['education_level'],
            "signup_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "trial_ends": (datetime.datetime.now() + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),
            "activated": False,
            "is_admin": False,
            "is_ceo": False
        })

        # Clear temp_user from session
        session.pop('temp_user', None)
        return redirect(url_for('login'))

    except Exception as e:
        session.pop('temp_user', None)
        return render_template('error.html', error=f"Signup failed: {str(e)}")

# Resend OTP (API-based)
@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        return redirect(url_for('signup'))
    
    new_otp = str(random.randint(100000, 999999))
    temp_user['otp'] = new_otp
    session['temp_user'] = temp_user

    try:
        headers = {
            "Authorization": f"Bearer {MAILTRAP_API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "from": {"email": "hello@brynsl.com", "name": "BrynSL"},
            "to": [{"email": temp_user['email']}],
            "subject": "Your New OTP Code",
            "text": f"Hello {temp_user['name']},\n\nYour NEW OTP is: {new_otp}\n\nExpires in 15 minutes.",
            "category": "OTP"
        }
        
        response = requests.post(MAILTRAP_API_URL, headers=headers, json=payload)
        
        if response.status_code != 200:
            return render_template('otp.html', error="Failed to resend OTP. Try again.")
        
        return render_template('otp.html', message="New OTP sent successfully!")
    
    except Exception as e:
        return render_template('otp.html', error=f"Error resending OTP: {str(e)}")



@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'uid' in session:
        return redirect(url_for('main_dashboard'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        res = requests.post(url, json=payload)
        data = res.json()

        if 'error' in data:
            error_message = data['error']['message']
            return render_template('error.html', error=error_message)
        
        session.permanent = True  # Make session persistent
        session['uid'] = data['localId']
        return redirect(url_for('main_dashboard'))

    return render_template('login.html')

# Add these new routes after the resend_otp route

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if user exists
        user_ref = db.reference('users')
        users = user_ref.get()
        user_id = None
        for uid, user in users.items():
            if user.get('email') == email:
                user_id = uid
                break
        
        if not user_id:
            return render_template('forgot_password.html', error="No account found with this email.")
        
        # Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_expiry = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Store in session
        session['reset_password'] = {
            "email": email,
            "uid": user_id,
            "otp": otp,
            "otp_expiry": otp_expiry
        }
        
        # Send OTP via Mailtrap API
        try:
            headers = {
                "Authorization": f"Bearer {MAILTRAP_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "from": {"email": "hello@brynsl.com", "name": "BrynSL"},
                "to": [{"email": email}],
                "subject": "Password Reset OTP",
                "text": f"Your OTP for password reset is: {otp}\n\nExpires in 15 minutes.",
                "category": "Password Reset"
            }
            
            response = requests.post(MAILTRAP_API_URL, headers=headers, json=payload)
            
            if response.status_code != 200:
                session.pop('reset_password', None)
                return render_template('forgot_password.html', error="Failed to send OTP. Please try again.")
            
            return redirect(url_for('verify_reset_otp'))
        
        except Exception as e:
            session.pop('reset_password', None)
            return render_template('forgot_password.html', error=f"Email service error: {str(e)}")
    
    return render_template('forgot_password.html')

# Replace the existing verify_reset_otp route with this corrected version
# Ensure this import is at the top of app.py
from firebase_admin import auth

# Replace the verify_reset_otp route with this version
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    reset_data = session.get('reset_password')
    if not reset_data:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        # Check if this is a resend OTP request
        if 'resend' in request.form:
            new_otp = str(random.randint(100000, 999999))
            reset_data['otp'] = new_otp
            reset_data['otp_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
            session['reset_password'] = reset_data
            
            try:
                headers = {
                    "Authorization": f"Bearer {MAILTRAP_API_TOKEN}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "from": {"email": "hello@brynsl.com", "name": "BrynSL"},
                    "to": [{"email": reset_data['email']}],
                    "subject": "New Password Reset OTP",
                    "text": f"Your new OTP for password reset is: {new_otp}\n\nExpires in 15 minutes.",
                    "category": "Password Reset"
                }
                
                response = requests.post(MAILTRAP_API_URL, headers=headers, json=payload)
                
                if response.status_code != 200:
                    return render_template('verify_reset_otp.html', error="Failed to resend OTP. Try again.")
                
                return render_template('verify_reset_otp.html', message="New OTP sent successfully!")
            
            except Exception as e:
                return render_template('verify_reset_otp.html', error=f"Error resending OTP: {str(e)}")
        
        # Verify OTP and handle new password
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        
        # Check OTP expiry
        otp_expiry = datetime.datetime.strptime(reset_data['otp_expiry'], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() > otp_expiry:
            session.pop('reset_password', None)
            return render_template('verify_reset_otp.html', error="OTP has expired. Please request a new one.")
        
        if otp != reset_data['otp']:
            return render_template('verify_reset_otp.html', error="Invalid OTP. Try again.")
        
        # Validate new password
        if len(new_password) < 6:
            return render_template('verify_reset_otp.html', error="Password must be at least 6 characters long.")
        
        # Update password using Firebase Admin SDK
        try:
            user = firebase_admin.auth.update_user(
                reset_data['uid'],
                password=new_password
            )
            
            # Clear session and redirect to login
            session.pop('reset_password', None)
            return redirect(url_for('login'))
        
        except firebase_admin.auth.AuthError as e:
            session.pop('reset_password', None)
            return render_template('verify_reset_otp.html', error=f"Password reset failed: {str(e)}")
        except Exception as e:
            session.pop('reset_password', None)
            return render_template('verify_reset_otp.html', error=f"Password reset failed: {str(e)}")
    
    return render_template('verify_reset_otp.html')


@app.route('/dashboard')
def dashboard():
    if 'uid' not in session:
        return redirect(url_for('login'))

    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    # Get unread notifications count
    user_notifications = user_notifications_ref.child(uid).get() or {}
    unread_count = sum(1 for n in user_notifications.values() if not n.get('read', False))

    # Check if user wants to access main dashboard or chat interface
    # Default behavior: redirect to main dashboard
    return redirect(url_for('main_dashboard'))

@app.route('/main-dashboard')
def main_dashboard():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()
    
    # Get unread notifications count
    user_notifications = user_notifications_ref.child(uid).get() or {}
    unread_count = sum(1 for n in user_notifications.values() if not n.get('read', False))
    
    # Get enabled features from admin settings
    enabled_features = get_enabled_features()
    
    return render_template('main_dashboard.html', 
                         email=user['email'], 
                         unread_count=unread_count,
                         enabled_features=enabled_features)

@app.route('/chat')
def chat_interface():
    if 'uid' not in session:
        return redirect(url_for('login'))

    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    # Get unread notifications count
    user_notifications = user_notifications_ref.child(uid).get() or {}
    unread_count = sum(1 for n in user_notifications.values() if not n.get('read', False))

    # The check for trial/activation status is removed from here.
    # The user will always be rendered the chat interface (index.html).
    # The check will be performed in the '/ask' route instead.

    return render_template('index.html', email=user['email'], unread_count=unread_count)

# Temporary test route to bypass authentication
@app.route('/dashboard-test')
def dashboard_test():
    # Mock user data for testing
    mock_user = {
        'email': 'test@example.com',
        'name': 'Test User'
    }
    mock_unread_count = 0
    
    return render_template('index.html', email=mock_user['email'], unread_count=mock_unread_count)


@app.route('/ask', methods=['POST'])
def ask_question():
    if 'uid' not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    # --- START: New check for trial/subscription status ---
    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    if user:
        trial_ends = datetime.datetime.strptime(user['trial_ends'], "%Y-%m-%d %H:%M:%S")
        now = datetime.datetime.now()
        is_activated = user.get('activated', False)

        # If trial is over and user is not activated, redirect.
        if now > trial_ends and not is_activated:
            return jsonify({
                "success": False, 
                "error": "Trial ended or subscription expired. Please check your profile status",
                "redirect": url_for('payment_pending_page'),
                "show_pay_button": True  # Add this flag to show pay now button
            }), 403 # Use 403 Forbidden status
    # --- END: New check ---

    try:
        question = request.form.get('question')
        language = request.form.get('language', 'sinhala')  # Default to Sinhala
        image = request.files.get('image')
        
        logger.debug(f"Using Llama 4 Maverick via OpenRouter API")
        
        # Check if API key is available
        if not OPENROUTER_API_KEY:
            logger.error("OpenRouter API key is missing")
            return jsonify({
                "success": False,
                "error": "AI service configuration error. Please contact support."
            }), 500
        
        if image:
            # For image processing with Llama 4 Maverick via OpenRouter
            # Convert image to base64 for API
            import base64
            image_data = image.read()
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # Create messages for vision capability using OpenRouter format
            messages = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": f"""You are a helpful educational assistant. Analyze the image and question carefully, then provide a clear, step-by-step solution in {language} language.

IMPORTANT FORMATTING RULES:
- Use ONLY plain text - NO LaTeX, NO mathematical symbols like $, \\frac, \\lambda, etc.
- Write mathematical expressions simply: use / for division, * for multiplication, ^ for exponents
- Use clear headings and bullet points
- Show all calculation steps clearly
- Give a final answer at the end
- Use emojis appropriately to make it engaging
- Keep explanations simple and educational

User question: {question}"""
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:{image.mimetype};base64,{image_base64}"
                            }
                        }
                    ]
                }
            ]
        else:
            # For text-only questions
            messages = [
                {
                    "role": "user",
                    "content": f"""You are a helpful AI assistant in BRYN App named BRYN AI and trained by CosmoSL. Provide a clear, accurate response in {language} language.

IMPORTANT FORMATTING RULES:
- Use ONLY plain text - NO LaTeX, NO mathematical symbols like $, \\frac, \\lambda, etc.
- Write mathematical expressions simply: use / for division, * for multiplication, ^ for exponents
- For complex problems, show step-by-step solutions
- Use clear structure with headings and bullet points
- Use emojis appropriately to make responses engaging
- Be concise but comprehensive
- Give practical, actionable answers when applicable

User input: {question}"""
                }
            ]
        
        # Make direct API call to OpenRouter using requests
        # This allows us to add the required OpenRouter headers
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": SITE_URL,  # Optional. Site URL for rankings on openrouter.ai
            "X-Title": SITE_NAME,  # Optional. Site title for rankings on openrouter.ai
        }
        
        payload = {
            "model": "meta-llama/llama-4-maverick:free",
            "messages": messages,
            "max_tokens": 1500,
            "temperature": 0.7
        }
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload
        )
        
        if response.status_code != 200:
            logger.error(f"OpenRouter API error: {response.status_code} - {response.text}")
            
            # Provide specific error messages based on status code
            if response.status_code == 401:
                error_msg = "Invalid API key. Please check your OpenRouter API key configuration."
            elif response.status_code == 403:
                error_msg = "Access forbidden. Please check your OpenRouter account permissions."
            elif response.status_code == 429:
                error_msg = "Rate limit exceeded. Please try again later."
            elif response.status_code == 500:
                error_msg = "OpenRouter service error. Please try again later."
            else:
                error_msg = f"AI service error: {response.status_code}"
                
            return jsonify({
                "success": False,
                "error": error_msg
            }), 500
        
        response_data = response.json()
        ai_response = response_data['choices'][0]['message']['content']
        
        return jsonify({
            "success": True,
            "response": ai_response
        })
    except Exception as e:
        logger.error(f"Error in ask_question: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/payment_pending')
def payment_pending_page():
    if 'uid' not in session:
        return redirect(url_for('login'))
    return render_template('payment_pending.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_panel():
    users_ref = db.reference('users')
    all_users = users_ref.get()
    total_users = len(all_users)
    search_query = request.args.get('search', '').lower()

    users = []
    now = datetime.datetime.now()

    if all_users:
        for uid, info in all_users.items():
            # Skip if user doesn't match search query
            if search_query and not (
                search_query in info.get('name', '').lower() or
                search_query in info.get('email', '').lower() or
                search_query in info.get('phone', '').lower() or
                search_query in uid.lower()
            ):
                continue

            activated = info.get('activated', False)
            payment_date_str = info.get('payment_date')
            duration_minutes = int(info.get('paid_duration_minutes', 0))

            if activated and payment_date_str and duration_minutes > 0:
                try:
                    payment_date = datetime.datetime.strptime(payment_date_str, "%Y-%m-%d %H:%M:%S")
                    expiry_time = payment_date + datetime.timedelta(minutes=duration_minutes)

                    if now > expiry_time:
                        db.reference(f'users/{uid}').update({"activated": False})
                        activated = False
                except Exception as e:
                    print(f"Error parsing payment_date for user {uid}: {e}")

            users.append({
                "uid": uid,
                "name": info.get('name'),
                "email": info.get('email'),
                "birthday": info.get('birthday'),
                "phone": info.get('phone'),
                "activated": activated,
                "trial_ends": info.get('trial_ends'),
                "payment_date": payment_date_str,
                "paid_duration_minutes": duration_minutes
            })

    return render_template('admin.html', users=users, search_query=search_query,total_users=total_users)

# Manual admin activation
@app.route('/admin/activate', methods=['POST'])
@admin_required
def admin_activate_user():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"}), 400

            required_fields = ['uid', 'admin_name', 'amount', 'referral_code', 'username', 'user_email']
            for field in required_fields:
                if field not in data:
                    return jsonify({"success": False, "error": f"Missing field: {field}"}), 400

            uid = data['uid']
            admin_name = data['admin_name']
            amount = data['amount']
            referral_code = data['referral_code']
            username = data['username']
            user_email = data['user_email']
            
            now = datetime.datetime.now()
            
            # Update user activation
            db.reference(f'users/{uid}').update({
                "activated": True,
                "payment_date": now.strftime("%Y-%m-%d %H:%M:%S"),
                "paid_duration_minutes": 43200  # 30 days in minutes
            })
            
            # Save transaction details
            transaction_ref = db.reference('admin_transactions').push()
            transaction_ref.set({
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "admin_name": admin_name,
                "user_id": uid,
                "username": username,
                "user_email": user_email,
                "amount": amount,
                "referral_code": referral_code,
                "activated_by": session.get('admin_uid', 'manual')  # default to 'manual' if not set
            })
            
            return jsonify({"success": True})
            
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": False, "error": "Method not allowed"}), 405

# Add this new route for CEO view
@app.route('/ceo')
@ceo_required
def ceo_view():
    users_ref = db.reference('users')
    all_users = users_ref.get() or {}
    total_users = len(all_users)

    transactions_ref = db.reference('admin_transactions')
    transactions = transactions_ref.get() or {}
    search_query = request.args.get('search', '').lower()
    
    # Sort transactions by timestamp (newest first)
    sorted_transactions = sorted(
        transactions.items(),
        key=lambda x: datetime.datetime.strptime(x[1]['timestamp'], "%Y-%m-%d %H:%M:%S"),
        reverse=True
    )
    
    # Filter transactions if search query exists
    filtered_transactions = {}
    for transaction_id, transaction in sorted_transactions:
        if (search_query in transaction.get('admin_name', '').lower() or
            search_query in transaction.get('user_email', '').lower() or
            search_query in transaction.get('username', '').lower() or
            search_query in transaction.get('referral_code', '').lower() or
            search_query in str(transaction.get('amount', '')).lower()):
            filtered_transactions[transaction_id] = transaction
    
    # Use filtered transactions if search exists, otherwise use all
    display_transactions = filtered_transactions if search_query else dict(sorted_transactions)
    
    # Calculate financial metrics (using original transactions, not filtered)
    total_income = 0
    monthly_income = 0
    daily_income = 0
    current_date = datetime.datetime.now()
    
    for transaction_id, transaction in transactions.items():
        try:
            amount = float(transaction.get('amount', 0))
            total_income += amount
            
            trans_date = datetime.datetime.strptime(transaction['timestamp'], "%Y-%m-%d %H:%M:%S")
            
            if trans_date.month == current_date.month and trans_date.year == current_date.year:
                monthly_income += amount
                
            if (trans_date.day == current_date.day and 
                trans_date.month == current_date.month and 
                trans_date.year == current_date.year):
                daily_income += amount
                
        except (ValueError, KeyError) as e:
            print(f"Error processing transaction {transaction_id}: {e}")
            continue
    
    return render_template('ceo.html', 
                         transactions=display_transactions,
                         total_income=total_income,
                         monthly_income=monthly_income,
                         daily_income=daily_income,
                         search_query=search_query,
                         total_users=total_users)

@app.route('/admin/download-invoice/<transaction_id>')
@ceo_required
def download_invoice(transaction_id):
    try:
        print(f"DEBUG: Starting invoice generation for transaction {transaction_id}")
        
        # Get transaction details
        transactions_ref = db.reference('admin_transactions')
        transaction = transactions_ref.child(transaction_id).get()
        
        if not transaction:
            print(f"ERROR: Transaction {transaction_id} not found")
            abort(404, description="Transaction not found")
        
        print(f"DEBUG: Transaction data: {transaction}")
        
        # Create PDF in memory with watermark
        buffer = io.BytesIO()
        
        # Custom PDF class with watermark
        class WatermarkDocTemplate(SimpleDocTemplate):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                
            def afterPage(self):
                # Add watermark to each page
                canvas = self.canv
                canvas.saveState()
                
                # Set watermark properties
                canvas.setFillColorRGB(0.94, 0.97, 1.0)  # Light blue #f0f9ff
                canvas.setFillAlpha(0.3)  # 30% transparency
                canvas.setFont('Helvetica-Bold', 60)
                
                # Calculate center position
                page_width = letter[0]
                page_height = letter[1]
                
                # Rotate and position watermark
                canvas.translate(page_width/2, page_height/2)
                canvas.rotate(45)
                
                # Draw watermark text
                watermark_text = "BRYN AI"
                text_width = canvas.stringWidth(watermark_text, 'Helvetica-Bold', 60)
                canvas.drawString(-text_width/2, 0, watermark_text)
                
                # Add secondary watermark
                canvas.setFont('Helvetica', 18)
                solutions_text = "SOLUTIONS"
                solutions_width = canvas.stringWidth(solutions_text, 'Helvetica', 18)
                canvas.drawString(-solutions_width/2, -30, solutions_text)
                
                canvas.restoreState()
        
        doc = WatermarkDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        print("DEBUG: Created document template")
        
        # Company Header
        print("DEBUG: Creating company header")
        company_style = ParagraphStyle(
            'CompanyHeader',
            parent=styles['Title'],
            fontSize=18,
            textColor=colors.HexColor('#1e40af'),
            alignment=TA_CENTER,
            spaceAfter=15
        )
        story.append(Paragraph("BRYN AI SOLUTIONS", company_style))
        print("DEBUG: Added company header")
        
        # Company Details
        company_info_style = ParagraphStyle(
            'CompanyInfo',
            parent=styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            spaceAfter=10
        )
        company_details = """
        Email: info@cosmosri.com | Website: www.cosmosri.com<br/>
        Advanced AI Learning Platform | Educational Technology Solutions<br/>
        Powered by Cosmo Solutions (Pvt) Ltd.
        """
        story.append(Paragraph(company_details, company_info_style))
        
        # Invoice Title
        invoice_style = ParagraphStyle(
            'InvoiceTitle',
            parent=styles['Heading1'],
            fontSize=14,
            textColor=colors.HexColor('#059669'),
            alignment=TA_CENTER,
            spaceAfter=15
        )
        story.append(Paragraph("PAYMENT INVOICE", invoice_style))
        
        # Invoice Information Table
        print("DEBUG: Creating invoice info table")
        invoice_date = datetime.datetime.now().strftime("%Y-%m-%d")
        invoice_data = [
            ['Invoice Date:', invoice_date],
            ['Transaction ID:', transaction_id],
            ['Transaction Date:', transaction.get('timestamp', 'N/A')],
            ['Processed By:', transaction.get('admin_name', 'Admin')]
        ]
        
        print(f"DEBUG: Invoice data: {invoice_data}")
        info_table = Table(invoice_data, colWidths=[1.5*inch, 2.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 10))
        
        # Customer Information
        customer_style = ParagraphStyle(
            'CustomerHeader',
            parent=styles['Heading2'],
            fontSize=11,
            textColor=colors.HexColor('#374151'),
            alignment=TA_CENTER,
            spaceAfter=8
        )
        story.append(Paragraph("Customer Information", customer_style))
        
        customer_data = [
            ['Customer Email:', transaction.get('user_email', 'N/A')],
            ['Username:', transaction.get('username', 'N/A')],
            ['Referral Code:', transaction.get('referral_code', 'N/A')]
        ]
        
        customer_table = Table(customer_data, colWidths=[1.5*inch, 2.5*inch])
        customer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f9ff')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bfdbfe')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(customer_table)
        story.append(Spacer(1, 15))
        
        # Payment Details
        payment_style = ParagraphStyle(
            'PaymentHeader',
            parent=styles['Heading2'],
            fontSize=11,
            textColor=colors.HexColor('#374151'),
            alignment=TA_CENTER,
            spaceAfter=8
        )
        story.append(Paragraph("Payment Details", payment_style))
        
        amount = float(transaction.get('amount', 0))
        payment_data = [
            ['Description', 'Amount (Rs.)'],
            ['AI Learning Platform Subscription', f"{amount:.2f}"],
            ['', ''],
            ['Total Amount', f"Rs. {amount:.2f}"]
        ]
        
        payment_table = Table(payment_data, colWidths=[2.5*inch, 1.5*inch])
        payment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#dcfce7')),
            ('TEXTCOLOR', (0, -1), (-1, -1), colors.HexColor('#166534')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#6b7280')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(payment_table)
        story.append(Spacer(1, 20))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.HexColor('#6b7280'),
            alignment=TA_CENTER,
            spaceAfter=5
        )
        footer_text = """
        Thank you for choosing BRYN AI Solutions!<br/>
        This is a computer-generated invoice and does not require a signature.<br/>
        For support inquiries, contact us at info@cosmosri.com
        """
        story.append(Paragraph(footer_text, footer_style))
        
        # Build PDF
        print("DEBUG: Building PDF...")
        doc.build(story)
        
        # Prepare response
        buffer.seek(0)
        pdf_data = buffer.getvalue()
        print(f"DEBUG: PDF generated successfully, size: {len(pdf_data)} bytes")
        
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=invoice_{transaction_id}_{invoice_date}.pdf'
        
        buffer.close()
        return response
        
    except ImportError as e:
        print(f"ERROR: Missing dependency - {str(e)}")
        return f"Missing required library. Please install reportlab: pip install reportlab", 500
    except Exception as e:
        print(f"ERROR: Error generating invoice for {transaction_id}: {str(e)}")
        print(f"ERROR: Exception type: {type(e).__name__}")
        import traceback
        print(f"ERROR: Traceback: {traceback.format_exc()}")
        return f"Error generating invoice: {str(e)}", 500

# Test route to check dependencies
@app.route('/test-pdf')
@ceo_required  
def test_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        import io
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("Test PDF Generation", styles['Title']))
        doc.build(story)
        
        buffer.seek(0)
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=test.pdf'
        
        buffer.close()
        return response
        
    except ImportError as e:
        return f"ReportLab not installed: {str(e)}", 500
    except Exception as e:
        return f"Error: {str(e)}", 500



@app.route('/admin/notifications', methods=['GET', 'POST'])
@admin_required
def admin_notifications():
    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']
        send_to = request.form.get('send_to', 'all')  # 'all' or 'selected'
        selected_users = request.form.getlist('selected_users[]')
        
        # Create notification
        new_notification = {
            'title': title,
            'message': message,
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'created_by': session.get('uid', 'admin')
        }
        
        # Save to notifications
        notification_ref = notifications_ref.push()
        notification_ref.set(new_notification)
        notification_id = notification_ref.key
        
        # Determine recipients
        if send_to == 'all':
            users_ref = db.reference('users')
            all_users = users_ref.get() or {}
            user_ids = list(all_users.keys())
        else:
            user_ids = selected_users
        
        # Create user notification entries
        for user_id in user_ids:
            user_notifications_ref.child(user_id).child(notification_id).set({
                'read': False,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return redirect(url_for('admin_notifications'))
    
    # GET request - show form and past notifications
    users_ref = db.reference('users')
    all_users = users_ref.get() or {}
    
    notifications = notifications_ref.get() or {}
    sorted_notifications = sorted(
        notifications.items(),
        key=lambda x: x[1]['created_at'],
        reverse=True
    )
    
    return render_template('admin_notifications.html', 
                         users=all_users,
                         notifications=dict(sorted_notifications))

@app.route('/admin/notification/<notification_id>')
@admin_required
def view_notification(notification_id):
    # Get the notification
    notification = notifications_ref.child(notification_id).get()
    if not notification:
        abort(404, description="Notification not found")

    # Get all users
    users_ref = db.reference('users')
    all_users = users_ref.get() or {}

    # Get all user notifications
    all_user_notifications = user_notifications_ref.get() or {}

    # Prepare user status data
    user_status = {}
    for user_id, user_data in all_users.items():
        # Check if user has this notification
        if notification_id in all_user_notifications.get(user_id, {}):
            user_status[user_id] = {
                'read': all_user_notifications[user_id][notification_id].get('read', False),
                'timestamp': all_user_notifications[user_id][notification_id].get('timestamp', 'N/A')
            }
        else:
            user_status[user_id] = {
                'read': False,
                'timestamp': 'Not received'
            }

    return render_template('view_notification.html',
                         notification=notification,
                         notification_id=notification_id,
                         users=all_users,
                         user_status=user_status)  # Make sure this is passed



@app.route('/notifications')
def user_notifications():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    
    # Get user's notifications
    user_notifications = user_notifications_ref.child(uid).get() or {}
    
    # Get notification details and count unread
    notifications_list = []
    unread_count = 0
    
    for notification_id, status in user_notifications.items():
        notification = notifications_ref.child(notification_id).get()
        if notification:
            is_read = status.get('read', False)
            if not is_read:
                unread_count += 1
            
            notifications_list.append({
                'id': notification_id,
                'title': notification['title'],
                'message': notification['message'],
                'created_at': notification['created_at'],
                'read': is_read
            })
    
    # Sort by timestamp (newest first)
    notifications_list.sort(key=lambda x: x['created_at'], reverse=True)
    
    return render_template('user_notifications.html',
                         notifications=notifications_list,
                         unread_count=unread_count)

@app.route('/notifications/mark_as_read/<notification_id>', methods=['POST'])
def mark_as_read(notification_id):
    if 'uid' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    
    user_notifications_ref.child(uid).child(notification_id).update({
        'read': True
    })
    
    return jsonify({'success': True})

@app.route('/api/notifications')
def api_notifications():
    if 'uid' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    
    # Get user's notifications
    user_notifications = user_notifications_ref.child(uid).get() or {}
    
    # Get notification details
    notifications_list = []
    
    for notification_id, status in user_notifications.items():
        notification = notifications_ref.child(notification_id).get()
        if notification:
            notifications_list.append({
                'id': notification_id,
                'title': notification['title'],
                'message': notification['message'],
                'created_at': notification['created_at'],
                'read': status.get('read', False)
            })
    
    # Sort by timestamp (newest first)
    notifications_list.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({
        'success': True,
        'notifications': notifications_list,
        'unread_count': sum(1 for n in notifications_list if not n['read'])
    })




@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect(url_for('login'))

    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    if not user:
        return redirect(url_for('login'))

    # Calculate account status
    now = datetime.datetime.now()
    if user.get('activated'):
        status = "Active"
        if user.get('payment_date') and user.get('paid_duration_minutes'):
            payment_date = datetime.datetime.strptime(user['payment_date'], "%Y-%m-%d %H:%M:%S")
            expiry_date = payment_date + datetime.timedelta(minutes=user['paid_duration_minutes'])
            status = f"Active (Expires: {expiry_date.strftime('%Y-%m-%d %H:%M')}"
    else:
        if user.get('trial_ends'):
            trial_ends = datetime.datetime.strptime(user['trial_ends'], "%Y-%m-%d %H:%M:%S")
            if now > trial_ends:
                status = "Expired"
            else:
                status = f"Trial (Expires: {trial_ends.strftime('%Y-%m-%d %H:%M')})"
        else:
            status = "Unknown"

    # Calculate age if birthday is provided
    age = None
    if user.get('birthday'):
        try:
            birth_date = datetime.datetime.strptime(user['birthday'], '%Y-%m-%d')
            age = now.year - birth_date.year - ((now.month, now.day) < (birth_date.month, birth_date.day))
        except ValueError:
            pass

    # Get user activity statistics
    ideas_ref = db.reference('ideas')
    all_ideas = ideas_ref.get() or {}
    user_ideas_count = sum(1 for idea in all_ideas.values() if isinstance(idea, dict) and idea.get('user_id') == uid)
    
    # Get latest idea submission
    latest_idea_date = None
    for idea in all_ideas.values():
        if isinstance(idea, dict) and idea.get('user_id') == uid:
            idea_date = idea.get('submitted_at')
            if idea_date and (not latest_idea_date or idea_date > latest_idea_date):
                latest_idea_date = idea_date

    # Get notification statistics
    user_notifications_ref = db.reference(f'user_notifications/{uid}')
    user_notifications = user_notifications_ref.get() or {}
    total_notifications = len(user_notifications)
    unread_notifications = sum(1 for notif in user_notifications.values() if not notif.get('read', False))
    
    # Get tuition requests if available
    tuition_requests_ref = db.reference('tuition_requests')
    all_tuition_requests = tuition_requests_ref.get() or {}
    user_tuition_requests = [req for req in all_tuition_requests.values() 
                           if isinstance(req, dict) and req.get('user_id') == uid]
    
    # Get bookmarks if available
    bookmarks_ref = db.reference(f'bookmarks/{uid}')
    bookmarks = bookmarks_ref.get() or {}
    bookmarks_count = len(bookmarks)

    return render_template('profile.html', 
                         email=user.get('email'),
                         name=user.get('name'),
                         birthday=user.get('birthday'),
                         age=age,
                         phone=user.get('phone'),
                         education_level=user.get('education_level'),
                         signup_date=user.get('signup_date'),
                         last_login=user.get('last_login'),
                         trial_ends=user.get('trial_ends'),
                         payment_date=user.get('payment_date'),
                         paid_duration_minutes=user.get('paid_duration_minutes'),
                         activated=user.get('activated', False),
                         status=status,
                         user_ideas_count=user_ideas_count,
                         latest_idea_date=latest_idea_date,
                         total_notifications=total_notifications,
                         unread_notifications=unread_notifications,
                         tuition_requests_count=len(user_tuition_requests),
                         bookmarks_count=bookmarks_count,
                         uid=uid)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'uid' not in session:
        return redirect(url_for('login'))

    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name', '').strip()
            birthday = request.form.get('birthday', '').strip()
            phone = request.form.get('phone', '').strip()
            education_level = request.form.get('education_level', '').strip()

            # Validate required fields
            if not name:
                return jsonify({'success': False, 'error': 'Name is required'}), 400
            
            if birthday and not validate_date(birthday):
                return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

            # Update user data in Firebase
            update_data = {
                'name': name,
                'birthday': birthday if birthday else user.get('birthday', ''),
                'phone': phone if phone else user.get('phone', ''),
                'education_level': education_level if education_level else user.get('education_level', '')
            }
            
            user_ref.update(update_data)
            
            return jsonify({'success': True, 'message': 'Profile updated successfully!'})
            
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to update profile: {str(e)}'}), 500
    
    # GET request - render edit form
    return render_template('edit_profile.html',
                         name=user.get('name'),
                         email=user.get('email'),
                         birthday=user.get('birthday'),
                         phone=user.get('phone'),
                         education_level=user.get('education_level'))

def validate_date(date_string):
    """Validate date format YYYY-MM-DD"""
    try:
        datetime.datetime.strptime(date_string, '%Y-%m-%d')
        return True
    except ValueError:
        return False

@app.route('/ideas', methods=['GET', 'POST'])
def ideas():
    if 'uid' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        idea_text = request.form.get('idea')
        if not idea_text:
            return render_template('ideas.html', error='Idea cannot be empty!', dark_theme=True)
        
        uid = session['uid']
        user_ref = db.reference(f'users/{uid}')
        user = user_ref.get()
        if not user:
            return redirect(url_for('login'))

        try:
            idea_ref = ideas_ref.push()
            idea_ref.set({
                'user_id': uid,
                'user_email': user.get('email'),
                'idea': idea_text,
                'submitted_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            return render_template('ideas.html', message='Thank you for your idea!', dark_theme=True)
        except Exception as e:
            return render_template('ideas.html', error=f'Failed to submit idea: {str(e)}', dark_theme=True)

    return render_template('ideas.html', dark_theme=True)
    return render_template('ideas.html', dark_theme=True)

@app.route('/admin/ideas')
@admin_required
def admin_ideas():
    search_query = request.args.get('search', '').lower()
    all_ideas = ideas_ref.get() or {}
    users_ref = db.reference('users')
    all_users = users_ref.get() or {}

    ideas = []
    for idea_id, idea_data in all_ideas.items():
        # Check if idea_data is a dictionary
        if not isinstance(idea_data, dict):
            logger.warning(f"Skipping invalid idea entry with ID {idea_id}: expected dict, got {type(idea_data)}")
            continue
        # Safely access fields with .get()
        if (search_query in idea_data.get('user_email', '').lower() or
            search_query in idea_data.get('idea', '').lower()):
            ideas.append({
                'id': idea_id,
                'user_email': idea_data.get('user_email', 'Unknown'),
                'description': idea_data.get('idea'),  # Changed 'idea' to 'description' to match your data structure
                'submitted_at': idea_data.get('submitted_at')
            })

    # Sort ideas by submitted_at (newest first), handling None values
    ideas.sort(key=lambda x: x.get('submitted_at', ''), reverse=True)
    total_ideas = len(all_ideas)

    return render_template('admin_ideas.html', ideas=ideas, search_query=search_query, total_ideas=total_ideas)


@app.route('/admin/user_stats')
@ceo_required
def user_stats():
    users_ref = db.reference('users')
    ideas_ref = db.reference('ideas')
    transactions_ref = db.reference('admin_transactions')
    notifications_ref = db.reference('notifications')
    user_notifications_ref = db.reference('user_notifications')

    all_users = users_ref.get() or {}
    all_ideas = ideas_ref.get() or {}
    all_transactions = transactions_ref.get() or {}
    all_notifications = notifications_ref.get() or {}
    all_user_notifications = user_notifications_ref.get() or {}

    # Query parameters for filtering and pagination
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    status_filter = request.args.get('status', 'all')  # all, active, trial, expired
    page = int(request.args.get('page', 1))
    per_page = 10

    # Parse dates
    now = datetime.datetime.now()
    try:
        start_dt = datetime.datetime.strptime(start_date, '%Y-%m-%d') if start_date else None
        end_dt = datetime.datetime.strptime(end_date, '%Y-%m-%d') if end_date else None
    except ValueError:
        start_dt, end_dt = None, None

    # User Metrics
    total_users = len(all_users)
    active_users = 0
    trial_users = 0
    expired_users = 0
    signup_trend = {}
    users_data = []
    education_level_stats = {}

    for uid, user in all_users.items():
        user_signup_date = user.get('signup_date', '')
        if start_dt and end_dt and user_signup_date:
            try:
                signup_dt = datetime.datetime.strptime(user_signup_date, "%Y-%m-%d %H:%M:%S")
                if not (start_dt <= signup_dt <= end_dt):
                    continue
            except ValueError:
                continue

        # Determine user status
        activated = user.get('activated', False)
        trial_ends = user.get('trial_ends', '')
        payment_date = user.get('payment_date', '')
        paid_duration = int(user.get('paid_duration_minutes', 0))

        status = 'expired'
        if activated and payment_date and paid_duration > 0:
            try:
                payment_dt = datetime.datetime.strptime(payment_date, "%Y-%m-%d %H:%M:%S")
                expiry_dt = payment_dt + datetime.timedelta(minutes=paid_duration)
                if now <= expiry_dt:
                    status = 'active'
                    active_users += 1
                else:
                    db.reference(f'users/{uid}').update({"activated": False})
                    status = 'expired'
                    expired_users += 1
            except ValueError:
                status = 'expired'
                expired_users += 1
        else:
            try:
                trial_end_dt = datetime.datetime.strptime(trial_ends, "%Y-%m-%d %H:%M:%S")
                if now <= trial_end_dt:
                    status = 'trial'
                    trial_users += 1
                else:
                    status = 'expired'
                    expired_users += 1
            except ValueError:
                status = 'expired'
                expired_users += 1

        if status_filter != 'all' and status != status_filter:
            continue

        users_data.append({
            'uid': uid,
            'email': user.get('email', 'Unknown'),
            'name': user.get('name', 'Unknown'),
            'status': status,
            'signup_date': user_signup_date
        })
        
        # Education level statistics
        education_level = user.get('education_level', 'Not Specified')
        education_level_stats[education_level] = education_level_stats.get(education_level, 0) + 1

        # Signup trend
        if user_signup_date:
            try:
                signup_dt = datetime.datetime.strptime(user_signup_date, "%Y-%m-%d %H:%M:%S")
                month_key = signup_dt.strftime("%Y-%m")
                signup_trend[month_key] = signup_trend.get(month_key, 0) + 1
            except ValueError:
                pass

    # Idea Metrics
    total_ideas = len(all_ideas)
    ideas_per_user = {}
    idea_trend = {}
    for idea_id, idea in all_ideas.items():
        if not isinstance(idea, dict):
            continue
        idea_date = idea.get('submitted_at', '')
        if start_dt and end_dt and idea_date:
            try:
                idea_dt = datetime.datetime.strptime(idea_date, "%Y-%m-%d %H:%M:%S")
                if not (start_dt <= idea_dt <= end_dt):
                    continue
            except ValueError:
                continue
        user_id = idea.get('user_id', '')
        ideas_per_user[user_id] = ideas_per_user.get(user_id, 0) + 1
        if idea_date:
            try:
                idea_dt = datetime.datetime.strptime(idea_date, "%Y-%m-%d %H:%M:%S")
                month_key = idea_dt.strftime("%Y-%m")
                idea_trend[month_key] = idea_trend.get(month_key, 0) + 1
            except ValueError:
                pass

    avg_ideas_per_user = sum(ideas_per_user.values()) / len(ideas_per_user) if ideas_per_user else 0

    # Transaction Metrics (CEO-only view)
    total_revenue = 0
    recent_transactions = []
    for trans_id, trans in all_transactions.items():
        try:
            amount = float(trans.get('amount', 0))
            trans_date = trans.get('timestamp', '')
            if start_dt and end_dt and trans_date:
                trans_dt = datetime.datetime.strptime(trans_date, "%Y-%m-%d %H:%M:%S")
                if not (start_dt <= trans_dt <= end_dt):
                    continue
            total_revenue += amount
            recent_transactions.append({
                'id': trans_id,
                'user_email': trans.get('user_email', 'Unknown'),
                'amount': amount,
                'timestamp': trans_date
            })
        except (ValueError, KeyError):
            continue
    recent_transactions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_transactions = recent_transactions[:5]  # Limit to 5 recent

    # Notification Metrics
    total_notifications = len(all_notifications)
    read_count = 0
    delivered_count = 0
    for user_id, user_nots in all_user_notifications.items():
        for not_id, status in user_nots.items():
            delivered_count += 1
            if status.get('read', False):
                read_count += 1
    read_rate = (read_count / delivered_count * 100) if delivered_count > 0 else 0

    # Prepare chart data
    signup_trend_data = [{'month': k, 'count': v} for k, v in sorted(signup_trend.items())][-6:]  # Last 6 months
    idea_trend_data = [{'month': k, 'count': v} for k, v in sorted(idea_trend.items())][-6:]

    # Pagination for users
    total_filtered_users = len(users_data)
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_users = users_data[start_index:end_index]
    
    # Calculate pagination info
    total_pages = (total_filtered_users + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    prev_page = page - 1 if has_prev else None
    next_page = page + 1 if has_next else None

    return render_template('user_stats.html',
                         total_users=total_users,
                         active_users=active_users,
                         trial_users=trial_users,
                         expired_users=expired_users,
                         total_ideas=total_ideas,
                         avg_ideas_per_user=round(avg_ideas_per_user, 2),
                         total_revenue=total_revenue,
                         recent_transactions=recent_transactions,
                         total_notifications=total_notifications,
                         read_rate=round(read_rate, 2),
                         signup_trend=signup_trend_data,
                         idea_trend=idea_trend_data,
                         education_level_stats=education_level_stats,
                         start_date=start_date,
                         end_date=end_date,
                         status_filter=status_filter,
                         users=paginated_users,
                         total_filtered_users=total_filtered_users,
                         current_page=page,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         prev_page=prev_page,
                         next_page=next_page,
                         active_page='user_stats')


# Study Planner Routes

@app.route('/study-planner')
def study_planner():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    
    # Get user's subjects
    user_subjects_ref = subjects_ref.child(uid)
    subjects = user_subjects_ref.get() or {}
    
    # Get user's study events
    user_events_ref = study_events_ref.child(uid)
    events = user_events_ref.get() or {}
    
    # Get user's study progress
    user_progress_ref = study_progress_ref.child(uid)
    progress = user_progress_ref.get() or {}
    
    return render_template('study_planner.html', 
                         subjects=subjects, 
                         events=events, 
                         progress=progress)

@app.route('/api/subjects', methods=['GET', 'POST', 'DELETE'])
def manage_subjects():
    if 'uid' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    user_subjects_ref = subjects_ref.child(uid)
    
    if request.method == 'GET':
        subjects = user_subjects_ref.get() or {}
        return jsonify(subjects)
    
    elif request.method == 'POST':
        data = request.json
        subject_name = data.get('name', '').strip()
        subject_color = data.get('color', '#6e48aa')
        
        if not subject_name:
            return jsonify({'error': 'Subject name is required'}), 400
        
        subject_id = str(int(datetime.datetime.now().timestamp() * 1000))
        subject_data = {
            'name': subject_name,
            'color': subject_color,
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        user_subjects_ref.child(subject_id).set(subject_data)
        return jsonify({'id': subject_id, **subject_data})
    
    elif request.method == 'DELETE':
        subject_id = request.json.get('id')
        if not subject_id:
            return jsonify({'error': 'Subject ID is required'}), 400
        
        user_subjects_ref.child(subject_id).delete()
        return jsonify({'success': True})

@app.route('/api/study-events', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_study_events():
    if 'uid' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    user_events_ref = study_events_ref.child(uid)
    
    if request.method == 'GET':
        events = user_events_ref.get() or {}
        return jsonify(events)
    
    elif request.method == 'POST':
        data = request.json
        required_fields = ['title', 'type', 'date', 'subject_id']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        event_id = str(int(datetime.datetime.now().timestamp() * 1000))
        event_data = {
            'title': data['title'],
            'type': data['type'],  # 'assignment', 'exam', 'study_session'
            'date': data['date'],
            'time': data.get('time', ''),
            'subject_id': data['subject_id'],
            'description': data.get('description', ''),
            'completed': False,
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        user_events_ref.child(event_id).set(event_data)
        return jsonify({'id': event_id, **event_data})
    
    elif request.method == 'PUT':
        data = request.json
        event_id = data.get('id')
        
        if not event_id:
            return jsonify({'error': 'Event ID is required'}), 400
        
        event_ref = user_events_ref.child(event_id)
        event_ref.update(data)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        event_id = request.json.get('id')
        if not event_id:
            return jsonify({'error': 'Event ID is required'}), 400
        
        user_events_ref.child(event_id).delete()
        return jsonify({'success': True})

@app.route('/api/study-sessions', methods=['GET', 'POST'])
def manage_study_sessions():
    if 'uid' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    user_sessions_ref = study_sessions_ref.child(uid)
    
    if request.method == 'GET':
        # Get sessions for the last 30 days
        sessions = user_sessions_ref.get() or {}
        return jsonify(sessions)
    
    elif request.method == 'POST':
        data = request.json
        required_fields = ['subject_id', 'duration', 'date']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        session_id = str(int(datetime.datetime.now().timestamp() * 1000))
        session_data = {
            'subject_id': data['subject_id'],
            'duration': data['duration'],  # in minutes
            'date': data['date'],
            'notes': data.get('notes', ''),
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        user_sessions_ref.child(session_id).set(session_data)
        
        # Update progress tracking
        update_study_progress(uid, data['subject_id'], data['duration'])
        
        return jsonify({'id': session_id, **session_data})

def update_study_progress(uid, subject_id, duration_minutes):
    """Update study progress for a subject"""
    user_progress_ref = study_progress_ref.child(uid).child(subject_id)
    
    # Get current progress
    current_progress = user_progress_ref.get() or {}
    
    # Update total study time
    total_minutes = current_progress.get('total_minutes', 0) + duration_minutes
    total_sessions = current_progress.get('total_sessions', 0) + 1
    
    # Calculate streak
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    last_study_date = current_progress.get('last_study_date', '')
    current_streak = current_progress.get('current_streak', 0)
    
    if last_study_date:
        last_date = datetime.datetime.strptime(last_study_date, "%Y-%m-%d")
        today_date = datetime.datetime.strptime(today, "%Y-%m-%d")
        days_diff = (today_date - last_date).days
        
        if days_diff == 1:
            current_streak += 1
        elif days_diff > 1:
            current_streak = 1
    else:
        current_streak = 1
    
    # Update progress data
    progress_data = {
        'total_minutes': total_minutes,
        'total_sessions': total_sessions,
        'current_streak': current_streak,
        'last_study_date': today,
        'updated_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    user_progress_ref.update(progress_data)

@app.route('/study-timer')
def study_timer():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    
    # Get user's subjects for timer
    user_subjects_ref = subjects_ref.child(uid)
    subjects = user_subjects_ref.get() or {}
    
    return render_template('study_timer.html', subjects=subjects)

# Tuition Feature Routes
@app.route('/tuition')
def tuition_form():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()
    
    return render_template('tuition_form.html', user=user)

@app.route('/tuition/submit', methods=['POST'])
def submit_tuition_request():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()
    
    # Get form data
    name = request.form.get('name')
    education_level = request.form.get('education_level')
    whatsapp = request.form.get('whatsapp')
    subject = request.form.get('subject')
    title = request.form.get('title')
    service_type = request.form.get('service_type')
    
    # Create tuition request
    request_data = {
        'user_id': uid,
        'user_name': name,
        'user_email': user.get('email'),
        'education_level': education_level,
        'whatsapp_no': whatsapp,
        'subject': subject,
        'title': title,
        'service_type': service_type,
        'status': 'pending',
        'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'admin_assigned': None
    }
    
    # Save to Firebase
    tuition_requests_ref = db.reference('tuition_requests')
    new_request = tuition_requests_ref.push(request_data)
    request_id = new_request.key
    
    # Create initial chat message with user details
    chat_data = {
        'request_id': request_id,
        'messages': {
            'initial': {
                'sender_type': 'system',
                'message': f"""New Tuition Request Details:
                
Name: {name}
Education Level: {education_level}
WhatsApp: {whatsapp}
Subject: {subject}
Title: {title}
Service Type: {service_type}
Request Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                
Please start the conversation below.""",
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        },
        'participants': {
            'user': uid,
            'admin': None
        },
        'last_message_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Save chat
    tuition_chats_ref = db.reference('tuition_chats')
    tuition_chats_ref.child(request_id).set(chat_data)
    
    # Send notification to the user
    notification_title = "Tuition Request Received"
    notification_message = "Your Request Received & Our team will contact you within 24 hours"
    
    # Create notification
    new_notification = {
        'title': notification_title,
        'message': notification_message,
        'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'created_by': 'system'
    }
    
    # Save to notifications
    notification_ref = notifications_ref.push()
    notification_ref.set(new_notification)
    notification_id = notification_ref.key
    
    # Create user notification entry
    user_notifications_ref.child(uid).child(notification_id).set({
        'read': False,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    return redirect(url_for('my_tuition_requests'))

@app.route('/my-tuition-requests')
def my_tuition_requests():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    
    # Get user's tuition requests
    tuition_requests_ref = db.reference('tuition_requests')
    all_requests = tuition_requests_ref.get() or {}
    
    user_requests = []
    for request_id, request_data in all_requests.items():
        if request_data.get('user_id') == uid:
            request_data['id'] = request_id
            user_requests.append(request_data)
    
    # Sort by creation date (newest first)
    user_requests.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return render_template('my_tuition_requests.html', requests=user_requests)

@app.route('/tuition-chat/<request_id>')
def tuition_chat(request_id):
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    uid = session['uid']
    
    # Get request details
    request_ref = db.reference(f'tuition_requests/{request_id}')
    request_data = request_ref.get()
    
    if not request_data:
        abort(404)
    
    # Check if user is participant (original user or admin)
    is_user = request_data.get('user_id') == uid
    is_admin_user = is_admin(uid)
    
    if not (is_user or is_admin_user):
        abort(403)
    
    # Get chat messages
    chat_ref = db.reference(f'tuition_chats/{request_id}')
    chat_data = chat_ref.get() or {}
    
    return render_template('tuition_chat.html', 
                         request_data=request_data, 
                         chat_data=chat_data, 
                         request_id=request_id)

@app.route('/tuition-chat/<request_id>/send', methods=['POST'])
def send_tuition_message(request_id):
    if 'uid' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    message = request.form.get('message', '').strip()
    
    if not message:
        return jsonify({'success': False, 'error': 'Message is required'}), 400
    
    # Verify user has access to this chat
    request_ref = db.reference(f'tuition_requests/{request_id}')
    request_data = request_ref.get()
    
    if not request_data:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    # Check if user is participant
    is_user = request_data.get('user_id') == uid
    is_admin_user = is_admin(uid)  # Use the proper admin check function
    
    if not (is_user or is_admin_user):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    # Add message to chat
    message_data = {
        'sender_id': uid,
        'sender_type': 'admin' if is_admin_user else 'user',
        'message': message,
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    chat_ref = db.reference(f'tuition_chats/{request_id}/messages')
    chat_ref.push(message_data)
    
    # Update last message time
    db.reference(f'tuition_chats/{request_id}').update({
        'last_message_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    return jsonify({'success': True})

@app.route('/tuition-chat/<request_id>/messages', methods=['GET'])
def get_tuition_messages(request_id):
    if 'uid' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    uid = session['uid']
    since = request.args.get('since', '')
    
    # Verify user has access to this chat
    request_ref = db.reference(f'tuition_requests/{request_id}')
    request_data = request_ref.get()
    
    if not request_data:
        return jsonify({'success': False, 'error': 'Request not found'}), 404
    
    # Check if user is participant
    is_user = request_data.get('user_id') == uid
    is_admin_user = is_admin(uid)
    
    if not (is_user or is_admin_user):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    # Get messages since the specified time
    chat_ref = db.reference(f'tuition_chats/{request_id}')
    chat_data = chat_ref.get() or {}
    
    messages = []
    if 'messages' in chat_data:
        for message_id, message in chat_data['messages'].items():
            if since and message.get('timestamp', '') <= since:
                continue
            messages.append(message)
    
    # Sort by timestamp
    messages.sort(key=lambda x: x.get('timestamp', ''))
    
    return jsonify({
        'success': True,
        'messages': messages,
        'last_message_time': chat_data.get('last_message_time', '')
    })

# Admin Tuition Management Routes
@app.route('/admin/tuition-requests')
@admin_required
def admin_tuition_requests():
    tuition_requests_ref = db.reference('tuition_requests')
    all_requests = tuition_requests_ref.get() or {}
    
    requests_list = []
    for request_id, request_data in all_requests.items():
        request_data['id'] = request_id
        requests_list.append(request_data)
    
    # Sort by creation date (newest first)
    requests_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return render_template('admin_tuition_requests.html', requests=requests_list, active_page='tuition_requests')

@app.route('/admin/tuition-chat/<request_id>')
@admin_required
def admin_tuition_chat(request_id):
    # Get request details
    request_ref = db.reference(f'tuition_requests/{request_id}')
    request_data = request_ref.get()
    
    if not request_data:
        abort(404)
    
    # Get chat messages
    chat_ref = db.reference(f'tuition_chats/{request_id}')
    chat_data = chat_ref.get() or {}
    
    # Assign admin to request if not already assigned
    if not request_data.get('admin_assigned'):
        db.reference(f'tuition_requests/{request_id}').update({
            'admin_assigned': session['uid'],
            'status': 'in_progress'
        })
    
    return render_template('admin_tuition_chat.html', 
                         request_data=request_data, 
                         chat_data=chat_data, 
                         request_id=request_id,
                         active_page='tuition_requests')

@app.route('/admin/tuition/update-status', methods=['POST'])
@admin_required
def update_tuition_status():
    """Update tuition request status by admin"""
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        new_status = data.get('status')
        
        if not request_id or not new_status:
            return jsonify({'success': False, 'error': 'Request ID and status are required'}), 400
        
        # Validate status
        valid_statuses = ['pending', 'in_progress', 'completed']
        if new_status not in valid_statuses:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        
        # Get current request data
        request_ref = db.reference(f'tuition_requests/{request_id}')
        request_data = request_ref.get()
        
        if not request_data:
            return jsonify({'success': False, 'error': 'Request not found'}), 404
        
        # Update the status
        request_ref.update({
            'status': new_status,
            'status_updated_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status_updated_by': session['uid']
        })
        
        # Add a system message to the chat about status change
        admin_user_ref = db.reference(f'users/{session["uid"]}')
        admin_user = admin_user_ref.get()
        admin_name = admin_user.get('name', 'Admin') if admin_user else 'Admin'
        
        status_message = f"Status updated to '{new_status.replace('_', ' ').title()}' by {admin_name}"
        
        status_update_data = {
            'sender_type': 'system',
            'message': status_message,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        chat_ref = db.reference(f'tuition_chats/{request_id}/messages')
        chat_ref.push(status_update_data)
        
        # Update last message time
        db.reference(f'tuition_chats/{request_id}').update({
            'last_message_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        print(f"DEBUG: Updated request {request_id} status to {new_status} by admin {session['uid']}")
        
        return jsonify({'success': True, 'message': f'Status updated to {new_status}'})
    
    except Exception as e:
        print(f"ERROR: Failed to update tuition status: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Feature Management Routes
@app.route('/admin/features')
@admin_required
def admin_features():
    """Admin page to manage feature visibility"""
    features_ref = db.reference('admin_settings/features')
    features = features_ref.get() or {}
    
    # Default feature settings if none exist
    default_features = {
        'ai_chat': {'enabled': True, 'name': 'AI Chat', 'description': 'AI-powered chat assistance'},
        'tuition': {'enabled': False, 'name': 'Tuition', 'description': 'Connect with expert tutors'},
        'papers': {'enabled': False, 'name': 'Papers', 'description': 'Access past papers and practice tests'},
        'ai_image': {'enabled': False, 'name': 'AI Image', 'description': 'Generate and analyze images'},
        'study_planner': {'enabled': True, 'name': 'Study Planner', 'description': 'Organize your study schedule'}
    }
    
    # Initialize database with default features if empty
    if not features:
        print("DEBUG: No features found in database, initializing with defaults")
        features_ref.set(default_features)
        features = default_features
    else:
        # Merge with existing settings to add any new features
        updated = False
        for feature_key, default_config in default_features.items():
            if feature_key not in features:
                features[feature_key] = default_config
                updated = True
        
        # Save any new features to database
        if updated:
            features_ref.set(features)
    
    print(f"DEBUG: Features data being sent to template: {features}")
    
    return render_template('admin_features.html', features=features, active_page='features')

@app.route('/admin/features/toggle', methods=['POST'])
@admin_required
def toggle_feature():
    """Toggle feature visibility"""
    try:
        data = request.get_json()
        feature_key = data.get('feature_key')
        enabled = data.get('enabled')
        
        if not feature_key:
            return jsonify({'success': False, 'error': 'Feature key is required'}), 400
        
        features_ref = db.reference('admin_settings/features')
        
        # Get current feature data
        current_feature = features_ref.child(feature_key).get()
        
        # Default feature data in case it doesn't exist
        default_features = {
            'ai_chat': {'name': 'AI Chat', 'description': 'AI-powered chat assistance'},
            'tuition': {'name': 'Tuition', 'description': 'Connect with expert tutors'},
            'papers': {'name': 'Papers', 'description': 'Access past papers and practice tests'},
            'ai_image': {'name': 'AI Image', 'description': 'Generate and analyze images'},
            'study_planner': {'name': 'Study Planner', 'description': 'Organize your study schedule'}
        }
        
        # Preserve existing data or use defaults
        feature_data = current_feature or default_features.get(feature_key, {})
        feature_data['enabled'] = enabled
        
        # Ensure name and description exist
        if 'name' not in feature_data and feature_key in default_features:
            feature_data['name'] = default_features[feature_key]['name']
        if 'description' not in feature_data and feature_key in default_features:
            feature_data['description'] = default_features[feature_key]['description']
        
        # Update the feature
        features_ref.child(feature_key).set(feature_data)
        
        print(f"DEBUG: Updated feature {feature_key} with data: {feature_data}")
        
        return jsonify({'success': True, 'message': f'Feature {feature_key} updated successfully'})
    
    except Exception as e:
        print(f"ERROR: Failed to toggle feature: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def get_enabled_features():
    """Helper function to get currently enabled features"""
    features_ref = db.reference('admin_settings/features')
    features = features_ref.get() or {}
    
    # Default enabled features if no settings exist
    default_enabled = {
        'ai_chat': True,
        'tuition': False,
        'papers': False,
        'ai_image': False,
        'study_planner': True
    }
    
    enabled_features = {}
    for feature_key, default_status in default_enabled.items():
        if feature_key in features:
            enabled_features[feature_key] = features[feature_key].get('enabled', default_status)
        else:
            enabled_features[feature_key] = default_status
    
    return enabled_features

@app.route('/api/firebase-config')
def get_firebase_config():
    """Return Firebase configuration for client-side initialization"""
    config = {
        'apiKey': os.getenv('FIREBASE_API_KEY'),
        'authDomain': f"{os.getenv('FIREBASE_PROJECT_ID')}.firebaseapp.com",
        'databaseURL': os.getenv('FIREBASE_DATABASE_URL'),
        'projectId': os.getenv('FIREBASE_PROJECT_ID')
    }
    
    print(f"DEBUG: Firebase config being sent to client: {config}")
    
    # Check for missing configuration
    missing_configs = [key for key, value in config.items() if not value]
    if missing_configs:
        print(f"WARNING: Missing Firebase configuration: {missing_configs}")
    
    return jsonify(config)

@app.route('/api/enabled-features')
def get_enabled_features_api():
    """API endpoint to get currently enabled features"""
    enabled_features = get_enabled_features()
    print(f"DEBUG: Enabled features API called, returning: {enabled_features}")
    return jsonify(enabled_features)

@app.route('/debug/firebase-test')
def debug_firebase_test():
    """Debug endpoint to test Firebase connectivity"""
    try :
        features_ref = db.reference('admin_settings/features')
        features = features_ref.get()
        
        return jsonify({
            'success': True,
            'firebase_data': features,
            'firebase_url': os.getenv('FIREBASE_DATABASE_URL'),
            'project_id': os.getenv('FIREBASE_PROJECT_ID'),
            'api_key_present': bool(os.getenv('FIREBASE_API_KEY'))
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'firebase_url': os.getenv('FIREBASE_DATABASE_URL'),
            'project_id': os.getenv('FIREBASE_PROJECT_ID'),
            'api_key_present': bool(os.getenv('FIREBASE_API_KEY'))
        })


# Papers Feature Routes
@app.route('/papers')
def papers():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    # Get search parameters
    subject = request.args.get('subject', '')
    paper_type = request.args.get('paper_type', '')
    
    # Get all papers from database
    all_papers = papers_ref.get() or {}
    
    papers_list = []
    subjects_set = set()  # To store unique subjects
    
    for paper_id, paper_data in all_papers.items():
        paper_data['id'] = paper_id
        papers_list.append(paper_data)
        # Add subject to subjects set
        if 'subject' in paper_data:
            subjects_set.add(paper_data['subject'])
    
    # Convert set to sorted list
    subjects_list = sorted(list(subjects_set))
    
    # Only apply filters and show papers if at least one filter is applied
    if subject or paper_type:
        filtered_papers = []
        for paper in papers_list:
            # Check subject (case insensitive partial match)
            subject_match = not subject or (paper.get('subject', '') and subject.lower() in paper['subject'].lower())
            
            # Check paper type (case insensitive exact match)
            paper_type_match = not paper_type or (paper.get('paper_type', '') and paper_type.lower() == paper['paper_type'].lower())
            
            if subject_match and paper_type_match:
                filtered_papers.append(paper)
        
        papers_list = filtered_papers
    else:
        # If no filters are applied, show an empty list
        papers_list = []
    
    # Sort by creation date (newest first)
    papers_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    return render_template('papers.html', papers=papers_list, subjects=subjects_list)

@app.route('/download_paper/<paper_id>')
def download_paper(paper_id):
    """Download a paper directly from Google Drive"""
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    try:
        # Get the paper from database
        paper_ref = papers_ref.child(paper_id)
        paper = paper_ref.get()
        
        if not paper:
            abort(404, description="Paper not found")
        
        # Get the Google Drive link
        drive_link = paper.get('drive_link')
        if not drive_link:
            abort(404, description="Paper link not found")
        
        # Convert Google Drive sharing link to direct download link
        # Handle different Google Drive URL formats
        direct_link = convert_drive_link_to_direct(drive_link)
        
        # Redirect to the direct download link
        return redirect(direct_link)
        
    except Exception as e:
        print(f"ERROR: Failed to download paper {paper_id}: {str(e)}")
        abort(500, description="Failed to download paper")

def convert_drive_link_to_direct(drive_link):
    """Convert Google Drive sharing link to direct download link"""
    import re
    
    # Handle different Google Drive URL formats
    # Format 1: https://drive.google.com/file/d/FILE_ID/view?usp=sharing
    file_id_match = re.search(r'/file/d/([^/]+)/', drive_link)
    if file_id_match:
        file_id = file_id_match.group(1)
        return f"https://drive.google.com/uc?export=download&id={file_id}"
    
    # Format 2: https://drive.google.com/open?id=FILE_ID
    open_id_match = re.search(r'[?&]id=([^&]+)', drive_link)
    if open_id_match:
        file_id = open_id_match.group(1)
        return f"https://drive.google.com/uc?export=download&id={file_id}"
    
    # Format 3: Already a direct link
    if 'uc?export=download' in drive_link:
        return drive_link
    
    # If we can't parse it, return the original link
    return drive_link

@app.route('/admin/papers')
@admin_required
def admin_papers():
    # Get all papers from database
    all_papers = papers_ref.get() or {}
    
    papers_list = []
    subjects_set = set()
    streams_set = set()
    
    for paper_id, paper_data in all_papers.items():
        paper_data['id'] = paper_id
        papers_list.append(paper_data)
        
        # Collect unique subjects and streams for filters
        if 'subject' in paper_data:
            subjects_set.add(paper_data['subject'])
        if 'stream' in paper_data:
            streams_set.add(paper_data['stream'])
    
    # Sort by creation date (newest first)
    papers_list.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    # Convert sets to sorted lists
    subjects_list = sorted(list(subjects_set))
    streams_list = sorted(list(streams_set))
    
    return render_template('admin_papers.html', 
                         papers=papers_list, 
                         subjects=subjects_list, 
                         streams=streams_list, 
                         active_page='papers')

@app.route('/admin/papers/add', methods=['POST'])
@admin_required
def admin_add_paper():
    try:
        # Get form data
        stream = request.form.get('stream')
        subject = request.form.get('subject')
        topic = request.form.get('topic')
        question_type = request.form.get('question_type')
        paper_type = request.form.get('paper_type')
        drive_link = request.form.get('drive_link')
        
        # Get conditional fields based on paper type
        year = request.form.get('year')
        province = request.form.get('province')
        school = request.form.get('school')
        
        if not all([stream, subject, topic, question_type, paper_type, drive_link]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Validate drive link
        if not drive_link.startswith('https://'):
            return jsonify({'success': False, 'error': 'Invalid drive link'}), 400
        
        # Create paper data
        paper_data = {
            'stream': stream,
            'subject': subject,
            'topic': topic,
            'question_type': question_type,
            'paper_type': paper_type,
            'drive_link': drive_link,
            'created_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'created_by': session['uid']
        }
        
        # Add conditional fields
        if year:
            paper_data['year'] = year
        if province:
            paper_data['province'] = province
        if school:
            paper_data['school'] = school
            
        # Save to database
        new_paper_ref = papers_ref.push(paper_data)
        
        return jsonify({'success': True, 'message': 'Paper added successfully', 'paper_id': new_paper_ref.key})
        
    except Exception as e:
        print(f"ERROR: Failed to add paper: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/papers/edit/<paper_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_paper(paper_id):
    try:
        # Get the paper from database
        paper_ref = papers_ref.child(paper_id)
        paper = paper_ref.get()
        
        if not paper:
            return jsonify({'success': False, 'error': 'Paper not found'}), 404
        
        if request.method == 'GET':
            # Return paper data for editing
            return jsonify({'success': True, 'paper': paper, 'paper_id': paper_id})
        
        # Handle POST request - update paper
        # Get form data
        stream = request.form.get('stream')
        subject = request.form.get('subject')
        topic = request.form.get('topic')
        question_type = request.form.get('question_type')
        paper_type = request.form.get('paper_type')
        drive_link = request.form.get('drive_link')
        
        # Get conditional fields based on paper type
        year = request.form.get('year')
        province = request.form.get('province')
        school = request.form.get('school')
        
        if not all([stream, subject, topic, question_type, paper_type, drive_link]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Validate drive link
        if not drive_link.startswith('https://'):
            return jsonify({'success': False, 'error': 'Invalid drive link'}), 400
        
        # Create updated paper data
        paper_data = {
            'stream': stream,
            'subject': subject,
            'topic': topic,
            'question_type': question_type,
            'paper_type': paper_type,
            'drive_link': drive_link,
            'created_at': paper.get('created_at', datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            'created_by': paper.get('created_by', session['uid']),
            'updated_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'updated_by': session['uid']
        }
        
        # Add conditional fields
        if year:
            paper_data['year'] = year
        if province:
            paper_data['province'] = province
        if school:
            paper_data['school'] = school
            
        # Update in database
        paper_ref.update(paper_data)
        
        return jsonify({'success': True, 'message': 'Paper updated successfully'})
        
    except Exception as e:
        print(f"ERROR: Failed to edit paper: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/papers/delete/<paper_id>', methods=['POST'])
@admin_required
def admin_delete_paper(paper_id):
    try:
        # Get the paper from database
        paper_ref = papers_ref.child(paper_id)
        paper = paper_ref.get()
        
        if not paper:
            return jsonify({'success': False, 'error': 'Paper not found'}), 404
        
        # Delete from database
        paper_ref.delete()
        
        return jsonify({'success': True, 'message': 'Paper deleted successfully'})
        
    except Exception as e:
        print(f"ERROR: Failed to delete paper: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("DEBUG", "True").lower() == "true"  # Enable debug mode
    app.run(host='0.0.0.0', port=port, debug=debug_mode)