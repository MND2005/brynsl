from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort
import firebase_admin
from firebase_admin import credentials, db, initialize_app
import requests
import datetime
from dotenv import load_dotenv
import google.generativeai as genai
import os
import tempfile
from functools import wraps
from functools import wraps
import random
from mailersend import emails
import smtplib
from email.message import EmailMessage
import logging



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


# Configure Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.0-flash')

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")  # from Firebase > Project Settings > General

# Add this near your other Firebase initialization
notifications_ref = db.reference('notifications')
user_notifications_ref = db.reference('user_notifications')
ideas_ref = db.reference('ideas')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/launch')
def launch():
    return render_template('launch.html')


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
        return redirect(url_for('dashboard'))
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
        return redirect(url_for('dashboard'))

    return render_template('login.html')

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

    today = datetime.date.today()
    trial_ends = datetime.datetime.strptime(user['trial_ends'], "%Y-%m-%d %H:%M:%S")
    now = datetime.datetime.now()

    if now > trial_ends and not user['activated']:
        return render_template('payment_pending.html')

    return render_template('index.html', email=user['email'], unread_count=unread_count)

@app.route('/ask', methods=['POST'])
def ask_question():
    if 'uid' not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    try:
        question = request.form.get('question')
        language = request.form.get('language', 'sinhala')  # Default to Sinhala
        image = request.files.get('image')
        image_parts = []
        
        if image:
            # Save temporarily and process
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                image.save(temp.name)
                image_part = {
                    "mime_type": image.mimetype,
                    "data": temp.read()
                }
                image_parts.append(image_part)
            
            # Modified prompt with language selection
            fixed_prompt = f"""
            Analyze the question, solve it, and give the explanation and answer in {language} language.
            Do not bold any text and only include texts and emojis.
            """
            question = f"{fixed_prompt}\n\nUser question: {question}"
        
        # Generate content
        if image_parts:
            response = model.generate_content([question, *image_parts])
        else:
            # For text-only questions, still include language preference
            prompt = f"""
            Chat in {language} language.
            Do not bold any text and only include texts.
            
           Answer to input: {question}
            """
            response = model.generate_content(prompt)
        
        return jsonify({
            "success": True,
            "response": response.text
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

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
                "paid_duration_minutes": 5  # 30 days in minutes
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




@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect(url_for('login'))

    uid = session['uid']
    user_ref = db.reference(f'users/{uid}')
    user = user_ref.get()

    if not user:
        return redirect(url_for('login'))

    # Calculate account status (same as before)
    now = datetime.datetime.now()
    if user.get('activated'):
        status = "Active"
        if user.get('payment_date') and user.get('paid_duration_minutes'):
            payment_date = datetime.datetime.strptime(user['payment_date'], "%Y-%m-%d %H:%M:%S")
            expiry_date = payment_date + datetime.timedelta(minutes=user['paid_duration_minutes'])
            status = f"Active (Expires: {expiry_date.strftime('%Y-%m-%d %H:%M')})"
    else:
        trial_ends = datetime.datetime.strptime(user['trial_ends'], "%Y-%m-%d %H:%M:%S")
        if now > trial_ends:
            status = "Expired"
        else:
            status = f"Trial (Expires: {trial_ends.strftime('%Y-%m-%d %H:%M')})"

    return render_template('profile.html', 
                         email=user.get('email'),
                         name=user.get('name'),
                         birthday=user.get('birthday'),
                         phone=user.get('phone'),
                         signup_date=user.get('signup_date'),
                         status=status)

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

    # Query parameters for filtering
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    status_filter = request.args.get('status', 'all')  # all, active, trial, expired

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
                         start_date=start_date,
                         end_date=end_date,
                         status_filter=status_filter,
                         users=users_data,
                         active_page='user_stats')

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)