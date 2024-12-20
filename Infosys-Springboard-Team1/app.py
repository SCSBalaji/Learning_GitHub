import sqlite3
import random
import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv
import os
import string

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'C:\\Users\\HP CORE I5\\Downloads\\hifi_eats\\Infosys-Springboard-Team1\\existing_database.db'
JWT_SECRET = 'your_jwt_secret'  # Add a secret key for JWT

# Configuring Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)


# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'mailforterting@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'Chaitanya@332006'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'mailforterting@gmail.com'  # Replace with your email

mail = Mail(app)
# Configuring OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/google/callback',
    client_kwargs={'scope': 'openid email profile'}
)
facebook = oauth.register(
    name='facebook',
    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),
    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET'),
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/facebook/callback',
    client_kwargs={'scope': 'email'}
)
twitter = oauth.register(
    name='twitter',
    client_id=os.environ.get('TWITTER_CLIENT_ID'),
    client_secret=os.environ.get('TWITTER_CLIENT_SECRET'),
    request_token_url='https://api.twitter.com/oauth/request_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    access_token_url='https://api.twitter.com/oauth/access_token',
    access_token_params=None,
    redirect_uri='http://localhost:5000/twitter/callback',
    client_kwargs={'scope': 'email'}
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_token(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None

# Function to generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP email
def send_otp_email(recipient, otp):
    msg = Message('Your OTP Code', recipients=[recipient])
    msg.body = f'Your OTP code is {otp}'
    msg.sender = app.config['MAIL_DEFAULT_SENDER']  # Ensure sender is specified
    mail.send(msg)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        contact_info = request.form['contact_info']
        
        # Generate OTP and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['contact_info'] = contact_info
        
        # Send OTP to user's email
        send_otp_email(contact_info, otp)
        
        flash('OTP sent to your registered contact.', 'success')
        return redirect(url_for('verify_otp'))
    
    return render_template('forgot.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        verification_code = request.form['verification_code']
        
        # Retrieve the OTP from the session
        stored_otp = session.get('otp')
        
        if verification_code == stored_otp:
            flash('Verification successful!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            # Hash the new password
            hashed_password = generate_password_hash(new_password)

            # Update the user's password in the database
            conn = get_db()
            cursor = conn.cursor()
            contact_info = session.get('contact_info')
            cursor.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_password, contact_info))
            conn.commit()
            conn.close()
            
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('signin'))  # Redirect to the sign-in page
        else:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('reset_password'))
    
    return render_template('reset_password.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['phone-email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            if check_password_hash(user['password_hash'], password):
                if user['is_active']:
                    session['user'] = email
                    flash('Sign in successful!', 'success')
                    
                    if user['is_admin']:
                        return redirect(url_for('admin_dashboard'))
                    return redirect(url_for('dashboard'))
                else:
                    flash('Please confirm your email before logging in.', 'error')
                    return redirect(url_for('signin'))
            else:
                flash('Incorrect password. Please try again.', 'error')
                return redirect(url_for('signin'))
        else:
            flash('Email not found. Please register or check your email.', 'error')
            return redirect(url_for('signin'))
    
    return render_template('signin.html')
def is_admin():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {user_email} is {'an admin' if user['is_admin'] == 1 else 'not an admin'}")
    return user and user['is_admin'] == 1

@app.route('/admin/assign_role', methods=['GET', 'POST'])
def assign_role():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        is_admin_role = request.form.get('is_admin') == 'on'

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_admin = ? WHERE email = ?', (1 if is_admin_role else 0, email))
        conn.commit()
        conn.close()

        flash(f'Role updated for {email}', 'success')
        return redirect(url_for('assign_role'))

    return render_template('assign_role.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        full_name = request.form['full_name']
        phone_number = request.form['phone_number']
        is_admin_role = request.form.get('is_admin') == 'on'
        cursor.execute(
            'UPDATE users SET full_name = ?, phone_number = ?, is_admin = ? WHERE id = ?',
            (full_name, phone_number, 1 if is_admin_role else 0, user_id)
        )
        conn.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/deactivate_user/<int:user_id>')
def deactivate_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deactivated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Google login route
@app.route('/google_login')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_auth():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    session['user'] = user_info['email']
    flash('You have successfully logged in with Google.', 'success')
    return redirect(url_for('dashboard'))

# Facebook login route
@app.route('/facebook_login')
def facebook_login():
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/callback')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    user_info = oauth.facebook.get('me?fields=id,name,email').json()
    session['user'] = user_info['email']
    flash('You have successfully logged in with Facebook.', 'success')
    return redirect(url_for('dashboard'))

# Twitter login route
@app.route('/twitter_login')
def twitter_login():
    redirect_uri = url_for('twitter_auth', _external=True)
    return oauth.twitter.authorize_redirect(redirect_uri)

@app.route('/twitter/callback')
def twitter_auth():
    token = oauth.twitter.authorize_access_token()
    user_info = oauth.twitter.get('account/verify_credentials.json').json()
    session['user'] = user_info['email']
    flash('You have successfully logged in with Twitter.', 'success')
    return redirect(url_for('dashboard'))



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        full_name = request.form['full-name']
        phone_number = request.form['phone-number']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute('INSERT INTO users (email, password_hash, full_name, phone_number, is_active) VALUES (?, ?, ?, ?, ?)',
                       (email, hashed_password, full_name, phone_number, 0))  # Initially inactive
        conn.commit()

        # Send confirmation email
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm your email', sender=os.environ.get('EMAIL_USER'), recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f"Hello, welcome to HiFi Eats! Please confirm your email by clicking the link below:\n\n{link}"
        mail.send(msg)
        
        flash('Registration successful! A confirmation email has been sent to your email address.', 'success')
        return redirect(url_for('signup'))
    
    return render_template('signup.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        # Update user status to confirmed in the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_active = 1 WHERE email = ?', (email,))
        conn.commit()
        conn.close()
    except SignatureExpired:
        flash('The confirmation link has expired.')
        return redirect(url_for('signup'))

    flash('Email confirmed successfully! You can now log in.')
    return redirect(url_for('signin'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        user_email = session['user']
        if is_admin():
            print("Admin user detected, redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))
        print("Regular user detected, rendering user dashboard")
        return render_template('dashboard.html', user_email=user_email)
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('signin'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)
