"""This file contains the authentication routes for user registration, login, and profile management.
The features like validation of user inputs, password hassing, password complexcity checks, 
CAPTCHA validation, logs registation attempts, JWT token creation, updation of login timestemp,etc."""


from flask import Blueprint, request, jsonify, session
from flask_jwt_extended import create_access_token, verify_jwt_in_request, get_jwt_identity
from datetime import datetime
import re
from functools import wraps

auth_bp = Blueprint('auth', __name__)

# Models will be imported when the blueprint is registered
User = None # demosnstrates the user model
LoginAttempt = None # demosntrates the login attempt model
db = None # here it is also a SQLAlchemy object used to interact with the database

def init_auth_routes(user_model, login_attempt_model, database):
    """Initialize routes with models"""
    global User, LoginAttempt, db
    User = user_model
    LoginAttempt = login_attempt_model
    db = database
User = None
LoginAttempt = None
db = None

def init_auth_models():# creates user as global variable.
    """Initialize models for auth blueprint"""
    global User, LoginAttempt, db
    from models import User, LoginAttempt, db

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_captcha(captcha_response):
    """Validate reCAPTCHA response"""
    # This is a placeholder - in production, use actual reCAPTCHA validation
    return True

def log_login_attempt(ip_address, email, success, user_agent=None):
    """Log login attempt to database"""
    attempt = LoginAttempt(
        ip_address=ip_address,
        email=email,
        success=success,
        user_agent=user_agent
    )
    db.session.add(attempt)
    db.session.commit()

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Authentication required'}), 401
    return decorated_function

@auth_bp.route('/register', methods=['POST']) # Used for user registrarion.
def register():
    try:
        data = request.get_json()
                
        # the following code make sure that input validation is performed.
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'User')
        captcha_response = data.get('captcha', '')
        
        # Validate required fields
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        password_valid, password_message = validate_password(password)
        if not password_valid:
            return jsonify({'error': password_message}), 400
        
        # Validate CAPTCHA
        if not validate_captcha(captcha_response):
            return jsonify({'error': 'CAPTCHA validation failed'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        
        # Validate role
        if role not in ['Admin', 'User']:
            role = 'User'
        
        # Create new user
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Log successful registration
        log_login_attempt(request.remote_addr, email, True, request.headers.get('User-Agent'))
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login(): # Funciton to handle user login and its validation.
    try:
        data = request.get_json()
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        captcha_response = data.get('captcha', '')
        
        # Validate required fields
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Validate CAPTCHA
        if not validate_captcha(captcha_response):
            return jsonify({'error': 'CAPTCHA validation failed'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user:
            log_login_attempt(request.remote_addr, email, False, request.headers.get('User-Agent'))
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_account_locked():
            return jsonify({'error': 'Account is temporarily locked due to multiple failed attempts'}), 423
        
        # Check if account is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Verify password
        if not user.check_password(password):
            user.increment_failed_attempts()
            log_login_attempt(request.remote_addr, email, False, request.headers.get('User-Agent'))
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Successful login
        user.unlock_account()  # Reset failed attempts
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Create JWT token
        access_token = create_access_token(
            identity=str(user.id),  # Convert to string for JWT subject
            additional_claims={'role': user.role, 'username': user.username}
        )
        
        # Debug logging
        print(f"Login successful for user: {user.username}, role: {user.role}")
        print(f"JWT token created with sub: {user.id}, role: {user.role}, username: {user.username}")
        
        log_login_attempt(request.remote_addr, email, True, request.headers.get('User-Agent'))
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout(): # Used for user logout
    # In a production app, you might want to blacklist the token
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/profile', methods=['GET'])
@require_auth
def profile(): # Used for fetching user profile information.
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch profile'}), 500


# This is the end of the authentication file.