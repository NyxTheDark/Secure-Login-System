from datetime import datetime, timedelta

# This will be set by app.py
db = None
bcrypt = None

class User:
    """User model - initialized dynamically"""
    pass

class LoginAttempt:
    """LoginAttempt model - initialized dynamically"""
    pass

# This function will be called from app.py to initialize models
def create_models(database, bcrypt_instance):
    global db, bcrypt
    db = database
    bcrypt = bcrypt_instance
    
    class User(db.Model):
        __tablename__ = 'users'
        
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        role = db.Column(db.String(20), nullable=False, default='User')  # Using String instead of Enum for SQLite compatibility
        is_active = db.Column(db.Boolean, default=True)
        failed_login_attempts = db.Column(db.Integer, default=0)
        account_locked_until = db.Column(db.DateTime, nullable=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        last_login = db.Column(db.DateTime, nullable=True)
        
        def set_password(self, password):
            """Hash and set the password"""
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        def check_password(self, password):
            """Check if provided password matches the hash"""
            return bcrypt.check_password_hash(self.password_hash, password)
        
        def is_account_locked(self):
            """Check if account is currently locked"""
            if self.account_locked_until:
                return datetime.utcnow() < self.account_locked_until
            return False
        
        def lock_account(self, minutes=30):
            """Lock account for specified minutes"""
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=minutes)
            db.session.commit()
        
        def unlock_account(self):
            """Unlock account and reset failed attempts"""
            self.failed_login_attempts = 0
            self.account_locked_until = None
            db.session.commit()
        
        def increment_failed_attempts(self):
            """Increment failed login attempts"""
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.lock_account()
            db.session.commit()
        
        def to_dict(self):
            """Convert user object to dictionary"""
            return {
                'id': self.id,
                'username': self.username,
                'email': self.email,
                'role': self.role,
                'is_active': self.is_active,
                'created_at': self.created_at.isoformat(),
                'last_login': self.last_login.isoformat() if self.last_login else None
            }

    class LoginAttempt(db.Model):
        __tablename__ = 'login_attempts'
        
        id = db.Column(db.Integer, primary_key=True)
        ip_address = db.Column(db.String(45), nullable=False)
        email = db.Column(db.String(120), nullable=True)
        success = db.Column(db.Boolean, nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        user_agent = db.Column(db.Text, nullable=True)
    
    # Update globals
    globals()['User'] = User
    globals()['LoginAttempt'] = LoginAttempt
    
    return User, LoginAttempt
