"""This is the main python file that combines all the other files into web application."""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt  # type: ignore
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from datetime import datetime, timedelta
import os
from functools import wraps
import re

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///user_auth.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string-change-this')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Initialize models
from models import create_models
User, LoginAttempt = create_models(db, bcrypt)

# Import blueprints after models to avoid circular imports
from routes.auth import auth_bp, init_auth_routes
from routes.admin import admin_bp, init_admin_routes
from routes.user import user_bp, init_user_routes

# Initialize routes with models
init_auth_routes(User, LoginAttempt, db)
init_admin_routes(User, LoginAttempt, db)
init_user_routes(User, db)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(user_bp, url_prefix='/user')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        print("💡 Try running: python init_db.py")
        exit(1)
    
    # Try port 5000, if busy try 5001, 5002, or any other free port just make appropriate changes here.
    port = 5000
    while True:
        try:
            print(f"🚀 Starting server on port {port}...")
            app.run(debug=True, host='0.0.0.0', port=port)
            break
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"⚠️  Port {port} is busy, trying {port + 1}...")
                port += 1
                if port > 5010:
                    print("❌ Could not find an available port between 5000-5010")
                    break
            else:
                raise e

# This is the end of app.py file.