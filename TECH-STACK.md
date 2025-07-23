# Tech Stack Overview

## Secure Login System

## **Backend**

### Core Framework
- **Flask 2.3.3**
- Python web framework
- Lightweoght and flexible
- Blueprint architecture for modular code.

### Databases and ORM
- **SQLAlchemy 3.0.5**: Object relational mapping.
- **SQLite**: Default database.
- **MySQL/PostgreSQL**: Production ready option.
- **PyMySQL**: MuSQL connector

### Security and Authentication
- Flask Bcyrpt 1.0.1
- Flask-JWT-Extended 4.5.3
- Cryptograpy 41.0.4

### Configuration and Environment
- Python-dotenv 1.0.0

### Validations
- Email-validator 2.0.0
- Request 2.31.0: HTTP library for external API calls
- Werkzeug 2.3.7: Flask dependency 

## **Frontend**

### Core Framework
- **HTML5**
- **CSS3**
- **Vasnilla JavaScript (ES6+)**

### UI/UX
Simple responsicve design (mobile friendly)
Clean and Professional interface.

### Database Engine
- **SQLite** (Development) - File-based database
- **MySQL/PostgreSQL** (Production) - Scalable RDBMS

### Data Models
```**sql**
Users Table:
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash (bcrypt)
- role (admin/user)
- is_active (Boolean)
- created_at (Timestamp)
- updated_at (Timestamp)

LoginAttempts Table:
- id (Primary Key)
- username (Foreign Key)
- attempt_time (Timestamp)
- success (Boolean)
- ip_address (String)
```

## Architecture Pattern

### Backend
- MVC pattern
- Blueprint pattern
- Dynamic module creation

### Security
- Input Validation
- Brute Forece Protection
- Secure Session

  ## Development Tools & Environment

### Language & Runtime
- **Python 3.13** - Programming language
- **pip** - Package manager
- **Virtual Environment** - Isolated dependencies

### Development Tools
- **VS Code** - Integrated Development Environment
- **Git** - Version control
- **GitHub** - Code repository
- **ngrok** - Local tunnel for external access

### Deployment Tools
- **Gunicorn** - Production WSGI server
- **Docker** (Optional) - Containerization
- **Heroku/PythonAnywhere** - Cloud deployment platforms

## 🌐 **Network & Deployment**

### **Local Development**
- **Flask Development Server** - Built-in server
- **Local Network Access** - 0.0.0.0 binding
- **ngrok Tunneling** - Public internet access

### **Production Deployment Options**
- **Cloud Platforms**: Heroku, PythonAnywhere, Railway, Render
- **VPS/Dedicated**: Ubuntu/CentOS with Nginx + Gunicorn
- **Container**: Docker + Kubernetes


## **Key Features Implemented**

### **Core Functionality**
✅ User Registration & Login  
✅ Password Security (bcrypt)  
✅ JWT Authentication  
✅ Role-Based Access Control  
✅ Admin Panel  
✅ Account Lockout Protection  
✅ Input Validation  
✅ Responsive Design  
✅ Real-time Form Validation  
✅ Secure Session Management  

### **Security Features**
✅ SQL Injection Prevention  
✅ Password Strength Requirements  
✅ Rate Limiting  
✅ Secure Headers  
✅ Environment Configuration  
✅ Error Handling  

## 📋 **Project Structure**

```
├── app.py                 # Main Flask application
├── config.py             # Configuration management
├── models.py             # Database models
├── requirements.txt      # Python dependencies
├── init_db.py           # Database initialization
├── routes/              # Modular route blueprints
│   ├── auth.py          # Authentication routes
│   ├── admin.py         # Admin panel routes
│   └── user.py          # User management routes
├── templates/           # HTML templates
│   ├── base.html        # Base template
│   ├── index.html       # Landing page
│   ├── login.html       # Login form
│   ├── register.html    # Registration form
│   └── dashboard.html   # User dashboard
├── static/              # Static assets
│   ├── css/
│   │   └── style.css    # Main stylesheet
│   └── js/
│       ├── main.js      # Core JavaScript
│       └── dashboard.js # Dashboard functionality
└── instance/            # Instance-specific files
    └── user_auth.db     # SQLite database
```
