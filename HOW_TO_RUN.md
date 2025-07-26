# 🚀 How to Run the User Authentication System

This guide will walk you through running the complete user registration and login system on your computer.

## 📋 Prerequisites

Before running the application, make sure you have:

1. **Python 3.7+** installed on your system
2. **Git** (if cloning from repository)
3. **Command line access** (Terminal/PowerShell/Command Prompt)

---

## 🛠️ Step 1: Setup and Installation

### Option A: If you already have the project folder
```bash
# Navigate to the project directory
cd c:\yourpath\valtec
```

### Option B: If downloading/cloning for the first time
```bash
# Clone the repository (if from Git)
git clone <repository-url>
cd valtec

# OR if you have a ZIP file, extract it and navigate to the folder
cd path/to/extracted/valtec
```

---

## 📦 Step 2: Install Dependencies

Install all required Python packages:

```bash
# Install required packages
pip install -r requirements.txt
```

**What this installs:**
- Flask (web framework)
- Flask-SQLAlchemy (database)
- Flask-Bcrypt (password hashing)
- Flask-JWT-Extended (authentication tokens)
- Other security and utility packages

---

## 🗄️ Step 3: Initialize the Database

Set up the database with sample data:

```bash
# Create database and add sample users
python init_db.py
```

**What this does:**
- Creates the SQLite database (`instance/user_auth.db`)
- Sets up user and login_attempts tables
- Adds sample users:
  - **Admin**: email: `admin@example.com`, password: `Admin123!`
  - **Regular User**: email: `user@example.com`, password: `User123!`

---

## 🏃‍♂️ Step 4: Run the Application

Start the Flask development server:

```bash
# Start the server
python app.py
```

**Expected output:**
```
✅ Database initialized successfully
🚀 Starting server on port 5000...
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.x.x:5000
 * Press CTRL+C to quit
```

**If port 5000 is busy:**
```
⚠️  Port 5000 is busy, trying 5001...
🚀 Starting server on port 5001...
```

---

## 🌐 Step 5: Access the Application

### Local Access
Open your web browser and go to:
- **http://localhost:5000** (local access only)
- **http://127.0.0.1:5000** (local access only)

### Network Access (for other devices on same Wi-Fi)
- **http://192.168.x.x:5000** (replace x.x with your actual IP)

---

## 👤 Step 6: Test the System

### Test User Registration
1. Go to **http://localhost:5000**
2. Click **"Sign Up"**
3. Fill in the registration form:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `Test123!`
   - Confirm Password: `Test123!`
4. Complete the CAPTCHA
5. Click **"Register"**

### Test User Login
1. Click **"Login"**
2. Use existing credentials:
   - **Regular User**: `user@example.com` / `User123!`
   - **Admin User**: `admin@example.com` / `Admin123!`
3. Complete the CAPTCHA
4. Click **"Login"**

### Test Admin Dashboard
1. Login as admin: `admin@example.com` / `Admin123!`
2. You'll see the admin dashboard with:
   - User management table
   - Platform statistics
   - User search and filtering options

---

## 🌍 Step 7: Make It Publicly Accessible (Optional)

To share your app with others over the internet:

### Install ngrok
```bash
# Download and install ngrok from https://ngrok.com/
# Or if you have it installed:
ngrok http 5000
```

**Expected output:**
```
Session Status     online
Forwarding         https://abc123.ngrok.io -> http://localhost:5000
```

Now anyone can access your app at the provided ngrok URL!

---

## 🛑 How to Stop the Application

To stop the server:
- Press **Ctrl+C** in the terminal where the app is running
- Or close the terminal window

---

## 🔧 Troubleshooting

### Common Issues and Solutions

**1. Port already in use**
```bash
# Error: Address already in use
# Solution: Use a different port
python app.py --port 5001
# Or kill the process using port 5000
```

**2. Database errors**
```bash
# Reset the database
python init_db.py
```

**3. Missing dependencies**
```bash
# Reinstall all packages
pip install -r requirements.txt --force-reinstall
```

**4. Admin not working**
```bash
# Reset admin password
python reset_admin.py
```

**5. Check database content**
```bash
# View all users
python check_db_content.py
```

---

## 📁 Project Structure

```

├── app.py                 # Main application file
├── config.py             # Configuration settings
├── models.py             # Database models
├── requirements.txt      # Python dependencies
├── init_db.py           # Database initialization
├── HOW_TO_RUN.md        # This guide
├── routes/              # Route handlers
│   ├── auth.py          # Authentication routes
│   ├── admin.py         # Admin routes
│   └── user.py          # User routes
├── templates/           # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
├── static/              # CSS, JS, images
│   ├── css/style.css
│   └── js/
└── instance/            # Database files
    └── user_auth.db
```

---

## 🎯 What You Can Do

Once running, you can:

✅ **Register new users**  
✅ **Login/logout securely**  
✅ **View user dashboard**  
✅ **Admin user management**  
✅ **Search and filter users**  
✅ **View platform statistics**  
✅ **Test security features**  

---

## 🚀 Quick Start Commands

**For immediate testing:**
```bash
# 1. Navigate to project
cd c:\Users\RUDRA\PycharmProjects\valtec

# 2. Install dependencies
pip install -r requirements.txt

# 3. Setup database
python init_db.py

# 4. Run the app
python app.py

# 5. Open browser to http://localhost:5000
```

---

## 🎉 Success!

If you see the welcome page with beautiful gradients and can register/login successfully, congratulations! Your user authentication system is running perfectly.
