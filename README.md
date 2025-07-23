# 🔐 Secure Login System with Role Management.

Greetings, Welcome to my flask based user authentication system. I have built this to show how you can create a really secure login system without all the complexity. Think of it as a solid foundation you can build on for any web app that needs user accounts.

## ✨ What can it do ?

### What do users get
- **Sign up easily** with recapta, password strength checker
- **Login easily** with *JWt tokens*
- **Automatic session Expiration** to maintain another layer of security so that even if you forgot you can always se logged out after a particular time inactivity.

### Security features.
- _**Brute Forece Protection**_ Accoiunt will be locked affter 5 unsuccessful attempts.
- _**CAPTHA checks**_ bots shouldn't be able to login in or sign up.
- _**Input Sanitization**_ No sql injection, CSRF or XSS attack can be used.
- _** Constant monitoring and Logs creation**_ Admin can check all the logs and activity that has benn done by the users.
- _**Password Hasing**_ done using bcrypt. 

### Role Management
- Admin: Can manage all users, see system stats, and handle security issues
- User: Get their own dashboard to manage their profile

### Admin Privileges
- User management.
- Role assignment and changes.
- System insight.
- Account recovery.

# � Getting started

### Get the code 
```bash
git clone https://github.com/NyxTheDark/Secure-Login-System.git
cd Secure-Login-System
```
### Set up your python environment.
```bash
python -m venv venv

# If you're on Windows:
venv\Scripts\activate

# If you're on Mac or Linux:
source venv/bin/activate
```

### Install the file needed
```bash
pip install -r requirements.txt
```
**Note**: If pip gives error try using pipx

### Set Up the Database
```bash
python init_db.py
```

### Fire it up
```bash
python app.py
```
**Note**: if python does not wpork try python3.

🎉 **That's it!** Open your browser and go to `http://localhost:5000`
**Note**: Local host is your IP address. 

## DEMO accounts
### Administrator
- Email: `admin@example.com`
- Password: `admin123!`
### USER
- Email: `user@example.com`
- Password: `User@123`

# Project Structure

```
user-auth-system/
├── app.py                 # The main Flask app (start here!)
├── models.py              # Database stuff (user accounts, login logs)
├── config.py              # Settings and configuration
├── init_db.py             # Sets up your database
├── requirements.txt       # All the Python packages you need
├── routes/
│   ├── auth.py           # Login, registration, logout
│   ├── admin.py          # Admin dashboard features
│   └── user.py           # User dashboard features
├── templates/
│   ├── base.html         # Basic page layout
│   ├── index.html        # Homepage
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── dashboard.html    # User/Admin dashboard
├── static/
│   ├── css/
│   │   └── style.css     # Makes everything look pretty
│   └── js/
│       ├── main.js       # Core JavaScript
│       └── dashboard.js  # Dashboard functionality
└── instance/
    └── user_auth.db      # Your SQLite database (created automatically)
```
# Environment Variables (If You Want to Change Stuff)

Create a `.env` file if you want to customize anything:

```bash
# Flask Settings
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=development
JWT_SECRET_KEY=your-jwt-secret-key

# Database (SQLite is fine for most people)
DATABASE_URL=sqlite:///user_auth.db

# Security Settings
BCRYPT_LOG_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=30

# Email Settings (if you want to send emails)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Switching Databases 

The app uses SQLite by default (which is perfect for most people), but you can switch:

- **SQLite** (default): `sqlite:///user_auth.db`
- **MySQL**: `mysql+pymysql://user:password@localhost/dbname`
- **PostgreSQL**: `postgresql://user:password@localhost/dbname`

### Any and all suggestions are welcome.

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/amazing-new-feature`)
3. Make your changes and commit them (`git commit -m 'Add amazing new feature'`)
4. Push to your branch (`git push origin feature/amazing-new-feature`)
5. Open a Pull Request.

Thank You for giving it a try.
