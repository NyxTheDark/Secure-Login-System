#!/usr/bin/env python3
"""It is used in the case that there is need for admin password reset."""
import sqlite3
import bcrypt

def reset_admin_password():
    """Reset admin password and unlock account"""
    db_path = "instance/user_auth.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current admin status
        cursor.execute("SELECT id, username, email, failed_login_attempts, account_locked_until FROM users WHERE role='Admin';")
        admin = cursor.fetchone()
        
        if admin:
            print(f"Admin user found: ID={admin[0]}, Username={admin[1]}, Email={admin[2]}")
            print(f"Failed attempts: {admin[3]}")
            print(f"Locked until: {admin[4]}")
            
            # Hash the correct password
            new_password = "Admin@123"
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            
            # Update admin password and unlock account
            cursor.execute("""
                UPDATE users 
                SET password_hash = ?, 
                    failed_login_attempts = 0, 
                    account_locked_until = NULL 
                WHERE role = 'Admin'
            """, (password_hash.decode('utf-8'),))
            
            conn.commit()
            print(f"Admin password reset to: {new_password}")
            print("Account unlocked successfully!")
            
        else:
            print("No admin user found!")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    reset_admin_password()
