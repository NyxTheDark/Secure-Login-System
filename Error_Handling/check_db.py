#!/usr/bin/env python3
"""It is an admin specific script used to check the database for admin users."""
import sqlite3
import os

def check_admin_users():
    db_path = "instance/user_auth.db"
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user';")
        if not cursor.fetchone():
            print("Users table doesn't exist!")
            return
        
        # Get all users
        cursor.execute("SELECT id, username, email, role, is_active FROM user;")
        users = cursor.fetchall()
        
        print("All users in database:")
        print("ID | Username | Email | Role | Active")
        print("-" * 50)
        
        for user in users:
            print(f"{user[0]} | {user[1]} | {user[2]} | {user[3]} | {user[4]}")
        
        # Check specifically for admin users
        cursor.execute("SELECT id, username, email, role FROM user WHERE role='Admin';")
        admin_users = cursor.fetchall()
        
        print(f"\nAdmin users found: {len(admin_users)}")
        for admin in admin_users:
            print(f"Admin: {admin[1]} ({admin[2]})")
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking database: {e}")

if __name__ == "__main__":
    check_admin_users()
