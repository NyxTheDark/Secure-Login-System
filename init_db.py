"""
Database initialization script
Run this script to create the database tables and add initial data
"""

from app import app, db
from models import User
import sys

def init_database():
    """Initialize the database with tables and sample data"""
    try:
        with app.app_context():
            # Create all tables
            print("Creating database tables...")
            db.create_all()
            
            # Check if admin user already exists
            admin_user = User.query.filter_by(email='admin@example.com').first()
            if not admin_user:
                # Create admin user
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    role='Admin'
                )
                admin_user.set_password('Admin@123')
                db.session.add(admin_user)
                print("Created admin user: admin@example.com (password: Admin@123)")
            
            # Check if demo user already exists
            demo_user = User.query.filter_by(email='user@example.com').first()
            if not demo_user:
                # Create demo user
                demo_user = User(
                    username='user',
                    email='user@example.com',
                    role='User'
                )
                demo_user.set_password('User@123')
                db.session.add(demo_user)
                print("Created demo user: user@example.com (password: User@123)")
            
            # Commit changes
            db.session.commit()
            print("Database initialization completed successfully!")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.session.rollback()
        sys.exit(1)

def reset_database():
    """Reset the database by dropping and recreating all tables"""
    try:
        with app.app_context():
            print("Dropping all tables...")
            db.drop_all()
            print("Recreating tables...")
            init_database()
            
    except Exception as e:
        print(f"Error resetting database: {e}")
        sys.exit(1)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'reset':
        reset_database()
    else:
        init_database()
