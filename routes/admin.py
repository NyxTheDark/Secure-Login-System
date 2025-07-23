"""This is flask file for admin routes. It contains routes for managing users, login attempts, statistics, \
admin privileges, privileges escalation and account management. """

from flask import Blueprint, request, jsonify
# flask allows one to create modulerized web applications. here it helps us to organise the admin routes.
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
# flask_jwt_extended is used to authenticate admin users and validate incoming requests, that contain the JWT tokens.
from datetime import datetime, timedelta
from functools import wraps  #It is a python decoration module.

admin_bp = Blueprint('admin', __name__) 
# here blueprint contains admin as blueprint name and __name__ as the import name, 
# this import name is used for resources location.

User = None #user name 
LoginAttempt = None # no. of login atemp made
db = None #It is the SQL Alchemy object. Used to interact with the database.

def init_admin_routes(user_model, login_attempt_model, database):
    """Initialize routes with models. Also inti_admin_routes searves as a global function to
    set the User, LoginAttempt and db variables."""
    global User, LoginAttempt, db
    User = user_model
    LoginAttempt = login_attempt_model
    db = database

def require_admin(f): 
    """ It is used to create role based flask function son that users with admin role can 
    access sensitive data and adminstrative endpoint privileges.
    Decorator to require admin role. It also ensures that the HTTP request that is comming
    has JWT tokens in authorization part."""
    @wraps(f)# Used to preserve the original metadata of the function being decorated.
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            current_user_id = get_jwt_identity()
            
            # Debug logging
            print(f"JWT Claims: {claims}")
            print(f"User ID: {current_user_id}")
            print(f"User role: {claims.get('role')}")
            
            if claims.get('role') != 'Admin': 
                """ it ensures that user without admin privilages get warning that the operation of 
                function that they are trying to get is""" 
                return jsonify({'error': 'Admin access required'}), 403
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Admin auth error: {str(e)}")
            return jsonify({'error': 'Authentication required'}), 401
    return decorated_function

"""The below code represents that functions like getting user list, id or roles can only be perforemed by admin users.
It is used to protect sensitive data and administrative endpoint privileges."""
@admin_bp.route('/users', methods=['GET'])
@require_admin
def get_all_users(): # Function to get all users
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        users = User.query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in users.items],
            'total': users.total,
            'pages': users.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch users'}), 500

@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@require_admin
def get_user(user_id): # Function to get a specific user by ID
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch user'}), 500

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@require_admin
def toggle_user_status(user_id): # Function to toggle user status (activate/deactivate)
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.is_active = not user.is_active
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        return jsonify({
            'message': f'User {status} successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user status'}), 500

@admin_bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@require_admin
def unlock_user_account(user_id): # Function to unlock a user account
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.unlock_account()
        
        return jsonify({
            'message': 'User account unlocked successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to unlock user account'}), 500

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@require_admin
def update_user_role(user_id): # Function to update user role
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if new_role not in ['Admin', 'User']:
            return jsonify({'error': 'Invalid role'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.role = new_role
        db.session.commit()
        
        return jsonify({
            'message': 'User role updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user role'}), 500

@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id): # Function to delete a user
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Prevent admin from deleting themselves
        current_user_id = get_jwt_identity()
        if user_id == current_user_id:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete user'}), 500

@admin_bp.route('/login-attempts', methods=['GET'])
@require_admin
def get_login_attempts(): # Function to get no. of login attempts
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        attempts = LoginAttempt.query.order_by(
            LoginAttempt.timestamp.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'attempts': [{
                'id': attempt.id,
                'ip_address': attempt.ip_address,
                'email': attempt.email,
                'success': attempt.success,
                'timestamp': attempt.timestamp.isoformat(),
                'user_agent': attempt.user_agent
            } for attempt in attempts.items],
            'total': attempts.total,
            'pages': attempts.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch login attempts'}), 500

@admin_bp.route('/stats', methods=['GET'])
@require_admin
def get_stats(): # Function to get statistics like total users, active users, etc.
    try:
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(role='Admin').count()
        locked_users = User.query.filter(User.account_locked_until.isnot(None)).count()
        
        recent_attempts = LoginAttempt.query.filter(
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        failed_attempts = LoginAttempt.query.filter(
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'admin_users': admin_users,
            'locked_users': locked_users,
            'recent_login_attempts': recent_attempts,
            'failed_attempts_week': failed_attempts
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch statistics'}), 500


#This is the end of admin routes file.