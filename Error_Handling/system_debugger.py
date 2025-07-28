#!/usr/bin/env python3

"""
This tool generate a report in console and JSON formate for the user to anlyze the system health and security status.
It checks for file permisssions, access control, database integrity, and security configurations.
"""

import sqlite3
import os
import json
import datetime
import re
from typing import Dict, List, Any, Tuple, Union

# Type aliases for better code readability and maintainability
IssueDict = Dict[str, Union[str, datetime.datetime]]
RecommendationDict = Dict[str, Union[str, datetime.datetime]]
DatabaseRow = Tuple[Any, ...]
ReportData = Dict[str, Any]

class SystemDebugger:    
    def __init__(self) -> None:
        """
        Initialize System Debugger with Default Configuration
        
        Default Configuration:
        - Database path: "instance/user_auth.db" (standard Flask instance location)
        - Issue tracking: Empty list for system problems and vulnerabilities
        - Recommendations: Empty list for improvement suggestions
        """
        # Database file path - standard Flask instance directory structure
        self.db_path: str = "instance/user_auth.db"
        
        # Collection of system issues discovered during diagnostic scans
        # Each issue contains category, description, severity level, and timestamp
        self.issues_found: List[IssueDict] = []
        
        # Collection of recommendations for system improvements
        # Each recommendation contains category, suggestion, and timestamp
        self.recommendations: List[RecommendationDict] = []
        
    def log_issue(self, category: str, issue: str, severity: str = "WARNING") -> None:
        """
        Record System Issue with Categorization and Severity Assessment
        """
        issue_record: IssueDict = {
            'category': category,
            'issue': issue,
            'severity': severity,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Add issue to internal tracking list for reporting and analysis
        self.issues_found.append(issue_record)
        
    def log_recommendation(self, category: str, recommendation: str) -> None:
        """
        Record System Improvement Recommendation
        The categories that are recommended are :
        - Security: Security hardening and vulnerability mitigation
        - Database: Database optimization and configuration improvements
        - Testing: Testing and validation enhancement suggestions
        - Dependencies: Software dependency and library recommendations
        - Performance: System performance and efficiency improvements
        """
        recommendation_record: RecommendationDict = {
            'category': category,
            'recommendation': recommendation,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Add recommendation to internal tracking list for reporting
        self.recommendations.append(recommendation_record)

    def check_database_health(self) -> bool:
        """
        Used to check the database health and integrity.
        """
        print("🔍 Checking Database Health...")
        
        # Verify database file exists and is accessible
        if not os.path.exists(self.db_path):
            self.log_issue("Database", "Database file not found", "CRITICAL")
            print(f"❌ Database not found at {self.db_path}")
            return False
        
        try:
            # Establish database connection with timeout for responsiveness testing
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Verify required tables exist for core functionality
            required_tables: List[str] = ['users', 'login_attempts']
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            table_rows: List[DatabaseRow] = cursor.fetchall()
            existing_tables: List[str] = [str(row[0]) for row in table_rows]
            
            # Check each required table and log missing tables as critical issues
            for table in required_tables:
                if table not in existing_tables:
                    self.log_issue("Database", f"Required table '{table}' missing", "CRITICAL")
                else:
                    print(f"✅ Table '{table}' exists")
            
            # Validate users table structure and required columns
            cursor.execute("PRAGMA table_info(users);")
            user_column_info: List[DatabaseRow] = cursor.fetchall()
            required_user_columns: List[str] = [
                'id', 'username', 'email', 'password_hash', 'role', 
                'is_active', 'failed_login_attempts', 'account_locked_until'
            ]
            
            # Extract column names from PRAGMA result (column name is at index 1)
            existing_user_columns: List[str] = [str(col[1]) for col in user_column_info]
            
            # Verify all required columns exist in users table
            for col in required_user_columns:
                if col not in existing_user_columns:
                    self.log_issue("Database", f"Required column '{col}' missing from users table", "CRITICAL")
                else:
                    print(f"✅ Users table has column '{col}'")
            
            # Verify admin user accounts exist for system administration
            cursor.execute("SELECT COUNT(*) FROM users WHERE role='Admin';")
            admin_result: DatabaseRow = cursor.fetchone()
            admin_count: int = int(admin_result[0]) if admin_result else 0
            
            if admin_count == 0:
                self.log_issue("Database", "No admin users found", "CRITICAL")
                self.log_recommendation("Database", "Create at least one admin user using reset_admin.py")
            else:
                print(f"✅ Found {admin_count} admin user(s)")
            
            # Monitor locked accounts for security analysis
            cursor.execute("SELECT COUNT(*) FROM users WHERE account_locked_until IS NOT NULL;")
            locked_result: DatabaseRow = cursor.fetchone()
            locked_count: int = int(locked_result[0]) if locked_result else 0
            
            if locked_count > 0:
                print(f"⚠️ Found {locked_count} locked account(s)")
                self.log_issue("Security", f"{locked_count} accounts are currently locked", "WARNING")
            
            # Close database connection properly
            conn.close()
            return True
            
        except sqlite3.Error as e:
            self.log_issue("Database", f"Database connection error: {str(e)}", "CRITICAL")
            print(f"❌ Database error: {str(e)}")
            return False
        except Exception as e:
            self.log_issue("Database", f"Unexpected database error: {str(e)}", "CRITICAL")
            print(f"❌ Unexpected error: {str(e)}")
            return False

    def check_file_permissions(self) -> None:
        """
        Check for the access control restrictions and permissions of critical files.
        """
        print("\n📁 Checking File Permissions...")
        
        # Define critical files that must exist and be accessible
        critical_files: List[str] = [
            'app.py',               # Flask application entry point
            'config.py',            # Configuration and secret keys
            'models.py',            # Database models and schema
            'instance/user_auth.db', # SQLite database file
            'routes/auth.py',       # Authentication route handlers
            'routes/admin.py',      # Administrative functionality
            'routes/user.py'        # User management routes
        ]
        
        # Analyze each critical file for existence and permissions
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    # Get file statistics and extract permission information
                    file_stats = os.stat(file_path)
                    permissions: str = oct(file_stats.st_mode)[-3:]  # Extract last 3 octal digits
                    file_size: int = file_stats.st_size
                    
                    print(f"✅ {file_path}: {permissions} ({file_size} bytes)")
                    
                    # Validate database file has write permissions (required for updates)
                    if file_path.endswith('.db'):
                        if not os.access(file_path, os.W_OK):
                            self.log_issue("Permissions", 
                                         f"Database file {file_path} is not writable", "CRITICAL")
                        if not os.access(file_path, os.R_OK):
                            self.log_issue("Permissions", 
                                         f"Database file {file_path} is not readable", "CRITICAL")
                    
                    # Check for overly permissive permissions (security risk)
                    if permissions.endswith('7'):  # World-writable
                        self.log_issue("Security", 
                                     f"File {file_path} is world-writable (permissions: {permissions})", 
                                     "WARNING")
                    
                    # Validate configuration files are not world-readable
                    if file_path == 'config.py' and permissions.endswith('4'):
                        self.log_issue("Security", 
                                     f"Configuration file {file_path} may be world-readable", 
                                     "WARNING")
                    
                except OSError as e:
                    self.log_issue("Permissions", 
                                 f"Cannot access file {file_path}: {str(e)}", "WARNING")
            else:
                # Log missing critical files as significant issues
                self.log_issue("Files", f"Critical file {file_path} not found", "CRITICAL")
                print(f"❌ Missing: {file_path}")
        
        # Check directory permissions for instance folder (database storage)
        instance_dir = "instance"
        if os.path.exists(instance_dir):
            try:
                dir_stats = os.stat(instance_dir)
                dir_permissions: str = oct(dir_stats.st_mode)[-3:]
                print(f"✅ {instance_dir}/: {dir_permissions} (directory)")
                
                # Ensure instance directory is writable for database operations
                if not os.access(instance_dir, os.W_OK):
                    self.log_issue("Permissions", 
                                 f"Instance directory {instance_dir} is not writable", "CRITICAL")
            except OSError as e:
                self.log_issue("Permissions", 
                             f"Cannot access instance directory: {str(e)}", "WARNING")
        else:
            self.log_issue("Files", "Instance directory not found", "CRITICAL")
            self.log_recommendation("Files", "Create instance directory for database storage")

    def check_security_configuration(self) -> None:
        """
        Check for cryptographic security configurations, session management, and other session security settings. 
        """
        print("\n🔒 Checking Security Configuration...")
        
        # Verify configuration file exists and analyze its contents
        if os.path.exists('config.py'):
            try:
                # Read configuration file with proper encoding support
                with open('config.py', 'r', encoding='utf-8') as f:
                    config_content: str = f.read()
                
                # Validate SECRET_KEY configuration (critical for session security)
                if 'SECRET_KEY' in config_content:
                    print("✅ SECRET_KEY configured")
                    
                    # Check for weak or default secret keys
                    secret_match = re.search(r'SECRET_KEY\s*=\s*["\']([^"\']+)["\']', config_content)
                    if secret_match:
                        secret_value: str = secret_match.group(1)
                        if len(secret_value) < 32:
                            self.log_issue("Security", 
                                         "SECRET_KEY is too short (recommend 32+ characters)", 
                                         "WARNING")
                        if secret_value in ['your-secret-key', 'change-me', 'secret', 'dev-key']:
                            self.log_issue("Security", 
                                         "SECRET_KEY appears to be a default/placeholder value", 
                                         "CRITICAL")
                else:
                    self.log_issue("Security", "SECRET_KEY not found in config", "CRITICAL")
                    self.log_recommendation("Security", 
                                          "Add SECRET_KEY with strong random value for session security")
                
                # Validate JWT secret key configuration (essential for token security)
                if 'JWT_SECRET_KEY' in config_content:
                    print("✅ JWT_SECRET_KEY configured")
                    
                    # Check if JWT key is different from session key (security best practice)
                    if 'JWT_SECRET_KEY = SECRET_KEY' in config_content:
                        self.log_issue("Security", 
                                     "JWT_SECRET_KEY should be different from SECRET_KEY", 
                                     "WARNING")
                else:
                    self.log_issue("Security", "JWT_SECRET_KEY not found in config", "CRITICAL")
                    self.log_recommendation("Security", 
                                          "Add JWT_SECRET_KEY for secure token authentication")
                
                # Check for dangerous development mode settings
                if 'DEBUG = True' in config_content:
                    self.log_issue("Security", "DEBUG mode is enabled", "WARNING")
                    self.log_recommendation("Security", "Disable DEBUG mode in production")
                    
                # Check for testing configurations that shouldn't be in production
                if 'TESTING = True' in config_content:
                    self.log_issue("Security", "TESTING mode is enabled", "WARNING")
                    
                # Validate database configuration security
                if 'sqlite://' in config_content.lower():
                    print("✅ SQLite database configuration detected")
                elif 'mysql://' in config_content.lower() or 'postgresql://' in config_content.lower():
                    if 'password' in config_content.lower():
                        self.log_issue("Security", 
                                     "Database password may be hardcoded in config", 
                                     "CRITICAL")
                
                # Check for secure session configuration
                if 'SESSION_COOKIE_SECURE' not in config_content:
                    self.log_recommendation("Security", 
                                          "Add SESSION_COOKIE_SECURE=True for HTTPS-only cookies")
                    
                if 'SESSION_COOKIE_HTTPONLY' not in config_content:
                    self.log_recommendation("Security", 
                                          "Add SESSION_COOKIE_HTTPONLY=True to prevent XSS")
                
            except IOError as e:
                self.log_issue("Security", f"Cannot read config.py: {str(e)}", "WARNING")
            except Exception as e:
                self.log_issue("Security", f"Error analyzing config.py: {str(e)}", "WARNING")
        else:
            self.log_issue("Security", "config.py file not found", "CRITICAL")
            self.log_recommendation("Security", 
                                  "Create config.py with proper security settings")

    def check_password_security(self) -> None:
        """
        Check password security by analyzing user password hashes and security compliance.
        """
        print("\n🛡️ Checking Password Security...")
        
        # Skip analysis if database is not accessible
        if not os.path.exists(self.db_path):
            self.log_issue("Database", "Cannot analyze password security - database not found", "WARNING")
            return
        
        try:
            # Connect to database with timeout for responsiveness
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Sample user accounts for password hash analysis (limit for performance)
            cursor.execute("SELECT username, password_hash FROM users LIMIT 5;")
            user_data: List[DatabaseRow] = cursor.fetchall()
            
            if not user_data:
                self.log_issue("Database", "No user accounts found for password analysis", "WARNING")
                conn.close()
                return
            
            # Define secure password hash patterns
            bcrypt_pattern: str = "$2b$"      # bcrypt hash identifier
            argon2_pattern: str = "$argon2"   # Argon2 hash identifier
            pbkdf2_pattern: str = "pbkdf2:"   # PBKDF2 hash identifier
            
            # Initialize security analysis counters
            secure_hashes: int = 0
            weak_hashes: int = 0
            unknown_hashes: int = 0
            
            # Analyze each user's password hash for security compliance
            for username, password_hash in user_data:
                username_str: str = str(username)
                hash_str: str = str(password_hash) if password_hash else ""
                
                if not hash_str:
                    self.log_issue("Security", 
                                 f"User '{username_str}' has empty password hash", "CRITICAL")
                    weak_hashes += 1
                elif hash_str.startswith(bcrypt_pattern):
                    print(f"✅ User '{username_str}': bcrypt hash detected (secure)")
                    secure_hashes += 1
                elif hash_str.startswith(argon2_pattern):
                    print(f"✅ User '{username_str}': Argon2 hash detected (secure)")
                    secure_hashes += 1
                elif hash_str.startswith(pbkdf2_pattern):
                    print(f"⚠️ User '{username_str}': PBKDF2 hash detected (acceptable)")
                    secure_hashes += 1
                elif len(hash_str) == 32:  # Likely MD5
                    self.log_issue("Security", 
                                 f"User '{username_str}' may be using MD5 hashing (insecure)", 
                                 "CRITICAL")
                    weak_hashes += 1
                elif len(hash_str) == 40:  # Likely SHA-1
                    self.log_issue("Security", 
                                 f"User '{username_str}' may be using SHA-1 hashing (insecure)", 
                                 "CRITICAL")
                    weak_hashes += 1
                elif len(hash_str) < 20:   # Likely plain text or weak hash
                    self.log_issue("Security", 
                                 f"User '{username_str}' has weak or plain text password", 
                                 "CRITICAL")
                    weak_hashes += 1
                else:
                    self.log_issue("Security", 
                                 f"User '{username_str}' has unknown password hash format", 
                                 "WARNING")
                    unknown_hashes += 1
            
            # Generate security assessment summary
            if weak_hashes == 0 and unknown_hashes == 0:
                print("✅ All passwords properly hashed with secure algorithms")
            else:
                if weak_hashes > 0:
                    self.log_recommendation("Security", 
                                          f"Re-hash {weak_hashes} passwords using bcrypt or Argon2")
                if unknown_hashes > 0:
                    self.log_recommendation("Security", 
                                          f"Verify {unknown_hashes} passwords with unknown hash formats")
            
            # Additional password policy checks
            cursor.execute("SELECT COUNT(*) FROM users WHERE password_hash IS NULL OR password_hash = '';")
            null_password_result: DatabaseRow = cursor.fetchone()
            null_passwords: int = int(null_password_result[0]) if null_password_result else 0
            
            if null_passwords > 0:
                self.log_issue("Security", 
                             f"{null_passwords} users have null or empty passwords", 
                             "CRITICAL")
            
            # Close database connection
            conn.close()
            
        except sqlite3.Error as e:
            self.log_issue("Security", f"Database error during password analysis: {str(e)}", "WARNING")
        except Exception as e:
            self.log_issue("Security", f"Cannot check password security: {str(e)}", "WARNING")

    def test_jwt_functionality(self) -> None:
        """
        Checks for the validity of JWT functionality and configuration.
        """
        print("\n🎫 Testing JWT Functionality...")
        
        try:
            # Test JWT library import capability (basic dependency check)
            try:
                # Import without using to avoid unused import warnings
                import flask_jwt_extended
                print("✅ flask-jwt-extended library is available")
                
                # Check for essential JWT functions availability
                required_functions: List[str] = ['create_access_token', 'decode_token', 'jwt_required', 'get_jwt_identity']
                missing_functions: List[str] = []
                
                for func_name in required_functions:
                    if not hasattr(flask_jwt_extended, func_name):
                        missing_functions.append(func_name)
                
                if missing_functions:
                    self.log_issue("Dependencies", 
                                 f"Missing JWT functions: {', '.join(missing_functions)}", 
                                 "CRITICAL")
                else:
                    print("✅ All essential JWT functions are available")
                
            except ImportError as import_error:
                self.log_issue("Dependencies", 
                             f"JWT module import error: {str(import_error)}", "CRITICAL")
                self.log_recommendation("Dependencies", 
                                      "Install flask-jwt-extended: pip install flask-jwt-extended")
                return  # Cannot continue without JWT library
            
            # Validate JWT configuration in config file
            if os.path.exists('config.py'):
                try:
                    with open('config.py', 'r', encoding='utf-8') as f:
                        config_content = f.read()
                    
                    # Check for JWT-specific configuration
                    jwt_configs: List[str] = [
                        'JWT_SECRET_KEY',
                        'JWT_ACCESS_TOKEN_EXPIRES', 
                        'JWT_ALGORITHM'
                    ]
                    
                    missing_configs: List[str] = []
                    for config in jwt_configs:
                        if config not in config_content:
                            missing_configs.append(config)
                    
                    if missing_configs:
                        self.log_recommendation("Configuration", 
                                              f"Consider adding JWT configurations: {', '.join(missing_configs)}")
                    else:
                        print("✅ JWT configuration appears complete")
                        
                except Exception as e:
                    self.log_issue("Configuration", 
                                 f"Cannot validate JWT configuration: {str(e)}", "WARNING")
            
            # Provide comprehensive testing recommendations
            self.log_recommendation("Testing", 
                                  "Create dedicated JWT test script with Flask app context")
            self.log_recommendation("Testing", 
                                  "Test token creation, validation, and expiration scenarios")
            self.log_recommendation("Security", 
                                  "Validate JWT secret key strength and uniqueness")
            
            print("💡 Note: Full JWT testing requires Flask application context")
            print("💡 Consider running dedicated JWT test scripts for comprehensive validation")
            
        except Exception as e:
            self.log_issue("Testing", f"Unexpected error during JWT testing: {str(e)}", "WARNING")

    def generate_debug_report(self) -> None:
        """
        Finalize Comprehensive System Diagnostic Report
        """
        print("\n" + "=" * 60)
        print("🔧 COMPREHENSIVE SYSTEM DIAGNOSTIC REPORT")
        print("=" * 60)
        
        # Execute complete diagnostic assessment across all system components
        print("🔍 Initiating comprehensive system analysis...")
        
        self.check_database_health()
        self.check_file_permissions()
        self.check_security_configuration()
        self.check_password_security()
        self.check_failed_login_attempts()
        self.check_user_accounts()
        self.test_jwt_functionality()
        
        # Analyze and categorize diagnostic findings
        print("\n📋 DIAGNOSTIC SUMMARY")
        print("-" * 30)
        
        # Categorize issues by severity for prioritized response
        critical_issues: List[IssueDict] = [
            issue for issue in self.issues_found if issue.get('severity') == 'CRITICAL'
        ]
        warning_issues: List[IssueDict] = [
            issue for issue in self.issues_found if issue.get('severity') == 'WARNING'
        ]
        
        # Display statistical summary of findings
        print(f"🚨 Critical Issues: {len(critical_issues)}")
        print(f"⚠️ Warnings: {len(warning_issues)}")
        print(f"💡 Recommendations: {len(self.recommendations)}")
        print(f"📊 Total Findings: {len(self.issues_found)}")
        
        # Display critical issues requiring immediate attention
        if critical_issues:
            print("\n🚨 CRITICAL ISSUES (Immediate Action Required):")
            for issue in critical_issues:
                category = issue.get('category', 'Unknown')
                description = issue.get('issue', 'No description')
                print(f"  [{category}] {description}")
        
        # Display warnings that should be addressed soon
        if warning_issues:
            print("\n⚠️ WARNINGS (Should be addressed):")
            for issue in warning_issues:
                category = issue.get('category', 'Unknown')
                description = issue.get('issue', 'No description')
                print(f"  [{category}] {description}")
        
        # Display actionable recommendations for improvement
        if self.recommendations:
            print("\n💡 SYSTEM IMPROVEMENT RECOMMENDATIONS:")
            for rec in self.recommendations:
                category = rec.get('category', 'Unknown')
                recommendation = rec.get('recommendation', 'No recommendation')
                print(f"  [{category}] {recommendation}")
        
        # Save comprehensive report for future reference and automation
        self.save_debug_report()
        
        # Provide clear next steps based on diagnostic results
        if critical_issues:
            print("\n🔧 IMMEDIATE ACTION REQUIRED:")
            print("1. 🚨 Address all critical issues immediately")
            print("2. 🔄 Run this diagnostic script again to verify fixes")
            print("3. 🧪 Test all system functionality after implementing fixes")
            print("4. 📋 Review recommendations for long-term improvements")
            print("5. 📅 Schedule regular diagnostic assessments")
        elif warning_issues:
            print("\n⚠️ RECOMMENDED ACTIONS:")
            print("1. 📝 Review and address warning issues when possible")
            print("2. 💡 Implement recommended improvements")
            print("3. 🔄 Run periodic diagnostic checks")
            print("4. 📊 Monitor system performance and security")
        else:
            print("\n✅ EXCELLENT SYSTEM HEALTH!")
            print("🎉 No critical issues or warnings detected")
            print("💡 Consider implementing recommendations for further optimization")
            print("📅 Schedule regular maintenance and monitoring")

    def save_debug_report(self) -> None:
        """
        Save the report in JSON format for future reference and automation.
        """
        try:
            # Construct comprehensive diagnostic report data structure
            report_data: ReportData = {
                'metadata': {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'system_debugger_version': '2.0',
                    'assessment_scope': 'comprehensive_system_diagnostic',
                    'total_checks_performed': 7  # Number of diagnostic methods executed
                },
                'issues': self.issues_found,
                'recommendations': self.recommendations,
                'summary': {
                    'total_issues': len(self.issues_found),
                    'critical_issues': len([i for i in self.issues_found if i.get('severity') == 'CRITICAL']),
                    'warning_issues': len([i for i in self.issues_found if i.get('severity') == 'WARNING']),
                    'info_issues': len([i for i in self.issues_found if i.get('severity') == 'INFO']),
                    'total_recommendations': len(self.recommendations),
                    'system_health_score': self._calculate_health_score()
                },
                'categories': {
                    'database_issues': len([i for i in self.issues_found if i.get('category') == 'Database']),
                    'security_issues': len([i for i in self.issues_found if i.get('category') == 'Security']),
                    'file_issues': len([i for i in self.issues_found if i.get('category') == 'Files']),
                    'permission_issues': len([i for i in self.issues_found if i.get('category') == 'Permissions']),
                    'dependency_issues': len([i for i in self.issues_found if i.get('category') == 'Dependencies'])
                }
            }
            
            # Write structured report to JSON file with readable formatting
            with open('debug_report.json', 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n📁 Comprehensive diagnostic report saved to: debug_report.json")
            print(f"📊 Report contains {len(self.issues_found)} issues and {len(self.recommendations)} recommendations")
            
        except IOError as e:
            print(f"❌ Failed to save diagnostic report (IO Error): {str(e)}")
            self.log_issue("System", f"Cannot save diagnostic report: {str(e)}", "WARNING")
        except (TypeError, ValueError) as e:
            print(f"❌ Failed to save diagnostic report (Data Error): {str(e)}")
            self.log_issue("System", f"Data encoding error in report: {str(e)}", "WARNING")
        except Exception as e:
            print(f"❌ Failed to save diagnostic report (Unexpected Error): {str(e)}")
            self.log_issue("System", f"Unexpected error saving report: {str(e)}", "WARNING")
    
    def _calculate_health_score(self) -> int:
        """
        Calculate Overall System Health Score
        
        Score Interpretation:
        - 90-100: Excellent system health
        - 70-89: Good health with minor issues
        - 50-69: Moderate health concerns
        - 25-49: Significant problems requiring attention
        - 0-24: Critical system issues
        """
        base_score = 100
        critical_penalty = len([i for i in self.issues_found if i.get('severity') == 'CRITICAL']) * 25
        warning_penalty = len([i for i in self.issues_found if i.get('severity') == 'WARNING']) * 5
        info_penalty = len([i for i in self.issues_found if i.get('severity') == 'INFO']) * 1
        
        final_score = max(0, base_score - critical_penalty - warning_penalty - info_penalty)
        return final_score

    def check_failed_login_attempts(self) -> None:
        """
        Check for the nimber of failed login attempts and potential security threats.
        """
        print("\n📊 Analyzing Login Attempts and Security Threats...")
        
        # Skip analysis if database is not accessible
        if not os.path.exists(self.db_path):
            self.log_issue("Database", "Cannot analyze login attempts - database not found", "WARNING")
            return
        
        try:
            # Connect to database for login attempt analysis
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Analyze recent failed login attempts for threat detection
            cursor.execute("""
                SELECT ip_address, COUNT(*) as attempts, MAX(timestamp) as last_attempt
                FROM login_attempts 
                WHERE success = 0 AND timestamp > datetime('now', '-24 hours')
                GROUP BY ip_address
                ORDER BY attempts DESC
                LIMIT 10
            """)
            
            failed_attempts_data: List[DatabaseRow] = cursor.fetchall()
            
            if failed_attempts_data:
                print("⚠️ Recent Failed Login Attempts (Last 24 hours):")
                for ip, attempts, last_attempt in failed_attempts_data:
                    ip_str = str(ip) if ip else "Unknown"
                    attempts_count = int(attempts) if attempts else 0
                    last_time = str(last_attempt) if last_attempt else "Unknown"
                    
                    print(f"  🌐 IP: {ip_str} - {attempts_count} attempts (last: {last_time})")
                    
                    # Flag high-risk IP addresses with excessive failed attempts
                    if attempts_count >= 10:
                        self.log_issue("Security", 
                                     f"High number of failed attempts from IP {ip_str}: {attempts_count}", 
                                     "WARNING")
                        self.log_recommendation("Security", 
                                              f"Consider blocking IP {ip_str} if attacks continue")
                    elif attempts_count >= 20:
                        self.log_issue("Security", 
                                     f"Very high failed attempts from IP {ip_str}: {attempts_count}", 
                                     "CRITICAL")
            else:
                print("✅ No concerning failed login attempts in last 24 hours")
            
            # Check for potential brute force attack patterns
            cursor.execute("""
                SELECT COUNT(*) as total_failed
                FROM login_attempts 
                WHERE success = 0 AND timestamp > datetime('now', '-1 hour')
            """)
            
            recent_failed_result: DatabaseRow = cursor.fetchone()
            recent_failed_count: int = int(recent_failed_result[0]) if recent_failed_result else 0
            
            # Alert on unusually high failed attempt rates
            if recent_failed_count > 50:
                self.log_issue("Security", 
                             f"High number of failed attempts in last hour: {recent_failed_count}", 
                             "CRITICAL")
                self.log_recommendation("Security", 
                                      "Implement rate limiting or IP blocking immediately")
                self.log_recommendation("Security", 
                                      "Review security logs and consider activating incident response")
            elif recent_failed_count > 20:
                self.log_issue("Security", 
                             f"Elevated failed login attempts in last hour: {recent_failed_count}", 
                             "WARNING")
                self.log_recommendation("Security", 
                                      "Monitor closely and prepare defensive measures")
            
            # Analyze successful vs failed login ratios for security health
            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_logins,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_logins
                FROM login_attempts 
                WHERE timestamp > datetime('now', '-24 hours')
            """)
            
            login_stats_result: DatabaseRow = cursor.fetchone()
            if login_stats_result:
                successful_logins = int(login_stats_result[0]) if login_stats_result[0] else 0
                failed_logins = int(login_stats_result[1]) if login_stats_result[1] else 0
                total_attempts = successful_logins + failed_logins
                
                if total_attempts > 0:
                    failure_rate = (failed_logins / total_attempts) * 100
                    print(f"📈 Login Statistics (24h): {successful_logins} successful, {failed_logins} failed ({failure_rate:.1f}% failure rate)")
                    
                    # Alert on unusually high failure rates
                    if failure_rate > 50:
                        self.log_issue("Security", 
                                     f"High login failure rate: {failure_rate:.1f}%", 
                                     "WARNING")
                        self.log_recommendation("Security", 
                                              "Investigate cause of high authentication failure rate")
            
            # Close database connection
            conn.close()
            
        except sqlite3.Error as e:
            self.log_issue("Security", f"Database error during login analysis: {str(e)}", "WARNING")
        except Exception as e:
            self.log_issue("Security", f"Cannot analyze login attempts: {str(e)}", "WARNING")

    def check_user_accounts(self) -> None:
        """
        Check user accounts for security compliance, status, and administrative roles.
        """
        print("\n👥 Analyzing User Account Security and Status...")
        
        # Skip analysis if database is not accessible
        if not os.path.exists(self.db_path):
            self.log_issue("Database", "Cannot analyze user accounts - database not found", "WARNING")
            return
        
        try:
            # Connect to database for user account analysis
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Gather comprehensive user account statistics
            cursor.execute("SELECT COUNT(*) FROM users;")
            total_users_result: DatabaseRow = cursor.fetchone()
            total_users: int = int(total_users_result[0]) if total_users_result else 0
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1;")
            active_users_result: DatabaseRow = cursor.fetchone()
            active_users: int = int(active_users_result[0]) if active_users_result else 0
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Admin';")
            admin_users_result: DatabaseRow = cursor.fetchone()
            admin_users: int = int(admin_users_result[0]) if admin_users_result else 0
            
            inactive_users: int = total_users - active_users
            
            # Display comprehensive user account statistics
            print(f"📈 User Account Statistics:")
            print(f"  👥 Total Users: {total_users}")
            print(f"  ✅ Active Users: {active_users}")
            print(f"  🔐 Admin Users: {admin_users}")
            print(f"  ❌ Inactive Users: {inactive_users}")
            
            # Validate administrative account configuration
            if admin_users == 0:
                self.log_issue("Security", "No administrative users found", "CRITICAL")
                self.log_recommendation("Security", "Create at least one admin account immediately")
            elif admin_users == 1:
                self.log_recommendation("Security", "Consider creating backup admin account for redundancy")
            elif admin_users > 5:
                self.log_issue("Security", f"Many admin accounts detected ({admin_users})", "WARNING")
                self.log_recommendation("Security", "Review admin account necessity and remove unused accounts")
            
            # Analyze accounts with security concerns (failed login attempts)
            cursor.execute("""
                SELECT username, email, failed_login_attempts, account_locked_until, is_active
                FROM users 
                WHERE failed_login_attempts > 0
                ORDER BY failed_login_attempts DESC
                LIMIT 10
            """)
            
            risky_accounts_data: List[DatabaseRow] = cursor.fetchall()
            if risky_accounts_data:
                print("\n⚠️ Accounts with Authentication Issues:")
                for username, email, attempts, locked_until, is_active in risky_accounts_data:
                    username_str = str(username) if username else "Unknown"
                    email_str = str(email) if email else "No email"
                    attempts_count = int(attempts) if attempts else 0
                    is_active_bool = bool(is_active) if is_active is not None else False
                    
                    # Determine account status for security analysis
                    if locked_until:
                        status = "🔒 LOCKED"
                        if attempts_count >= 5:
                            self.log_issue("Security", 
                                         f"Account {username_str} locked with {attempts_count} failed attempts", 
                                         "WARNING")
                    elif not is_active_bool:
                        status = "❌ INACTIVE"
                    else:
                        status = "✅ ACTIVE"
                        if attempts_count >= 3:
                            self.log_issue("Security", 
                                         f"Active account {username_str} has {attempts_count} recent failed attempts", 
                                         "WARNING")
                    
                    print(f"  👤 {username_str} ({email_str}): {attempts_count} failed attempts - {status}")
            else:
                print("✅ No accounts with recent authentication issues detected")
            
            # Check for dormant administrative accounts
            cursor.execute("""
                SELECT username, email, role
                FROM users 
                WHERE role = 'Admin' AND is_active = 0
            """)
            
            inactive_admin_data: List[DatabaseRow] = cursor.fetchall()
            if inactive_admin_data:
                print(f"\n⚠️ Inactive Administrative Accounts ({len(inactive_admin_data)}):")
                for username, email, role in inactive_admin_data:
                    username_str = str(username) if username else "Unknown"
                    email_str = str(email) if email else "No email"
                    print(f"  🔐 {username_str} ({email_str}) - Role: {role}")
                    self.log_recommendation("Security", 
                                          f"Review inactive admin account {username_str} for deletion or reactivation")
            
            # Close database connection
            conn.close()
            
        except sqlite3.Error as e:
            self.log_issue("Database", f"Database error during user account analysis: {str(e)}", "WARNING")
        except Exception as e:
            self.log_issue("Database", f"Cannot check user accounts: {str(e)}", "WARNING")

    def run_diagnostics(self) -> None:
        """
        Execute Comprehensive System Diagnostic Assessment
        """
        print("🔧 Starting Comprehensive System Diagnostic Assessment...")
        print("=" * 70)
        
        try:
            # Phase 1: Core Database Health Assessment
            print("\n🗄️ PHASE 1: Database Health Assessment")
            print("-" * 40)
            db_healthy = self.check_database_health()
            
            if not db_healthy:
                print("⚠️ Critical database issues detected - some checks may be limited")
            
            # Phase 2: File System Security Analysis
            print("\n📁 PHASE 2: File System Security Analysis")
            print("-" * 40)
            self.check_file_permissions()
            
            # Phase 3: Security Configuration Audit
            print("\n🔒 PHASE 3: Security Configuration Audit")
            print("-" * 40)
            self.check_security_configuration()
            
            # Phase 4: Password Security Assessment
            print("\n🛡️ PHASE 4: Password Security Assessment")
            print("-" * 40)
            self.check_password_security()
            
            # Phase 5: Authentication System Testing
            print("\n🎫 PHASE 5: JWT Authentication System Testing")
            print("-" * 40)
            self.test_jwt_functionality()
            
            # Phase 6: Threat Detection Analysis (only if database is healthy)
            if db_healthy:
                print("\n🚨 PHASE 6: Threat Detection and Security Analysis")
                print("-" * 40)
                self.check_failed_login_attempts()
                
                # Phase 7: User Account Management Review
                print("\n👥 PHASE 7: User Account Management Review")
                print("-" * 40)
                self.check_user_accounts()
            else:
                print("\n⚠️ Skipping threat detection and user analysis due to database issues")
            
            # Generate comprehensive summary report
            print("\n📊 PHASE 8: Generating Comprehensive Report")
            print("-" * 40)
            self.save_debug_report()
            
            # Display diagnostic summary
            print("\n" + "=" * 70)
            print("📋 DIAGNOSTIC ASSESSMENT SUMMARY")
            print("=" * 70)
            
            critical_issues = len([issue for issue in self.issues_found if issue.get('severity') == 'CRITICAL'])
            warning_issues = len([issue for issue in self.issues_found if issue.get('severity') == 'WARNING'])
            total_recommendations = len(self.recommendations)
            
            print(f"🔴 Critical Issues: {critical_issues}")
            print(f"🟡 Warning Issues: {warning_issues}")
            print(f"💡 Recommendations: {total_recommendations}")
            print(f"🎯 Health Score: {self._calculate_health_score()}%")
            
            if critical_issues == 0 and warning_issues == 0:
                print("\n✅ System Status: HEALTHY - No significant issues detected")
            elif critical_issues > 0:
                print(f"\n🚨 System Status: CRITICAL - {critical_issues} critical issues require immediate attention")
            else:
                print(f"\n⚠️ System Status: WARNING - {warning_issues} issues should be addressed")
            
            print("=" * 70)
            
        except Exception as e:
            self.log_issue("System", f"Diagnostic execution error: {str(e)}", "CRITICAL")
            print(f"❌ Unexpected error during diagnostic assessment: {str(e)}")


# Main Execution Block
if __name__ == "__main__":
    """
    Execute the System Diagnostic Tool
    """
    print("🚀 Initializing ValTec System Diagnostic Tool v2.0")
    print("=" * 60)
    
    # Create system debugger instance with enhanced capabilities
    debugger: SystemDebugger = SystemDebugger()
    
    # Execute comprehensive system diagnostic assessment
    debugger.run_diagnostics()
    
    print("\n" + "=" * 60)
    print("🏁 System diagnostic assessment completed successfully")
    print("📋 Review the generated report and implement recommended fixes")
    print("🔄 Run this tool regularly to maintain system health and security")
    print("=" * 60)

# This is the end of the system_debugger.py script.