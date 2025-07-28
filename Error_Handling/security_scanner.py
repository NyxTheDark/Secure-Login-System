#!/usr/bin/env python3

"""

This script provides a comprehensive security vulnerability assessment fro SecureAuth.

Security Categories Covered:
1. SQL Injection Prevention
2. Cross-Site Scripting (XSS) Protection
3. Authentication Security
4. Session Management
5. Input Validation
6. Database Security
7. Configuration Security
"""

import os
import re
import json
import sqlite3
import datetime
from typing import List, Dict, Any, Optional

# Type definitions for better code clarity
VulnerabilityDict = Dict[str, Any]
RecommendationDict = Dict[str, Any]
SecurityReportDict = Dict[str, Any]

class SecurityScanner:
    """
    This class automates security testing for web applications, focusing on common vulnerabilities.
    
    Methodology:
        log_vulnerability: Records a discovered security vulnerability
        log_recommendation: Records a security improvement recommendation
        scan_sql_injection_vulnerabilities: Detects potential SQL injection flaws
        scan_xss_vulnerabilities: Identifies Cross-Site Scripting vulnerabilities
        scan_authentication_vulnerabilities: Analyzes authentication security
        scan_session_security: Reviews session management implementation
        scan_input_validation: Checks input validation and sanitization
        scan_database_security: Examines database security configuration
        scan_configuration_security: Reviews application configuration security
        generate_security_report: Orchestrates all scans and generates comprehensive report
        save_security_report: Persists security findings to JSON file
    """
    
    def __init__(self) -> None:
        """
        Initialize the Security Scanner
        """
        # Initialize lists with proper type annotations to store security findings
        self.vulnerabilities: List[VulnerabilityDict] = []
        self.security_recommendations: List[RecommendationDict] = []
        
        # Define severity classification system for consistent vulnerability rating
        self.severity_levels: List[str] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
    def log_vulnerability(self, title: str, description: str, severity: str, file_path: Optional[str] = None) -> None:
        """
        Write a security vulnerability record in the form of logs.
        """
        # Create comprehensive vulnerability record with all relevant metadata
        vuln: VulnerabilityDict = {
            'title': title,                                    # Vulnerability classification
            'description': description,                        # Specific instance details
            'severity': severity,                             # Risk level assessment
            'file_path': file_path,                           # Location of vulnerability
            'timestamp': datetime.datetime.now().isoformat()  # Discovery timestamp
        }
        
        # Add vulnerability to the master list for reporting and analysis
        self.vulnerabilities.append(vuln)
        
    def log_recommendation(self, category: str, recommendation: str, priority: str = "MEDIUM") -> None:
        """
        If any vulnerability has been loged, then this will log a recommendation to solve that vulnerability.
        """
        # Create structured recommendation record for security improvement tracking
        rec: RecommendationDict = {
            'category': category,                             # Security domain classification
            'recommendation': recommendation,                 # Specific improvement action
            'priority': priority,                            # Implementation priority
            'timestamp': datetime.datetime.now().isoformat() # Recommendation timestamp
        }
        
        # Add recommendation to the master list for inclusion in final report
        self.security_recommendations.append(rec)

    def scan_sql_injection_vulnerabilities(self) -> None:
        """
        Detect SQL Injection Vulnerabilities.
        """
        print("🔍 Scanning for SQL Injection Vulnerabilities...")
        
        # Define target Python files that may contain database operations
        python_files: List[str] = [
            'app.py',           # Main Flask application
            'models.py',        # Database models and schema
            'routes/auth.py',   # Authentication routes
            'routes/admin.py',  # Admin panel routes
            'routes/user.py'    # User management routes
        ]
        
        # Define regex patterns that indicate potential SQL injection vulnerabilities
        dangerous_patterns: List[str] = [
            r'execute\s*\(\s*["\'].*?%.*?["\']',          # String formatting in SQL: execute("SELECT * FROM users WHERE id=%s" % user_id)
            r'execute\s*\(\s*f["\'].*?\{.*?\}.*?["\']',   # F-string in SQL: execute(f"SELECT * FROM users WHERE id={user_id}")
            r'execute\s*\(\s*.*?\+.*?\)',                 # String concatenation: execute("SELECT * FROM users WHERE id=" + user_id)
        ]
        
        # Scan each target file for SQL injection vulnerabilities
        for file_path in python_files:
            if os.path.exists(file_path):
                try:
                    # Read and analyze file content line by line
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content: str = f.read()
                        lines: List[str] = content.split('\n')
                        
                    # Check each line against dangerous patterns
                    for i, line in enumerate(lines, 1):
                        for pattern in dangerous_patterns:
                            if re.search(pattern, line):
                                self.log_vulnerability(
                                    "Potential SQL Injection",
                                    f"Line {i}: {line.strip()}",
                                    "HIGH",
                                    file_path
                                )
                
                except Exception as e:
                    print(f"Error scanning {file_path}: {str(e)}")
        
        # Validate secure coding practices in authentication routes
        try:
            with open('routes/auth.py', 'r') as f:
                auth_content: str = f.read()
                
            # Check for SQLAlchemy ORM usage (recommended secure practice)
            if 'query.filter_by(' in auth_content and 'execute(' not in auth_content:
                print("✅ Using SQLAlchemy ORM (safer than raw SQL)")
            # Check for parameterized queries (safe SQL practice)
            elif '?' in auth_content or '%s' in auth_content:
                print("✅ Found parameterized queries")
            else:
                self.log_recommendation(
                    "SQL Security", 
                    "Ensure all database queries use parameterization or ORM", 
                    "HIGH"
                )
                
        except Exception as e:
            print(f"Error checking parameterized queries: {str(e)}")

    def scan_xss_vulnerabilities(self) -> None:
        """
        Detect XSS vulnerabilities in HTML templates and JavaScript code.
        """
        print("\n🔍 Scanning for XSS Vulnerabilities...")
        
        # Discover all HTML template files in the templates directory
        template_files: List[str] = []
        for root, _, files in os.walk('templates'):  # Note: dirs parameter unused but required by os.walk
            for file in files:
                if file.endswith('.html'):
                    template_files.append(os.path.join(root, file))
        
        # Define regex patterns that indicate potential XSS vulnerabilities
        dangerous_patterns: List[str] = [
            r'\{\{\s*.*?\s*\|\s*safe\s*\}\}',    # Jinja2 |safe filter: {{ user_input|safe }}
            r'<script.*?>.*?</script>',          # Inline script tags: <script>alert('xss')</script>
            r'innerHTML\s*=',                    # Direct DOM manipulation: element.innerHTML = userInput
        ]
        
        # Scan each template file for XSS vulnerability patterns
        for file_path in template_files:
            try:
                # Read and analyze template content line by line
                with open(file_path, 'r', encoding='utf-8') as f:
                    content: str = f.read()
                    lines: List[str] = content.split('\n')
                    
                # Check each line against dangerous XSS patterns
                for i, line in enumerate(lines, 1):
                    for pattern in dangerous_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.log_vulnerability(
                                "Potential XSS Vulnerability",
                                f"Line {i}: {line.strip()}",
                                "MEDIUM",
                                file_path
                            )
                            
            except Exception as e:
                print(f"Error scanning {file_path}: {str(e)}")
        
        # Check for Content Security Policy (CSP) implementation in main app
        if os.path.exists('app.py'):
            try:
                # Try different encodings to handle various file formats
                encodings_to_try: List[str] = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
                app_content: Optional[str] = None
                
                for encoding in encodings_to_try:
                    try:
                        with open('app.py', 'r', encoding=encoding) as f:
                            app_content = f.read()
                        break  # Successfully read file
                    except UnicodeDecodeError:
                        continue  # Try next encoding
                        
                if app_content:
                    # Verify CSP headers are implemented (important XSS protection)
                    if 'Content-Security-Policy' not in app_content:
                        self.log_recommendation(
                            "XSS Protection", 
                            "Implement Content Security Policy (CSP) headers to prevent XSS attacks", 
                            "MEDIUM"
                        )
                    else:
                        print("✅ CSP headers found")
                else:
                    print("Warning: Could not read app.py with any supported encoding")
                    
            except Exception as e:
                print(f"Error checking CSP: {str(e)}")

    def scan_authentication_vulnerabilities(self) -> None:
        """
        Authentication Security Analysis by examining authentication routes and practices
        like password validation, brute force protection, and session management.
        
        Returns:
            None: Authentication vulnerabilities logged to internal vulnerability list
        """
        print("\n🔍 Scanning Authentication Security...")
        
        # Analyze authentication implementation in the auth routes file
        if os.path.exists('routes/auth.py'):
            try:
                with open('routes/auth.py', 'r') as f:
                    auth_content: str = f.read()
                
                # Check for password validation function implementation
                if 'validate_password' in auth_content:
                    print("✅ Password validation function found")
                    
                    # Verify minimum password length requirement (NIST baseline)
                    if 'len(password) < 8' in auth_content:
                        print("✅ Minimum password length check (8 characters)")
                    else:
                        self.log_vulnerability(
                            "Weak Password Policy", 
                            "Minimum password length may be insufficient or missing", 
                            "MEDIUM"
                        )
                    
                    # Check for password complexity requirements
                    complexity_patterns: List[str] = [
                        '[A-Z]',           # Uppercase letters
                        '[a-z]',           # Lowercase letters  
                        r'\d',             # Numeric digits
                        '[!@#$%^&*()]'     # Special characters
                    ]
                    
                    for pattern in complexity_patterns:
                        if pattern in auth_content:
                            print(f"✅ Password complexity check found: {pattern}")
                        else:
                            self.log_vulnerability(
                                "Weak Password Policy", 
                                f"Missing complexity requirement: {pattern}", 
                                "LOW"
                            )
                else:
                    self.log_vulnerability(
                        "Missing Password Validation", 
                        "No password validation function found", 
                        "HIGH"
                    )
                
                # Check for brute force protection mechanisms
                if 'account_locked' in auth_content or 'failed_attempts' in auth_content:
                    print("✅ Account lockout mechanism found")
                else:
                    self.log_vulnerability(
                        "Missing Brute Force Protection", 
                        "No account lockout mechanism detected", 
                        "HIGH"
                    )
                
                # Check for rate limiting implementation
                if 'rate_limit' not in auth_content:
                    self.log_recommendation(
                        "Rate Limiting", 
                        "Implement rate limiting for login attempts to prevent brute force attacks", 
                        "MEDIUM"
                    )
                
            except Exception as e:
                print(f"Error scanning authentication: {str(e)}")

    def scan_session_security(self) -> None:
        """
        Session Management Security Analysis by analyzing JWT tokens and Flask session configuration.
        """
        print("\n🔍 Scanning Session Security...")
        
        # Analyze Flask application configuration for session security
        if os.path.exists('app.py'):
            try:
                # Try different encodings to handle various file formats
                encodings_to_try: List[str] = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
                app_content: Optional[str] = None
                
                for encoding in encodings_to_try:
                    try:
                        with open('app.py', 'r', encoding=encoding) as f:
                            app_content = f.read()
                        break  # Successfully read file
                    except UnicodeDecodeError:
                        continue  # Try next encoding
                        
                if app_content:
                    # Check for Flask SECRET_KEY configuration (critical for session security)
                    if 'SECRET_KEY' in app_content:
                        print("✅ SECRET_KEY configured")
                    else:
                        self.log_vulnerability(
                            "Missing Secret Key", 
                            "Flask SECRET_KEY not configured - sessions vulnerable to tampering", 
                            "CRITICAL"
                        )
                    
                    # Check for JWT secret key configuration (essential for token security)  
                    if 'JWT_SECRET_KEY' in app_content:
                        print("✅ JWT_SECRET_KEY configured")
                    else:
                        self.log_vulnerability(
                            "Missing JWT Secret", 
                            "JWT_SECRET_KEY not configured - tokens vulnerable to forgery", 
                            "HIGH"
                        )
                    
                    # Check for secure session cookie configuration
                    if 'SESSION_COOKIE_SECURE' not in app_content:
                        self.log_recommendation(
                            "Session Security", 
                            "Set SESSION_COOKIE_SECURE=True to ensure cookies only sent over HTTPS", 
                            "MEDIUM"
                        )
                    
                    # Check for HttpOnly session cookie flag (prevents XSS access)
                    if 'SESSION_COOKIE_HTTPONLY' not in app_content:
                        self.log_recommendation(
                            "Session Security", 
                            "Set SESSION_COOKIE_HTTPONLY=True to prevent JavaScript access to session cookies", 
                            "MEDIUM"
                        )
                else:
                    print("Warning: Could not read app.py with any supported encoding")
                
            except Exception as e:
                print(f"Error scanning session security: {str(e)}")

    def scan_input_validation(self) -> None:
        """
        Analyze Input Validation Practices.
        """
        print("\n🔍 Scanning Input Validation...")
        
        # Define route files that handle user input
        routes: List[str] = [
            'routes/auth.py',   # Authentication and registration input
            'routes/admin.py',  # Administrative operations input
            'routes/user.py'    # User profile and settings input
        ]
        
        # Analyze each route file for input validation practices
        for route_file in routes:
            if os.path.exists(route_file):
                try:
                    with open(route_file, 'r') as f:
                        content: str = f.read()
                    
                    # Check for input sanitization (good security practice)
                    if 'strip()' in content:
                        print(f"✅ Input stripping found in {route_file}")
                    
                    # Check for email validation implementation
                    if 'validate_email' in content:
                        print(f"✅ Email validation found in {route_file}")
                    
                    # Check for unsafe direct JSON access without validation
                    if 'request.get_json()' in content:
                        if 'get(' not in content:
                            self.log_vulnerability(
                                "Unsafe Input Handling", 
                                f"Direct JSON access without validation in {route_file}", 
                                "MEDIUM"
                            )
                
                except Exception as e:
                    print(f"Error scanning {route_file}: {str(e)}")

    def scan_database_security(self) -> None:
        """
        Database Security Assessment to ensure database integrity.
        """
        print("\n🔍 Scanning Database Security...")
        
        # Define path to the SQLite database file
        db_path: str = "instance/user_auth.db"
        
        # Verify database file exists and is accessible
        if not os.path.exists(db_path):
            self.log_vulnerability(
                "Missing Database", 
                "Database file not found - application cannot function", 
                "CRITICAL"
            )
            return
        
        try:
            # Establish database connection for security analysis
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check admin user password security (critical security control)
            cursor.execute("SELECT username, password_hash FROM users WHERE role='Admin';")
            admin_users = cursor.fetchall()
            
            for username, password_hash in admin_users:
                # Verify bcrypt hashing is used (industry standard for password security)
                if not password_hash.startswith('$2b$'):
                    self.log_vulnerability(
                        "Weak Password Hashing", 
                        f"Admin user '{username}' may not use bcrypt hashing algorithm", 
                        "HIGH"
                    )
                else:
                    print(f"✅ Admin '{username}' uses bcrypt hashing")
            
            # Check for users with empty or null passwords (critical security flaw)
            cursor.execute("SELECT COUNT(*) FROM users WHERE password_hash IS NULL OR password_hash = '';")
            empty_passwords: int = cursor.fetchone()[0]
            
            if empty_passwords > 0:
                self.log_vulnerability(
                    "Empty Passwords", 
                    f"{empty_passwords} user accounts have empty passwords", 
                    "CRITICAL"
                )
            
            # Check for inactive administrative accounts (security monitoring)
            cursor.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND is_active=0;")
            inactive_admins: int = cursor.fetchone()[0]
            
            if inactive_admins > 0:
                self.log_vulnerability(
                    "Inactive Admin Accounts", 
                    f"{inactive_admins} administrative accounts are inactive", 
                    "MEDIUM"
                )
            
            # Close database connection to prevent resource leaks
            conn.close()
            
        except Exception as e:
            self.log_vulnerability(
                "Database Access Error", 
                f"Cannot access database for security analysis: {str(e)}", 
                "HIGH"
            )

    def scan_configuration_security(self) -> None:
        """
        Check the configuration files for security issues.
        """
        print("\n🔍 Scanning Configuration Security...")
        
        # Define configuration files to analyze for security issues
        config_files: List[str] = [
            'config.py',  # Application configuration
            '.env',       # Environment variables
            'app.py'      # Flask app configuration
        ]
        
        # Analyze each configuration file for security misconfigurations
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    # Try different encodings to handle various file formats
                    encodings_to_try: List[str] = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
                    content: Optional[str] = None
                    
                    for encoding in encodings_to_try:
                        try:
                            with open(config_file, 'r', encoding=encoding) as f:
                                content = f.read()
                            break  # Successfully read file
                        except UnicodeDecodeError:
                            continue  # Try next encoding
                            
                    if content:
                        # Check for hardcoded passwords (major security risk)
                        if 'password' in content.lower() and '=' in content:
                            lines: List[str] = content.split('\n')
                            for i, line in enumerate(lines, 1):
                                # Skip commented lines to avoid false positives
                                if ('password' in line.lower() and '=' in line 
                                    and not line.strip().startswith('#')):
                                    self.log_vulnerability(
                                        "Hardcoded Password", 
                                        f"Potential hardcoded password in {config_file}:{i}", 
                                        "HIGH"
                                    )
                        
                        # Check for debug mode enabled (security risk in production)
                        if 'DEBUG = True' in content:
                            self.log_vulnerability(
                                "Debug Mode Enabled", 
                                f"DEBUG mode enabled in {config_file} - information disclosure risk", 
                                "MEDIUM"
                            )
                        
                        # Check for weak or default secret keys
                        if 'SECRET_KEY' in content:
                            secret_match = re.search(r'SECRET_KEY\s*=\s*["\']([^"\']+)["\']', content)
                            if secret_match:
                                secret: str = secret_match.group(1)
                                # Validate secret key strength
                                if len(secret) < 32:
                                    self.log_vulnerability(
                                        "Weak Secret Key", 
                                        "SECRET_KEY is too short (minimum 32 characters recommended)", 
                                        "HIGH"
                                    )
                                # Check for common default values
                                elif secret in ['your-secret-key', 'change-me', 'secret', 'dev-key']:
                                    self.log_vulnerability(
                                        "Default Secret Key", 
                                        "SECRET_KEY appears to be a default or placeholder value", 
                                        "CRITICAL"
                                    )
                    else:
                        print(f"Warning: Could not read {config_file} with any supported encoding")
                
                except Exception as e:
                    print(f"Error scanning {config_file}: {str(e)}")

    def generate_security_report(self) -> int:
        """
        Generates an comprehensive security report.
        The scoring is as follows:
        - 90-100: Excellent security posture
        - 70-89: Good security with minor improvements needed
        - 50-69: Moderate security risks present
        - Below 50: Significant vulnerabilities requiring immediate attention
        """
        print("\n" + "=" * 60)
        print("🛡️ SECURITY VULNERABILITY SCAN REPORT")
        print("=" * 60)
        
        # Execute comprehensive security assessment across all categories
        self.scan_sql_injection_vulnerabilities()
        self.scan_xss_vulnerabilities()
        self.scan_authentication_vulnerabilities()
        self.scan_session_security()
        self.scan_input_validation()
        self.scan_database_security()
        self.scan_configuration_security()
        
        # Categorize vulnerabilities by severity level for prioritized remediation
        critical_vulns: List[VulnerabilityDict] = [
            v for v in self.vulnerabilities if v['severity'] == 'CRITICAL'
        ]
        high_vulns: List[VulnerabilityDict] = [
            v for v in self.vulnerabilities if v['severity'] == 'HIGH'
        ]
        medium_vulns: List[VulnerabilityDict] = [
            v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'
        ]
        low_vulns: List[VulnerabilityDict] = [
            v for v in self.vulnerabilities if v['severity'] == 'LOW'
        ]
        
        # Display vulnerability summary with visual indicators
        print(f"\n📊 VULNERABILITY SUMMARY")
        print(f"🚨 Critical: {len(critical_vulns)}")
        print(f"🔴 High: {len(high_vulns)}")
        print(f"🟡 Medium: {len(medium_vulns)}")
        print(f"🟢 Low: {len(low_vulns)}")
        print(f"📋 Total: {len(self.vulnerabilities)}")
        
        # Display critical vulnerabilities requiring immediate attention
        if critical_vulns:
            print(f"\n🚨 CRITICAL VULNERABILITIES (Fix Immediately!):")
            for vuln in critical_vulns:
                print(f"  • {vuln['title']}: {vuln['description']}")
                if vuln['file_path']:
                    print(f"    File: {vuln['file_path']}")
        
        # Display high severity vulnerabilities requiring priority attention
        if high_vulns:
            print(f"\n🔴 HIGH SEVERITY VULNERABILITIES:")
            for vuln in high_vulns:
                print(f"  • {vuln['title']}: {vuln['description']}")
                if vuln['file_path']:
                    print(f"    File: {vuln['file_path']}")
        
        # Display security recommendations for proactive improvements
        if self.security_recommendations:
            print(f"\n💡 SECURITY RECOMMENDATIONS:")
            for rec in self.security_recommendations:
                priority_icon: str = (
                    "🔴" if rec['priority'] == 'HIGH' 
                    else "🟡" if rec['priority'] == 'MEDIUM' 
                    else "🟢"
                )
                print(f"  {priority_icon} [{rec['category']}] {rec['recommendation']}")
        
        # Calculate overall security score using weighted vulnerability penalties
        total_points: int = 100
        critical_penalty: int = len(critical_vulns) * 25
        high_penalty: int = len(high_vulns) * 15
        medium_penalty: int = len(medium_vulns) * 5
        low_penalty: int = len(low_vulns) * 1
        
        security_score: int = max(0, total_points - critical_penalty - high_penalty - medium_penalty - low_penalty)
        
        # Display security score with interpretation
        print(f"\n🏆 SECURITY SCORE: {security_score}/100")
        
        if security_score >= 90:
            print("✅ Excellent security posture!")
        elif security_score >= 70:
            print("⚠️ Good security, but some improvements needed")
        elif security_score >= 50:
            print("⚠️ Moderate security risks present")
        else:
            print("🚨 Significant security vulnerabilities detected!")
        
        # Save detailed findings to persistent storage
        self.save_security_report()
        
        return security_score

    def save_security_report(self) -> None:
        """
        Save Comprehensive Security Report to JSON File with timestamp, recommendations, and summary.
        """
        try:
            # Create comprehensive report data structure
            report_data: SecurityReportDict = {
                'timestamp': datetime.datetime.now().isoformat(),
                'vulnerabilities': self.vulnerabilities,
                'recommendations': self.security_recommendations,
                'summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                    'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                    'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                    'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
                }
            }
            
            # Write report to JSON file with readable formatting
            with open('security_report.json', 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"\n📁 Detailed security report saved to: security_report.json")
            
        except Exception as e:
            print(f"Failed to save security report: {str(e)}")

if __name__ == "__main__":
    """
    This is used for:
    1. Initialize SecurityScanner instance
    2. Execute complete security assessment across all categories
    3. Display final security score and recommendations
    4. Provide actionable feedback based on score threshold
    """
    # Initialize security scanner instance for comprehensive assessment
    scanner: SecurityScanner = SecurityScanner()
    
    # Execute complete security vulnerability scan across all categories
    security_score: int = scanner.generate_security_report()
    
    # Display final assessment results with actionable recommendations
    print(f"\n🔍 Security scan completed. Score: {security_score}/100")
    
    # Provide guidance based on security score threshold
    if security_score < 70:
        print("⚠️ Please address the identified vulnerabilities to improve security.")
    elif security_score >= 90:
        print("✅ Excellent security posture maintained!")
    else:
        print("👍 Good security level with room for minor improvements.")

# This is the end of the security_scanner.py script.