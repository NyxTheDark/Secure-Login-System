#!/usr/bin/env python3

"""
This script performs comprehensive testing of the entire user authentication system,
including edge cases, security testing, and debugging scenarios.
It covers user registration, login, admin functionality, and security features like brute force protection.
It also generates a detailed report of the test results.
IF you are using this script, please ensure you have the necessary permissions and that it complies with your testing policies.

Note: If you want only individual tests, you can import this class and call the method directly.
Also some of the tests are dependent on each other, so ensure to run them in the correct order.
You can also use files like secure_test_suite.py, edge_case_tester.py, system_debugger.py, master_test_suit.py for specific tests.
"""
import requests
import json
import time
import random
import string
from typing import Dict, Any, Optional, List

class ComprehensiveTestSuite:
    """
    This class is built to perform end-to-end testing of the entire authentication system including:
    - User registration and validation
    - Login functionality and security
    - Admin dashboard operations
    - Security features (brute force protection, role-based access)
    - Edge cases and invalid data handling
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        """
        Initialize the test suite with base configuration
        """
        self.base_url = base_url
        
        # Test result tracking with proper type annotations
        self.test_results: List[Dict[str, Any]] = []  # Stores detailed test results
        self.admin_token: Optional[str] = None  # JWT token for admin authentication
        self.user_token: Optional[str] = None   # JWT token for user authentication
        
        # Test data collections with type annotations
        self.test_users: List[Dict[str, str]] = []    # Valid test users created during testing
        self.failed_tests: List[str] = []             # Names of tests that failed
        self.passed_tests: List[str] = []             # Names of tests that passed
        
    def log_test(self, test_name: str, status: str, details: str = "") -> None:
        """
        This method:
        1. Creates a detailed test result record with timestamp
        2. Categorizes tests as passed or failed
        3. Provides console output with visual indicators
        4. Stores results for final report generation
        """
        # Create structured test result record
        result: Dict[str, Any] = {
            'test': test_name,
            'status': status,
            'details': details,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.test_results.append(result)
        
        # Track test outcomes for summary statistics
        if status == "PASS":
            self.passed_tests.append(test_name)
            print(f"✅ {test_name}: PASSED")
        else:
            self.failed_tests.append(test_name)
            print(f"❌ {test_name}: FAILED - {details}")
        
        # Display additional details if provided
        if details:
            print(f"   Details: {details}")

    def generate_random_string(self, length: int = 8) -> str:
        """
        Generate random alphanumeric string for unique test data so that it can be used for
        creating unique usernames, emails, and other test identifiers.
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_test_email(self) -> str:
        """
        Generate unique email address for testing
        """
        return f"test_{self.generate_random_string()}@example.com"

    def test_server_connectivity(self) -> bool:
        """
        Test server connectivity and availability
        It verifies:
        1. The Flask server is running and accessible
        2. The server responds to HTTP requests
        3. The application is properly configured
        """
        print("\n🔌 Testing Server Connectivity...")
        try:
            # Send GET request to root endpoint with timeout
            response = requests.get(self.base_url, timeout=5)
            
            if response.status_code == 200:
                self.log_test("Server Connectivity", "PASS", 
                            f"Server responding with status {response.status_code}")
                return True
            else:
                self.log_test("Server Connectivity", "FAIL", 
                            f"Server returned status {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            self.log_test("Server Connectivity", "FAIL", 
                        "Connection refused - server may not be running")
            return False
        except requests.exceptions.Timeout:
            self.log_test("Server Connectivity", "FAIL", 
                        "Request timeout - server may be overloaded")
            return False
        except Exception as e:
            self.log_test("Server Connectivity", "FAIL", f"Connection error: {str(e)}")
            return False

    def test_user_registration_valid(self) -> bool:
        """
        Test valid user registration with correct data by:
        1. Creating a user with valid username, email, and password
        2. Ensuring password meets security requirements
        3. Verifying proper HTTP response codes
        4. Storing successful registrations for subsequent tests
        """
        print("\n👤 Testing Valid User Registration...")
        
        # Create test user data with secure password meeting all requirements
        test_data: Dict[str, str] = {
            "username": f"testuser_{self.generate_random_string()}",
            "email": self.generate_test_email(),
            "password": "TestPass123!",  # Meets all security requirements
            "captcha": "verified"        # Simulated CAPTCHA verification
        }
        
        try:
            # Send registration request to the API
            response = requests.post(f"{self.base_url}/auth/register", json=test_data)
            
            if response.status_code == 201:
                # Store successful registration for use in other tests
                self.test_users.append(test_data)
                self.log_test("Valid User Registration", "PASS", 
                            f"User {test_data['username']} registered successfully")
                return True
            else:
                self.log_test("Valid User Registration", "FAIL", 
                            f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_test("Valid User Registration", "FAIL", f"Request exception: {str(e)}")
            return False
        except Exception as e:
            self.log_test("Valid User Registration", "FAIL", f"Unexpected exception: {str(e)}")
            return False

    def test_duplicate_registration(self) -> None:
        """
        This test validates that the system properly prevents duplicate user registrations by:
        1. Attempting to register with an email that already exists
        2. Verifying the system returns appropriate error response (400 Bad Request)
        3. Ensuring data integrity is maintained
        """
        print("\n🚫 Testing Duplicate Registration Prevention...")
        
        # Check if we have test users to work with
        if not self.test_users:
            self.log_test("Duplicate Registration Prevention", "SKIP", 
                        "No test users available - depends on valid registration test")
            return
        
        # Create registration data with same email but different username
        duplicate_data: Dict[str, str] = {
            "username": f"duplicate_{self.generate_random_string()}",
            "email": self.test_users[0]["email"],  # Use existing email
            "password": "TestPass123!",
            "captcha": "verified"
        }
        
        try:
            # Attempt duplicate registration
            response = requests.post(f"{self.base_url}/auth/register", json=duplicate_data)
            
            if response.status_code == 400:
                self.log_test("Duplicate Registration Prevention", "PASS", 
                            "Duplicate email correctly rejected with 400 status")
            else:
                self.log_test("Duplicate Registration Prevention", "FAIL", 
                            f"Expected 400 Bad Request, got {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.log_test("Duplicate Registration Prevention", "FAIL", 
                        f"Request exception: {str(e)}")
        except Exception as e:
            self.log_test("Duplicate Registration Prevention", "FAIL", 
                        f"Unexpected exception: {str(e)}")

    def test_invalid_data_registration(self) -> None:
        """
        This comprehensive test validates that the system properly handles invalid input by:
        1. Testing various invalid data scenarios (empty fields, malformed data, etc.)
        2. Ensuring proper error responses are returned (400 Bad Request)
        3. Validating that security requirements are enforced
        4. Preventing invalid users from being created in the database
        note: This test is essential for maintaining data integrity and user security.
        """
        print("\n❌ Testing Invalid Data Registration...")
        
        # Define test cases with proper type annotations
        # Each test case includes: name, data payload, and expected HTTP status
        invalid_test_cases: List[Dict[str, Any]] = [
            {
                "name": "Empty Password",
                "data": {
                    "username": "testuser", 
                    "email": "test@test.com", 
                    "password": "", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Invalid Email Format", 
                "data": {
                    "username": "testuser", 
                    "email": "invalid-email", 
                    "password": "TestPass123!", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Weak Password",
                "data": {
                    "username": "testuser", 
                    "email": "weak@test.com", 
                    "password": "weak", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Missing Username",
                "data": {
                    "email": "missing@test.com", 
                    "password": "TestPass123!", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Special Characters in Password Only",
                "data": {
                    "username": "testuser", 
                    "email": "special@test.com", 
                    "password": "!@#$%^&*()", 
                    "captcha": "verified"
                },
                "expected_status": 400
            }
        ]
        
        # Test each invalid data scenario
        for test_case in invalid_test_cases:
            try:
                response = requests.post(f"{self.base_url}/auth/register", json=test_case["data"])
                
                if response.status_code == test_case["expected_status"]:
                    self.log_test(f"Invalid Registration - {test_case['name']}", "PASS", 
                                "Correctly rejected invalid data")
                else:
                    self.log_test(f"Invalid Registration - {test_case['name']}", "FAIL", 
                                f"Expected {test_case['expected_status']}, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test(f"Invalid Registration - {test_case['name']}", "FAIL", 
                            f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test(f"Invalid Registration - {test_case['name']}", "FAIL", 
                            f"Unexpected exception: {str(e)}")

    def test_admin_login(self) -> bool:
        """
        Test admin login functionality and JWT token retrieval
        """
        print("\n🔑 Testing Admin Login...")
        
        # Default admin credentials (should be configured in system)
        admin_data: Dict[str, str] = {
            "email": "admin@example.com",
            "password": "Admin123!",
            "captcha": "verified"
        }
        
        try:
            # Send login request to authentication endpoint
            response = requests.post(f"{self.base_url}/auth/login", json=admin_data)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    self.admin_token = data.get('access_token')
                    
                    if self.admin_token:
                        self.log_test("Admin Login", "PASS", 
                                    "Admin logged in successfully with JWT token")
                        return True
                    else:
                        self.log_test("Admin Login", "FAIL", 
                                    "Login successful but no access token received")
                        return False
                        
                except json.JSONDecodeError:
                    self.log_test("Admin Login", "FAIL", 
                                "Invalid JSON response from server")
                    return False
            else:
                self.log_test("Admin Login", "FAIL", 
                            f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_test("Admin Login", "FAIL", f"Request exception: {str(e)}")
            return False
        except Exception as e:
            self.log_test("Admin Login", "FAIL", f"Unexpected exception: {str(e)}")
            return False

    def test_user_login(self) -> bool:
        """
        Test regular user login functionality
        """
        print("\n🔐 Testing User Login...")
        
        # Check if we have registered test users available
        if not self.test_users:
            self.log_test("User Login", "SKIP", 
                        "No test users available - depends on user registration test")
            return False
        
        # Use first registered test user for login
        user_data: Dict[str, str] = {
            "email": self.test_users[0]["email"],
            "password": self.test_users[0]["password"],
            "captcha": "verified"
        }
        
        try:
            # Send login request
            response = requests.post(f"{self.base_url}/auth/login", json=user_data)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    self.user_token = data.get('access_token')
                    
                    if self.user_token:
                        self.log_test("User Login", "PASS", 
                                    "User logged in successfully with JWT token")
                        return True
                    else:
                        self.log_test("User Login", "FAIL", 
                                    "Login successful but no access token received")
                        return False
                        
                except json.JSONDecodeError:
                    self.log_test("User Login", "FAIL", 
                                "Invalid JSON response from server")
                    return False
            else:
                self.log_test("User Login", "FAIL", 
                            f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_test("User Login", "FAIL", f"Request exception: {str(e)}")
            return False
        except Exception as e:
            self.log_test("User Login", "FAIL", f"Unexpected exception: {str(e)}")
            return False

    def test_brute_force_protection(self) -> None:
        """
        system reacks the number of password attempts, if the number of unsuccessful attempts 
        reach 5 then the account will be locked for 30 minutes and the admin as well as the account
        will be notified and the accounts can only be unlocked by the admin.
        """
        print("\n🛡️ Testing Brute Force Protection...")
        
        # Create dedicated test user for brute force testing
        brute_force_user: Dict[str, str] = {
            "username": f"brutetest_{self.generate_random_string()}",
            "email": self.generate_test_email(),
            "password": "BruteTest123!",
            "captcha": "verified"
        }
        
        # First, register the test user
        try:
            reg_response = requests.post(f"{self.base_url}/auth/register", json=brute_force_user)
            if reg_response.status_code != 201:
                self.log_test("Brute Force Protection", "FAIL", 
                            f"Could not create test user: {reg_response.status_code}")
                return
        except Exception as e:
            self.log_test("Brute Force Protection", "FAIL", 
                        f"User creation failed: {str(e)}")
            return
        
        # Attempt multiple failed logins to trigger lockout
        failed_attempts = 0
        max_attempts = 6  # Try 6 attempts to ensure lockout at 5
        
        for i in range(max_attempts):
            try:
                # Use intentionally wrong password
                bad_login: Dict[str, str] = {
                    "email": brute_force_user["email"],
                    "password": "WrongPassword123!",  # Intentionally incorrect
                    "captcha": "verified"
                }
                
                response = requests.post(f"{self.base_url}/auth/login", json=bad_login)
                
                if response.status_code == 401:
                    # Unauthorized - expected for wrong password
                    failed_attempts += 1
                    print(f"   Attempt {i+1}: Failed login (expected)")
                    
                elif response.status_code == 423:
                    # Account locked - this is what we're testing for
                    self.log_test("Brute Force Protection", "PASS", 
                                f"Account locked after {failed_attempts} failed attempts")
                    return
                    
                elif response.status_code == 429:
                    # Too many requests - also acceptable security measure
                    self.log_test("Brute Force Protection", "PASS", 
                                f"Rate limiting activated after {failed_attempts} attempts")
                    return
                else:
                    self.log_test("Brute Force Protection", "FAIL", 
                                f"Unexpected status {response.status_code} on attempt {i+1}")
                    return
                    
            except Exception as e:
                self.log_test("Brute Force Protection", "FAIL", 
                            f"Exception during attempt {i+1}: {str(e)}")
                return
                
        # If we get here, account was not locked after max attempts
        self.log_test("Brute Force Protection", "FAIL", 
                    f"Account was not locked after {max_attempts} failed attempts")

    def test_admin_functionality(self) -> None:
        """
        Test admin dashboard functionality and user management operations
        """
        print("\n👨‍💼 Testing Admin Dashboard Functionality...")
        
        # Check if admin token is available
        if not self.admin_token:
            self.log_test("Admin Functionality", "SKIP", 
                        "No admin token available - depends on admin login test")
            return
        
        # Prepare authorization headers for admin requests
        headers: Dict[str, str] = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Test 1: Get all users with pagination
        try:
            response = requests.get(f"{self.base_url}/admin/users?page=1&per_page=10", 
                                  headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    self.log_test("Admin Get Users", "PASS", 
                                f"Successfully retrieved user list with {len(users_data.get('users', []))} users")
                except json.JSONDecodeError:
                    self.log_test("Admin Get Users", "FAIL", "Invalid JSON in users response")
            else:
                self.log_test("Admin Get Users", "FAIL", 
                            f"Status: {response.status_code}, Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            self.log_test("Admin Get Users", "FAIL", f"Request exception: {str(e)}")
        except Exception as e:
            self.log_test("Admin Get Users", "FAIL", f"Unexpected exception: {str(e)}")
        
        # Test 2: Get system statistics
        try:
            response = requests.get(f"{self.base_url}/admin/stats", 
                                  headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    stats = response.json()
                    # Validate expected statistics fields
                    expected_fields = ['total_users', 'active_users', 'total_logins']
                    missing_fields = [field for field in expected_fields if field not in stats]
                    
                    if not missing_fields:
                        self.log_test("Admin Statistics", "PASS", 
                                    f"Retrieved complete stats: {stats}")
                    else:
                        self.log_test("Admin Statistics", "FAIL", 
                                    f"Missing statistics fields: {missing_fields}")
                        
                except json.JSONDecodeError:
                    self.log_test("Admin Statistics", "FAIL", "Invalid JSON in statistics response")
            else:
                self.log_test("Admin Statistics", "FAIL", 
                            f"Status: {response.status_code}, Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            self.log_test("Admin Statistics", "FAIL", f"Request exception: {str(e)}")
        except Exception as e:
            self.log_test("Admin Statistics", "FAIL", f"Unexpected exception: {str(e)}")

    def test_unauthorized_access(self) -> None:
        """
        Test unauthorized access protection for secured endpoints:
        1. Protected endpoints reject requests without authentication tokens
        2. Proper HTTP 401 Unauthorized responses are returned
        3. System prevents unauthorized access to sensitive data
        4. Authentication middleware is properly configured
        """
        print("\n🚨 Testing Unauthorized Access Protection...")
        
        # Define protected endpoints that should require authentication
        protected_endpoints: List[tuple[str, str]] = [
            ("/admin/users", "GET"),        # Admin user management
            ("/admin/stats", "GET"),        # Admin statistics
            ("/user/profile", "GET"),       # User profile access
            ("/admin/users/1/toggle-status", "POST")  # Admin user operations
        ]
        
        # Test each protected endpoint without authentication
        for endpoint, method in protected_endpoints:
            try:
                # Send request without Authorization header
                if method == "GET":
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                elif method == "POST":
                    response = requests.post(f"{self.base_url}{endpoint}", timeout=5)
                else:
                    continue  # Skip unsupported methods
                
                if response.status_code == 401:
                    self.log_test(f"Unauthorized Access - {endpoint}", "PASS", 
                                "Correctly rejected unauthorized request with 401")
                elif response.status_code == 422:
                    # Some JWT implementations return 422 for missing tokens
                    self.log_test(f"Unauthorized Access - {endpoint}", "PASS", 
                                "Correctly rejected request with 422 (missing token)")
                else:
                    self.log_test(f"Unauthorized Access - {endpoint}", "FAIL", 
                                f"Expected 401 Unauthorized, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test(f"Unauthorized Access - {endpoint}", "FAIL", 
                            f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test(f"Unauthorized Access - {endpoint}", "FAIL", 
                            f"Unexpected exception: {str(e)}")

    def test_role_based_access(self) -> None:
        """
        Test role-based access control (RBAC) enforcement. A proper HTTP response is returned.
        """
        print("\n🎭 Testing Role-Based Access Control...")
        
        # Check if user token is available
        if not self.user_token:
            self.log_test("Role-Based Access", "SKIP", 
                        "No user token available - depends on user login test")
            return
        
        # Prepare user authorization headers
        user_headers: Dict[str, str] = {"Authorization": f"Bearer {self.user_token}"}
        
        # Test admin endpoint access with user token (should be forbidden)
        admin_endpoints: List[str] = [
            "/admin/users",
            "/admin/stats", 
            "/admin/users/1/toggle-status"
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = requests.get(f"{self.base_url}{endpoint}", 
                                      headers=user_headers, timeout=5)
                
                if response.status_code == 403:
                    self.log_test(f"Role-Based Access - {endpoint}", "PASS", 
                                "User correctly denied admin access with 403 Forbidden")
                elif response.status_code == 401:
                    # Some implementations might return 401 for role issues
                    self.log_test(f"Role-Based Access - {endpoint}", "PASS", 
                                "User correctly denied admin access with 401")
                else:
                    self.log_test(f"Role-Based Access - {endpoint}", "FAIL", 
                                f"Expected 403 Forbidden, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test(f"Role-Based Access - {endpoint}", "FAIL", 
                            f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test(f"Role-Based Access - {endpoint}", "FAIL", 
                            f"Unexpected exception: {str(e)}")

    def run_all_tests(self) -> None:
        """
        This method orchestrates all test phases in the proper order:
        1. Infrastructure tests (server connectivity)
        2. Core functionality tests (registration, login)
        3. Security tests (brute force, unauthorized access)
        4. Admin functionality tests
        5. Role-based access control tests
        """
        print("🚀 Starting Comprehensive End-to-End Testing Suite")
        print("=" * 60)
        print("This suite tests all aspects of the authentication system:")
        print("• User registration and validation")
        print("• Login security and token management") 
        print("• Admin dashboard functionality")
        print("• Security protections and access controls")
        print("• Edge cases and error handling")
        print("=" * 60)
        
        start_time = time.time()
        
        # Phase 1: Infrastructure Tests
        print("\n🏗️ PHASE 1: Infrastructure Testing")
        if not self.test_server_connectivity():
            print("❌ Server not accessible. Stopping all tests.")
            print("Please ensure the Flask application is running on", self.base_url)
            return
        
        # Phase 2: Core Functionality Tests  
        print("\n🔧 PHASE 2: Core Functionality Testing")
        self.test_user_registration_valid()
        self.test_duplicate_registration()
        self.test_invalid_data_registration()
        
        # Phase 3: Authentication Tests
        print("\n🔐 PHASE 3: Authentication Testing")
        self.test_admin_login()
        self.test_user_login()
        
        # Phase 4: Security Tests
        print("\n🛡️ PHASE 4: Security Testing")
        self.test_brute_force_protection()
        self.test_unauthorized_access()
        self.test_role_based_access()
        
        # Phase 5: Admin Functionality Tests
        print("\n👨‍💼 PHASE 5: Admin Dashboard Testing")
        self.test_admin_functionality()
        
        # Generate comprehensive summary report
        end_time = time.time()
        self.generate_test_report(end_time - start_time)

    def generate_test_report(self, duration: float) -> None:
        """
        Generate test summary report
        """
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST SUMMARY REPORT")
        print("=" * 60)
        
        # Calculate test statistics
        total_tests = len(self.test_results)
        passed_count = len(self.passed_tests)
        failed_count = len(self.failed_tests)
        skipped_count = total_tests - passed_count - failed_count
        success_rate = (passed_count / total_tests * 100) if total_tests > 0 else 0
        
        # Display summary statistics
        print(f"📈 EXECUTION SUMMARY:")
        print(f"   Total Tests Run: {total_tests}")
        print(f"   ✅ Passed: {passed_count}")
        print(f"   ❌ Failed: {failed_count}")
        print(f"   ⏭️ Skipped: {skipped_count}")
        print(f"   🎯 Success Rate: {success_rate:.1f}%")
        print(f"   ⏱️ Duration: {duration:.2f} seconds")
        print(f"   🔍 Average per test: {(duration/total_tests):.2f}s")
        
        # Display failed tests for debugging
        if self.failed_tests:
            print(f"\n❌ FAILED TESTS ({len(self.failed_tests)}):")
            for test in self.failed_tests:
                print(f"   • {test}")
                # Find detailed failure reason
                for result in self.test_results:
                    if result['test'] == test and result['status'] == 'FAIL':
                        if result['details']:
                            print(f"     → {result['details']}")
                        break
        
        # Display passed tests for confirmation
        if self.passed_tests:
            print(f"\n✅ PASSED TESTS ({len(self.passed_tests)}):")
            for test in self.passed_tests:
                print(f"   • {test}")
        
        # Overall assessment
        print(f"\n🔍 OVERALL ASSESSMENT:")
        if success_rate >= 90:
            print("   🟢 EXCELLENT: System is highly reliable and secure")
        elif success_rate >= 75:
            print("   🟡 GOOD: System is mostly functional with minor issues")
        elif success_rate >= 50:
            print("   🟠 NEEDS ATTENTION: Significant issues require fixes")
        else:
            print("   🔴 CRITICAL: Major problems need immediate attention")
        
        # Save detailed report to file
        self.save_detailed_report()

    def save_detailed_report(self) -> None:
        """
        Save detailed test results to JSON file for analysis
        The report can be used for:
        - Automated CI/CD pipeline integration
        - Historical trend analysis
        - Debugging and troubleshooting
        - Compliance and audit documentation
        """
        try:
            # Prepare comprehensive report data
            report_data: Dict[str, Any] = {
                'metadata': {
                    'test_suite_version': '1.0.0',
                    'execution_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'target_system': self.base_url,
                    'test_environment': 'development'
                },
                'summary': {
                    'total_tests': len(self.test_results),
                    'passed': len(self.passed_tests),
                    'failed': len(self.failed_tests),
                    'skipped': len(self.test_results) - len(self.passed_tests) - len(self.failed_tests),
                    'success_rate': (len(self.passed_tests) / len(self.test_results) * 100) if self.test_results else 0
                },
                'test_categories': {
                    'infrastructure': [r for r in self.test_results if 'Connectivity' in r['test']],
                    'authentication': [r for r in self.test_results if any(x in r['test'] for x in ['Login', 'Registration'])],
                    'security': [r for r in self.test_results if any(x in r['test'] for x in ['Brute Force', 'Unauthorized', 'Role-Based'])],
                    'admin_functionality': [r for r in self.test_results if 'Admin' in r['test']]
                },
                'detailed_results': self.test_results,
                'failed_tests_analysis': [
                    {
                        'test_name': result['test'],
                        'failure_reason': result['details'],
                        'timestamp': result['timestamp']
                    }
                    for result in self.test_results if result['status'] == 'FAIL'
                ]
            }
            
            # Write report to file
            with open('comprehensive_test_report.json', 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n📁 Detailed JSON report saved to: comprehensive_test_report.json")
            print("   This report can be used for automated analysis and CI/CD integration")
            
        except IOError as e:
            print(f"❌ Failed to save report file: {str(e)}")
        except Exception as e:
            print(f"❌ Unexpected error while saving report: {str(e)}")

if __name__ == "__main__":
    """
    Main execution block for running the comprehensive test suite
    
    This block:
    1. Creates a test suite instance with default configuration
    2. Executes all tests in the proper order
    3. Handles any unexpected errors gracefully
    4. Provides clear feedback to the user
    
    The test suite can be customized by modifying the base_url parameter.
    """
    try:
        print("🧪 ValTec Authentication System - Comprehensive Test Suite")
        print("Version 1.0.0 - End-to-End Testing Framework")
        print("-" * 60)
        
        # Initialize and run test suite
        tester = ComprehensiveTestSuite()
        tester.run_all_tests()
        
        print("\n🎉 Test suite execution completed!")
        print("Check the generated reports for detailed analysis.")
        
    except KeyboardInterrupt:
        print("\n⚠️ Test suite interrupted by user")
    except Exception as e:
        print(f"\n💥 Fatal error during test execution: {str(e)}")
        print("Please check your system configuration and try again.")

# This is the end of the comprehensive_test_suite.py module.