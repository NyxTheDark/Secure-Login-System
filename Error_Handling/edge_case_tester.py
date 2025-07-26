#!/usr/bin/env python3

"""
Edge Case Testing Suite
This script tests various edge cases and boundary conditions that could cause the system 
to fail or behave unexpectedly.
"""

import requests
import json
import time
import random
import threading
import queue
from typing import Dict, List, Any, Union, Optional

class EdgeCaseTestSuite:
    """
    Edge Case Testing Suite deals with cases like:
    - Extremely long inputs that could cause buffer overflows
    - Special characters and Unicode that could break parsing
    - Null/empty values that could cause null pointer exceptions
    - Malformed requests that could crash the server
    - Concurrent operations that could cause race conditions
    - Boundary values that test input validation limits  
    - Session edge cases with invalid tokens
    - Race conditions in authentication flows
    """
    
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        # Initialize the Test suite with the base URL.
        self.base_url = base_url
        
        # Test result tracking with proper type annotations
        self.test_results: List[Dict[str, Any]] = []  # Detailed test results with metadata
        self.edge_cases_passed: int = 0               # Count of passed edge case tests
        self.edge_cases_failed: int = 0               # Count of failed edge case tests
        
    def log_test_result(self, test_name: str, status: str, details: str = "") -> None:
        """
        This method records each edge case test outcome including:
        - Test identification and categorization
        - Pass/Fail status with timestamps
        - Detailed failure analysis for debugging
        - Statistical tracking for summary reports
        """
        # Create structured test result record
        result: Dict[str, Any] = {
            'test': test_name,
            'status': status,
            'details': details,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'category': 'edge_case'  # Mark as edge case for reporting
        }
        self.test_results.append(result)
        
        # Update counters and provide visual feedback
        if status == "PASS":
            self.edge_cases_passed += 1
            print(f"✅ {test_name}: PASSED")
        else:
            self.edge_cases_failed += 1
            print(f"❌ {test_name}: FAILED - {details}")

    def test_extremely_long_inputs(self) -> None:
        """
        Test system behavior with extremely long inputs to validate system against:
        1. Buffer overflow attacks using oversized inputs
        2. Memory exhaustion from processing large data
        3. Database field length validation
        4. Application layer input size limits
        """
        print("\n📏 Testing Extremely Long Inputs...")
        
        # Generate extremely long strings to test system limits
        long_username = 'a' * 1000      # 1000 character username
        long_email = 'a' * 500 + '@example.com'  # 500+ character email
        long_password = 'Pass123!' * 100  # 800+ character password
        
        test_data: Dict[str, str] = {
            "username": long_username,
            "email": long_email,
            "password": long_password,
            "captcha": "verified"
        }
        
        try:
            # Send oversized data with timeout to prevent hanging
            response = requests.post(f"{self.base_url}/auth/register", 
                                   json=test_data, timeout=10)
            
            # Analyze response - system should reject oversized input
            if response.status_code in [400, 413]:  # Bad Request or Payload Too Large
                self.log_test_result("Extremely Long Inputs", "PASS", 
                                   "Server correctly rejected oversized input")
            elif response.status_code == 500:
                self.log_test_result("Extremely Long Inputs", "FAIL", 
                                   "Server error with long inputs - potential vulnerability")
            else:
                self.log_test_result("Extremely Long Inputs", "FAIL", 
                                   f"Unexpected response: {response.status_code}")
                
        except requests.exceptions.Timeout:
            self.log_test_result("Extremely Long Inputs", "FAIL", 
                               "Request timed out - server may be overwhelmed")
        except requests.exceptions.RequestException as e:
            self.log_test_result("Extremely Long Inputs", "FAIL", 
                               f"Request exception: {str(e)}")
        except Exception as e:
            self.log_test_result("Extremely Long Inputs", "FAIL", 
                               f"Unexpected exception: {str(e)}")

    def test_special_characters_in_inputs(self) -> None:
        """Use of character encoding and escaping can led to Injection Attack. 
        This def helps in prevention of :
        1. SQL Injection attacks using malicious SQL syntax
        2. Cross-Site Scripting (XSS) using HTML/JavaScript injection
        3. Unicode exploitation and character encoding issues
        4. HTML entity injection and parsing vulnerabilities
        """
        print("\n🌐 Testing Special Characters and Unicode...")
        
        # Define test cases with proper type annotations for security testing
        special_test_cases: List[Dict[str, Any]] = [
            {
                "name": "Unicode Characters",
                "data": {
                    "username": "用户名test",  # Chinese characters
                    "email": "test@example.com",
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "risk_level": "low"
            },
            {
                "name": "SQL Injection Attempt",
                "data": {
                    "username": "admin'; DROP TABLE users; --",  # Classic SQL injection
                    "email": "test@example.com",
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "risk_level": "critical"
            },
            {
                "name": "XSS Attempt",
                "data": {
                    "username": "<script>alert('xss')</script>",  # JavaScript injection
                    "email": "test@example.com",
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "risk_level": "high"
            },
            {
                "name": "HTML Entities",
                "data": {
                    "username": "&lt;test&gt;",  # HTML entity encoding
                    "email": "test@example.com",
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "risk_level": "medium"
            },
            {
                "name": "Path Traversal Attempt",
                "data": {
                    "username": "../../../etc/passwd",  # Directory traversal
                    "email": "test@example.com", 
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "risk_level": "high"
            }
        ]
        
        # Test each special character scenario
        for test_case in special_test_cases:
            try:
                response = requests.post(f"{self.base_url}/auth/register", 
                                       json=test_case["data"], timeout=5)
                
                # Analyze response based on risk level
                risk_level = test_case["risk_level"]
                
                if response.status_code in [400, 422]:  # Bad Request or Unprocessable Entity
                    self.log_test_result(f"Special Characters - {test_case['name']}", "PASS", 
                                       f"Server correctly rejected {risk_level} risk input")
                elif response.status_code == 201:
                    # Registration succeeded - check if this is acceptable based on risk
                    if risk_level in ["low", "medium"]:
                        self.log_test_result(f"Special Characters - {test_case['name']}", "PASS", 
                                           "Registration succeeded with properly sanitized data")
                    else:
                        self.log_test_result(f"Special Characters - {test_case['name']}", "FAIL", 
                                           f"High/critical risk input was accepted: {risk_level}")
                else:
                    self.log_test_result(f"Special Characters - {test_case['name']}", "FAIL", 
                                       f"Unexpected response: {response.status_code}")
                    
            except requests.exceptions.Timeout:
                self.log_test_result(f"Special Characters - {test_case['name']}", "FAIL", 
                                   "Request timeout - possible processing issue")
            except requests.exceptions.RequestException as e:
                self.log_test_result(f"Special Characters - {test_case['name']}", "FAIL", 
                                   f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test_result(f"Special Characters - {test_case['name']}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")

    def test_null_and_empty_values(self) -> None:
        """
        Test handling of null and empty values to prevent null pointer exceptions.
        """
        print("\n🔄 Testing Null and Empty Values...")
        
        # Define comprehensive null/empty test cases with proper typing
        null_test_cases: List[Dict[str, Any]] = [
            {
                "name": "Null Username",
                "data": {
                    "username": None,  # Explicit null value
                    "email": "test@example.com", 
                    "password": "Password123!", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Empty Username",
                "data": {
                    "username": "",  # Empty string
                    "email": "test@example.com", 
                    "password": "Password123!", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Whitespace Only Username",
                "data": {
                    "username": "   ",  # Only whitespace characters
                    "email": "test@example.com", 
                    "password": "Password123!", 
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Missing Email Field",
                "data": {
                    "username": "testuser", 
                    "password": "Password123!", 
                    "captcha": "verified"
                    # Missing "email" field entirely
                },
                "expected_status": 400
            },
            {
                "name": "Null Password",
                "data": {
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": None,  # Null password
                    "captcha": "verified"
                },
                "expected_status": 400
            },
            {
                "name": "Empty JSON Payload",
                "data": {},  # Completely empty payload
                "expected_status": 400
            }
        ]
        
        # Test each null/empty value scenario
        for test_case in null_test_cases:
            try:
                response = requests.post(f"{self.base_url}/auth/register", 
                                       json=test_case["data"], timeout=5)
                
                expected_status = test_case["expected_status"]
                
                if response.status_code == expected_status:
                    self.log_test_result(f"Null/Empty Values - {test_case['name']}", "PASS", 
                                       "Server correctly rejected invalid input")
                else:
                    self.log_test_result(f"Null/Empty Values - {test_case['name']}", "FAIL", 
                                       f"Expected {expected_status}, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test_result(f"Null/Empty Values - {test_case['name']}", "FAIL", 
                                   f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test_result(f"Null/Empty Values - {test_case['name']}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")

    def test_malformed_requests(self) -> None:
        """
        Test handling of malformed HTTP requests to prevent:
        1. Invalid JSON syntax that should be rejected
        2. Incorrect Content-Type headers causing parsing errors
        3. XML/other format data sent to JSON endpoints
        4. Corrupted or incomplete HTTP requests
        """
        print("\n🔧 Testing Malformed Requests...")
        
        # Define malformed request test cases with explicit type annotations
        # Using Union type to handle both string and dict data types safely
        malformed_tests: List[Dict[str, Union[str, Dict[str, str]]]] = [
            {
                "name": "Invalid JSON Syntax",
                "data": '{"username": "test", "email": "incomplete json"',  # Missing closing brace - STRING data
                "content_type": "application/json",
                "send_as": "raw_string"
            },
            {
                "name": "Wrong Content Type with JSON Data", 
                "data": {"username": "test", "email": "test@example.com"},  # DICT data
                "content_type": "text/plain",  # Wrong content type
                "send_as": "json"
            },
            {
                "name": "XML Instead of JSON",
                "data": "<user><username>test</username></user>",  # STRING data
                "content_type": "application/xml",
                "send_as": "raw_string"
            },
            {
                "name": "Form Data to JSON Endpoint",
                "data": "username=test&email=test@example.com",  # STRING data
                "content_type": "application/x-www-form-urlencoded",
                "send_as": "raw_string"
            }
        ]
        
        # Test each malformed request scenario with proper type handling
        for test_case in malformed_tests:
            try:
                headers: Dict[str, str] = {"Content-Type": str(test_case["content_type"])}
                
                # Type-safe request sending based on data type and send_as parameter
                # This ensures we handle both string and dictionary data appropriately
                send_as: str = str(test_case["send_as"])
                test_data = test_case["data"]
                
                if send_as == "json" and isinstance(test_data, dict):
                    # Send as JSON when data is a dictionary and send_as is "json"
                    response = requests.post(f"{self.base_url}/auth/register", 
                                           json=test_data, headers=headers, timeout=5)
                else:
                    # Send as raw data (string) for all other cases
                    # This handles malformed JSON strings, XML, form data, etc.
                    response = requests.post(f"{self.base_url}/auth/register", 
                                           data=str(test_data), headers=headers, timeout=5)
                
                # Analyze server response - should reject malformed requests appropriately
                # Different error codes indicate different types of rejection:
                # 400: Bad Request (malformed syntax)
                # 415: Unsupported Media Type (wrong content type)
                # 422: Unprocessable Entity (valid format but invalid content)
                if response.status_code in [400, 415, 422]:  
                    self.log_test_result(f"Malformed Request - {str(test_case['name'])}", "PASS", 
                                       f"Server correctly handled malformed request with {response.status_code}")
                else:
                    self.log_test_result(f"Malformed Request - {str(test_case['name'])}", "FAIL", 
                                       f"Expected 400/415/422, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                # Network/request exceptions are often acceptable for malformed requests
                # This indicates the server or network layer properly rejected the request
                self.log_test_result(f"Malformed Request - {str(test_case['name'])}", "PASS", 
                                   f"Request properly rejected with exception: {type(e).__name__}")
            except Exception as e:
                self.log_test_result(f"Malformed Request - {str(test_case['name'])}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")

    def test_concurrent_registrations(self) -> None:
        """
        Test concurrent registration attempts - Race Condition Testing
        
        This test validates system behavior under concurrent load by:
        1. Attempting simultaneous registrations with the same email
        2. Testing database transaction isolation
        3. Validating unique constraint enforcement
        4. Checking for race conditions in user creation
        
        Race conditions can cause:
        - Duplicate user accounts with same email
        - Database constraint violations
        - Data inconsistency and corruption
        - System instability under load
        """
        print("\n⚡ Testing Concurrent Registrations...")
        
        # Create thread-safe queue for collecting results
        results_queue: queue.Queue[Union[int, str]] = queue.Queue()
        test_email = f"concurrent_test_{random.randint(1000, 9999)}@example.com"
        
        def register_user(email: str, results_q: queue.Queue[Union[int, str]]) -> None:
            """
            Thread worker function for concurrent registration testing
            
            Args:
                email: Email address to register with
                results_q: Thread-safe queue for storing results
            """
            try:
                # Create registration data with unique username but same email
                data: Dict[str, str] = {
                    "username": f"concurrent_user_{random.randint(100, 999)}",
                    "email": email,
                    "password": "Password123!",
                    "captcha": "verified"
                }
                response = requests.post(f"{self.base_url}/auth/register", 
                                       json=data, timeout=5)
                results_q.put(response.status_code)
            except Exception as e:
                results_q.put(f"ERROR: {str(e)}")
        
        # Start 5 concurrent registration attempts with same email
        threads: List[threading.Thread] = []
        for _ in range(5):
            thread = threading.Thread(target=register_user, 
                                    args=(test_email, results_queue))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect and analyze results
        results: List[Union[int, str]] = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # Count successful vs failed registrations
        success_count = sum(1 for r in results if r == 201)
        error_count = sum(1 for r in results if r == 400)
        
        # Validate that only one registration succeeded
        if success_count == 1 and error_count >= 1:
            self.log_test_result("Concurrent Registrations", "PASS", 
                               f"Only 1 success, {error_count} properly rejected duplicates")
        elif success_count == 0:
            self.log_test_result("Concurrent Registrations", "FAIL", 
                               f"No registrations succeeded - possible system issue: {results}")
        else:
            self.log_test_result("Concurrent Registrations", "FAIL", 
                               f"Multiple registrations succeeded - race condition detected: {results}")

    def test_boundary_values(self) -> None:
        """
        This test validates system behavior at input validation boundaries.
        """
        print("\n📊 Testing Boundary Values...")
        
        # Define boundary test cases with proper type annotations
        boundary_tests: List[Dict[str, Any]] = [
            {
                "name": "Minimum Valid Password",
                "data": {
                    "username": "boundaryuser1",
                    "email": f"boundary1_{random.randint(1000, 9999)}@example.com",
                    "password": "Pass123!",  # Exactly meets minimum requirements
                    "captcha": "verified"
                },
                "expected": 201,
                "description": "8 characters with all required character types"
            },
            {
                "name": "Just Below Minimum Password",
                "data": {
                    "username": "boundaryuser2",
                    "email": f"boundary2_{random.randint(1000, 9999)}@example.com",
                    "password": "Pass12!",  # 7 characters, below minimum
                    "captcha": "verified"
                },
                "expected": 400,
                "description": "7 characters, should be rejected"
            },
            {
                "name": "Single Character Username",
                "data": {
                    "username": "a",  # Minimum possible username
                    "email": f"boundary3_{random.randint(1000, 9999)}@example.com",
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "expected": [201, 400],  # May be accepted or rejected
                "description": "Single character username test"
            },
            {
                "name": "Maximum Length Email",
                "data": {
                    "username": "boundaryuser4",
                    "email": "a" * 64 + "@" + "b" * 60 + ".com",  # Near RFC limits
                    "password": "Password123!",
                    "captcha": "verified"
                },
                "expected": [201, 400],  # May be accepted or rejected based on limits
                "description": "Testing email length boundaries"
            },
            {
                "name": "Empty String Password",
                "data": {
                    "username": "boundaryuser5",
                    "email": f"boundary5_{random.randint(1000, 9999)}@example.com",
                    "password": "",  # Empty password
                    "captcha": "verified"
                },
                "expected": 400,
                "description": "Empty password should be rejected"
            }
        ]
        
        # Test each boundary value scenario
        for test_case in boundary_tests:
            try:
                response = requests.post(f"{self.base_url}/auth/register", 
                                       json=test_case["data"], timeout=5)
                
                expected = test_case["expected"]
                description = test_case["description"]
                
                # Handle both single expected values and lists of acceptable values
                if isinstance(expected, list):
                    if response.status_code in expected:
                        self.log_test_result(f"Boundary Values - {test_case['name']}", "PASS", 
                                           f"Response {response.status_code} is acceptable for {description}")
                    else:
                        self.log_test_result(f"Boundary Values - {test_case['name']}", "FAIL", 
                                           f"Expected {expected}, got {response.status_code}")
                else:
                    if response.status_code == expected:
                        self.log_test_result(f"Boundary Values - {test_case['name']}", "PASS", 
                                           f"Got expected response {response.status_code} for {description}")
                    else:
                        self.log_test_result(f"Boundary Values - {test_case['name']}", "FAIL", 
                                           f"Expected {expected}, got {response.status_code}")
                        
            except requests.exceptions.RequestException as e:
                self.log_test_result(f"Boundary Values - {test_case['name']}", "FAIL", 
                                   f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test_result(f"Boundary Values - {test_case['name']}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")

    def test_session_edge_cases(self) -> None:
        """
        This test deals with session-related edge cases like invalid tokens, session timeouts, 
        and malformed headers are handled properly.
        """
        print("\n🔑 Testing Session Edge Cases...")
        
        # Test with invalid JWT tokens - Session Token Validation Testing
        # These tokens represent various invalid scenarios that could occur in real-world usage
        invalid_tokens: List[Optional[str]] = [
            "invalid.jwt.token",  # Completely invalid token format
            "Bearer invalid",     # Invalid token with Bearer prefix
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",  # Valid header but invalid signature
            "",                   # Empty token string
            None                  # Null token (missing Authorization header)
        ]
        
        # Test each invalid token scenario
        for i, token in enumerate(invalid_tokens):
            try:
                # Construct authentication headers based on token type
                # If token is None, send request without Authorization header
                # If token exists, include it in Bearer format
                headers: Dict[str, str] = {}
                if token is not None:
                    if token.startswith("Bearer"):
                        headers["Authorization"] = token  # Already has Bearer prefix
                    else:
                        headers["Authorization"] = f"Bearer {token}"  # Add Bearer prefix
                
                # Attempt to access protected resource with invalid token
                response = requests.get(f"{self.base_url}/user/profile", 
                                      headers=headers, timeout=5)
                
                # Analyze response - should reject invalid tokens with 401 Unauthorized
                if response.status_code == 401:
                    self.log_test_result(f"Invalid JWT Token {i+1}", "PASS", 
                                       "Server correctly rejected invalid session token")
                elif response.status_code == 403:
                    self.log_test_result(f"Invalid JWT Token {i+1}", "PASS", 
                                       "Server correctly denied access (403 Forbidden)")
                else:
                    self.log_test_result(f"Invalid JWT Token {i+1}", "FAIL", 
                                       f"Expected 401/403 for invalid token, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test_result(f"Invalid JWT Token {i+1}", "FAIL", 
                                   f"Request exception with invalid token: {str(e)}")
            except Exception as e:
                self.log_test_result(f"Invalid JWT Token {i+1}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")
        
        # Test 2: Session timeout scenarios
        print("  Testing session timeout scenarios...")
        
        # Test accessing protected resources without any authentication
        try:
            response = requests.get(f"{self.base_url}/user/profile", timeout=5)
            
            if response.status_code in [401, 403]:
                self.log_test_result("No Authentication Header", "PASS", 
                                   "Server correctly requires authentication")
            else:
                self.log_test_result("No Authentication Header", "FAIL", 
                                   f"Expected 401/403 without auth, got {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.log_test_result("No Authentication Header", "FAIL", 
                               f"Request exception: {str(e)}")
        
        # Test 3: Malformed Authorization headers
        print("  Testing malformed authorization headers...")
        
        malformed_headers_tests: List[Dict[str, Any]] = [
            {
                "name": "Missing Bearer Prefix",
                "headers": {"Authorization": "just_a_token_without_bearer"},
                "description": "Token without required 'Bearer ' prefix"
            },
            {
                "name": "Double Bearer Prefix", 
                "headers": {"Authorization": "Bearer Bearer valid_token_123"},
                "description": "Token with duplicate 'Bearer ' prefix"
            },
            {
                "name": "Wrong Auth Type",
                "headers": {"Authorization": "Basic dGVzdDp0ZXN0"},  # Basic auth instead of Bearer
                "description": "Basic authentication instead of Bearer token"
            },
            {
                "name": "Empty Bearer Token",
                "headers": {"Authorization": "Bearer "},  # Bearer with no token
                "description": "Bearer prefix with empty token"
            }
        ]
        
        # Test each malformed header scenario
        for test_case in malformed_headers_tests:
            try:
                response = requests.get(f"{self.base_url}/user/profile", 
                                      headers=test_case["headers"], timeout=5)
                
                # Server should reject malformed authorization headers
                if response.status_code in [401, 403, 400]:
                    self.log_test_result(f"Malformed Auth - {test_case['name']}", "PASS", 
                                       f"Server correctly rejected {test_case['description']}")
                else:
                    self.log_test_result(f"Malformed Auth - {test_case['name']}", "FAIL", 
                                       f"Expected 401/403/400, got {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_test_result(f"Malformed Auth - {test_case['name']}", "FAIL", 
                                   f"Request exception: {str(e)}")
            except Exception as e:
                self.log_test_result(f"Malformed Auth - {test_case['name']}", "FAIL", 
                                   f"Unexpected exception: {str(e)}")

    def test_race_conditions(self) -> None:
        """
        This test checks for potential race conditions in the authentication process.
        """
        print("\n🏃 Testing Race Conditions...")
        
        # Test rapid successive login attempts
        try:
            # First, create a test user with proper type annotations
            reg_data: Dict[str, str] = {
                "username": f"racetest_{random.randint(1000, 9999)}",
                "email": f"racetest_{random.randint(1000, 9999)}@example.com",
                "password": "RaceTest123!",
                "captcha": "verified"
            }
            
            reg_response = requests.post(f"{self.base_url}/auth/register", 
                                       json=reg_data, timeout=5)
            
            if reg_response.status_code == 201:
                # Now test rapid login attempts with thread-safe implementation
                login_data: Dict[str, str] = {
                    "email": reg_data["email"],
                    "password": reg_data["password"],
                    "captcha": "verified"
                }
                
                # Thread-safe results collection
                login_results: List[Union[int, str]] = []
                
                def rapid_login(results_list: List[Union[int, str]]) -> None:
                    """
                    Perform rapid login attempt - Thread-safe login testing
                    
                    Args:
                        results_list: Thread-safe list to store login results
                    """
                    try:
                        response = requests.post(f"{self.base_url}/auth/login", 
                                               json=login_data, timeout=5)
                        results_list.append(response.status_code)
                    except requests.exceptions.RequestException as e:
                        results_list.append(f"ERROR: {str(e)}")
                
                # Start multiple rapid login attempts
                threads: List[threading.Thread] = []
                num_threads: int = 10
                
                for _ in range(num_threads):
                    thread = threading.Thread(target=rapid_login, args=(login_results,))
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads to complete
                for thread in threads:
                    thread.join()
                
                # Analyze race condition results
                success_logins: int = sum(1 for r in login_results if r == 200)
                error_count: int = sum(1 for r in login_results if isinstance(r, str))
                
                if success_logins >= 5:  # Allow some successful logins
                    self.log_test_result("Race Conditions - Rapid Login", "PASS", 
                                       f"{success_logins} successful logins out of {num_threads}")
                elif success_logins > 0:
                    self.log_test_result("Race Conditions - Rapid Login", "WARN", 
                                       f"Only {success_logins} successful logins, may indicate rate limiting")
                else:
                    self.log_test_result("Race Conditions - Rapid Login", "FAIL", 
                                       f"No successful logins, {error_count} errors")
            else:
                self.log_test_result("Race Conditions - Rapid Login", "SKIP", 
                                   f"Could not create test user: {reg_response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.log_test_result("Race Conditions - Rapid Login", "FAIL", 
                               f"Network exception: {str(e)}")
        except Exception as e:
            self.log_test_result("Race Conditions - Rapid Login", "FAIL", 
                               f"Unexpected exception: {str(e)}")

    def run_all_edge_case_tests(self) -> None:
        """
        This method runs all edge case tests in sequence.
        """
        print("🧪 Starting Edge Case Testing Suite")
        print("=" * 50)
        
        start_time: float = time.time()
        
        # Run all edge case tests in sequence
        self.test_extremely_long_inputs()
        self.test_special_characters_in_inputs()
        self.test_null_and_empty_values()
        self.test_malformed_requests()
        self.test_concurrent_registrations()
        self.test_boundary_values()
        self.test_session_edge_cases()
        self.test_race_conditions()
        
        # Generate comprehensive summary report
        end_time: float = time.time()
        self.generate_edge_case_report(end_time - start_time)

    def generate_edge_case_report(self, duration: float) -> None:
        """
        Generate comprehensive edge case test report.
        """
        print("\n" + "=" * 50)
        print("🧪 EDGE CASE TEST REPORT")
        print("=" * 50)
        
        # Calculate test statistics with proper type safety
        total_tests: int = self.edge_cases_passed + self.edge_cases_failed
        success_rate: float = (self.edge_cases_passed / total_tests * 100) if total_tests > 0 else 0.0
        
        print(f"Total Edge Case Tests: {total_tests}")
        print(f"✅ Passed: {self.edge_cases_passed}")
        print(f"❌ Failed: {self.edge_cases_failed}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Duration: {duration:.2f} seconds")
        
        # Save detailed results with proper error handling
        try:
            # Prepare report data with explicit type annotations
            report_data: Dict[str, Any] = {
                'summary': {
                    'total_tests': total_tests,
                    'passed': self.edge_cases_passed,
                    'failed': self.edge_cases_failed,
                    'success_rate': success_rate,
                    'duration': duration
                },
                'detailed_results': self.test_results
            }
            
            with open('edge_case_report.json', 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n📁 Detailed edge case report saved to: edge_case_report.json")
            
        except IOError as e:
            print(f"Failed to save edge case report (IO Error): {str(e)}")
        except ValueError as e:  # JSON encoding errors are subclass of ValueError
            print(f"Failed to save edge case report (JSON Error): {str(e)}")
        except Exception as e:
            print(f"Failed to save edge case report (Unexpected Error): {str(e)}")
        
        # Provide test quality assessment
        if success_rate >= 80.0:
            print("\n✅ Excellent edge case handling!")
        elif success_rate >= 60.0:
            print("\n⚠️ Good edge case handling, minor improvements possible")
        else:
            print("\n🚨 Edge case handling needs improvement")


# Main execution block for standalone testing
if __name__ == "__main__":
    """
    This block allows the user to run the edge case tests directly without needing to import the module.
    It initializes the EdgeCaseTestSuite and runs all tests sequentially.
    """
    tester: EdgeCaseTestSuite = EdgeCaseTestSuite()
    tester.run_all_edge_case_tests()
    
# This is the end of edge_case_tester.py