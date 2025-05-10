#!/usr/bin/env python3
"""
TFHE-RS NIF HTTP Client

This script demonstrates interaction with the TFHE-RS NIF device through HTTP calls.
It performs various homomorphic encryption operations and tests error cases.
"""

import requests
import json
import base64
import time
import sys
import os
import hashlib
import re
import email.parser
import cgi
import io

# Base URL for the HyperBEAM node
BASE_URL = "http://localhost:9696"
DEVICE_PATH = "/~dev-tfhe-rs@1.0"

def print_header(message):
    """Print a header message."""
    print("\n" + "=" * 80)
    print(f" {message}")
    print("=" * 80)

def print_success(message):
    """Print a success message."""
    print(f"✅ {message}")

def print_error(message):
    """Print an error message."""
    print(f"❌ {message}")

def print_info(message):
    """Print an info message."""
    print(f"ℹ️ {message}")

def make_get_request(endpoint):
    """Make a GET request to the specified endpoint."""
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def make_get_request_with_progress(endpoint):
    """Make a GET request to the specified endpoint with progress tracking."""
    url = f"{BASE_URL}{endpoint}"
    try:
        # Make request with streaming enabled
        response = requests.get(url, stream=True)
        
        if response.status_code != 200:
            print_error(f"Request failed with status code: {response.status_code}")
            return None
            
        # Get content length if available
        total_size = int(response.headers.get('content-length', 0))
        
        # Initialize variables for tracking
        bytes_received = 0
        chunks = []
        spinner = "|/-\\"
        spinner_idx = 0
        start_time = time.time()
        
        # Process the response in chunks
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)
                bytes_received += len(chunk)
                
                # Update progress display
                mb_received = bytes_received / (1024 * 1024)
                elapsed_time = time.time() - start_time
                speed = mb_received / elapsed_time if elapsed_time > 0 else 0
                
                if total_size > 0:
                    percent = bytes_received * 100 / total_size
                    progress = f"{spinner[spinner_idx]} Received: {mb_received:.2f} MB ({percent:.1f}%) - {speed:.2f} MB/s"
                else:
                    progress = f"{spinner[spinner_idx]} Received: {mb_received:.2f} MB - {speed:.2f} MB/s"
                
                print(progress, end='\r')
                spinner_idx = (spinner_idx + 1) % len(spinner)
        
        print()  # New line after progress complete
        
        # Combine chunks and create a new response object
        content = b''.join(chunks)
        
        # Create a new response object with the content
        new_response = requests.Response()
        new_response.status_code = response.status_code
        new_response.headers = response.headers
        new_response._content = content
        
        return new_response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def make_post_request(endpoint, data):
    """Make a POST request to the specified endpoint with the given data."""
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=data, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def get_info():
    """Get information about the TFHE-RS library."""
    endpoint = f"{DEVICE_PATH}/get_info_http"
    
    response = make_get_request(endpoint)
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to get info: {response.status_code} - {response.text}")

def parse_multipart_form_data(response):
    """Parse multipart form-data content from response.
    
    Args:
        response: The requests.Response object
        
    Returns:
        dict: A dictionary mapping part names to their content
    """
    # Verify Content-Type header exists and contains boundary
    content_type = response.headers.get('Content-Type', '')
    if not content_type or 'multipart/form-data' not in content_type:
        raise Exception("Invalid Content-Type header: expected multipart/form-data")
    
    try:
        boundary = content_type.split('boundary=')[1].strip('"')
    except IndexError:
        raise Exception("Could not find boundary in Content-Type header")
    
    print_info(f"Found boundary: {boundary}")
    
    # Create environment for cgi.FieldStorage
    environ = {
        'CONTENT_LENGTH': str(len(response.content)),
        'CONTENT_TYPE': content_type,
        'REQUEST_METHOD': 'POST'
    }
    
    # Create file-like object from response content
    fp = io.BytesIO(response.content)
    
    try:
        # Parse multipart form data using cgi.FieldStorage
        fs = cgi.FieldStorage(fp=fp, environ=environ, keep_blank_values=True)
        result = {}
        
        # Extract parts
        for key in fs.keys():
            result[key] = fs[key].value
            print_info(f"Successfully parsed part {key} with {len(result[key])} bytes")
            
        # Validate required parts exist
        if "2" not in result or "3" not in result:
            raise Exception("Missing required parts '2' and/or '3' in response")
            
        print_success(f"Successfully processed {len(result)} parts")
        return result
        
    except Exception as e:
        print_error(f"Error parsing multipart form-data: {str(e)}")
        print_info("First 100 bytes of response content:")
        print_info(response.content[:100])
        raise Exception(f"Failed to parse multipart form-data: {str(e)}")

def generate_client_key():
    """Generate a new client key."""
    endpoint = f"{DEVICE_PATH}/generate_client_key_http"
    
    print_info("Starting client key generation...")
    response = make_get_request(endpoint)
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        client_key = response.content
        client_key_size = len(client_key) / 1024
        print_info(f"Client key size: {client_key_size:.2f} KB")
        return client_key
    else:
        raise Exception(f"Failed to generate client key: {response.status_code} - {response.text}")

def generate_server_key(client_key):
    """Generate a server key from a client key."""
    endpoint = f"{DEVICE_PATH}/generate_server_key_http"
    
    print_info("Starting server key generation (this may take some time)...")
    
    # Make a POST request with the client key as the request body
    try:
        url = f"{BASE_URL}{endpoint}"
        response = requests.post(url, data=client_key, 
                               headers={'Content-Type': 'application/octet-stream'},
                               stream=True)
        
        if response.status_code != 200:
            print_error(f"Request failed with status code: {response.status_code}")
            if response.text:
                print_error(f"Response: {response.text}")
            return None
            
        # Get content length if available
        total_size = int(response.headers.get('content-length', 0))
        
        # Initialize variables for tracking
        bytes_received = 0
        chunks = []
        spinner = "|/-\\"
        spinner_idx = 0
        start_time = time.time()
        
        # Process the response in chunks
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)
                bytes_received += len(chunk)
                
                # Update progress display
                mb_received = bytes_received / (1024 * 1024)
                elapsed_time = time.time() - start_time
                speed = mb_received / elapsed_time if elapsed_time > 0 else 0
                
                if total_size > 0:
                    percent = bytes_received * 100 / total_size
                    progress = f"{spinner[spinner_idx]} Received: {mb_received:.2f} MB ({percent:.1f}%) - {speed:.2f} MB/s"
                else:
                    progress = f"{spinner[spinner_idx]} Received: {mb_received:.2f} MB - {speed:.2f} MB/s"
                
                print(progress, end='\r')
                spinner_idx = (spinner_idx + 1) % len(spinner)
        
        print()  # New line after progress complete
        
        # Combine chunks
        server_key = b''.join(chunks)
        server_key_size = len(server_key) / (1024 * 1024)
        print_info(f"Server key size: {server_key_size:.2f} MB")
        
        return server_key
        
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def generate_keys():
    """Generate a new key pair (client key and server key)."""
    try:
        # First generate the client key
        client_key = generate_client_key()
        if client_key is None:
            raise Exception("Failed to generate client key")
            
        # Then generate the server key using the client key
        server_key = generate_server_key(client_key)
        if server_key is None:
            raise Exception("Failed to generate server key")
            
        return client_key, server_key
            
    except Exception as e:
        print_error(f"Key generation failed: {str(e)}")
        raise

def encrypt_integer(value, client_key):
    """Encrypt an integer using a client key."""
    endpoint = f"{DEVICE_PATH}/encrypt_integer_http"
    
    print_info(f"Encrypting integer: {value}")
    
    # Make a POST request with the value and client key as form data
    form_data = {
        "value": str(value),  # Explicitly convert integer to string
        "client_key": client_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Return the response content (encrypted value)
        encrypted_value = response.content
        print_info(f"Encryption successful, ciphertext size: {len(encrypted_value)} bytes")
        return encrypted_value
    else:
        raise Exception(f"Failed to encrypt integer: {response.status_code} - {response.text}")

def decrypt_integer(ciphertext, client_key):
    """Decrypt an encrypted integer using a client key."""
    endpoint = f"{DEVICE_PATH}/decrypt_integer_http"
    
    print_info(f"Decrypting ciphertext (size: {len(ciphertext)} bytes)")
    
    # Make a POST request with the ciphertext and client key as form data
    form_data = {
        "ciphertext": ciphertext,
        "client_key": client_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Parse the response to get the decrypted value
        try:
            value = int(response.text)
            print_info(f"Decryption successful: {value}")
            return value
        except ValueError:
            raise Exception(f"Invalid integer in response: {response.text}")
    else:
        raise Exception(f"Failed to decrypt integer: {response.status_code} - {response.text}")

def add_ciphertexts(ciphertext1, ciphertext2, server_key):
    """Add two encrypted integers."""
    endpoint = f"{DEVICE_PATH}/add_ciphertexts_http"
    
    print_info(f"Adding two encrypted values (sizes: {len(ciphertext1)} bytes and {len(ciphertext2)} bytes)")
    
    # Make a POST request with the ciphertexts and server key as form data
    form_data = {
        "ciphertext1": ciphertext1,
        "ciphertext2": ciphertext2,
        "server_key": server_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Return the response content (result ciphertext)
        result = response.content
        print_info(f"Addition successful, result size: {len(result)} bytes")
        return result
    else:
        raise Exception(f"Failed to add ciphertexts: {response.status_code} - {response.text}")

def subtract_ciphertexts(ciphertext1, ciphertext2, server_key):
    """Subtract one encrypted integer from another."""
    endpoint = f"{DEVICE_PATH}/subtract_ciphertexts_http"
    
    print_info(f"Subtracting encrypted values (sizes: {len(ciphertext1)} bytes and {len(ciphertext2)} bytes)")
    
    # Make a POST request with the ciphertexts and server key as form data
    form_data = {
        "ciphertext1": ciphertext1,
        "ciphertext2": ciphertext2,
        "server_key": server_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Return the response content (result ciphertext)
        result = response.content
        print_info(f"Subtraction successful, result size: {len(result)} bytes")
        return result
    else:
        raise Exception(f"Failed to subtract ciphertexts: {response.status_code} - {response.text}")

def encrypt_ascii_string(plaintext, client_key):
    """Encrypt an ASCII string."""
    endpoint = f"{DEVICE_PATH}/encrypt_ascii_string_http"
    
    print_info(f"Encrypting ASCII string: '{plaintext}'")
    
    # Make a POST request with the plaintext and client key as form data
    form_data = {
        "plaintext": plaintext,
        "client_key": client_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Return the response content (encrypted string)
        encrypted_string = response.content
        print_info(f"Encryption successful, ciphertext size: {len(encrypted_string)} bytes")
        return encrypted_string
    else:
        raise Exception(f"Failed to encrypt ASCII string: {response.status_code} - {response.text}")

def decrypt_ascii_string(ciphertext, client_key):
    """Decrypt an encrypted ASCII string."""
    endpoint = f"{DEVICE_PATH}/decrypt_ascii_string_http"
    
    print_info(f"Decrypting ASCII string ciphertext (size: {len(ciphertext)} bytes)")
    
    # Make a POST request with the ciphertext and client key as form data
    form_data = {
        "ciphertext": ciphertext,
        "client_key": client_key
    }
    
    # Use direct requests.post with form data
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # Return the decrypted string
        decrypted_text = response.text
        print_info(f"Decryption successful: '{decrypted_text}'")
        return decrypted_text
    else:
        raise Exception(f"Failed to decrypt ASCII string: {response.status_code} - {response.text}")

# def run_info_and_key_gen():
#     """Run the get_info part and key generation with progress tracking."""
#     try:
#         print_header("TFHE-RS NIF HTTP Client - Info and Key Generation")
        
#         # Get TFHE-RS library information
#         print_info("\nGetting TFHE-RS library information...")
#         info = get_info()
#         print_info(f"TFHE-RS Info: {info}")
        
#         # Generate keys with progress tracking
#         print_info("\nGenerating TFHE keys with progress tracking...")
#         try:
#             client_key, server_key = generate_keys()
#             print_success("Key generation completed successfully!")
#         except Exception as e:
#             print_error(f"Key generation failed: {str(e)}")
        
#         print_success("\nOperation completed!")
        
#     except Exception as e:
#         print_error(f"Error: {str(e)}")
#         return 1
    
#     return 0

# def run_test():
#     """Run the TFHE-RS NIF test."""
#     try:
#         print_header("TFHE-RS NIF HTTP Client Test")
        
#         # 1. Get TFHE-RS library information
#         print_info("\n1. Getting TFHE-RS library information...")
#         info = get_info()
#         print_info(f"TFHE-RS Info: {info}")
        
#         # 2. Generate two pairs of keys
#         print_info("\n2. Generating key pairs...")
#         client_key1, server_key1 = generate_keys()
#         print_success("Key pair 1 generated successfully")
        
#         client_key2, server_key2 = generate_keys()
#         print_success("Key pair 2 generated successfully")
        
#         # 3. Encrypt two integers with the first client key
#         value1 = 42
#         value2 = 17
#         print_info(f"\n3. Encrypting integers: {value1} and {value2} with key pair 1")
        
#         encrypted_value1 = encrypt_integer(value1, client_key1)
#         encrypted_value2 = encrypt_integer(value2, client_key1)
        
#         print_success("Integers encrypted successfully")
        
#         # 4. Perform homomorphic operations with the correct server key
#         print_info("\n4. Performing homomorphic operations with the correct keys...")
        
#         # Addition
#         encrypted_sum = add_ciphertexts(encrypted_value1, encrypted_value2, server_key1)
#         decrypted_sum = decrypt_integer(encrypted_sum, client_key1)
#         print_success(f"Homomorphic addition: {value1} + {value2} = {decrypted_sum}")
        
#         # Subtraction
#         encrypted_diff = subtract_ciphertexts(encrypted_value1, encrypted_value2, server_key1)
#         decrypted_diff = decrypt_integer(encrypted_diff, client_key1)
#         print_success(f"Homomorphic subtraction: {value1} - {value2} = {decrypted_diff}")
        
#         # 5. Try to decrypt with the wrong key
#         print_info("\n5. Trying to decrypt with the wrong key...")
#         try:
#             wrong_decryption = decrypt_integer(encrypted_value1, client_key2)
#             if wrong_decryption != value1:
#                 print_success(f"Decryption with wrong key returned different value: {wrong_decryption} (original: {value1})")
#             else:
#                 print_error(f"Decryption with wrong key returned the original value: {wrong_decryption}")
#                 print_error("WARNING: Decryption with wrong key should return a different value!")
#         except Exception as e:
#             print_success(f"Decryption with wrong key failed with exception: {str(e)}")
        
#         # 6. Try to perform operations with the wrong key
#         print_info("\n6. Trying to perform operations with mismatched keys...")
#         try:
#             wrong_addition = add_ciphertexts(encrypted_value1, encrypted_value2, server_key2)
#             wrong_decryption = decrypt_integer(wrong_addition, client_key1)
#             expected_sum = value1 + value2
#             if wrong_decryption != expected_sum:
#                 print_success(f"Operation with wrong key returned different value: {wrong_decryption} (expected: {expected_sum})")
#             else:
#                 print_error(f"Operation with wrong key returned the expected sum: {wrong_decryption}")
#                 print_error("WARNING: Operation with wrong key should return a different value!")
#         except Exception as e:
#             print_success(f"Operation with wrong key failed with exception: {str(e)}")
        
#         # 7. Encrypt and decrypt an ASCII string
#         message = "Hello, TFHE-RS!"
#         msg_length = len(message)
#         print_info(f"\n7. Encrypting and decrypting ASCII string: '{message}'")
        
#         encrypted_message = encrypt_ascii_string(message, msg_length, client_key1)
#         decrypted_message = decrypt_ascii_string(encrypted_message, msg_length, client_key1)
        
#         print_info(f"Original message: '{message}'")
#         print_info(f"Decrypted message: '{decrypted_message}'")
        
#         if message == decrypted_message:
#             print_success("ASCII string encryption/decryption successful!")
#         else:
#             print_error("WARNING: ASCII string encryption/decryption failed!")
        
#         # 8. Try to decrypt the ASCII string with the wrong key
#         print_info("\n8. Trying to decrypt ASCII string with the wrong key...")
#         try:
#             wrong_decryption = decrypt_ascii_string(encrypted_message, msg_length, client_key2)
#             if wrong_decryption != message:
#                 print_success(f"Decryption with wrong key returned different value: '{wrong_decryption}' (original: '{message}')")
#             else:
#                 print_error(f"Decryption with wrong key returned the original message: '{wrong_decryption}'")
#                 print_error("WARNING: Decryption with wrong key should return a different value!")
#         except Exception as e:
#             print_success(f"Decryption with wrong key failed with exception: {str(e)}")
        
#         print_success("\nAll tests completed!")
        
#     except Exception as e:
#         print_error(f"Error: {str(e)}")
#         return 1
    
#     return 0

def run_homomorphic_operations_test():
    """Run a test of the encryption, decryption, and homomorphic operations."""
    try:
        print_header("TFHE-RS NIF HTTP Client - Homomorphic Operations Test")
        
        # Get TFHE-RS library information
        print_info("\nGetting TFHE-RS library information...")
        info = get_info()
        print_info(f"TFHE-RS Info: {info}")
        
        # Generate a client key
        print_info("\nGenerating client key...")
        client_key = generate_client_key()
        client_key_size = len(client_key) / 1024
        print_info(f"Client key generated, size: {client_key_size:.2f} KB")
        
        # Generate server key from client key
        print_info("\nGenerating server key from client key...")
        server_key = generate_server_key(client_key)
        server_key_size = len(server_key) / (1024 * 1024)
        print_info(f"Server key generated, size: {server_key_size:.2f} MB")
        
        # Test encryption/decryption
        value1 = 42
        value2 = 17
        
        print_info(f"\nEncrypting first value: {value1}")
        encrypted_value1 = encrypt_integer(value1, client_key)
        
        print_info(f"\nEncrypting second value: {value2}")
        encrypted_value2 = encrypt_integer(value2, client_key)
        
        if encrypted_value1 is not None and encrypted_value2 is not None:
            print_success(f"Successfully encrypted values: {value1} and {value2}")
            
            # Test homomorphic addition
            print_info(f"\nPerforming homomorphic addition: {value1} + {value2}")
            encrypted_sum = add_ciphertexts(encrypted_value1, encrypted_value2, server_key)
            
            # Decrypt the result
            print_info("\nDecrypting the result of addition...")
            decrypted_sum = decrypt_integer(encrypted_sum, client_key)
            
            expected_sum = value1 + value2
            if decrypted_sum == expected_sum:
                print_success(f"Addition successful: {value1} + {value2} = {decrypted_sum}")
            else:
                print_error(f"Addition failed: expected {expected_sum}, got {decrypted_sum}")
            
            # Test homomorphic subtraction
            print_info(f"\nPerforming homomorphic subtraction: {value1} - {value2}")
            encrypted_diff = subtract_ciphertexts(encrypted_value1, encrypted_value2, server_key)
            
            # Decrypt the result
            print_info("\nDecrypting the result of subtraction...")
            decrypted_diff = decrypt_integer(encrypted_diff, client_key)
            
            expected_diff = value1 - value2
            if decrypted_diff == expected_diff:
                print_success(f"Subtraction successful: {value1} - {value2} = {decrypted_diff}")
            else:
                print_error(f"Subtraction failed: expected {expected_diff}, got {decrypted_diff}")
            
        else:
            print_error("Failed to encrypt values")
        
        print_success("\nHomomorphic operations test completed!")
        
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return 1
    
    return 0

def run_ascii_string_test():
    """Run a test for encrypting and decrypting ASCII strings."""
    try:
        print_header("TFHE-RS NIF HTTP Client - ASCII String Test")
        
        # Get TFHE-RS library information
        print_info("\nGetting TFHE-RS library information...")
        info = get_info()
        print_info(f"TFHE-RS Info: {info}")
        
        # Generate a client key
        print_info("\nGenerating client key...")
        client_key = generate_client_key()
        client_key_size = len(client_key) / 1024
        print_info(f"Client key generated, size: {client_key_size:.2f} KB")
        
        # Test encrypting and decrypting ASCII strings
        test_strings = [
            "Hello, TFHE-RS!",
            "This is a test of ASCII string encryption.",
            "1234567890!@#$%^&*()",
            "The quick brown fox jumps over the lazy dog."
        ]
        
        all_passed = True
        for idx, test_string in enumerate(test_strings, 1):
            print_info(f"\nTest {idx}: Encrypting string: '{test_string}'")
            
            # Encrypt the string
            encrypted_string = encrypt_ascii_string(test_string, client_key)
            
            if encrypted_string is not None:
                # Decrypt the string
                print_info("Decrypting the string...")
                decrypted_string = decrypt_ascii_string(encrypted_string, client_key)
                
                if decrypted_string == test_string:
                    print_success(f"Test {idx} successful! Original: '{test_string}', Decrypted: '{decrypted_string}'")
                else:
                    print_error(f"Test {idx} failed! Original: '{test_string}', Decrypted: '{decrypted_string}'")
                    all_passed = False
            else:
                print_error(f"Test {idx} failed! Could not encrypt the string.")
                all_passed = False
        
        if all_passed:
            print_success("\nAll ASCII string tests passed successfully!")
        else:
            print_error("\nSome ASCII string tests failed!")
        
        print_success("\nASCII string test completed!")
        
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    # Uncomment one of the following lines to run the desired test
    # sys.exit(run_homomorphic_operations_test())
    sys.exit(run_ascii_string_test())
