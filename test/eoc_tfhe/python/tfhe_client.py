#!/usr/bin/env python3
"""
TFHE NIF HTTP Client

This script demonstrates interaction with the TFHE NIF device through HTTP calls.
It performs various homomorphic encryption operations and tests error cases.
"""

import requests
import json
import base64
import time
import sys
import os
import hashlib

# Base URL for the HyperBEAM node
BASE_URL = "http://localhost:8734"
DEVICE_PATH = "/~eoc-tfhe@1.0"

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
    """Get information about the TFHE library."""
    endpoint = f"{DEVICE_PATH}/get_info_http"
    
    response = make_get_request(endpoint)
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to get info: {response.status_code} - {response.text}")

def generate_secret_key():
    """Generate a new secret key."""
    endpoint = f"{DEVICE_PATH}/generate_secret_key_http"
    
    response = make_get_request(endpoint)
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to generate secret key: {response.status_code} - {response.text}")

def generate_public_key(secret_key):
    """Generate a public key from a secret key."""
    endpoint = f"{DEVICE_PATH}/generate_public_key_http"
    
    # Send the secret key directly in the body as a string
    response = requests.post(f"{BASE_URL}{endpoint}", data=secret_key)
    
    if response is None:
        raise Exception("No response received")
    
    if response.status_code == 200:
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to generate public key: {response.status_code} - {response.text}")

def encrypt_integer(value, secret_key):
    """Encrypt an integer using a secret key."""
    endpoint = f"{DEVICE_PATH}/encrypt_integer_http"
    
    # Send the value and secret key as form data
    form_data = {
        "value": str(value),
        "secret_key": secret_key  # secret_key is already a base64-encoded string
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
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to encrypt integer: {response.status_code} - {response.text}")

def decrypt_integer(ciphertext, secret_key):
    """Decrypt an encrypted integer using a secret key."""
    endpoint = f"{DEVICE_PATH}/decrypt_integer_http"
    
    # Send the ciphertext and secret key as form data
    form_data = {
        "ciphertext": ciphertext,  # ciphertext is already a base64-encoded string
        "secret_key": secret_key   # secret_key is already a base64-encoded string
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
        # The response is the decrypted integer
        try:
            return int(response.text)
        except ValueError:
            raise Exception(f"Invalid integer in response: {response.text}")
    else:
        raise Exception(f"Failed to decrypt integer: {response.status_code} - {response.text}")

def add_ciphertexts(ciphertext1, ciphertext2, public_key):
    """Add two encrypted integers."""
    endpoint = f"{DEVICE_PATH}/add_ciphertexts_http"
    
    # Send the ciphertexts and public key as form data
    form_data = {
        "ciphertext1": ciphertext1,  # ciphertext1 is already a base64-encoded string
        "ciphertext2": ciphertext2,  # ciphertext2 is already a base64-encoded string
        "public_key": public_key     # public_key is already a base64-encoded string
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
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to add ciphertexts: {response.status_code} - {response.text}")

def subtract_ciphertexts(ciphertext1, ciphertext2, public_key):
    """Subtract one encrypted integer from another."""
    endpoint = f"{DEVICE_PATH}/subtract_ciphertexts_http"
    
    # Send the ciphertexts and public key as form data
    form_data = {
        "ciphertext1": ciphertext1,  # ciphertext1 is already a base64-encoded string
        "ciphertext2": ciphertext2,  # ciphertext2 is already a base64-encoded string
        "public_key": public_key     # public_key is already a base64-encoded string
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
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to subtract ciphertexts: {response.status_code} - {response.text}")

def encrypt_ascii_string(plaintext, msg_length, secret_key):
    """Encrypt an ASCII string."""
    endpoint = f"{DEVICE_PATH}/encrypt_ascii_string_http"
    
    # Send the plaintext, message length, and secret key as form data
    form_data = {
        "plaintext": plaintext,
        "msg_length": str(msg_length),
        "secret_key": secret_key  # secret_key is already a base64-encoded string
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
        # The response is already a base64-encoded string
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to encrypt ASCII string: {response.status_code} - {response.text}")

def decrypt_ascii_string(ciphertext, msg_length, secret_key):
    """Decrypt an encrypted ASCII string."""
    endpoint = f"{DEVICE_PATH}/decrypt_ascii_string_http"
    
    # Send the ciphertext, message length, and secret key as form data
    form_data = {
        "ciphertext": ciphertext,  # ciphertext is already a base64-encoded string
        "msg_length": str(msg_length),
        "secret_key": secret_key   # secret_key is already a base64-encoded string
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
        # The response is the decrypted plaintext
        return response.text
    else:
        raise Exception(f"Failed to decrypt ASCII string: {response.status_code} - {response.text}")

def run_test():
    """Run the TFHE NIF test."""
    try:
        print_header("TFHE NIF HTTP Client Test")
        
        # 1. Get TFHE library information
        print_info("\n1. Getting TFHE library information...")
        info = get_info()
        print_info(f"TFHE Info: {info}")
        
        # 2. Generate two pairs of keys
        print_info("\n2. Generating key pairs...")
        secret_key1 = generate_secret_key()
        print_success("Secret key 1 generated successfully")
        
        public_key1 = generate_public_key(secret_key1)
        print_success("Public key 1 generated successfully")
        
        secret_key2 = generate_secret_key()
        print_success("Secret key 2 generated successfully")
        
        public_key2 = generate_public_key(secret_key2)
        print_success("Public key 2 generated successfully")
        
        # 3. Encrypt two integers with the first secret key
        value1 = 42
        value2 = 17
        print_info(f"\n3. Encrypting integers: {value1} and {value2} with key pair 1")
        
        encrypted_value1 = encrypt_integer(value1, secret_key1)
        encrypted_value2 = encrypt_integer(value2, secret_key1)
        
        print_success("Integers encrypted successfully")
        
        # 4. Perform homomorphic operations with the correct public key
        print_info("\n4. Performing homomorphic operations with the correct keys...")
        
        # Addition
        encrypted_sum = add_ciphertexts(encrypted_value1, encrypted_value2, public_key1)
        decrypted_sum = decrypt_integer(encrypted_sum, secret_key1)
        print_success(f"Homomorphic addition: {value1} + {value2} = {decrypted_sum}")
        
        # Subtraction
        encrypted_diff = subtract_ciphertexts(encrypted_value1, encrypted_value2, public_key1)
        decrypted_diff = decrypt_integer(encrypted_diff, secret_key1)
        print_success(f"Homomorphic subtraction: {value1} - {value2} = {decrypted_diff}")
        
        # 5. Try to decrypt with the wrong key
        print_info("\n5. Trying to decrypt with the wrong key...")
        try:
            wrong_decryption = decrypt_integer(encrypted_value1, secret_key2)
            if wrong_decryption != value1:
                print_success(f"Decryption with wrong key returned different value: {wrong_decryption} (original: {value1})")
            else:
                print_error(f"Decryption with wrong key returned the original value: {wrong_decryption}")
                print_error("WARNING: Decryption with wrong key should return a different value!")
        except Exception as e:
            print_success(f"Decryption with wrong key failed with exception: {str(e)}")
        
        # # 6. Try to perform operations with the wrong key
        # print_info("\n6. Trying to perform operations with mismatched keys...")
        # try:
        #     wrong_addition = add_ciphertexts(encrypted_value1, encrypted_value2, public_key2)
        #     wrong_decryption = decrypt_integer(wrong_addition, secret_key1)
        #     expected_sum = value1 + value2
        #     if wrong_decryption != expected_sum:
        #         print_success(f"Operation with wrong key returned different value: {wrong_decryption} (expected: {expected_sum})")
        #     else:
        #         print_error(f"Operation with wrong key returned the expected sum: {wrong_decryption}")
        #         print_error("WARNING: Operation with wrong key should return a different value!")
        # except Exception as e:
        #     print_success(f"Operation with wrong key failed with exception: {str(e)}")
        
        # 7. Encrypt and decrypt an ASCII string
        message = "Hello, TFHE!"
        msg_length = len(message)
        print_info(f"\n7. Encrypting and decrypting ASCII string: '{message}'")
        
        encrypted_message = encrypt_ascii_string(message, msg_length, secret_key1)
        decrypted_message = decrypt_ascii_string(encrypted_message, msg_length, secret_key1)
        
        print_info(f"Original message: '{message}'")
        print_info(f"Decrypted message: '{decrypted_message}'")
        
        if message == decrypted_message:
            print_success("ASCII string encryption/decryption successful!")
        else:
            print_error("WARNING: ASCII string encryption/decryption failed!")
        
        # 8. Try to decrypt the ASCII string with the wrong key
        print_info("\n8. Trying to decrypt ASCII string with the wrong key...")
        try:
            wrong_decryption = decrypt_ascii_string(encrypted_message, msg_length, secret_key2)
            if wrong_decryption != message:
                print_success(f"Decryption with wrong key returned different value: '{wrong_decryption}' (original: '{message}')")
            else:
                print_error(f"Decryption with wrong key returned the original message: '{wrong_decryption}'")
                print_error("WARNING: Decryption with wrong key should return a different value!")
        except Exception as e:
            print_success(f"Decryption with wrong key failed with exception: {str(e)}")
        
        print_success("\nAll tests completed!")
        
    except Exception as e:
        print_error(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(run_test())
