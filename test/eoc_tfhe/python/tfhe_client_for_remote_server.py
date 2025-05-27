#!/usr/bin/env python3
"""
TFHE NIF HTTP Client (Remote)

This script demonstrates interaction with the TFHE NIF device through HTTP calls
to a remote HyperBEAM node at http://lab.bemjax.com:9696.
It performs various homomorphic encryption operations and tests error cases.
"""

import requests
import json
import base64
import time
import sys
import os
import hashlib

# Base URL for the remote HyperBEAM node
BASE_URL = "http://lab.bemjax.com:9696"
DEVICE_PATH = "/~eoc-tfhe@1.0"

def print_header(message):
    print("\n" + "=" * 80)
    print(f" {message} ({BASE_URL})")
    print("=" * 80)

def print_success(message):
    print(f"✅ {message}")

def print_error(message):
    print(f"❌ {message}")

def print_info(message):
    print(f"ℹ️ {message}")

def make_get_request(endpoint):
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.get(url)
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def make_post_request(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=data, headers=headers)
        return response
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def get_info():
    endpoint = f"{DEVICE_PATH}/get_info_http"
    response = make_get_request(endpoint)
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to get info: {response.status_code} - {response.text}")

def generate_secret_key():
    endpoint = f"{DEVICE_PATH}/generate_secret_key_http"
    response = make_get_request(endpoint)
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to generate secret key: {response.status_code} - {response.text}")

def generate_public_key(secret_key):
    endpoint = f"{DEVICE_PATH}/generate_public_key_http"
    response = requests.post(f"{BASE_URL}{endpoint}", data=secret_key)
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to generate public key: {response.status_code} - {response.text}")

def encrypt_integer(value, secret_key):
    endpoint = f"{DEVICE_PATH}/encrypt_integer_http"
    form_data = {
        "value": str(value),
        "secret_key": secret_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to encrypt integer: {response.status_code} - {response.text}")

def decrypt_integer(ciphertext, secret_key):
    endpoint = f"{DEVICE_PATH}/decrypt_integer_http"
    form_data = {
        "ciphertext": ciphertext,
        "secret_key": secret_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        try:
            return int(response.text)
        except ValueError:
            raise Exception(f"Invalid integer in response: {response.text}")
    else:
        raise Exception(f"Failed to decrypt integer: {response.status_code} - {response.text}")

def add_ciphertexts(ciphertext1, ciphertext2, public_key):
    endpoint = f"{DEVICE_PATH}/add_ciphertexts_http"
    form_data = {
        "ciphertext1": ciphertext1,
        "ciphertext2": ciphertext2,
        "public_key": public_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to add ciphertexts: {response.status_code} - {response.text}")

def subtract_ciphertexts(ciphertext1, ciphertext2, public_key):
    endpoint = f"{DEVICE_PATH}/subtract_ciphertexts_http"
    form_data = {
        "ciphertext1": ciphertext1,
        "ciphertext2": ciphertext2,
        "public_key": public_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to subtract ciphertexts: {response.status_code} - {response.text}")

def encrypt_ascii_string(plaintext, msg_length, secret_key):
    endpoint = f"{DEVICE_PATH}/encrypt_ascii_string_http"
    form_data = {
        "plaintext": plaintext,
        "msg_length": str(msg_length),
        "secret_key": secret_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.content.decode('utf-8')
    else:
        raise Exception(f"Failed to encrypt ASCII string: {response.status_code} - {response.text}")

def decrypt_ascii_string(ciphertext, msg_length, secret_key):
    endpoint = f"{DEVICE_PATH}/decrypt_ascii_string_http"
    form_data = {
        "ciphertext": ciphertext,
        "msg_length": str(msg_length),
        "secret_key": secret_key
    }
    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.post(url, data=form_data)
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None
    if response is None:
        raise Exception("No response received")
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to decrypt ASCII string: {response.status_code} - {response.text}")

def run_test():
    try:
        print_header("TFHE NIF HTTP Client Test (Remote)")
        print_info("\n1. Getting TFHE library information...")
        info = get_info()
        print_info(f"TFHE Info: {info}")

        print_info("\n2. Generating key pairs...")
        secret_key1 = generate_secret_key()
        print_success("Secret key 1 generated successfully")
        public_key1 = generate_public_key(secret_key1)
        print_success("Public key 1 generated successfully")
        secret_key2 = generate_secret_key()
        print_success("Secret key 2 generated successfully")
        public_key2 = generate_public_key(secret_key2)
        print_success("Public key 2 generated successfully")

        value1 = 42
        value2 = 17
        print_info(f"\n3. Encrypting integers: {value1} and {value2} with key pair 1")
        encrypted_value1 = encrypt_integer(value1, secret_key1)
        encrypted_value2 = encrypt_integer(value2, secret_key1)
        print_success("Integers encrypted successfully")

        print_info("\n4. Performing homomorphic operations with the correct keys...")
        encrypted_sum = add_ciphertexts(encrypted_value1, encrypted_value2, public_key1)
        decrypted_sum = decrypt_integer(encrypted_sum, secret_key1)
        print_success(f"Homomorphic addition: {value1} + {value2} = {decrypted_sum}")

        encrypted_diff = subtract_ciphertexts(encrypted_value1, encrypted_value2, public_key1)
        decrypted_diff = decrypt_integer(encrypted_diff, secret_key1)
        print_success(f"Homomorphic subtraction: {value1} - {value2} = {decrypted_diff}")

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