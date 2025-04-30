# Getting Started with HyperBEAM: Implementing a TFHE NIF Device

This guide demonstrates how to implement a Fully Homomorphic Encryption (TFHE) Native Implemented Function (NIF) device in HyperBEAM. We'll walk through each step of the process, from setting up the native code to testing the implementation.

## Table of Contents

1. [Introduction to TFHE and NIFs](#1-introduction-to-tfhe-and-nifs)
2. [Implementation Steps](#2-implementation-steps)
3. [Run & Test](#3-run--test)
4. [Using the TFHE NIF Device](#4-using-the-tfhe-nif-device)
5. [Conclusion](#5-conclusion)

## 1. Introduction to TFHE and NIFs

### What is TFHE?

TFHE (Fast Fully Homomorphic Encryption over the Torus) is a cryptographic library that enables computation on encrypted data without decrypting it first. This allows for secure processing of sensitive information while maintaining privacy.

Key features of TFHE include:
- Homomorphic encryption of integers and ASCII strings
- Homomorphic operations (addition, subtraction) on encrypted data
- Secure key generation and management

### What are NIFs?

NIFs (Native Implemented Functions) are a way to implement Erlang functions in C/C++. They provide high performance for computationally intensive tasks and access to system resources and libraries not available in Erlang.

## 2. Implementation Steps

### 2.1 Setting Up the Native Code

First, we created the directory structure and files for our NIF implementation:

```bash
mkdir -p native/eoc_tfhe_nif
```

The `native/eoc_tfhe_nif` directory contains:
- `Makefile`: For building the NIF library
- `eoc_tfhe_nif.cpp`: C++ implementation of TFHE functions

The C++ implementation includes functions for:
- Getting library information
- Generating secret and public keys
- Encrypting and decrypting integers
- Performing homomorphic operations (addition, subtraction)
- Encrypting and decrypting ASCII strings

### 2.2 Creating the Erlang NIF Module

We created `src/dev_tfhe_nif.erl` to interface with the C++ implementation:

```erlang
-module(dev_tfhe_nif).
-export([info/1, compute/3, init/3, terminate/3, restore/3, snapshot/3, test_func/1]).
-export([get_info/0, get_info_http/1, 
         generate_secret_key/0, generate_secret_key_http/1, 
         generate_public_key/1, generate_public_key_http/1,
         encrypt_integer/2, encrypt_integer_http/1, 
         decrypt_integer/2, decrypt_integer_http/1, 
         add_ciphertexts/3, add_ciphertexts_http/1, 
         subtract_ciphertexts/3, subtract_ciphertexts_http/1, 
         encrypt_ascii_string/3, encrypt_ascii_string_http/1, 
         decrypt_ascii_string/3, decrypt_ascii_string_http/1]).
```

The module includes:
- Native functions (get_info, generate_secret_key, etc.)
- HTTP wrapper functions for each native function
- Device callback functions (info, compute, init, etc.)

### 2.3 Configuring the Build System

We modified `rebar.config` to include the TFHE NIF compilation:

```erlang
{pre_hooks, [
    {"(linux|darwin|solaris)", compile, "make -C native/eoc_tfhe_nif"},
    {"(freebsd)", compile, "gmake -C native/eoc_tfhe_nif"}
]}.

{post_hooks, [
    {"(linux|darwin|solaris)", clean, "make -C native/eoc_tfhe_nif clean"},
    {"(freebsd)", clean, "gmake -C native/eoc_tfhe_nif clean"}
]}.
```

### 2.4 Registering the Device

We added the TFHE NIF device to the preloaded devices in `src/hb_opts.erl`:

```erlang
preloaded_devices => 
    #{
        % ... other devices ...
        <<"~eoc-tfhe@1.0">> => dev_tfhe_nif
    }
```

We also updated `config.flat` to include the TFHE NIF device:

```
devices:
  # ... other devices ...
  eoc-tfhe@1.0: dev_tfhe_nif
```

## 3. Run & Test

### 3.1 Compile the Codebase

```bash
rebar3 compile
```

### 3.2 Start HyperBEAM

```bash
rebar3 shell
1> hb:start_mainnet().
```

### 3.3 Run Unit Tests

```bash
HB_DEBUG=1 rebar3 eunit --module=dev_tfhe_nif
```

The unit tests verify:
- Key generation
- Integer encryption and decryption
- Homomorphic operations
- ASCII string encryption and decryption

## 4. Using the TFHE NIF Device

### 4.1 Via Erlang Shell

You can interact with the TFHE NIF device directly from the Erlang shell:

```erlang
1> SecretKey = dev_tfhe_nif:generate_secret_key().
2> PublicKey = dev_tfhe_nif:generate_public_key(SecretKey).
3> Encrypted1 = dev_tfhe_nif:encrypt_integer(42, SecretKey).
4> Encrypted2 = dev_tfhe_nif:encrypt_integer(17, SecretKey).
5> EncryptedSum = dev_tfhe_nif:add_ciphertexts(Encrypted1, Encrypted2, PublicKey).
6> dev_tfhe_nif:decrypt_integer(EncryptedSum, SecretKey).
59
```

### 4.2 Via HTTP API

You can also interact with the TFHE NIF device through HTTP calls using the Python client:

```bash
python3 test/eoc_tfhe/python/tfhe_client.py
```

The Python client demonstrates:
- Getting TFHE library information
- Generating key pairs
- Encrypting and decrypting integers
- Performing homomorphic operations
- Encrypting and decrypting ASCII strings

You can also use curl to interact with the device:

```bash
# Get TFHE library information
curl http://localhost:8734/~eoc-tfhe@1.0/get_info_http

# Generate a secret key
curl http://localhost:8734/~eoc-tfhe@1.0/generate_secret_key_http
```

## 5. Conclusion

This guide demonstrated how to implement a TFHE NIF device in HyperBEAM, enabling homomorphic encryption operations directly within the Erlang runtime. The implementation showcases HyperBEAM's capabilities for integrating native code through NIFs and exposing functionality through HTTP endpoints.

All source code for this implementation is available in the [EntityOfCode/tfhe_hb](https://github.com/EntityOfCode/tfhe_hb) repository.
