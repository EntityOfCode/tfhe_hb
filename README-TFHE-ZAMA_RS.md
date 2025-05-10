![hyperbeam_logo-thin-3](https://github.com/user-attachments/assets/fcca891c-137e-4022-beff-360eb2a0d05e)

# HyperBEAM with TFHE-RS Integration

This branch (`zama-tfhe-rs`) integrates [Zama's TFHE-RS library](https://github.com/zama-ai/tfhe-rs) into HyperBEAM, providing Fully Homomorphic Encryption (FHE) capabilities through the `~dev-tfhe-rs@1.0` device.

## About TFHE-RS

TFHE-RS is a pure Rust implementation of TFHE for boolean and integer arithmetics over encrypted data. It enables computation on encrypted data without requiring access to the plaintext or decryption keys.

Key features of TFHE-RS:
- Low-level cryptographic library that implements Zama's variant of TFHE, including programmable bootstrapping
- Implementation of the original TFHE boolean API
- Short integer API enabling exact, unbounded FHE integer arithmetics
- Size-efficient public key encryption
- Ciphertext and server key compression for efficient data transfer

## HyperBEAM Integration

We've integrated TFHE-RS into HyperBEAM through a Rust NIF (Native Implemented Function) that provides the following capabilities:

### Exposed Functions

The `~dev-tfhe-rs@1.0` device exposes these functions via HTTP endpoints:

- `get_info_http`: Retrieves version and configuration information about the TFHE-RS integration
- `generate_client_key_http`: Generates a new client key (equivalent to private key)
- `generate_server_key_http`: Generates a server key from a client key for homomorphic operations
- `encrypt_integer_http`: Encrypts a 32-bit unsigned integer using a client key
- `decrypt_integer_http`: Decrypts an encrypted integer using a client key
- `add_ciphertexts_http`: Performs homomorphic addition on two encrypted integers
- `subtract_ciphertexts_http`: Performs homomorphic subtraction on two encrypted integers

Future additions planned:
- ASCII string encryption/decryption
- More homomorphic operations (multiplication, division, etc.)
- Support for advanced FHE operations

## Getting Started

### Prerequisites

To build and run HyperBEAM with TFHE-RS support, you need:

- Erlang OTP 27
- Rebar3
- Rust compiler (version >= 1.84)
- Cargo build tools

### Building and Running

1. Clone the repository and checkout this branch:
   ```bash
   git clone https://github.com/permaweb/HyperBEAM.git
   cd HyperBEAM
   git checkout zama-tfhe-rs
   ```

2. Build the project:
   ```bash
   rebar3 compile
   ```

3. Launch the HyperBEAM shell with the mainnet configuration:
   ```bash
   rebar3 shell --eval "hb:start_mainnet(#{
     port => 9696
   })."
   ```

This starts HyperBEAM with the TFHE-RS device available on port 9696.

### Testing

You can run the unit tests for the TFHE-RS integration with:

```bash
rebar3 eunit --module=dev_tfhe_rs_nif_tests
```

## Python Client Example

The repository includes a Python client script for testing and demonstrating the TFHE-RS integration.

Location: `test/eoc_tfhe/python/tfhe_rs_client.py`

This script demonstrates:
- Connecting to the HyperBEAM node
- Generating encryption keys
- Encrypting and decrypting integers
- Performing homomorphic operations (addition, subtraction) on encrypted data

### Using the Python Client

1. Ensure HyperBEAM is running with port 9696 exposed
2. Run the Python script:
   ```bash
   python3 test/eoc_tfhe/python/tfhe_rs_client.py
   ```

The script will:
1. Connect to the HyperBEAM node
2. Generate client and server keys
3. Encrypt test values
4. Perform homomorphic operations
5. Decrypt and validate results

## Security Considerations

This integration uses the default security parameters provided by TFHE-RS, which are designed for the IND-CPA security model with a bootstrapping failure probability of 2^-64. For production use, ensure these parameters meet your security requirements.

## References

- [TFHE-RS Repository](https://github.com/zama-ai/tfhe-rs)
- [TFHE-RS Documentation](https://docs.zama.ai/tfhe-rs)
- [TFHE-RS Handbook](https://github.com/zama-ai/tfhe-rs-handbook/blob/main/tfhe-rs-handbook.pdf)

## Contributing

Contributions to improve the TFHE-RS integration are welcome. Please follow the standard HyperBEAM contribution guidelines.
