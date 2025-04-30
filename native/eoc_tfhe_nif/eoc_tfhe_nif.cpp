/**
 * @file eoc_tfhe_nif.cpp
 * @brief C++ NIF implementation for the EOC-TFHE device
 */

#include "erl_nif.h"
#include <string.h>
#include <stdio.h>
#include <sstream>
#include <iostream>

// Include TFHE headers
#include "tfhe.h"
#include <string.h>
#include <set>


// Base64 encoding/decoding functions
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::string &in)
{
    std::string ret;
    int val = 0;
    int valb = -6;
    for (unsigned char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            ret.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        ret.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (ret.size() % 4)
        ret.push_back('=');
    return ret;
}

std::string base64_decode(const std::string &in)
{
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in)
    {
        if (T[c] == -1)
            break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Constants for TFHE
int32_t minimum_lambda = 100;
static const int32_t Msize = (1LL << 31) - 1;
static const double alpha = 1. / (10. * Msize);

/**
 * @brief Get information about the TFHE library
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM String with information
 */
static ERL_NIF_TERM get_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    const char* info = "EOC-TFHE Device v1.0.0 - A HyperBEAM device that provides homomorphic encryption operations using the TFHE library. Copyright (c) 2025 EOC.";
    return enif_make_string(env, info, ERL_NIF_LATIN1);
}

/**
 * @brief Generate a new secret key
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM generate_secret_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 0) {
        return enif_make_badarg(env);
    }

    try {
        // Set random seed
        uint32_t seed = time(NULL);
        srand(seed);
        tfhe_random_generator_setSeed(&seed, 1);
        
        // Generate parameters and keys
        TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
        TFheGateBootstrappingSecretKeySet *secretKey = new_random_gate_bootstrapping_secret_keyset(params);
        
        // Serialize the secret key
        std::ostringstream oss;
        export_tfheGateBootstrappingSecretKeySet_toStream(oss, secretKey);
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in generate_secret_key", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Generate a public key from a secret key
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM generate_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    try {
        // Get the secret key from Erlang
        ErlNifBinary secret_key_bin;
        if (!enif_inspect_binary(env, argv[0], &secret_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid secret key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binary to a C++ string
        std::string secretKeyEncoded(reinterpret_cast<char*>(secret_key_bin.data), secret_key_bin.size);
        std::string secretKeyDecoded = base64_decode(secretKeyEncoded);
        
        // Deserialize the secret key
        std::istringstream iss(secretKeyDecoded);
        TFheGateBootstrappingSecretKeySet *secretKey = new_tfheGateBootstrappingSecretKeySet_fromStream(iss);
        
        // Get the public key
        TFheGateBootstrappingCloudKeySet *publicKey = const_cast<TFheGateBootstrappingCloudKeySet *>(&secretKey->cloud);
        
        // Serialize the public key
        std::ostringstream oss;
        export_tfheGateBootstrappingCloudKeySet_toStream(oss, publicKey);
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in generate_public_key", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Encrypt an integer using a secret key
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM encrypt_integer(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    try {
        // Get the integer value from Erlang
        int value;
        if (!enif_get_int(env, argv[0], &value)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid integer format", ERL_NIF_LATIN1));
        }
        
        // Get the secret key from Erlang
        ErlNifBinary secret_key_bin;
        if (!enif_inspect_binary(env, argv[1], &secret_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid secret key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binary to a C++ string
        std::string secretKeyEncoded(reinterpret_cast<char*>(secret_key_bin.data), secret_key_bin.size);
        std::string secretKeyDecoded = base64_decode(secretKeyEncoded);
        
        // Deserialize the secret key
        std::istringstream iss(secretKeyDecoded);
        TFheGateBootstrappingSecretKeySet *secretKey = new_tfheGateBootstrappingSecretKeySet_fromStream(iss);
        
        // Encrypt the integer
        Torus32 valueT = modSwitchToTorus32(value, Msize);
        LweSample *ciphertext = new_gate_bootstrapping_ciphertext(secretKey->params);
        lweSymEncrypt(ciphertext, valueT, alpha, secretKey->lwe_key);
        
        // Serialize the ciphertext
        std::ostringstream oss;
        export_lweSample_toStream(oss, ciphertext, secretKey->params->in_out_params);
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_ciphertext(ciphertext);
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in encrypt_integer", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Decrypt an encrypted integer using a secret key
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM decrypt_integer(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    try {
        // Get the ciphertext from Erlang
        ErlNifBinary ciphertext_bin;
        if (!enif_inspect_binary(env, argv[0], &ciphertext_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext format", ERL_NIF_LATIN1));
        }
        
        // Get the secret key from Erlang
        ErlNifBinary secret_key_bin;
        if (!enif_inspect_binary(env, argv[1], &secret_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid secret key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binaries to C++ strings
        std::string ciphertextEncoded(reinterpret_cast<char*>(ciphertext_bin.data), ciphertext_bin.size);
        std::string secretKeyEncoded(reinterpret_cast<char*>(secret_key_bin.data), secret_key_bin.size);
        
        std::string ciphertextDecoded = base64_decode(ciphertextEncoded);
        std::string secretKeyDecoded = base64_decode(secretKeyEncoded);
        
        // Deserialize the secret key
        std::istringstream issKey(secretKeyDecoded);
        TFheGateBootstrappingSecretKeySet *secretKey = new_tfheGateBootstrappingSecretKeySet_fromStream(issKey);
        
        // Deserialize the ciphertext
        std::istringstream issCipher(ciphertextDecoded);
        LweSample *ciphertext = new_gate_bootstrapping_ciphertext(secretKey->params);
        import_lweSample_fromStream(issCipher, ciphertext, secretKey->params->in_out_params);
        
        // Decrypt the integer
        Torus32 decrypted = lweSymDecrypt(ciphertext, secretKey->lwe_key, Msize);
        int value = modSwitchFromTorus32(decrypted, Msize);
        
        // Clean up
        delete_gate_bootstrapping_ciphertext(ciphertext);
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Return the decrypted value
        return enif_make_int(env, value);
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in decrypt_integer", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Add two encrypted integers
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM add_ciphertexts(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    try {
        // Get the first ciphertext from Erlang
        ErlNifBinary ciphertext1_bin;
        if (!enif_inspect_binary(env, argv[0], &ciphertext1_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext1 format", ERL_NIF_LATIN1));
        }
        
        // Get the second ciphertext from Erlang
        ErlNifBinary ciphertext2_bin;
        if (!enif_inspect_binary(env, argv[1], &ciphertext2_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext2 format", ERL_NIF_LATIN1));
        }
        
        // Get the public key from Erlang
        ErlNifBinary public_key_bin;
        if (!enif_inspect_binary(env, argv[2], &public_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid public key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binaries to C++ strings
        std::string ciphertext1Encoded(reinterpret_cast<char*>(ciphertext1_bin.data), ciphertext1_bin.size);
        std::string ciphertext2Encoded(reinterpret_cast<char*>(ciphertext2_bin.data), ciphertext2_bin.size);
        std::string publicKeyEncoded(reinterpret_cast<char*>(public_key_bin.data), public_key_bin.size);
        
        std::string ciphertext1Decoded = base64_decode(ciphertext1Encoded);
        std::string ciphertext2Decoded = base64_decode(ciphertext2Encoded);
        std::string publicKeyDecoded = base64_decode(publicKeyEncoded);
        
        // Deserialize the public key
        std::istringstream issKey(publicKeyDecoded);
        TFheGateBootstrappingCloudKeySet *publicKey = new_tfheGateBootstrappingCloudKeySet_fromStream(issKey);
        
        // Deserialize the ciphertexts
        std::istringstream iss1(ciphertext1Decoded);
        std::istringstream iss2(ciphertext2Decoded);
        
        LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext(publicKey->params);
        LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext(publicKey->params);
        LweSample *ciphertextSum = new_gate_bootstrapping_ciphertext(publicKey->params);
        
        import_lweSample_fromStream(iss1, ciphertext1, publicKey->params->in_out_params);
        import_lweSample_fromStream(iss2, ciphertext2, publicKey->params->in_out_params);
        
        // Add the ciphertexts
        lweCopy(ciphertextSum, ciphertext1, publicKey->params->in_out_params);
        lweAddTo(ciphertextSum, ciphertext2, publicKey->params->in_out_params);
        
        // Serialize the result
        std::ostringstream oss;
        export_lweSample_toStream(oss, ciphertextSum, publicKey->params->in_out_params);
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_ciphertext(ciphertext1);
        delete_gate_bootstrapping_ciphertext(ciphertext2);
        delete_gate_bootstrapping_ciphertext(ciphertextSum);
        delete_gate_bootstrapping_cloud_keyset(publicKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in add_ciphertexts", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Subtract one encrypted integer from another
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM subtract_ciphertexts(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    try {
        // Get the first ciphertext from Erlang
        ErlNifBinary ciphertext1_bin;
        if (!enif_inspect_binary(env, argv[0], &ciphertext1_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext1 format", ERL_NIF_LATIN1));
        }
        
        // Get the second ciphertext from Erlang
        ErlNifBinary ciphertext2_bin;
        if (!enif_inspect_binary(env, argv[1], &ciphertext2_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext2 format", ERL_NIF_LATIN1));
        }
        
        // Get the public key from Erlang
        ErlNifBinary public_key_bin;
        if (!enif_inspect_binary(env, argv[2], &public_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid public key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binaries to C++ strings
        std::string ciphertext1Encoded(reinterpret_cast<char*>(ciphertext1_bin.data), ciphertext1_bin.size);
        std::string ciphertext2Encoded(reinterpret_cast<char*>(ciphertext2_bin.data), ciphertext2_bin.size);
        std::string publicKeyEncoded(reinterpret_cast<char*>(public_key_bin.data), public_key_bin.size);
        
        std::string ciphertext1Decoded = base64_decode(ciphertext1Encoded);
        std::string ciphertext2Decoded = base64_decode(ciphertext2Encoded);
        std::string publicKeyDecoded = base64_decode(publicKeyEncoded);
        
        // Deserialize the public key
        std::istringstream issKey(publicKeyDecoded);
        TFheGateBootstrappingCloudKeySet *publicKey = new_tfheGateBootstrappingCloudKeySet_fromStream(issKey);
        
        // Deserialize the ciphertexts
        std::istringstream iss1(ciphertext1Decoded);
        std::istringstream iss2(ciphertext2Decoded);
        
        LweSample *ciphertext1 = new_gate_bootstrapping_ciphertext(publicKey->params);
        LweSample *ciphertext2 = new_gate_bootstrapping_ciphertext(publicKey->params);
        LweSample *ciphertextDiff = new_gate_bootstrapping_ciphertext(publicKey->params);
        
        import_lweSample_fromStream(iss1, ciphertext1, publicKey->params->in_out_params);
        import_lweSample_fromStream(iss2, ciphertext2, publicKey->params->in_out_params);
        
        // Subtract the ciphertexts
        lweCopy(ciphertextDiff, ciphertext1, publicKey->params->in_out_params);
        lweSubTo(ciphertextDiff, ciphertext2, publicKey->params->in_out_params);
        
        // Serialize the result
        std::ostringstream oss;
        export_lweSample_toStream(oss, ciphertextDiff, publicKey->params->in_out_params);
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_ciphertext(ciphertext1);
        delete_gate_bootstrapping_ciphertext(ciphertext2);
        delete_gate_bootstrapping_ciphertext(ciphertextDiff);
        delete_gate_bootstrapping_cloud_keyset(publicKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in subtract_ciphertexts", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Encrypt an ASCII string
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM encrypt_ascii_string(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    try {
        // Get the plaintext from Erlang
        ErlNifBinary plaintext_bin;
        if (!enif_inspect_binary(env, argv[0], &plaintext_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid plaintext format", ERL_NIF_LATIN1));
        }
        
        // Get the message length from Erlang
        int msg_length;
        if (!enif_get_int(env, argv[1], &msg_length)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid message length format", ERL_NIF_LATIN1));
        }
        
        // Get the secret key from Erlang
        ErlNifBinary secret_key_bin;
        if (!enif_inspect_binary(env, argv[2], &secret_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid secret key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binaries to C++ strings
        std::string plaintextStr(reinterpret_cast<char*>(plaintext_bin.data), plaintext_bin.size);
        std::string secretKeyEncoded(reinterpret_cast<char*>(secret_key_bin.data), secret_key_bin.size);
        std::string secretKeyDecoded = base64_decode(secretKeyEncoded);
        
        // Deserialize the secret key
        std::istringstream issKey(secretKeyDecoded);
        TFheGateBootstrappingSecretKeySet *secretKey = new_tfheGateBootstrappingSecretKeySet_fromStream(issKey);
        
        // Encrypt the ASCII string
        LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(msg_length, secretKey->params);
        
        for (int i = 0; i < msg_length; ++i) {
            Torus32 msgT = modSwitchToTorus32(static_cast<int32_t>(plaintextStr.at(i)), Msize);
            lweSymEncrypt(ciphertext + i, msgT, alpha, secretKey->lwe_key);
        }
        
        // Serialize the result
        std::ostringstream oss;
        for (int i = 0; i < msg_length; ++i) {
            export_lweSample_toStream(oss, ciphertext + i, secretKey->params->in_out_params);
        }
        
        // Base64 encode the serialized string
        std::string encoded = base64_encode(oss.str());
        
        // Clean up
        delete_gate_bootstrapping_ciphertext_array(msg_length, ciphertext);
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, encoded.size(), &result);
        memcpy(bin_data, encoded.c_str(), encoded.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in encrypt_ascii_string", ERL_NIF_LATIN1));
    }
}

/**
 * @brief Decrypt an encrypted ASCII string
 * 
 * @param env NIF environment
 * @param argc Number of arguments
 * @param argv Arguments
 * @return ERL_NIF_TERM Result
 */
static ERL_NIF_TERM decrypt_ascii_string(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    try {
        // Get the ciphertext from Erlang
        ErlNifBinary ciphertext_bin;
        if (!enif_inspect_binary(env, argv[0], &ciphertext_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid ciphertext format", ERL_NIF_LATIN1));
        }
        
        // Get the message length from Erlang
        int msg_length;
        if (!enif_get_int(env, argv[1], &msg_length)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid message length format", ERL_NIF_LATIN1));
        }
        
        // Get the secret key from Erlang
        ErlNifBinary secret_key_bin;
        if (!enif_inspect_binary(env, argv[2], &secret_key_bin)) {
            return enif_make_tuple2(env, 
                enif_make_atom(env, "error"),
                enif_make_string(env, "Invalid secret key format", ERL_NIF_LATIN1));
        }
        
        // Convert the binaries to C++ strings
        std::string ciphertextEncoded(reinterpret_cast<char*>(ciphertext_bin.data), ciphertext_bin.size);
        std::string secretKeyEncoded(reinterpret_cast<char*>(secret_key_bin.data), secret_key_bin.size);
        
        std::string ciphertextDecoded = base64_decode(ciphertextEncoded);
        std::string secretKeyDecoded = base64_decode(secretKeyEncoded);
        
        // Deserialize the secret key
        std::istringstream issKey(secretKeyDecoded);
        TFheGateBootstrappingSecretKeySet *secretKey = new_tfheGateBootstrappingSecretKeySet_fromStream(issKey);
        
        // Deserialize the ciphertext
        std::istringstream issCipher(ciphertextDecoded);
        LweSample *ciphertext = new_gate_bootstrapping_ciphertext_array(msg_length, secretKey->params);
        
        for (int i = 0; i < msg_length; ++i) {
            import_lweSample_fromStream(issCipher, ciphertext + i, secretKey->params->in_out_params);
        }
        
        // Decrypt the ASCII string
        std::string plaintext;
        for (int i = 0; i < msg_length; ++i) {
            Torus32 decryptedT = lweSymDecrypt(ciphertext + i, secretKey->lwe_key, Msize);
            plaintext.push_back(static_cast<char>(modSwitchFromTorus32(decryptedT, Msize)));
        }
        
        // Clean up
        delete_gate_bootstrapping_ciphertext_array(msg_length, ciphertext);
        delete_gate_bootstrapping_secret_keyset(secretKey);
        
        // Convert the C++ string to an Erlang binary
        ERL_NIF_TERM result;
        unsigned char* bin_data = enif_make_new_binary(env, plaintext.size(), &result);
        memcpy(bin_data, plaintext.c_str(), plaintext.size());
        
        return result;
    } catch (const std::exception& e) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, e.what(), ERL_NIF_LATIN1));
    } catch (...) {
        return enif_make_tuple2(env, 
            enif_make_atom(env, "error"),
            enif_make_string(env, "Unknown error in decrypt_ascii_string", ERL_NIF_LATIN1));
    }
}

// NIF function table
static ErlNifFunc nif_funcs[] = {
    {"get_info", 0, get_info},
    {"generate_secret_key", 0, generate_secret_key},
    {"generate_public_key", 1, generate_public_key},
    {"encrypt_integer", 2, encrypt_integer},
    {"decrypt_integer", 2, decrypt_integer},
    {"add_ciphertexts", 3, add_ciphertexts},
    {"subtract_ciphertexts", 3, subtract_ciphertexts},
    {"encrypt_ascii_string", 3, encrypt_ascii_string},
    {"decrypt_ascii_string", 3, decrypt_ascii_string}
};

// NIF initialization
ERL_NIF_INIT(dev_tfhe_nif, nif_funcs, NULL, NULL, NULL, NULL)
