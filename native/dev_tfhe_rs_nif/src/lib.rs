use tfhe::{ConfigBuilder, generate_keys as tfhe_generate_keys, ClientKey, ServerKey, FheUint32, FheAsciiString};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use rustler::{Env, ResourceArc, NifResult, Term, Binary};
use rustler::types::atom;
use std::sync::Mutex;
use std::io::Cursor;
use base64::{Engine as _, engine::general_purpose};

// Cannot derive Debug as ServerKey doesn't implement Debug
struct TfheClientKey(Mutex<ClientKey>);

// Cannot derive Debug as ServerKey doesn't implement Debug
struct TfheServerKey(Mutex<ServerKey>);

// Maximum size for serialized data (1GB)
const MAX_SERIALIZED_SIZE: u64 = 1 << 30; // 1GB

rustler::init!(
    "dev_tfhe_rs_nif",
    [
        get_info, 
        generate_client_key,
        generate_server_key,
        encrypt_integer,
        decrypt_integer,
        add_ciphertexts,
        subtract_ciphertexts
        // Commented out functions to be implemented later
        // encrypt_ascii_string,
        // decrypt_ascii_string
    ],
    load = on_load
);

fn on_load(env: Env, _: rustler::Term) -> bool {
    rustler::resource!(TfheClientKey, env);
    rustler::resource!(TfheServerKey, env);
    true
}

#[rustler::nif]
fn get_info() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let config = ConfigBuilder::default().build();
    format!("TFHE-RS NIF Device v{} (using TFHE-RS config: {:?})", version, config)
}

/// Generate a client key (equivalent to secret key in the C++ implementation)
#[rustler::nif]
fn generate_client_key() -> String {
    let config = ConfigBuilder::default().build();
    
    // Generate just the client key
    let client_key = ClientKey::generate(config);
    
    // Serialize and base64 encode the client key
    let mut client_buffer = Vec::new();
    safe_serialize(&client_key, &mut client_buffer, MAX_SERIALIZED_SIZE).unwrap();
    let client_key_base64 = general_purpose::STANDARD.encode(&client_buffer);
    
    client_key_base64
}

/// Generate a server key from a client key (equivalent to public key in the C++ implementation)
#[rustler::nif]
fn generate_server_key(client_key_base64: String) -> Result<String, rustler::Error> {
    // Decode the base64 client key
    let client_key_buffer = match general_purpose::STANDARD.decode(&client_key_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode base64: {:?}", e))))
    };
    
    // Deserialize the client key
    let cursor = Cursor::new(&client_key_buffer);
    let client_key = match safe_deserialize::<ClientKey>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(key) => key,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize client key: {:?}", e))))
    };
    
    // Generate the server key from the client key
    let server_key = ServerKey::new(&client_key);
    
    // Serialize and base64 encode the server key
    let mut server_buffer = Vec::new();
    match safe_serialize(&server_key, &mut server_buffer, MAX_SERIALIZED_SIZE) {
        Ok(_) => {},
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to serialize server key: {:?}", e))))
    }
    
    let server_key_base64 = general_purpose::STANDARD.encode(&server_buffer);
    Ok(server_key_base64)
}

#[rustler::nif]
fn encrypt_integer(value: u32, client_key_base64: String) -> Result<String, rustler::Error> {
    // First, decode and deserialize the client key
    let buffer = match general_purpose::STANDARD.decode(&client_key_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode base64: {:?}", e))))
    };
    
    // Deserialize the client key
    let cursor = Cursor::new(&buffer);
    let client_key = match safe_deserialize::<ClientKey>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(key) => key,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize client key: {:?}", e))))
    };
    
    // Encrypt the integer
    let encrypted_value = match FheUint32::try_encrypt(value, &client_key) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to encrypt integer: {:?}", e))))
    };
    
    // Serialize and base64 encode the encrypted value
    let mut buffer = Vec::new();
    match safe_serialize(&encrypted_value, &mut buffer, MAX_SERIALIZED_SIZE) {
        Ok(_) => {},
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to serialize encrypted value: {:?}", e))))
    }
    
    let encoded = general_purpose::STANDARD.encode(&buffer);
    Ok(encoded)
}

#[rustler::nif]
fn decrypt_integer(encrypted_value_base64: String, client_key_base64: String) -> Result<u32, rustler::Error> {
    // First, decode and deserialize the client key
    let key_buffer = match general_purpose::STANDARD.decode(&client_key_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode client key base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&key_buffer);
    let client_key = match safe_deserialize::<ClientKey>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(key) => key,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize client key: {:?}", e))))
    };
    
    // Decode and deserialize the encrypted value
    let encrypted_buffer = match general_purpose::STANDARD.decode(&encrypted_value_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode encrypted value base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&encrypted_buffer);
    let encrypted_value = match safe_deserialize::<FheUint32>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize encrypted value: {:?}", e))))
    };
    
    // Decrypt the integer
    let decrypted = encrypted_value.decrypt(&client_key);
    Ok(decrypted)
}

#[rustler::nif]
fn add_ciphertexts(
    ct1_base64: String, 
    ct2_base64: String, 
    server_key_base64: String
) -> Result<String, rustler::Error> {
    // Decode and deserialize the server key
    let key_buffer = match general_purpose::STANDARD.decode(&server_key_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode server key base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&key_buffer);
    let server_key = match safe_deserialize::<ServerKey>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(key) => key,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize server key: {:?}", e))))
    };
    
    // Decode and deserialize the first ciphertext
    let ct1_buffer = match general_purpose::STANDARD.decode(&ct1_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode first ciphertext base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&ct1_buffer);
    let ct1 = match safe_deserialize::<FheUint32>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize first ciphertext: {:?}", e))))
    };
    
    // Decode and deserialize the second ciphertext
    let ct2_buffer = match general_purpose::STANDARD.decode(&ct2_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode second ciphertext base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&ct2_buffer);
    let ct2 = match safe_deserialize::<FheUint32>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize second ciphertext: {:?}", e))))
    };
    
    // Set the server key for operations
    tfhe::set_server_key(server_key);
    
    // Perform the addition
    let result = &ct1 + &ct2;
    
    // Serialize and base64 encode the result
    let mut buffer = Vec::new();
    match safe_serialize(&result, &mut buffer, MAX_SERIALIZED_SIZE) {
        Ok(_) => {},
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to serialize result: {:?}", e))))
    }
    
    let encoded = general_purpose::STANDARD.encode(&buffer);
    Ok(encoded)
}

#[rustler::nif]
fn subtract_ciphertexts(
    ct1_base64: String, 
    ct2_base64: String, 
    server_key_base64: String
) -> Result<String, rustler::Error> {
    // Decode and deserialize the server key
    let key_buffer = match general_purpose::STANDARD.decode(&server_key_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode server key base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&key_buffer);
    let server_key = match safe_deserialize::<ServerKey>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(key) => key,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize server key: {:?}", e))))
    };
    
    // Decode and deserialize the first ciphertext
    let ct1_buffer = match general_purpose::STANDARD.decode(&ct1_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode first ciphertext base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&ct1_buffer);
    let ct1 = match safe_deserialize::<FheUint32>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize first ciphertext: {:?}", e))))
    };
    
    // Decode and deserialize the second ciphertext
    let ct2_buffer = match general_purpose::STANDARD.decode(&ct2_base64) {
        Ok(buffer) => buffer,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode second ciphertext base64: {:?}", e))))
    };
    
    let cursor = Cursor::new(&ct2_buffer);
    let ct2 = match safe_deserialize::<FheUint32>(cursor, MAX_SERIALIZED_SIZE) {
        Ok(value) => value,
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize second ciphertext: {:?}", e))))
    };
    
    // Set the server key for operations
    tfhe::set_server_key(server_key);
    
    // Perform the subtraction
    let result = &ct1 - &ct2;
    
    // Serialize and base64 encode the result
    let mut buffer = Vec::new();
    match safe_serialize(&result, &mut buffer, MAX_SERIALIZED_SIZE) {
        Ok(_) => {},
        Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to serialize result: {:?}", e))))
    }
    
    let encoded = general_purpose::STANDARD.encode(&buffer);
    Ok(encoded)
}

// #[rustler::nif]
// fn encrypt_ascii_string(
//     plaintext: String,
//     client_key_base64: String
// ) -> Result<String, rustler::Error> {
//     // Decode and deserialize the client key
//     let buffer = match general_purpose::STANDARD.decode(&client_key_base64) {
//         Ok(buffer) => buffer,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode base64: {:?}", e))))
//     };
    
//     let cursor = Cursor::new(&buffer);
//     let client_key = match safe_deserialize::<ClientKey>(cursor, MAX_SERIALIZED_SIZE) {
//         Ok(key) => key,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize client key: {:?}", e))))
//     };
    
//     // Encrypt the ASCII string
//     let encrypted_string = match FheAsciiString::try_encrypt(&plaintext, &client_key) {
//         Ok(encrypted) => encrypted,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to encrypt ASCII string: {:?}", e))))
//     };
    
//     // Serialize and base64 encode the encrypted string
//     let mut buffer = Vec::new();
//     match safe_serialize(&encrypted_string, &mut buffer, MAX_SERIALIZED_SIZE) {
//         Ok(_) => {},
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to serialize encrypted string: {:?}", e))))
//     }
    
//     let encoded = general_purpose::STANDARD.encode(&buffer);
//     Ok(encoded)
// }

// #[rustler::nif]
// fn decrypt_ascii_string(
//     encrypted_string_base64: String,
//     client_key_base64: String
// ) -> Result<String, rustler::Error> {
//     // Decode and deserialize the client key
//     let key_buffer = match general_purpose::STANDARD.decode(&client_key_base64) {
//         Ok(buffer) => buffer,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode client key base64: {:?}", e))))
//     };
    
//     let cursor = Cursor::new(&key_buffer);
//     let client_key = match safe_deserialize::<ClientKey>(cursor, MAX_SERIALIZED_SIZE) {
//         Ok(key) => key,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize client key: {:?}", e))))
//     };
    
//     // Decode and deserialize the encrypted string
//     let encrypted_buffer = match general_purpose::STANDARD.decode(&encrypted_string_base64) {
//         Ok(buffer) => buffer,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to decode encrypted string base64: {:?}", e))))
//     };
    
//     let cursor = Cursor::new(&encrypted_buffer);
//     let encrypted_string = match safe_deserialize::<FheAsciiString>(cursor, MAX_SERIALIZED_SIZE) {
//         Ok(value) => value,
//         Err(e) => return Err(rustler::Error::Term(Box::new(format!("Failed to deserialize encrypted string: {:?}", e))))
//     };
    
//     // Decrypt the ASCII string
//     let decrypted = encrypted_string.decrypt(&client_key);
//     Ok(decrypted)
// }
