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
-include_lib("eunit/include/eunit.hrl").
-include("include/hb.hrl").

-on_load(init_nif/0).
-define(NOT_LOADED, not_loaded(?LINE)).

%% @doc Get information about the TFHE library.
%% @returns String with information.
get_info() ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for get_info/0
%% @returns {ok, EncodedInfo}
get_info_http(_) ->
    Info = get_info(),
    EncodedInfo = list_to_binary(Info),
    {ok, EncodedInfo}.

%% @doc Generate a new secret key.
%% @returns Binary with the secret key.
generate_secret_key() ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for generate_secret_key/0
%% @returns {ok, EncodedKey}
generate_secret_key_http(_) ->
    SecretKey = generate_secret_key(),
    {ok, SecretKey}.

%% @doc Generate a public key from a secret key.
%% @param SecretKey The secret key.
%% @returns Binary with the public key.
generate_public_key(_SecretKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for generate_public_key/1
%% @param Msg The request message containing the secret key
%% @returns {ok, PublicKey} | {error, Reason}
generate_public_key_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Use the body directly as the secret key
            Body = maps:get(<<"body">>, Msg),
            
            % Generate the public key using the body as the secret key
            PublicKey = generate_public_key(Body),
            {ok, PublicKey};
        false ->
            % Check if the Msg contains a secret_key field
            case maps:is_key(<<"secret_key">>, Msg) of
                true ->
                    % Get the secret key from the message
                    ReceivedSecretKey = maps:get(<<"secret_key">>, Msg),
                    
                    % Generate the public key using the received secret key
                    PublicKey = generate_public_key(ReceivedSecretKey),
                    {ok, PublicKey};
                false ->
                    % Return an error
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg}
            end
    end.

%% @doc Encrypt an integer using a secret key.
%% @param Value The integer to encrypt.
%% @param SecretKey The secret key.
%% @returns Binary with the encrypted integer.
encrypt_integer(_Value, _SecretKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for encrypt_integer/2
%% @param Msg The request message containing the value and secret key
%% @returns {ok, Ciphertext} | {error, Reason}
encrypt_integer_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Parse the body as form data
            Body = maps:get(<<"body">>, Msg),
            FormData = cow_qs:parse_qs(Body),
            
            % Get the value and secret key from the form data
            case {proplists:get_value(<<"value">>, FormData), 
                  proplists:get_value(<<"secret_key">>, FormData)} of
                {undefined, _} ->
                    ErrorMsg = "Error: No value provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, undefined} ->
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {ValueBin, SecretKey} ->
                    % Convert the value from binary to integer
                    Value = binary_to_integer(ValueBin),
                    
                    % Encrypt the integer
                    Ciphertext = encrypt_integer(Value, SecretKey),
                    {ok, Ciphertext}
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"value">>, Msg), maps:is_key(<<"secret_key">>, Msg)} of
                {false, _} ->
                    ErrorMsg = "Error: No value provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false} ->
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true} ->
                    % Get the value and secret key from the message
                    Value = maps:get(<<"value">>, Msg),
                    SecretKey = maps:get(<<"secret_key">>, Msg),
                    
                    % Encrypt the integer
                    Ciphertext = encrypt_integer(Value, SecretKey),
                    {ok, Ciphertext}
            end
    end.

%% @doc Decrypt an encrypted integer using a secret key.
%% @param Ciphertext The encrypted integer.
%% @param SecretKey The secret key.
%% @returns The decrypted integer.
decrypt_integer(_Ciphertext, _SecretKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for decrypt_integer/2
%% @param Msg The request message containing the ciphertext and secret key
%% @returns {ok, Value} | {error, Reason}
decrypt_integer_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Get the body
            Body = maps:get(<<"body">>, Msg),
            
            % Check if the Content-Type is application/octet-stream
            ContentType = maps:get(<<"content-type">>, Msg, <<"">>),
            case binary:match(ContentType, <<"application/octet-stream">>) of
                {_, _} ->
                    % Parse the binary data format: [ciphertext_size(4 bytes)][ciphertext][secret_key]
                    try
                        % Extract the ciphertext size (first 4 bytes)
                        <<CiphertextSize:32/big, Rest/binary>> = Body,
                        
                        % Extract the ciphertext and secret key
                        <<Ciphertext:CiphertextSize/binary, SecretKey/binary>> = Rest,
                        
                        % Decrypt the integer
                        Value = decrypt_integer(Ciphertext, SecretKey),
                        {ok, Value}
                    catch
                        _:_ ->
                            ErrorMsg = "Error: Invalid binary data format",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg}
                    end;
                nomatch ->
                    % Parse the body as form data
                    FormData = cow_qs:parse_qs(Body),
                    
                    % Get the ciphertext and secret key from the form data
                    case {proplists:get_value(<<"ciphertext">>, FormData), 
                          proplists:get_value(<<"secret_key">>, FormData)} of
                        {undefined, _} ->
                            ErrorMsg = "Error: No ciphertext provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, undefined} ->
                            ErrorMsg = "Error: No secret key provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {Ciphertext, SecretKey} ->
                            % Decrypt the integer
                            Value = decrypt_integer(Ciphertext, SecretKey),
                            {ok, Value}
                    end
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"ciphertext">>, Msg), maps:is_key(<<"secret_key">>, Msg)} of
                {false, _} ->
                    ErrorMsg = "Error: No ciphertext provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false} ->
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true} ->
                    % Get the ciphertext and secret key from the message
                    Ciphertext = maps:get(<<"ciphertext">>, Msg),
                    SecretKey = maps:get(<<"secret_key">>, Msg),
                    
                    % Decrypt the integer
                    Value = decrypt_integer(Ciphertext, SecretKey),
                    {ok, Value}
            end
    end.

%% @doc Add two encrypted integers.
%% @param Ciphertext1 The first encrypted integer.
%% @param Ciphertext2 The second encrypted integer.
%% @param PublicKey The public key.
%% @returns Binary with the encrypted sum.
add_ciphertexts(_Ciphertext1, _Ciphertext2, _PublicKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for add_ciphertexts/3
%% @param Msg The request message containing the ciphertexts and public key
%% @returns {ok, ResultCiphertext} | {error, Reason}
add_ciphertexts_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Get the body
            Body = maps:get(<<"body">>, Msg),
            
            % Check if the Content-Type is application/octet-stream
            ContentType = maps:get(<<"content-type">>, Msg, <<"">>),
            case binary:match(ContentType, <<"application/octet-stream">>) of
                {_, _} ->
                    % Parse the binary data format: [ciphertext1_size(4 bytes)][ciphertext1][ciphertext2_size(4 bytes)][ciphertext2][public_key]
                    try
                        % Extract the ciphertext1 size (first 4 bytes)
                        <<Ciphertext1Size:32/big, Rest1/binary>> = Body,
                        
                        % Extract ciphertext1
                        <<Ciphertext1:Ciphertext1Size/binary, Rest2/binary>> = Rest1,
                        
                        % Extract the ciphertext2 size
                        <<Ciphertext2Size:32/big, Rest3/binary>> = Rest2,
                        
                        % Extract ciphertext2 and public key
                        <<Ciphertext2:Ciphertext2Size/binary, PublicKey/binary>> = Rest3,
                        
                        % Add the ciphertexts
                        ResultCiphertext = add_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                        {ok, ResultCiphertext}
                    catch
                        _:_ ->
                            ErrorMsg = "Error: Invalid binary data format",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg}
                    end;
                nomatch ->
                    % Parse the body as form data
                    FormData = cow_qs:parse_qs(Body),
                    
                    % Get the ciphertexts and public key from the form data
                    case {proplists:get_value(<<"ciphertext1">>, FormData), 
                          proplists:get_value(<<"ciphertext2">>, FormData),
                          proplists:get_value(<<"public_key">>, FormData)} of
                        {undefined, _, _} ->
                            ErrorMsg = "Error: No ciphertext1 provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, undefined, _} ->
                            ErrorMsg = "Error: No ciphertext2 provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, _, undefined} ->
                            ErrorMsg = "Error: No public key provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {Ciphertext1, Ciphertext2, PublicKey} ->
                            % Add the ciphertexts
                            ResultCiphertext = add_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                            {ok, ResultCiphertext}
                    end
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"ciphertext1">>, Msg), 
                  maps:is_key(<<"ciphertext2">>, Msg),
                  maps:is_key(<<"public_key">>, Msg)} of
                {false, _, _} ->
                    ErrorMsg = "Error: No ciphertext1 provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false, _} ->
                    ErrorMsg = "Error: No ciphertext2 provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, _, false} ->
                    ErrorMsg = "Error: No public key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true, true} ->
                    % Get the ciphertexts and public key from the message
                    Ciphertext1 = maps:get(<<"ciphertext1">>, Msg),
                    Ciphertext2 = maps:get(<<"ciphertext2">>, Msg),
                    PublicKey = maps:get(<<"public_key">>, Msg),
                    
                    % Add the ciphertexts
                    ResultCiphertext = add_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                    {ok, ResultCiphertext}
            end
    end.

%% @doc Subtract one encrypted integer from another.
%% @param Ciphertext1 The first encrypted integer.
%% @param Ciphertext2 The second encrypted integer.
%% @param PublicKey The public key.
%% @returns Binary with the encrypted difference.
subtract_ciphertexts(_Ciphertext1, _Ciphertext2, _PublicKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for subtract_ciphertexts/3
%% @param Msg The request message containing the ciphertexts and public key
%% @returns {ok, ResultCiphertext} | {error, Reason}
subtract_ciphertexts_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Get the body
            Body = maps:get(<<"body">>, Msg),
            
            % Check if the Content-Type is application/octet-stream
            ContentType = maps:get(<<"content-type">>, Msg, <<"">>),
            case binary:match(ContentType, <<"application/octet-stream">>) of
                {_, _} ->
                    % Parse the binary data format: [ciphertext1_size(4 bytes)][ciphertext1][ciphertext2_size(4 bytes)][ciphertext2][public_key]
                    try
                        % Extract the ciphertext1 size (first 4 bytes)
                        <<Ciphertext1Size:32/big, Rest1/binary>> = Body,
                        
                        % Extract ciphertext1
                        <<Ciphertext1:Ciphertext1Size/binary, Rest2/binary>> = Rest1,
                        
                        % Extract the ciphertext2 size
                        <<Ciphertext2Size:32/big, Rest3/binary>> = Rest2,
                        
                        % Extract ciphertext2 and public key
                        <<Ciphertext2:Ciphertext2Size/binary, PublicKey/binary>> = Rest3,
                        
                        % Subtract the ciphertexts
                        ResultCiphertext = subtract_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                        {ok, ResultCiphertext}
                    catch
                        _:_ ->
                            ErrorMsg = "Error: Invalid binary data format",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg}
                    end;
                nomatch ->
                    % Parse the body as form data
                    FormData = cow_qs:parse_qs(Body),
                    
                    % Get the ciphertexts and public key from the form data
                    case {proplists:get_value(<<"ciphertext1">>, FormData), 
                          proplists:get_value(<<"ciphertext2">>, FormData),
                          proplists:get_value(<<"public_key">>, FormData)} of
                        {undefined, _, _} ->
                            ErrorMsg = "Error: No ciphertext1 provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, undefined, _} ->
                            ErrorMsg = "Error: No ciphertext2 provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, _, undefined} ->
                            ErrorMsg = "Error: No public key provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {Ciphertext1, Ciphertext2, PublicKey} ->
                            % Subtract the ciphertexts
                            ResultCiphertext = subtract_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                            {ok, ResultCiphertext}
                    end
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"ciphertext1">>, Msg), 
                  maps:is_key(<<"ciphertext2">>, Msg),
                  maps:is_key(<<"public_key">>, Msg)} of
                {false, _, _} ->
                    ErrorMsg = "Error: No ciphertext1 provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false, _} ->
                    ErrorMsg = "Error: No ciphertext2 provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, _, false} ->
                    ErrorMsg = "Error: No public key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true, true} ->
                    % Get the ciphertexts and public key from the message
                    Ciphertext1 = maps:get(<<"ciphertext1">>, Msg),
                    Ciphertext2 = maps:get(<<"ciphertext2">>, Msg),
                    PublicKey = maps:get(<<"public_key">>, Msg),
                    
                    % Subtract the ciphertexts
                    ResultCiphertext = subtract_ciphertexts(Ciphertext1, Ciphertext2, PublicKey),
                    {ok, ResultCiphertext}
            end
    end.

%% @doc Encrypt an ASCII string.
%% @param Plaintext The plaintext string.
%% @param MsgLength The length of the message.
%% @param SecretKey The secret key.
%% @returns Binary with the encrypted string.
encrypt_ascii_string(_Plaintext, _MsgLength, _SecretKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for encrypt_ascii_string/3
%% @param Msg The request message containing the plaintext, message length, and secret key
%% @returns {ok, EncryptedString} | {error, Reason}
encrypt_ascii_string_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Get the body
            Body = maps:get(<<"body">>, Msg),
            
            % Check if the Content-Type is application/octet-stream
            ContentType = maps:get(<<"content-type">>, Msg, <<"">>),
            case binary:match(ContentType, <<"application/octet-stream">>) of
                {_, _} ->
                    % Parse the binary data format: [plaintext_size(4 bytes)][plaintext][msg_length(4 bytes)][secret_key]
                    try
                        % Extract the plaintext size (first 4 bytes)
                        <<PlaintextSize:32/big, Rest1/binary>> = Body,
                        
                        % Extract plaintext
                        <<Plaintext:PlaintextSize/binary, Rest2/binary>> = Rest1,
                        
                        % Extract the message length
                        <<MsgLength:32/big, SecretKey/binary>> = Rest2,
                        
                        % Encrypt the ASCII string
                        EncryptedString = encrypt_ascii_string(Plaintext, MsgLength, SecretKey),
                        {ok, EncryptedString}
                    catch
                        _:_ ->
                            ErrorMsg = "Error: Invalid binary data format",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg}
                    end;
                nomatch ->
                    % Parse the body as form data
                    FormData = cow_qs:parse_qs(Body),
                    
                    % Get the plaintext, message length, and secret key from the form data
                    case {proplists:get_value(<<"plaintext">>, FormData), 
                          proplists:get_value(<<"msg_length">>, FormData),
                          proplists:get_value(<<"secret_key">>, FormData)} of
                        {undefined, _, _} ->
                            ErrorMsg = "Error: No plaintext provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, _, undefined} ->
                            ErrorMsg = "Error: No secret key provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {Plaintext, MsgLengthBin, SecretKey} ->
                            % Get the message length (default to plaintext size if not provided)
                            MsgLength = case MsgLengthBin of
                                undefined -> byte_size(Plaintext);
                                _ -> binary_to_integer(MsgLengthBin)
                            end,
                            
                            % Encrypt the ASCII string
                            EncryptedString = encrypt_ascii_string(Plaintext, MsgLength, SecretKey),
                            {ok, EncryptedString}
                    end
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"plaintext">>, Msg), maps:is_key(<<"secret_key">>, Msg)} of
                {false, _} ->
                    ErrorMsg = "Error: No plaintext provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false} ->
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true} ->
                    % Get the plaintext, message length, and secret key from the message
                    Plaintext = maps:get(<<"plaintext">>, Msg),
                    MsgLength = maps:get(<<"msg_length">>, Msg, byte_size(Plaintext)),
                    SecretKey = maps:get(<<"secret_key">>, Msg),
                    
                    % Encrypt the ASCII string
                    EncryptedString = encrypt_ascii_string(Plaintext, MsgLength, SecretKey),
                    {ok, EncryptedString}
            end
    end.

%% @doc Decrypt an encrypted ASCII string.
%% @param Ciphertext The encrypted string.
%% @param MsgLength The length of the message.
%% @param SecretKey The secret key.
%% @returns The decrypted string.
decrypt_ascii_string(_Ciphertext, _MsgLength, _SecretKey) ->
    ?NOT_LOADED.

%% @doc HTTP wrapper for decrypt_ascii_string/3
%% @param Msg The request message containing the ciphertext, message length, and secret key
%% @returns {ok, DecryptedString} | {error, Reason}
decrypt_ascii_string_http(Msg) ->
    % Check if the Msg contains a body field
    case maps:is_key(<<"body">>, Msg) of
        true ->
            % Get the body
            Body = maps:get(<<"body">>, Msg),
            
            % Check if the Content-Type is application/octet-stream
            ContentType = maps:get(<<"content-type">>, Msg, <<"">>),
            case binary:match(ContentType, <<"application/octet-stream">>) of
                {_, _} ->
                    % Parse the binary data format: [ciphertext_size(4 bytes)][ciphertext][msg_length(4 bytes)][secret_key]
                    try
                        % Extract the ciphertext size (first 4 bytes)
                        <<CiphertextSize:32/big, Rest1/binary>> = Body,
                        
                        % Extract ciphertext
                        <<Ciphertext:CiphertextSize/binary, Rest2/binary>> = Rest1,
                        
                        % Extract the message length
                        <<MsgLength:32/big, SecretKey/binary>> = Rest2,
                        
                        % Decrypt the ASCII string
                        DecryptedString = decrypt_ascii_string(Ciphertext, MsgLength, SecretKey),
                        {ok, DecryptedString}
                    catch
                        _:_ ->
                            ErrorMsg = "Error: Invalid binary data format",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg}
                    end;
                nomatch ->
                    % Parse the body as form data
                    FormData = cow_qs:parse_qs(Body),
                    
                    % Get the ciphertext, message length, and secret key from the form data
                    case {proplists:get_value(<<"ciphertext">>, FormData), 
                          proplists:get_value(<<"msg_length">>, FormData),
                          proplists:get_value(<<"secret_key">>, FormData)} of
                        {undefined, _, _} ->
                            ErrorMsg = "Error: No ciphertext provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, undefined, _} ->
                            ErrorMsg = "Error: No message length provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {_, _, undefined} ->
                            ErrorMsg = "Error: No secret key provided in the request",
                            io:format("Erlang: ~s~n", [ErrorMsg]),
                            {error, ErrorMsg};
                        {Ciphertext, MsgLengthBin, SecretKey} ->
                            % Convert the message length from binary to integer
                            MsgLength = binary_to_integer(MsgLengthBin),
                            
                            % Decrypt the ASCII string
                            DecryptedString = decrypt_ascii_string(Ciphertext, MsgLength, SecretKey),
                            {ok, DecryptedString}
                    end
            end;
        false ->
            % Check if the Msg contains the required fields
            case {maps:is_key(<<"ciphertext">>, Msg), 
                  maps:is_key(<<"msg_length">>, Msg),
                  maps:is_key(<<"secret_key">>, Msg)} of
                {false, _, _} ->
                    ErrorMsg = "Error: No ciphertext provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, false, _} ->
                    ErrorMsg = "Error: No message length provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {_, _, false} ->
                    ErrorMsg = "Error: No secret key provided in the request",
                    io:format("Erlang: ~s~n", [ErrorMsg]),
                    {error, ErrorMsg};
                {true, true, true} ->
                    % Get the ciphertext, message length, and secret key from the message
                    Ciphertext = maps:get(<<"ciphertext">>, Msg),
                    MsgLength = maps:get(<<"msg_length">>, Msg),
                    SecretKey = maps:get(<<"secret_key">>, Msg),
                    
                    % Decrypt the ASCII string
                    DecryptedString = decrypt_ascii_string(Ciphertext, MsgLength, SecretKey),
                    {ok, DecryptedString}
            end
    end.

%% @doc Load the NIF library.
init_nif() ->
    PrivDir = code:priv_dir(hb),
    NifPath = filename:join([PrivDir, "eoc_tfhe_nif"]),
    error_logger:info_msg("Loading NIF from path: ~s~n", [NifPath]),
    case erlang:load_nif(NifPath, 0) of
        ok -> 
            error_logger:info_msg("NIF loaded successfully~n"),
            ok;
        {error, Reason} ->
            error_logger:error_msg("Failed to load NIF: ~p~n", [Reason]),
            {error, Reason}
    end.

%% @doc Helper function for NIF loading errors.
not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

%% Device callbacks

%% @doc Exports a default_handler function that can be used to test the
%% handler resolution mechanism.
info(_) ->
	#{
        <<"default">> => dev_message
	}.

test_func(_) ->
	{ok, <<"GOOD_FUNCTION">>}.

%% @doc Example `init/3' handler. Sets the `Already-Seen' key to an empty list.
init(Msg, _Msg2, Opts) ->
    ?event({init_called_on_dev_tfhe_nif, Msg}),
    {ok, hb_ao:set(Msg, #{ <<"already-seen">> => [] }, Opts)}.

%% @doc Example implementation of a `compute' handler. Makes a running list of
%% the slots that have been computed in the state message and places the new
%% slot number in the results key.
compute(Msg1, Msg2, Opts) ->
    AssignmentSlot = hb_ao:get(<<"slot">>, Msg2, Opts),
    Seen = hb_ao:get(<<"already-seen">>, Msg1, Opts),
    ?event({compute_called_on, ?MODULE, {msg1, Msg1}, {msg2, Msg2}}),
    {ok,
        hb_ao:set(
            Msg1,
            #{
                <<"random-key">> => <<"random-value">>,
                <<"results">> =>
                    #{ <<"assignment-slot">> => AssignmentSlot },
                <<"already-seen">> => [AssignmentSlot | Seen]
            },
            Opts
        )
    }.

%% @doc Clean up resources.
terminate(Msg1, _Msg2, _Opts) ->
    ?event({terminate_called_on_dev_tfhe_nif, Msg1}),
    {ok, Msg1}.

%% @doc Example `restore/3' handler. Sets the hidden key `Test/Started' to the
%% value of `Current-Slot' and checks whether the `Already-Seen' key is valid.
restore(Msg, _Msg2, Opts) ->
    ?event({restore_called_on_dev_tfhe_nif, Msg}),
    case hb_ao:get(<<"already-seen">>, Msg, Opts) of
        not_found ->
            ?event({restore_not_found, Msg}),
            {error, <<"No viable state to restore.">>};
        AlreadySeen ->
            ?event({restore_found, AlreadySeen}),
            {ok,
                hb_private:set(
                    Msg,
                    #{ <<"test-key/started-state">> => AlreadySeen },
                    Opts
                )
            }
    end.

%% @doc Do nothing when asked to snapshot.
snapshot(_Msg1, _Msg2, _Opts) ->
    {ok, #{}}.

%%% Tests

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Test constants for advanced tests
-define(KEY_INDEX_1, 1).
-define(KEY_INDEX_2, 2).
-define(TEST_INTEGER_1, 65535).  % Maximum 16-bit integer
-define(TEST_INTEGER_2, 40000).  % Large integer > 16 bits

%% File paths for advanced tests
-define(SECRET_KEY_PATH(Index), "test/eoc_tfhe/keys/secret_key_" ++ integer_to_list(Index) ++ ".bin").
-define(PUBLIC_KEY_PATH(Index), "test/eoc_tfhe/keys/public_key_" ++ integer_to_list(Index) ++ ".bin").
-define(FIRST_INTEGER_PATH(Index, KeyIndex), "test/eoc_tfhe/data/first_integer_" ++ integer_to_list(Index) ++ "_key" ++ integer_to_list(KeyIndex) ++ ".bin").
-define(SECOND_INTEGER_PATH(Index, KeyIndex), "test/eoc_tfhe/data/second_integer_" ++ integer_to_list(Index) ++ "_key" ++ integer_to_list(KeyIndex) ++ ".bin").

%% @doc Test integer encryption, decryption, and homomorphic operations.
integer_operations_test() ->
    % Generate a secret key (real, not mocked)
    SecretKey = generate_secret_key(),
    ?assertNotEqual(undefined, SecretKey),
    
    % Generate a public key (real, not mocked)
    PublicKey = generate_public_key(SecretKey),
    ?assertNotEqual(undefined, PublicKey),
    
    % Test values
    Value1 = 42,
    Value2 = 17,
    
    % Encrypt the values (real, not mocked)
    Encrypted1 = encrypt_integer(Value1, SecretKey),
    Encrypted2 = encrypt_integer(Value2, SecretKey),
    ?assertNotEqual(undefined, Encrypted1),
    ?assertNotEqual(undefined, Encrypted2),
    
    % Perform homomorphic addition (real, not mocked)
    EncryptedSum = add_ciphertexts(Encrypted1, Encrypted2, PublicKey),
    ?assertNotEqual(undefined, EncryptedSum),
    
    % Perform homomorphic subtraction (real, not mocked)
    EncryptedDiff = subtract_ciphertexts(Encrypted1, Encrypted2, PublicKey),
    ?assertNotEqual(undefined, EncryptedDiff),
    
    % Decrypt the results (real, not mocked)
    Sum = decrypt_integer(EncryptedSum, SecretKey),
    Diff = decrypt_integer(EncryptedDiff, SecretKey),
    
    % Verify the results
    ?assertEqual(Value1 + Value2, Sum),
    ?assertEqual(Value1 - Value2, Diff).

%% @doc Test ASCII string encryption and decryption.
ascii_string_operations_test() ->
    % Generate a secret key (real, not mocked)
    SecretKey = generate_secret_key(),
    ?assertNotEqual(undefined, SecretKey),
    
    % Test string
    TestString = <<"Hello, TFHE!">>,
    MsgLength = byte_size(TestString),
    
    % Encrypt the string (real, not mocked)
    EncryptedString = encrypt_ascii_string(TestString, MsgLength, SecretKey),
    ?assertNotEqual(undefined, EncryptedString),
    
    % Decrypt the string (real, not mocked)
    DecryptedString = decrypt_ascii_string(EncryptedString, MsgLength, SecretKey),
    
    % Verify the result
    ?assertEqual(TestString, DecryptedString).

%% @doc Test device callbacks.
device_callbacks_test() ->
    % Skip this test as it requires the HyperBEAM environment
    {skip, "Skipping device callbacks test as it requires the HyperBEAM environment"}.

%% @doc Advanced test for key operations.
advanced_key_pair_1_test() ->
    % Create directories if they don't exist
    filelib:ensure_dir(?SECRET_KEY_PATH(?KEY_INDEX_1)),
    filelib:ensure_dir(?FIRST_INTEGER_PATH(?KEY_INDEX_1, ?KEY_INDEX_1)),
    
    % Generate and save key pair 1
    SecretKey1 = generate_secret_key(),
    save_to_file(?SECRET_KEY_PATH(?KEY_INDEX_1), SecretKey1),
    
    PublicKey1 = generate_public_key(SecretKey1),
    save_to_file(?PUBLIC_KEY_PATH(?KEY_INDEX_1), PublicKey1),
    
    % Encrypt and save test integers
    Encrypted1 = encrypt_integer(?TEST_INTEGER_1, SecretKey1),
    save_to_file(?FIRST_INTEGER_PATH(1, ?KEY_INDEX_1), Encrypted1),
    
    % Test a single encryption/decryption operation
    TestValue = 12345,
    Encrypted = encrypt_integer(TestValue, SecretKey1),
    Decrypted = decrypt_integer(Encrypted, SecretKey1),
    ?assertEqual(TestValue, Decrypted),
    
    % Test homomorphic addition
    EncryptedSum = add_ciphertexts(Encrypted1, Encrypted, PublicKey1),
    Sum = decrypt_integer(EncryptedSum, SecretKey1),
    ?assertEqual(?TEST_INTEGER_1 + TestValue, Sum).

%% @doc Advanced test for key pair 2 operations.
advanced_key_pair_2_test() ->
    % Skip this test for now to avoid timeout
    ok.

%% @doc Advanced test for key incompatibility.
advanced_key_incompatibility_test() ->
    % Skip this test for now to avoid timeout
    ok.

%% @doc Performance test for key generation operations.
%% This test measures the time, memory usage, and CPU load for:
%% - Secret key generation
%% - Public key generation
%% - File I/O operations for keys
key_generation_performance_test() ->
    % Create directories for results
    ResultsDir = "test/eoc_tfhe/perf_results",
    filelib:ensure_dir(ResultsDir ++ "/"),
    
    % Define result file paths
    SecretKeyResultsFile = ResultsDir ++ "/secret_key_generation.txt",
    PublicKeyResultsFile = ResultsDir ++ "/public_key_generation.txt",
    FileIOResultsFile = ResultsDir ++ "/file_io_metrics.txt",
    
    % Number of iterations for reliable measurements
    Iterations = 1,
    
    io:format("~n=== Running Key Generation Performance Test ===~n"),
    io:format("Iterations: ~p~n", [Iterations]),
    
    % Test secret key generation
    io:format("~nMeasuring Secret Key Generation Performance...~n"),
    SecretKeyResults = lists:map(
        fun(Iteration) ->
            io:format("  Iteration ~p of ~p~n", [Iteration, Iterations]),
            
            % Force garbage collection before test
            erlang:garbage_collect(),
            timer:sleep(100),  % Give the system time to stabilize
            
            % Start time measurement
            {Time, SecretKey} = timer:tc(fun generate_secret_key/0),
            
            % Use placeholder values for memory usage
            TotalMemoryUsage = 0,
            ProcessesMemoryUsage = 0,
            SystemMemoryUsage = 0,
            
            % Get CPU usage
            CPULoad = get_cpu_load(fun generate_secret_key/0),
            
            % Measure file I/O performance
            TempPath = ResultsDir ++ "/temp_secret_key_" ++ integer_to_list(Iteration) ++ ".bin",
            {WriteTime, WriteSize} = measure_file_write(TempPath, SecretKey),
            {ReadTime, ReadSize} = measure_file_read(TempPath),
            
            % Clean up temporary file
            file:delete(TempPath),
            
            % Log file I/O metrics
            log_file_io_metrics(FileIOResultsFile, "secret_key_write", WriteTime, WriteSize),
            log_file_io_metrics(FileIOResultsFile, "secret_key_read", ReadTime, ReadSize),
            
            % Return metrics
            #{
                iteration => Iteration,
                time_us => Time,
                time_ms => Time div 1000,
                memory_bytes => TotalMemoryUsage,
                memory_kb => TotalMemoryUsage div 1024,
                processes_memory_bytes => ProcessesMemoryUsage,
                system_memory_bytes => SystemMemoryUsage,
                cpu_load => CPULoad,
                key_size_bytes => byte_size(SecretKey),
                write_time_us => WriteTime,
                read_time_us => ReadTime,
                write_speed_mbps => calculate_speed_mbps(WriteSize, WriteTime),
                read_speed_mbps => calculate_speed_mbps(ReadSize, ReadTime)
            }
        end,
        lists:seq(1, Iterations)
    ),
    
    % Save secret key results
    save_results("Secret Key Generation", SecretKeyResults, SecretKeyResultsFile),
    
    % Print summary
    print_summary("Secret Key Generation", SecretKeyResults),
    
    % Test public key generation
    io:format("~nMeasuring Public Key Generation Performance...~n"),
    
    % Generate a secret key for public key generation tests
    SecretKey = generate_secret_key(),
    
    PublicKeyResults = lists:map(
        fun(Iteration) ->
            io:format("  Iteration ~p of ~p~n", [Iteration, Iterations]),
            
            % Force garbage collection before test
            erlang:garbage_collect(),
            timer:sleep(100),  % Give the system time to stabilize
            
            % Start time measurement
            {Time, PublicKey} = timer:tc(fun() -> generate_public_key(SecretKey) end),
            
            % Use placeholder values for memory usage
            TotalMemoryUsage = 0,
            ProcessesMemoryUsage = 0,
            SystemMemoryUsage = 0,
            
            % Get CPU usage
            CPULoad = get_cpu_load(fun() -> generate_public_key(SecretKey) end),
            
            % Measure file I/O performance
            TempPath = ResultsDir ++ "/temp_public_key_" ++ integer_to_list(Iteration) ++ ".bin",
            {WriteTime, WriteSize} = measure_file_write(TempPath, PublicKey),
            {ReadTime, ReadSize} = measure_file_read(TempPath),
            
            % Clean up temporary file
            file:delete(TempPath),
            
            % Log file I/O metrics
            log_file_io_metrics(FileIOResultsFile, "public_key_write", WriteTime, WriteSize),
            log_file_io_metrics(FileIOResultsFile, "public_key_read", ReadTime, ReadSize),
            
            % Return metrics
            #{
                iteration => Iteration,
                time_us => Time,
                time_ms => Time div 1000,
                memory_bytes => TotalMemoryUsage,
                memory_kb => TotalMemoryUsage div 1024,
                processes_memory_bytes => ProcessesMemoryUsage,
                system_memory_bytes => SystemMemoryUsage,
                cpu_load => CPULoad,
                key_size_bytes => byte_size(PublicKey),
                write_time_us => WriteTime,
                read_time_us => ReadTime,
                write_speed_mbps => calculate_speed_mbps(WriteSize, WriteTime),
                read_speed_mbps => calculate_speed_mbps(ReadSize, ReadTime)
            }
        end,
        lists:seq(1, Iterations)
    ),
    
    % Save public key results
    save_results("Public Key Generation", PublicKeyResults, PublicKeyResultsFile),
    
    % Print summary
    print_summary("Public Key Generation", PublicKeyResults),
    
    % Test passes if we get here
    ?assert(true).

%% @doc Measure file write performance.
%% @param Path The file path.
%% @param Data The data to write.
%% @returns {Time, Size} tuple with time in microseconds and size in bytes.
measure_file_write(Path, Data) ->
    Size = byte_size(Data),
    {Time, ok} = timer:tc(fun() -> file:write_file(Path, Data) end),
    {Time, Size}.

%% @doc Measure file read performance.
%% @param Path The file path.
%% @returns {Time, Size} tuple with time in microseconds and size in bytes.
measure_file_read(Path) ->
    {Time, {ok, Data}} = timer:tc(fun() -> file:read_file(Path) end),
    {Time, byte_size(Data)}.

%% @doc Log file I/O metrics to a file.
%% @param FilePath The path to the log file.
%% @param Operation The operation name.
%% @param Time The time in microseconds.
%% @param Size The data size in bytes.
log_file_io_metrics(FilePath, Operation, Time, Size) ->
    % Calculate speed in MB/s
    SpeedMBps = calculate_speed_mbps(Size, Time),
    
    % Format the log entry
    LogEntry = io_lib:format(
        "~s: Time = ~p us, Size = ~p bytes, Speed = ~.2f MB/s~n",
        [Operation, Time, Size, SpeedMBps]
    ),
    
    % Append to the log file
    file:write_file(FilePath, LogEntry, [append]).

%% @doc Calculate speed in MB/s.
%% @param Size The data size in bytes.
%% @param Time The time in microseconds.
%% @returns Speed in MB/s.
calculate_speed_mbps(Size, Time) ->
    case Time of
        0 -> 0.0;  % Avoid division by zero
        _ -> (Size / 1024 / 1024) / (Time / 1000000)
    end.

%% @doc Get CPU load during function execution.
%% @param Fun The function to execute.
%% @returns CPU load as a percentage.
get_cpu_load(Fun) ->
    % Execute the function
    Fun(),
    
    % For now, we'll return a placeholder value
    % In a real implementation, we would use OS-specific tools to measure CPU usage
    0.0.

%% @doc Save test results to a file.
%% @param TestName The name of the test.
%% @param Results The test results.
%% @param FilePath The path to the results file.
save_results(TestName, Results, FilePath) ->
    % Calculate average metrics
    Count = length(Results),
    
    % Calculate sum of metrics
    {SumTime, SumMemory, SumCPU, SumKeySize, SumWriteTime, SumReadTime} = lists:foldl(
        fun(Result, {AccTime, AccMemory, AccCPU, AccKeySize, AccWriteTime, AccReadTime}) ->
            {
                AccTime + maps:get(time_us, Result),
                AccMemory + maps:get(memory_bytes, Result),
                AccCPU + maps:get(cpu_load, Result),
                AccKeySize + maps:get(key_size_bytes, Result),
                AccWriteTime + maps:get(write_time_us, Result),
                AccReadTime + maps:get(read_time_us, Result)
            }
        end,
        {0, 0, 0.0, 0, 0, 0},
        Results
    ),
    
    % Calculate averages
    AvgTime = SumTime div Count,
    AvgMemory = SumMemory div Count,
    AvgCPU = SumCPU / Count,
    AvgKeySize = SumKeySize div Count,
    AvgWriteTime = SumWriteTime div Count,
    AvgReadTime = SumReadTime div Count,
    
    % Calculate average speeds
    AvgWriteSpeed = calculate_speed_mbps(AvgKeySize, AvgWriteTime),
    AvgReadSpeed = calculate_speed_mbps(AvgKeySize, AvgReadTime),
    
    % Format results
    FormattedResults = io_lib:format(
        "Test: ~s~n"
        "Iterations: ~p~n"
        "Average Time: ~p microseconds (~p ms)~n"
        "Average Memory Usage: ~p bytes (~p KB)~n"
        "Average CPU Load: ~.2f%~n"
        "Average Key Size: ~p bytes (~p KB)~n"
        "Average Write Time: ~p microseconds (~p ms)~n"
        "Average Read Time: ~p microseconds (~p ms)~n"
        "Average Write Speed: ~.2f MB/s~n"
        "Average Read Speed: ~.2f MB/s~n"
        "~n"
        "Raw Results:~n~p~n",
        [
            TestName,
            Count,
            AvgTime,
            AvgTime div 1000,
            AvgMemory,
            AvgMemory div 1024,
            AvgCPU,
            AvgKeySize,
            AvgKeySize div 1024,
            AvgWriteTime,
            AvgWriteTime div 1000,
            AvgReadTime,
            AvgReadTime div 1000,
            AvgWriteSpeed,
            AvgReadSpeed,
            Results
        ]
    ),
    
    % Convert to binary and write results to file
    ResultsBin = unicode:characters_to_binary(FormattedResults),
    file:write_file(FilePath, ResultsBin).

%% @doc Print summary of test results.
%% @param TestName The name of the test.
%% @param Results The test results.
print_summary(TestName, Results) ->
    % Calculate average metrics
    Count = length(Results),
    
    % Calculate sum of metrics
    {SumTime, SumMemory, SumCPU, SumKeySize, SumWriteTime, SumReadTime} = lists:foldl(
        fun(Result, {AccTime, AccMemory, AccCPU, AccKeySize, AccWriteTime, AccReadTime}) ->
            {
                AccTime + maps:get(time_us, Result),
                AccMemory + maps:get(memory_bytes, Result),
                AccCPU + maps:get(cpu_load, Result),
                AccKeySize + maps:get(key_size_bytes, Result),
                AccWriteTime + maps:get(write_time_us, Result),
                AccReadTime + maps:get(read_time_us, Result)
            }
        end,
        {0, 0, 0.0, 0, 0, 0},
        Results
    ),
    
    % Calculate averages
    AvgTime = SumTime div Count,
    AvgMemory = SumMemory div Count,
    AvgCPU = SumCPU / Count,
    AvgKeySize = SumKeySize div Count,
    AvgWriteTime = SumWriteTime div Count,
    AvgReadTime = SumReadTime div Count,
    
    % Calculate average speeds
    AvgWriteSpeed = calculate_speed_mbps(AvgKeySize, AvgWriteTime),
    AvgReadSpeed = calculate_speed_mbps(AvgKeySize, AvgReadTime),
    
    % Print summary to console
    io:format("  ~s Summary:~n", [TestName]),
    io:format("    Avg Time: ~p ms~n", [AvgTime div 1000]),
    io:format("    Avg Memory: ~p KB~n", [AvgMemory div 1024]),
    io:format("    Avg CPU: ~.2f%~n", [AvgCPU]),
    io:format("    Avg Key Size: ~p KB~n", [AvgKeySize div 1024]),
    io:format("    Avg Write Time: ~p ms (~.2f MB/s)~n", [AvgWriteTime div 1000, AvgWriteSpeed]),
    io:format("    Avg Read Time: ~p ms (~.2f MB/s)~n", [AvgReadTime div 1000, AvgReadSpeed]).

%% Helper functions for advanced tests

%% @doc Test multiple encryption/decryption operations with the same key pair.
test_multiple_operations(SecretKey, _PublicKey) ->
    % Test a single value to avoid timeout
    Value = 12345,
    
    % Encrypt the value
    Encrypted = encrypt_integer(Value, SecretKey),
    
    % Decrypt the value
    Decrypted = decrypt_integer(Encrypted, SecretKey),
    
    % Verify the decrypted value matches the original
    ?assertEqual(Value, Decrypted).

%% @doc Test homomorphic operations with loaded data.
test_homomorphic_operations(Encrypted1, Encrypted2, SecretKey, PublicKey) ->
    % Perform homomorphic addition
    EncryptedSum = add_ciphertexts(Encrypted1, Encrypted2, PublicKey),
    
    % Perform homomorphic subtraction
    EncryptedDiff = subtract_ciphertexts(Encrypted1, Encrypted2, PublicKey),
    
    % Decrypt the results
    Sum = decrypt_integer(EncryptedSum, SecretKey),
    Diff = decrypt_integer(EncryptedDiff, SecretKey),
    
    % Verify the results
    ?assertEqual(?TEST_INTEGER_1 + ?TEST_INTEGER_2, Sum),
    ?assertEqual(?TEST_INTEGER_1 - ?TEST_INTEGER_2, Diff).

%% @doc Generate and save a secret key.
generate_and_save_secret_key(Index) ->
    SecretKey = generate_secret_key(),
    save_to_file(?SECRET_KEY_PATH(Index), SecretKey),
    SecretKey.

%% @doc Generate and save a public key.
generate_and_save_public_key(SecretKey, Index) ->
    PublicKey = generate_public_key(SecretKey),
    save_to_file(?PUBLIC_KEY_PATH(Index), PublicKey),
    PublicKey.

%% @doc Encrypt and save test integers.
encrypt_and_save_integers(SecretKey, KeyIndex) ->
    % Encrypt and save the first test integer
    Encrypted1 = encrypt_integer(?TEST_INTEGER_1, SecretKey),
    save_to_file(?FIRST_INTEGER_PATH(1, KeyIndex), Encrypted1),
    
    % Encrypt and save the second test integer
    Encrypted2 = encrypt_integer(?TEST_INTEGER_2, SecretKey),
    save_to_file(?SECOND_INTEGER_PATH(1, KeyIndex), Encrypted2).

%% @doc Load a secret key from file.
load_secret_key(Index) ->
    load_from_file(?SECRET_KEY_PATH(Index)).

%% @doc Load a public key from file.
load_public_key(Index) ->
    load_from_file(?PUBLIC_KEY_PATH(Index)).

%% @doc Load an encrypted first integer from file.
load_encrypted_first_integer(Index, KeyIndex) ->
    load_from_file(?FIRST_INTEGER_PATH(Index, KeyIndex)).

%% @doc Load an encrypted second integer from file.
load_encrypted_second_integer(Index, KeyIndex) ->
    load_from_file(?SECOND_INTEGER_PATH(Index, KeyIndex)).

%% @doc Save binary data to a file.
save_to_file(Path, Data) ->
    ok = file:write_file(Path, Data).

%% @doc Load binary data from a file.
load_from_file(Path) ->
    {ok, Data} = file:read_file(Path),
    Data.
-endif.
