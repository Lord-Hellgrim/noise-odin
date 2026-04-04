package noise

import "internals"


/// This file defines the API for the noise protocol package. You should never need to call an internals procedure
/// or use an internals type.

/// In general, to complete a noise handshake you must:
///     If you are initiating the connection, call initiator_step passing nil to the input_message parameter.
///     Send the resulting []u8 to the responder (genrally a server) with the stream method of your choice (see examples)
///     if the status code of the initiator_step call was .Handshake_Complete, you will have received a valid Cipherstates
///     struct. Otherwise, read the response from the responder and feed the response data as the input_message to the
///     next call to initiator_step until it returns .Handshake_Complete. You will then have a Cipherstates struct
///     That you can pass to the prepare_message and open_message procedures to prepare messages for sending
///     to the responder and for opening messages sent by the responder.

///     If you are the responder, the method is much the same, except you must pass a valid input_message received
///     from an initiator to the first call to responder_step. Repeat until the returned status is .Handshake_Complete.

/// A noise_networking package is available to provide a simple abstraction layer for using noise over TCP. The design
/// intent of the noise_networking package is to work well with odins nbio.

NoiseStatus :: internals.NoiseStatus

HandshakeState :: internals.HandshakeState
handshakestate_initialize :: internals.handshakestate_initialize
read_message :: internals.handshakestate_read_message
write_message :: internals.handshakestate_write_message

KeyPair :: internals.KeyPair
keypair_random :: internals.keypair_random

DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL
parse_protocol_string :: internals.parse_protocol_string

CryptoBuffer :: internals.CryptoBuffer
cryptobuffer_from_slice :: internals.cryptobuffer_from_slice

to_le_bytes :: internals.to_le_bytes

CipherStates :: struct {
    c1_i_to_r: internals.CipherState,
    c2_r_to_i: internals.CipherState,
    initiator: bool,
}

initiator_step :: proc(handshakestate: ^HandshakeState, input_message: []u8, payload : []u8 = nil, allocator := context.allocator) -> (CipherStates, []u8, NoiseStatus) {
    output_message : []u8
    c1, c2 : internals.CipherState
    status : NoiseStatus
    payload_buffer : []u8
    
    if input_message == nil {
        output_message, c1, c2, status = write_message(handshakestate, payload, allocator)
    } else {
        payload_buffer, c1, c2, status = read_message(handshakestate, input_message)
        if status != .Handshake_Complete {
            output_message, c1, c2, status = write_message(handshakestate, payload, allocator)
        }
    }

    return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = true}, output_message, status
}

responder_step :: proc(handshakestate: ^HandshakeState, input_message: []u8, payload : []u8 = nil, allocator := context.allocator) -> (CipherStates, []u8, NoiseStatus) {
    output_message : []u8
    if input_message == nil {
        return {}, {}, .invalid_message_passed_to_read_message,
    }

    payload_buffer, c1, c2, status := read_message(handshakestate, input_message)
    if status != .Handshake_Complete {
        output_message, c1, c2, status = write_message(handshakestate, payload, allocator)
    }

    return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = false}, output_message, status
}

// This function will overwrite "data" with the encrypted data
prepare_message :: proc(cstates: ^CipherStates, data: []u8) -> (CryptoBuffer, NoiseStatus) {
    result : CryptoBuffer
    status : NoiseStatus
    nonce : u64
    switch cstates.initiator {
        case true: {
            nonce := cstates.c1_i_to_r.n
            result, status = internals.cipherstate_EncryptWithAd(&cstates.c1_i_to_r, nil, data)
        }
        case false: {
            nonce := cstates.c2_r_to_i.n
            result, status = internals.cipherstate_EncryptWithAd(&cstates.c2_r_to_i, nil, data)
        }
    }
    return result, status
}

// This function will overwrite the "encrypted_message" with the decrypted data
open_message :: proc(cstates: ^CipherStates, encrypted_message: CryptoBuffer) -> ([]u8, NoiseStatus) {
    result : []u8
    status : NoiseStatus
    switch cstates.initiator {
        case true: {
            result, status = internals.cipherstate_DecryptWithAd(&cstates.c2_r_to_i, nil, encrypted_message)
        }
        case false: {
            result, status = internals.cipherstate_DecryptWithAd(&cstates.c1_i_to_r, nil, encrypted_message)
        }
    }
    return result, status
}

