package noise

import "internals"

import "core:net"
import "core:fmt"


NoiseStatus :: internals.NoiseStatus

HandshakeState :: internals.HandshakeState
read_message :: internals.handshakestate_read_message
write_message :: internals.handshakestate_write_message

KeyPair :: internals.KeyPair
keypair_random :: internals.keypair_random

DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL

parse_protocol_string :: internals.parse_protocol_string

CryptoBuffer :: internals.CryptoBuffer

// levels of abstraction
// level 1 -> 
//      send_data(data, address)
// level 2 -> 
//      initiate_connection_all_the_way(address, options := default_options) -> Connection, Status
//      accept_connection_all_the_way(socket, options := default options) -> Connection, Status 
//      connection_send(Connection, data, options := default_options) -> Status
//      connection_receive(Connection, options := default_options) -> data, Status
//      close_connection(Connection) -> Status
// level 3 -> 
//      step_connection(^Connection, ^HandshakeState, options := default) -> ConnectionStatus
// level 4 -> 
//      prepare_handshake_step(data, ^HandshakeState) -> distinct? []u8, Status
//      prepare_message(data, CipherStates) -> distinct? []u8, Status


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
prepare_message :: proc(cstates: ^CipherStates, data: []u8) -> CryptoBuffer {
    result : CryptoBuffer
    status : NoiseStatus
    switch cstates.initiator {
        case true: {
            result, status = internals.cipherstate_EncryptWithAd(&cstates.c1_i_to_r, nil, data)
        }
        case false: {
            result, status = internals.cipherstate_EncryptWithAd(&cstates.c2_r_to_i, nil, data)
        }
    }
    return result
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



