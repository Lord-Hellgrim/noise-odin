package noise

import "internals"

import "core:net"
import "core:fmt"


NoiseStatus :: internals.NoiseStatus

DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL

keypair_random :: internals.keypair_random

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
    
    if input_message == nil {
        output_message, c1, c2, status = internals.handshakestate_write_message(handshakestate, payload, allocator)
    } else {
        c1, c2, status = internals.handshakestate_read_message(handshakestate, input_message)
        if status != .Handshake_Complete {
            output_message, c1, c2, status = internals.handshakestate_write_message(handshakestate, payload, allocator)
        }
    }

    return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = true}, output_message, status
}

responder_step :: proc(handshakestate: ^HandshakeState, input_message: []u8, payload : []u8 = nil, allocator := context.allocator) -> (CipherStates, []u8, NoiseStatus) {
    output_message : []u8
    if input_message == nil {
        return {}, {}, .nil_passed_to_read_message,
    }

    c1, c2, status := internals.handshakestate_read_message(handshakestate, input_message)
    if status != .Handshake_Complete {
        output_message, c1, c2, status = internals.handshakestate_write_message(handshakestate, payload, allocator)
    }

    return CipherStates{c1_i_to_r = c1, c2_r_to_i = c2, initiator = false}, output_message, status
}

// This function will overwrite the message slice
initiator_prepare_message :: proc(cstates: ^CipherStates, message: []u8) -> CryptoBuffer {
    cryptobuffer := internals.cipherstate_EncryptWithAd(&cstates.c1_i_to_r, nil, message)
    return cryptobuffer
}

// This function will overwrite the encrypted message slice
responder_open_message :: proc(cstates: ^CipherStates, encrypted_message: ^[]u8) -> ([]u8, NoiseStatus) {
    cryptobuffer := internals.cryptobuffer_from_slice(encrypted_message^)
    return internals.cipherstate_DecryptWithAd(&cstates.c1_i_to_r, nil, cryptobuffer)
}

// This function will overwrite the message slice
responder_prepare_message :: proc(cstates: ^CipherStates, message: []u8) -> CryptoBuffer {
    cryptobuffer := internals.cipherstate_EncryptWithAd(&cstates.c2_r_to_i, nil, message)
    return cryptobuffer
}

// This function will overwrite the encrypted message slice
initiator_open_message :: proc(cstates: ^CipherStates, encrypted_message: ^[]u8) -> ([]u8, NoiseStatus) {
    cryptobuffer := internals.cryptobuffer_from_slice(encrypted_message^)
    return internals.cipherstate_DecryptWithAd(&cstates.c2_r_to_i, nil, cryptobuffer)
}


KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

