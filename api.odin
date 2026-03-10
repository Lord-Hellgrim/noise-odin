package noise

import "internals"

import "core:net"
import "core:fmt"


NoiseStatus :: internals.NoiseStatus

DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL

keypair_random :: internals.keypair_random

parse_protocol_string :: internals.parse_protocol_string

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

initiate_connection :: proc()


step_state :: proc(state: ^HandshakeState, message: []u8, payload: []u8 = {}) -> ([]u8, CipherStates, NoiseStatus) {
    c1, c2: internals.CipherState
    status : NoiseStatus
    handshake_message : []u8
    if state.initiator {
        if state.current_pattern % 2 == 0 {
            c1, c2, status = internals.handshakestate_read_message(state, message)
        } else {
            handshake_message, c1, c2, status = internals.handshakestate_write_message(state, payload)
        }
    } else {
        if state.current_pattern % 2 == 0 {
            handshake_message, c1, c2, status = internals.handshakestate_write_message(state, payload)
        } else {
            c1, c2, status = internals.handshakestate_read_message(state, message)
        }
    }

    cstates := CipherStates {
        c1_i_to_r = c1,
        c2_r_to_i = c2,
        initiator = state.initiator
    }

    return handshake_message, cstates, status
     
}

ConnectionStatus :: enum {
    pending,
    complete,
    error,
    io_error,
}

KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

