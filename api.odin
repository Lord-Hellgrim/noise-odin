package noise

import "internals"

import "core:net"
import "core:fmt"


NoiseStatus :: internals.NoiseStatus


Connection :: struct {
    initiator_cipherstate: internals.CipherState,
    responder_cipherstate: internals.CipherState,
    socket: net.TCP_Socket,
    peer: net.Endpoint,
    initiator: bool,
}


DEFAULT_PROTOCOL_NAME :: internals.DEFAULT_PROTOCOL_NAME
DEFAULT_PROTOCOL :: internals.DEFAULT_PROTOCOL

keypair_random :: internals.keypair_random

parse_protocol_string :: internals.parse_protocol_string

// levels of abstraction
// Top -> send_data(data, address) Cache connection details in global data
// level 1 -> open/accept, send/receive, close
// level 2 -> step_by_step_open, send/receive all (calls send_receive until EOF), close
// level 3 -> step_by_step_open, step_by_step send/receive ( mostly receive ), close
// level 4 -> step_by_step open, user handles sockets, prepare for sending/receiving
// level 5 -> ???


connection_send :: proc(self: ^Connection, message: []u8) -> NoiseStatus {
    fmt.println("calling connection_send")
    buffer := make_dynamic_array([dynamic]u8)
    defer delete_dynamic_array(buffer)
    ciphertext : internals.CryptoBuffer
    switch self.initiator {
        case true: {
            ciphertext = internals.cipherstate_EncryptWithAd(&self.initiator_cipherstate, nil, message)
        }
        case false: {
            ciphertext = internals.cipherstate_EncryptWithAd(&self.responder_cipherstate, nil, message)
        }
    }
    ciphertext_len := internals.to_le_bytes(u64(len(ciphertext.main_body) + 24))
    fmt.println("ciphertext_len: %v", ciphertext_len)
    internals.extend_from_slice(&buffer, ciphertext_len[:])
    internals.extend_from_slice(&buffer, ciphertext.main_body[:])
    internals.extend_from_slice(&buffer, ciphertext.tag[:])
    net.send_tcp(self.socket, buffer[:])
    // net.send_tcp(self.socket, ciphertext_len[:])
    // net.send_tcp(self.socket, ciphertext.main_body)
    // net.send_tcp(self.socket, ciphertext.tag[:])
    return .Ok
}


connection_receive :: proc(self: ^Connection) -> ([]u8, NoiseStatus) {
    size_buffer : [8]u8
    net.recv_tcp(self.socket, size_buffer[:])

    data_len := internals.u64_from_be_slice(size_buffer[:])
    if data_len >  internals.MAX_PACKET_SIZE {
        fmt.println("data_len: %v", data_len)
        return nil, .Io
    }
    data := make_dynamic_array([dynamic]u8)
    defer delete(data)
    buffer : [4096]u8
    total_read: u64 = 0
    
    for total_read < data_len {
        to_read := min(4096, data_len - total_read)
        bytes_received, status := net.recv_tcp(self.socket, buffer[:to_read])
        fmt.println(status)
        if bytes_received == 0 {
            return nil, .Io
        }
        internals.extend_from_slice(&data, buffer[:bytes_received])
        total_read += u64(bytes_received)
    }

    data_buffer := internals.cryptobuffer_from_slice(data[:])

    decrypted_data: []u8
    switch self.initiator {
        case true: {
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.initiator_cipherstate, nil, data_buffer)
        }
        case false: {
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.responder_cipherstate, nil, data_buffer)
        }

    };

    return decrypted_data, .Ok
}


initiate_connection_all_the_way :: proc(address: string, protocol_name := internals.DEFAULT_PROTOCOL_NAME) -> (Connection, NoiseStatus) {
    protocol, parse_error := internals.parse_protocol_string(protocol_name)
    if parse_error == .Protocol_could_not_be_parsed {
        return connection_nullcon(), .Protocol_could_not_be_parsed
    }
    zeroslice : [internals.DHLEN]u8
    peer, parsing_status := net.parse_endpoint(address)
    if parsing_status == false {
        return connection_nullcon(), .invalid_address
    }
    stream, _ := net.dial_tcp(peer)
    s := internals.keypair_random(protocol)
    handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        true,
        nil,
        s,
        internals.keypair_empty(protocol),
        zeroslice,
        zeroslice,
        protocol_name = protocol_name
    )
    
    // -> e
    internals.handshakestate_write_message(&handshake_state, stream)

    // <- e, ee, s, es
    internals.handshakestate_read_message(&handshake_state, stream)

    // -> s, se
    res1, res2, status := internals.handshakestate_write_message(&handshake_state, stream)

    #partial switch status {
        case .Ok: {
            return Connection {
                    initiator_cipherstate = res1,
                    responder_cipherstate = res2,
                    socket = stream,
                    peer = peer,
                }, 
                status
            }
        case: {
            return connection_nullcon(), status
        }
    }

}


ConnectionStatus :: enum {
    pending,
    complete,
    error,
    io_error,
}


step_connection :: proc(potential_connection: ^Connection, handshake_state: ^HandshakeState) -> ConnectionStatus{

    initiator_cipherstate, responder_cipherstate : internals.CipherState
    status : NoiseStatus = nil
    if handshake_state.initiator {
        if handshake_state.current_pattern % 2 == 0 {
            initiator_cipherstate, responder_cipherstate, status = internals.handshakestate_write_message(handshake_state, potential_connection.socket)
        } else {
            initiator_cipherstate, responder_cipherstate, status = internals.handshakestate_read_message(handshake_state, potential_connection.socket)
        }
    } else {
        if handshake_state.current_pattern % 2 == 0 {
            initiator_cipherstate, responder_cipherstate, status = internals.handshakestate_read_message(handshake_state, potential_connection.socket)
        } else {
            initiator_cipherstate, responder_cipherstate, status = internals.handshakestate_write_message(handshake_state, potential_connection.socket)
        }
    }

    #partial switch status {
        case .Handshake_Complete: {
            potential_connection.initiator_cipherstate = initiator_cipherstate
            potential_connection.responder_cipherstate = responder_cipherstate
            return .complete
        }
        case .Io:
            return .io_error
        case .Pending_Handshake:
            return .pending
        case:
            return .error
    }
}


KeyPair :: internals.KeyPair


HandshakeState :: internals.HandshakeState


accept_connection_all_the_way :: proc(
    stream: net.TCP_Socket,
    peer: net.Endpoint,
    s: KeyPair,
    protocol_name := internals.DEFAULT_PROTOCOL_NAME
) -> (Connection, NoiseStatus) {
    zeroslice : [internals.DHLEN]u8
    protocol, protocol_parse_error := internals.parse_protocol_string(protocol_name)
    if protocol_parse_error == .Protocol_could_not_be_parsed {
        return connection_nullcon(), .Protocol_could_not_be_parsed
    }
    handshakestate, proto := internals.handshakestate_Initialize(false, nil, s, internals.keypair_empty(protocol), zeroslice, zeroslice);

    // <- e
    C1, C2, status := internals.handshakestate_read_message(&handshakestate, stream)
    fmt.println("status at e: %v", status)

    // -> e, ee, s, es
    C1, C2, status = internals.handshakestate_write_message(&handshakestate, stream)
    fmt.println("status at e, ee, s, es: %v", status)

     // <- s, se
    C1, C2, status = internals.handshakestate_read_message(&handshakestate, stream)
    fmt.println("status at s, se: %v", status)

    #partial switch status {
        case .Handshake_Complete:  {
            fmt.println("returning Connection!!")
            return Connection {
                initiator_cipherstate = C1,
                responder_cipherstate = C2,
                socket = stream,
                peer = peer,
            }, .Ok
        }
        case: {
            fmt.println(status)
            return connection_nullcon(), .Io
        }
    }
}


connection_nullcon :: proc() -> Connection {
    zeroslice : [internals.DHLEN]u8
    return Connection{
        initiator_cipherstate = internals.cipherstate_InitializeKey(zeroslice, internals.ERROR_PROTOCOL), 
        responder_cipherstate = internals.cipherstate_InitializeKey(zeroslice, internals.ERROR_PROTOCOL), 
        socket = net.TCP_Socket(0),
    }
}

