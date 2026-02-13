package noise

import "internals"

import "core:net"
import "core:fmt"



NoiseError :: internals.NoiseStatus


Connection :: struct {
    initiator_cipherstate: internals.CipherState,
    responder_cipherstate: internals.CipherState,
    socket: net.TCP_Socket,
    peer: net.Endpoint,
    initiator: bool,
}

keypair_random :: internals.keypair_random


connection_send :: proc(self: ^Connection, message: []u8) -> NoiseError {
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
        ciphertext_len := internals.to_le_bytes(u64(len(ciphertext.main_body) + 28))
        // extend_from_slice(&buffer, ciphertext_len[:])
        // extend_from_slice(&buffer, ciphertext[:])
        net.send_tcp(self.socket, ciphertext_len[:])
        net.send_tcp(self.socket, ciphertext.main_body)
        net.send_tcp(self.socket, ciphertext.tag[:])
        return .Ok
    }

connection_receive :: proc(self: ^Connection) -> ([]u8, NoiseError) {
    size_buffer : [8]u8
    net.recv_tcp(self.socket, size_buffer[:])

    data_len := internals.u64_from_le_slice(size_buffer[:])
    if data_len >  internals.MAX_PACKET_SIZE {
        return nil, .Io
    }
    data := make_dynamic_array([dynamic]u8)
    defer delete(data)
    buffer : [4096]u8
    total_read: u64 = 0
    
    for total_read < data_len {
        to_read := min(4096, data_len - total_read)
        bytes_received, _ := net.recv_tcp(self.socket, buffer[:to_read])
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


initiate_connection_all_the_way :: proc(address: string) -> (Connection, NoiseError) {
    zeroslice : [internals.DHLEN]u8
    peer, parsing_failed := net.parse_endpoint(address)
    if parsing_failed {
        return connection_nullcon(), .invalid_address
    }
    stream, _ := net.dial_tcp(peer)
    s := internals.keypair_random()
    handshake_state := internals.handshakestate_Initialize(
        true,
        nil,
        s,
        internals.keypair_empty(),
        zeroslice,
        zeroslice
    )
    
    // -> e
    internals.handshakestate_WriteMessage(&handshake_state, stream)

    // <- e, ee, s, es
    internals.handshakestate_ReadMessage(&handshake_state, stream)

    // -> s, se
    res1, res2, status := internals.handshakestate_WriteMessage(&handshake_state, stream)

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
}

step_connection :: proc(potential_connection: ^Connection, handshake_state: ^HandshakeState) -> ConnectionStatus{

    initiator_cipherstate, responder_cipherstate : internals.CipherState
    status : NoiseError
    if handshake_state.initiator {
        if handshake_state.current_pattern % 2 == 0 {
            internals.handshakestate_WriteMessage(handshake_state, potential_connection.socket)
        }
    }
}

KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

accept_connection_all_the_way :: proc(stream: net.TCP_Socket, peer: net.Endpoint, s: KeyPair) -> (Connection, NoiseError) {
    zeroslice : [internals.DHLEN]u8
    handshakestate := internals.handshakestate_Initialize(false, nil, s, internals.keypair_empty(), zeroslice, zeroslice);

    // <- e
    C1, C2, status := internals.handshakestate_ReadMessage(&handshakestate, stream)

    // -> e, ee, s, es
    C1, C2, status = internals.handshakestate_WriteMessage(&handshakestate, stream)

     // <- s, se
    C1, C2, status = internals.handshakestate_ReadMessage(&handshakestate, stream)

    fmt.println("returning Connection!!")
    #partial switch status {
        case .Ok:  {
            return Connection {
                initiator_cipherstate = C1,
                responder_cipherstate = C2,
                socket = stream,
                peer = peer,
            }, .Ok
        }
        case: {
            return connection_nullcon(), .Io
        }
    }

}



connection_nullcon :: proc() -> Connection {
    zeroslice : [internals.DHLEN]u8
    return Connection{
        initiator_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        responder_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        socket = net.TCP_Socket(0), 
        peer = ""
    }
}

