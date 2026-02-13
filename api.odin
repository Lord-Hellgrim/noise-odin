package noise

import "internals"

import "core:net"
import "core:fmt"



NoiseError :: internals.NoiseStatus


Connection :: struct {
    initiator_cipherstate: internals.CipherState,
    responder_cipherstate: internals.CipherState,
    stream: net.TCP_Socket,
    peer: string,
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
        net.send_tcp(self.stream, ciphertext_len[:])
        net.send_tcp(self.stream, ciphertext.main_body)
        net.send_tcp(self.stream, ciphertext.tag[:])
        return .NoError
    }

connection_receive :: proc(self: ^Connection) -> ([]u8, NoiseError) {
        size_buffer : [8]u8
        net.recv_tcp(self.stream, size_buffer[:])
    
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
            bytes_received, _ := net.recv_tcp(self.stream, buffer[:to_read])
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

        return decrypted_data, .NoError
    }


initiate_connection :: proc(address: string) -> (Connection, NoiseError) {
    zeroslice : [internals.DHLEN]u8
    stream, _ := net.dial_tcp_from_hostname_and_port_string(address)
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
    res1, res2, connection_error := internals.handshakestate_WriteMessage(&handshake_state, stream)

    switch res1 {
        case res1.?: {
            return Connection {
                    initiator_cipherstate = res1.?,
                    responder_cipherstate = res2.?,
                    stream = stream,
                    peer = ""
                }, .NoError
            }
        case nil: {
            return Connection{
                initiator_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
                responder_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
                stream = net.TCP_Socket(0), 
                peer = ""
            }, 
            .Io
        } 
    }

    return Connection{
        initiator_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        responder_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        stream = net.TCP_Socket(0), 
        peer = ""}, 
        .WrongState
}

KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

ACCEPT_CONNECTION :: proc(stream: net.TCP_Socket, s: KeyPair) -> (Connection, NoiseError) {
    handshakestate, _ := ACCEPT_CONNECTION_STEP_1(stream, s)

    ACCEPT_CONNECTION_STEP_2(stream, &handshakestate)

    connection, _ := ACCEPT_CONNECTION_STEP_3(stream, &handshakestate)

    return connection, .NoError
}

ACCEPT_CONNECTION_STEP_1 :: proc(stream: net.TCP_Socket, s: KeyPair) -> (HandshakeState, NoiseError) {
    zeroslice : [internals.DHLEN]u8
    handshakestate := internals.handshakestate_Initialize(false, nil, s, internals.keypair_empty(), zeroslice, zeroslice);

    // <- e
    internals.handshakestate_ReadMessage(&handshakestate, stream)

    return handshakestate, .NoError
}

ACCEPT_CONNECTION_STEP_2 :: proc(stream: net.TCP_Socket, handshakestate: ^HandshakeState) -> NoiseError {
    
    internals.handshakestate_WriteMessage(handshakestate, stream)

    return .NoError
}

ACCEPT_CONNECTION_STEP_3 :: proc(stream: net.TCP_Socket, handshakestate: ^HandshakeState) -> (Connection, NoiseError) {
    // <- s, se
    res1, res2, _ := internals.handshakestate_ReadMessage(handshakestate, stream)

    fmt.println("returning Connection!!")
    switch res1 {
        case res1.(internals.CipherState):  {
            return Connection {
                initiator_cipherstate = res1.?,
                responder_cipherstate = res2.?,
                stream = stream,
                peer = ""
            }, .NoError
        }
        case nil: {
            return connection_nullcon(), .Io
        }
    }
    return connection_nullcon(), .WrongState
}


connection_nullcon :: proc() -> Connection {
    zeroslice : [internals.DHLEN]u8
    return Connection{
        initiator_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        responder_cipherstate = internals.cipherstate_InitializeKey(zeroslice), 
        stream = net.TCP_Socket(0), 
        peer = ""
    }
}

