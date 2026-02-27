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


Connection :: struct {
    i_to_r: internals.CipherState,
    r_to_i: internals.CipherState,
    initiator: bool,
    socket: net.TCP_Socket,
    peer: net.Endpoint,
}

CipherStates :: struct {
    i_to_r: internals.CipherState,
    r_to_i: internals.CipherState,
    initiator: bool,
}


connection_send :: proc(self: ^Connection, message: []u8) -> NoiseStatus {
    fmt.println("calling connection_send")
    ciphertext : internals.CryptoBuffer
    switch self.initiator {
        case true: {
            ciphertext = internals.cipherstate_EncryptWithAd(&self.i_to_r, nil, message)
        }
        case false: {
            ciphertext = internals.cipherstate_EncryptWithAd(&self.r_to_i, nil, message)
        }
    }
    ciphertext_len := internals.to_le_bytes(u64(len(ciphertext.main_body) + 24))
    net.send_tcp(self.socket, ciphertext_len[:])
    net.send_tcp(self.socket, ciphertext.main_body)
    net.send_tcp(self.socket, ciphertext.tag[:])
    return .Ok
}

connection_alloc_and_receive :: proc(self: ^Connection, allocator := context.allocator) -> ([dynamic]u8, NoiseStatus) {
    data := make([dynamic]u8)
    result := connection_receive(self, &data)

    return data, result
}

connection_receive :: proc(self: ^Connection, data: ^[dynamic]u8, allocator := context.allocator) -> (NoiseStatus) {
    size_buffer : [8]u8
    net.recv_tcp(self.socket, size_buffer[:])

    data_len := internals.u64_from_be_slice(size_buffer[:])
    if data_len >  internals.MAX_PACKET_SIZE {
        fmt.println("data_len: %v", data_len)
        return .Io
    }
    buffer : [4096]u8
    total_read: u64 = 0
    
    for total_read < data_len {
        to_read := min(4096, data_len - total_read)
        bytes_received, status := net.recv_tcp(self.socket, buffer[:to_read])
        fmt.println(status)
        if bytes_received == 0 {
            return .Io
        }
        append(data, ..buffer[:bytes_received])
        total_read += u64(bytes_received)
    }

    data_buffer := internals.cryptobuffer_from_slice(buffer[:])

    decrypted_data: []u8
    switch self.initiator {
        case true: {
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.i_to_r, nil, data_buffer)
        }
        case false: {
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.r_to_i, nil, data_buffer)
        }

    };

    return .Ok
}

ConnectionStatus :: enum {
    pending,
    complete,
    error,
    io_error,
}

KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

