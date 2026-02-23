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
// Top -> send_data(data, address) Cache connection details in global data
// level 1 -> open/accept, send/receive, close
// level 2 -> step_by_step_open, send/receive all (calls send_receive until EOF), close
// level 3 -> step_by_step_open, step_by_step send/receive ( mostly receive ), close
// level 4 -> step_by_step open, user handles sockets, prepare for sending/receiving
// level 5 -> ???


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
    fmt.println("ciphertext_len: %v", ciphertext_len)
    net.send_tcp(self.socket, ciphertext_len[:])
    net.send_tcp(self.socket, ciphertext.main_body)
    net.send_tcp(self.socket, ciphertext.tag[:])
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
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.i_to_r, nil, data_buffer)
        }
        case false: {
            decrypted_data, _ = internals.cipherstate_DecryptWithAd(&self.r_to_i, nil, data_buffer)
        }

    };

    return decrypted_data, .Ok
}

ConnectionStatus :: enum {
    pending,
    complete,
    error,
    io_error,
}

KeyPair :: internals.KeyPair

HandshakeState :: internals.HandshakeState

