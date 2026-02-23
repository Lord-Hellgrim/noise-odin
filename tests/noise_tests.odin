package test


import "core:testing"
import "core:os"
import "core:slice"
import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/x25519"
import "core:fmt"
import "core:log"

import "../../noise"
import "../../noise/internals"


@(test)
testing_encryption :: proc(t: ^testing.T) {
    test_bytes, read_error := os.read_entire_file("Noise_protocol_text.txt", context.allocator)
    defer delete(test_bytes)

    backup_bytes := slice.clone(test_bytes)
    defer delete(backup_bytes)

    key : [32]u8
    crypto.rand_bytes(key[:])

    ciphertext, error := internals.ENCRYPT(key, 1, {}, test_bytes, internals.DEFAULT_PROTOCOL)
    testing.expect(t, !slice.equal(ciphertext.main_body, backup_bytes))
    decrypted, status := internals.DECRYPT(key, 1, {}, ciphertext, internals.DEFAULT_PROTOCOL)
    testing.expect(t, slice.equal(decrypted, backup_bytes))
}


@(test)
testing_concat_bytes :: proc(t: ^testing.T) {
    for i in 0..<100 {
        a := make([]u8, 100)
        b := make([]u8, 78)
        crypto.rand_bytes(a)
        crypto.rand_bytes(b)
        truth := make([dynamic]u8)
        append(&truth, ..a)
        append(&truth, ..b)
        c := internals.concat_bytes(a, b)
        testing.expect(t, slice.equal(c, truth[:]))
        delete(a)
        delete(b)
        delete(c)
        delete(truth)
    }
}

@(test)
testing_matching_cipherstates :: proc(t: ^testing.T) {
    protocol := internals.DEFAULT_PROTOCOL
    zeroslice : ecdh.Public_Key
    initiator_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        true,
        nil,
        internals.GENERATE_KEYPAIR(internals.DEFAULT_PROTOCOL),
        internals.keypair_empty(protocol),
        zeroslice,
        zeroslice,
        protocol_name = internals.DEFAULT_PROTOCOL_NAME,
    )

    responder_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        false,
        nil,
        internals.GENERATE_KEYPAIR(internals.DEFAULT_PROTOCOL),
        internals.keypair_empty(internals.DEFAULT_PROTOCOL),
        zeroslice,
        zeroslice,
        protocol_name = internals.DEFAULT_PROTOCOL_NAME,
    )

    message, ic1, ic2, istatus := internals.handshakestate_write_message(&initiator_handshake_state, {})
    defer delete(message)

    rc1, rc2, rstatus := internals.handshakestate_read_message(&responder_handshake_state, message)

    message, rc1, rc2, rstatus = internals.handshakestate_write_message(&responder_handshake_state, {})

    ic1, ic2, istatus = internals.handshakestate_read_message(&initiator_handshake_state, message)

    message, ic1, ic2, istatus = internals.handshakestate_write_message(&initiator_handshake_state, {})
    
    rc1, rc2, rstatus = internals.handshakestate_read_message(&responder_handshake_state, message)

    testing.expect(t, rc1 == ic1, "Responder and initiator C1 match")
    testing.expect(t, rc2 == ic2, "Responder and initiator C2 match")
}