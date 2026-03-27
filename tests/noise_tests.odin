package test

import "core:math/rand"

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
testing_matching_cipherstates_with_default_protocol :: proc(t: ^testing.T) {
    protocol := internals.DEFAULT_PROTOCOL
    zeroslice : ecdh.Public_Key
    initiator_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        true,
        nil,
        internals.GENERATE_KEYPAIR(internals.DEFAULT_PROTOCOL),
        nil,
        nil,
        nil,
        protocol_name = internals.DEFAULT_PROTOCOL_NAME,
    )

    responder_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        false,
        nil,
        internals.GENERATE_KEYPAIR(internals.DEFAULT_PROTOCOL),
        nil,
        nil,
        nil,
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

@(test)
testing_api_basics :: proc(t: ^testing.T) {
    protocol_name := "Noise_NK_25519_AESGCM_SHA256"
    protocol, parse_status := internals.parse_protocol_string(protocol_name)
    initiator_s := internals.GENERATE_KEYPAIR(protocol)
    responder_s := internals.GENERATE_KEYPAIR(protocol)

    initiator_handshakestate, ini_ini_status := internals.handshakestate_Initialize(
        true,
        nil, 
        initiator_s, 
        nil, 
        responder_s.public,
        nil,
        protocol_name = protocol_name,
    )
    responder_handshakestate, res_ini_status := internals.handshakestate_Initialize(
        false,
        nil,
        responder_s,
        nil,
        nil,
        nil,
        protocol_name = protocol_name
    )
    fmt. println("ini_ini_status: ", ini_ini_status)
    fmt. println("res_ini_status: ", res_ini_status)
    testing.expect(t, ini_ini_status == .Ok)
    testing.expect(t, res_ini_status == .Ok)

    ini_status, res_status : noise.NoiseStatus
    ini_cstates, res_cstates : noise.CipherStates
    ini_message, res_message : []u8
    res_complete := false

    for {
        ini_cstates, ini_message, ini_status = noise.initiator_step(&initiator_handshakestate, res_message)
        if res_complete {
            break
        }
        res_cstates, res_message, res_status = noise.responder_step(&responder_handshakestate, ini_message, nil)
        if res_status == .Handshake_Complete {
            res_complete = true
        }
    }
    
    testing.expect(t, ini_cstates.c1_i_to_r == res_cstates.c1_i_to_r)
    testing.expect(t, ini_cstates.c2_r_to_i == res_cstates.c2_r_to_i)

    internals.handshakestate_destroy(&initiator_handshakestate)
    internals.handshakestate_destroy(&responder_handshakestate)

    fmt.println("SUCCESS!!")
}

testing_random_protocols :: proc(t: ^testing.T) {
    
    for i in 0..<10_000 {

        protocol := internals.random_protocol()
        protocol_name := internals.protocol_text_from_struct(protocol)
        // protocol_name := "Noise_IX_448_AESGCM_SHA256"
        // protocol, parse_error := parse_protocol_string(protocol_name)
        fmt.println(protocol_name)
        initiator_s := internals.GENERATE_KEYPAIR(protocol)
        responder_s := internals.GENERATE_KEYPAIR(protocol)
        ini_rs : Maybe(ecdh.Public_Key) = nil
        res_rs : Maybe(ecdh.Public_Key) = nil
        pattern := internals.map_pattern(protocol.handshake_pattern)
        fmt.println(pattern)
        if slice.contains(pattern.pre_messages, internals.PreToken.res_s) {
            fmt.println("here")
            ini_rs = responder_s.public
        }
        if slice.contains(pattern.pre_messages, internals.PreToken.ini_s){
            res_rs = initiator_s.public
        }

        initiator_handshakestate, ini_ini_status := internals.handshakestate_Initialize(
            true,
            nil, 
            initiator_s, 
            nil, 
            ini_rs,
            nil,
            protocol_name = protocol_name,
        )
        responder_handshakestate, res_ini_status := internals.handshakestate_Initialize(
            false,
            nil,
            responder_s,
            nil,
            res_rs,
            nil,
            protocol_name = protocol_name
        )
        fmt.println("ini_ini_status: ", ini_ini_status)
        fmt.println("res_ini_status: ", res_ini_status)
        testing.expect(t, ini_ini_status == .Ok)
        testing.expect(t, res_ini_status == .Ok)
        
        ini_status, res_status : noise.NoiseStatus
        ini_cstates, res_cstates : noise.CipherStates
        ini_message, res_message : []u8
        res_complete := false
        
        for {
            if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
                break
            }
            ini_cstates, res_message, ini_status = noise.initiator_step(&initiator_handshakestate, ini_message, nil)
            if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
                break
            }
            res_cstates, ini_message, res_status = noise.responder_step(&responder_handshakestate, res_message, nil)
        }
        
        testing.expect(t, ini_cstates.c1_i_to_r == res_cstates.c1_i_to_r)
        testing.expect(t, ini_cstates.c2_r_to_i == res_cstates.c2_r_to_i)
        
        og_test_data := make([]u8, rand.int_range(128, 1_000_000))
        defer delete(og_test_data)
        crypto.rand_bytes(og_test_data[:])
        backup_og := slice.clone(og_test_data)
        defer delete(backup_og)

        prepared_test_data := noise.prepare_message(&ini_cstates, og_test_data[:])
        decrypted_test_data, decrypt_status := noise.open_message(&res_cstates, prepared_test_data)

        testing.expect(t, slice.equal(backup_og[:], decrypted_test_data))
        
        internals.handshakestate_destroy(&initiator_handshakestate)
        internals.handshakestate_destroy(&responder_handshakestate)
    }

}