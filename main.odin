package noise

import "core:fmt"
import "core:net"
import "core:strings"
import "core:slice"
import "core:time"
import "core:os"
import "core:crypto/ecdh"
import "core:crypto"
import "core:math/rand"
import "core:mem"

import "internals"




test_1000_random_protocols :: proc() {
    
    test_log := strings.builder_make()

    any_test_failed := false
    stopwatch : time.Stopwatch
    time.stopwatch_start(&stopwatch)
    for i in 0..<1000 {

        protocol := internals.random_protocol()
        protocol_name := internals.protocol_text_from_struct(protocol)
        // protocol_name := "Noise_KNpsk2_448_ChaChaPoly_SHA256"
        // protocol, parse_error := parse_protocol_string(protocol_name)
        fmt.sbprintfln(&test_log, protocol_name)
        initiator_s := internals.GENERATE_KEYPAIR(protocol)
        responder_s := internals.GENERATE_KEYPAIR(protocol)
        ini_rs : Maybe(ecdh.Public_Key) = nil
        res_rs : Maybe(ecdh.Public_Key) = nil
        pattern := internals.map_pattern(protocol.handshake_pattern)
        fmt.sbprintfln(&test_log, "%v", pattern)
        if slice.contains(pattern.pre_messages, internals.PreToken.res_s) {
            fmt.sbprintfln(&test_log, "here")
            ini_rs = responder_s.public
        }
        if slice.contains(pattern.pre_messages, internals.PreToken.ini_s){
            res_rs = initiator_s.public
        }

        psk : [32]u8
        if internals.is_psk_pattern(pattern) {
            crypto.rand_bytes(psk[:])
        }

        initiator_handshakestate, ini_ini_status := internals.handshakestate_Initialize(
            true,
            nil, 
            initiator_s, 
            nil, 
            ini_rs,
            nil,
            protocol_name = protocol_name,
            psk = psk
        )
        responder_handshakestate, res_ini_status := internals.handshakestate_Initialize(
            false,
            nil,
            responder_s,
            nil,
            res_rs,
            nil,
            protocol_name = protocol_name,
            psk = psk
        )
        if ini_ini_status != .Ok { any_test_failed = true}
        if res_ini_status != .Ok { any_test_failed = true}
        
        ini_status, res_status : NoiseStatus
        ini_cstates, res_cstates : CipherStates
        ini_message, res_message : []u8
        res_complete := false
        
        for {
            if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
                break
            }
            ini_cstates, res_message, ini_status = initiator_step(&initiator_handshakestate, ini_message, nil)
            if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
                break
            }
            res_cstates, ini_message, res_status = responder_step(&responder_handshakestate, res_message, nil)
        }
        
        if ini_cstates.c1_i_to_r != res_cstates.c1_i_to_r {any_test_failed = true}
        if ini_cstates.c2_r_to_i != res_cstates.c2_r_to_i {any_test_failed = true}
        
        og_test_data := make([]u8, rand.int_range(128, 1_000_000))
        defer delete(og_test_data)
        crypto.rand_bytes(og_test_data[:])
        backup_og := slice.clone(og_test_data)
        defer delete(backup_og)

        prepared_test_data := prepare_message(&ini_cstates, og_test_data[:])
        decrypted_test_data, decrypt_status := open_message(&res_cstates, prepared_test_data)

        if !slice.equal(backup_og[:], decrypted_test_data) {any_test_failed = true}
        
        
        internals.handshakestate_destroy(&initiator_handshakestate)
        internals.handshakestate_destroy(&responder_handshakestate)
        if i%100 == 0 {
            fmt.println(i)
        }
    }
    time.stopwatch_stop(&stopwatch)

    if any_test_failed {
        fmt.println(strings.to_string(test_log))
    } else {
        fmt.println("SUCCESS!!")
        fmt.println("Elapsed time: ", stopwatch._accumulation)
        fmt.println("Time per handshake and message: ", stopwatch._accumulation / 1000)
    }

    strings.builder_destroy(&test_log)
}

test_one_protocol :: proc(protocol_name: string) {
    test_log := strings.builder_make()
    defer strings.builder_destroy(&test_log)
    any_test_failed := false
    // protocol := internals.random_protocol()
    // protocol_name := internals.protocol_text_from_struct(protocol)

    sw : time.Stopwatch
    time.stopwatch_start(&sw)
    protocol, parse_error := parse_protocol_string(protocol_name)
    
    initiator_s := internals.GENERATE_KEYPAIR(protocol)
    responder_s := internals.GENERATE_KEYPAIR(protocol)
    ini_rs : Maybe(ecdh.Public_Key) = nil
    res_rs : Maybe(ecdh.Public_Key) = nil
    pattern := internals.map_pattern(protocol.handshake_pattern)
    time.stopwatch_stop(&sw)
    fmt.println("time 1: ", time.stopwatch_duration(sw))

    time.stopwatch_reset(&sw)

    time.stopwatch_start(&sw)
    if slice.contains(pattern.pre_messages, internals.PreToken.res_s) {
        ini_rs = responder_s.public
    }
    if slice.contains(pattern.pre_messages, internals.PreToken.ini_s){
        res_rs = initiator_s.public
    }

    psk : [32]u8
    if internals.is_psk_pattern(pattern) {
        crypto.rand_bytes(psk[:])
    }

    initiator_handshakestate, ini_ini_status := internals.handshakestate_Initialize(
        true,
        nil, 
        initiator_s, 
        nil, 
        ini_rs,
        nil,
        protocol_name = protocol_name,
        psk = psk
    )
    responder_handshakestate, res_ini_status := internals.handshakestate_Initialize(
        false,
        nil,
        responder_s,
        nil,
        res_rs,
        nil,
        protocol_name = protocol_name,
        psk = psk
    )

    time.stopwatch_stop(&sw)
    fmt.println("Time 2: ", time.stopwatch_duration(sw))
    if ini_ini_status != .Ok { any_test_failed = true}
    if res_ini_status != .Ok { any_test_failed = true}
    
    ini_status, res_status : NoiseStatus
    ini_cstates, res_cstates : CipherStates
    ini_message, res_message : []u8
    res_complete := false
    time.stopwatch_reset(&sw)
    for {
        if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
            break
        }
        ini_cstates, res_message, ini_status = initiator_step(&initiator_handshakestate, ini_message, nil)
        if ini_status == .Handshake_Complete && res_status == .Handshake_Complete {
            break
        }
        res_cstates, ini_message, res_status = responder_step(&responder_handshakestate, res_message, nil)
    }
    
    if ini_cstates.c1_i_to_r != res_cstates.c1_i_to_r {any_test_failed = true}
    if ini_cstates.c2_r_to_i != res_cstates.c2_r_to_i {any_test_failed = true}
    
    time.stopwatch_start(&sw)
    og_test_data := make([]u8, 80_000)
    defer delete(og_test_data)
    crypto.rand_bytes(og_test_data[:])
    backup_og := slice.clone(og_test_data)
    defer delete(backup_og)

    prepared_test_data := prepare_message(&ini_cstates, og_test_data[:])
    decrypted_test_data, decrypt_status := open_message(&res_cstates, prepared_test_data)
    time.stopwatch_stop(&sw)
    fmt.println("Time cipher: ", time.stopwatch_duration(sw))
    if !slice.equal(backup_og[:], decrypted_test_data) {any_test_failed = true}
    
    
    internals.handshakestate_destroy(&initiator_handshakestate)
    internals.handshakestate_destroy(&responder_handshakestate)
}


benchmark_dh :: proc() {
    allo : mem.Dynamic_Arena
    mem.dynamic_arena_init(&allo)
    allocator := mem.dynamic_arena_allocator(&allo)

    protocol := DEFAULT_PROTOCOL

    p1 := internals.GENERATE_KEYPAIR(protocol)
    p2 := internals.GENERATE_KEYPAIR(protocol)
    
    sw : time.Stopwatch
    time.stopwatch_start(&sw)
    outputs : [1000][]u8
    for i in 0..<1000 {
        outputs[i] = internals.DH(&p1, &p2.public, allocator)
    }
    time.stopwatch_stop(&sw)
    fmt.println("Time dh: ", time.stopwatch_duration(sw) / 1000)
}

benchmark_hash :: proc() {
    allo : mem.Dynamic_Arena
    mem.dynamic_arena_init(&allo)
    allocator := mem.dynamic_arena_allocator(&allo)

    protocol := DEFAULT_PROTOCOL

    h1 : [128]u8
    h2 : [128]u8
    crypto.rand_bytes(h1[:])
    crypto.rand_bytes(h2[:])
    
    sw : time.Stopwatch
    time.stopwatch_start(&sw)
    outputs : [1000][]u8
    for i in 0..<1000 {
        outputs[i] = internals.HASH(allocator, protocol, h1[:], h2[:])
    }
    time.stopwatch_stop(&sw)
    fmt.println("Time hash: ", time.stopwatch_duration(sw) / 1000)
}

benchmark_cipher :: proc() {
    allo : mem.Dynamic_Arena
    mem.dynamic_arena_init(&allo)
    allocator := mem.dynamic_arena_allocator(&allo)

    protocol := DEFAULT_PROTOCOL

    k : [32]u8
    h2 : [128]u8
    crypto.rand_bytes(k[:])
    crypto.rand_bytes(h2[:])
    
    sw : time.Stopwatch
    time.stopwatch_start(&sw)
    plaintexts : [1000][128]u8
    for &t in plaintexts {
        crypto.rand_bytes(t[:])
    } 

    outputs : [1000]CryptoBuffer
    for i in 0..<1000 {
        outputs[i], _ = internals.ENCRYPT(k, u64(i), nil, plaintexts[i][:], protocol)
    }
    time.stopwatch_stop(&sw)
    fmt.println("Time cipher: ", time.stopwatch_duration(sw) / 1000)
}

main :: proc() {

    protocol_name := "Noise_NN_448_ChaChaPoly_SHA256"
    protocol, status := internals.parse_protocol_string(protocol_name)
    fmt.println(protocol_name)
    test_one_protocol(protocol_name)

    // test_1000_random_protocols()

    // benchmark_dh()
    // benchmark_hash()
    // benchmark_cipher()
    
}
