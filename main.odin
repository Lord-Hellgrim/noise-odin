package noise

import "core:fmt"
import "core:net"
import "core:strings"
import "core:slice"
import "core:time"
import "core:os"
import "core:crypto/ecdh"

import "internals"


main :: proc() {
    protocol := internals.random_protocol()
    protocol_name := internals.protocol_text_from_struct(protocol)
    // protocol_name := "Noise_XX_448_AESGCM_SHA256"
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

    psk: [32]u8
    if internals.is_psk_pattern(pattern) {
        psk = internals.random_psk()
    }

    initiator_handshakestate, ini_ini_status := internals.handshakestate_Initialize(
        true,
        nil, 
        initiator_s, 
        nil, 
        ini_rs,
        nil,
        protocol_name = protocol_name,
        psk = psk,
    )
    responder_handshakestate, res_ini_status := internals.handshakestate_Initialize(
        false,
        nil,
        responder_s,
        nil,
        res_rs,
        nil,
        protocol_name = protocol_name,
        psk = psk,
    )
    fmt.println("ini_ini_status: ", ini_ini_status)
    fmt.println("res_ini_status: ", res_ini_status)
    assert(ini_ini_status == .Ok)
    assert(res_ini_status == .Ok)
    
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
    
    assert(ini_cstates.c1_i_to_r == res_cstates.c1_i_to_r)
    assert(ini_cstates.c2_r_to_i == res_cstates.c2_r_to_i)
    
    internals.handshakestate_destroy(&initiator_handshakestate)
    internals.handshakestate_destroy(&responder_handshakestate)
    fmt.println("SUCCESS!!")

}
