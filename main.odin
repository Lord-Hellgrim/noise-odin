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
    assert(ini_ini_status == .Ok)
    assert(res_ini_status == .Ok)

    ini_status, res_status : NoiseStatus
    ini_cstates, res_cstates : CipherStates
    ini_message, res_message : []u8
    res_complete := false
    for {
        if res_complete {
            ini_cstates, ini_message, ini_status = initiator_step(&initiator_handshakestate, nil)
        } else {
            ini_cstates, ini_message, ini_status = initiator_step(&initiator_handshakestate, nil)
        }
        
        res_cstates, res_message, res_status = responder_step(&responder_handshakestate, ini_message, nil)
        if res_status == .Handshake_Complete {
            res_complete = true
        }
    }

    assert(ini_cstates.c1_i_to_r == res_cstates.c1_i_to_r)
    assert(ini_cstates.c2_r_to_i == res_cstates.c2_r_to_i)

}
