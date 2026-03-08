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

    // protocol := internals.random_protocol()
    // protocol_name := internals.protocol_text_from_struct(protocol)
    protocol_name := "Noise_NK_448_AESGCM_SHA256"
    protocol, _ := internals.parse_protocol_string(protocol_name)
    fmt.println(protocol)
    fmt.println(protocol_name)
    zeroslice : ecdh.Public_Key
    initiator_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        true,
        nil,
        internals.GENERATE_KEYPAIR(protocol),
        internals.keypair_empty(protocol),
        zeroslice,
        zeroslice,
        protocol_name = protocol_name,
    )

    responder_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        false,
        nil,
        internals.GENERATE_KEYPAIR(protocol),
        internals.keypair_empty(protocol),
        zeroslice,
        zeroslice,
        protocol_name = protocol_name,
    )

    message, ic1, ic2, istatus := internals.handshakestate_write_message(&initiator_handshake_state, {})
    defer delete(message)

    rc1, rc2, rstatus := internals.handshakestate_read_message(&responder_handshake_state, message)

    message, rc1, rc2, rstatus = internals.handshakestate_write_message(&responder_handshake_state, {})

    ic1, ic2, istatus = internals.handshakestate_read_message(&initiator_handshake_state, message)

    message, ic1, ic2, istatus = internals.handshakestate_write_message(&initiator_handshake_state, {})
    
    rc1, rc2, rstatus = internals.handshakestate_read_message(&responder_handshake_state, message)

    assert(rc1 == ic1)
    assert(rc2 == ic2)

}
