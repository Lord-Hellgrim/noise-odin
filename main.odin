package noise

import "core:fmt"
import "core:net"
import "core:strings"
import "core:slice"
import "core:time"
import "core:os"

import "internals"

multi_return :: proc(a: int, b: int, c := 1, d := 2) -> int {
    return a+b+c+d
}

main :: proc() {
    test_message := make([]u8, 256)
    test_string, read_error := os.read_entire_file("Noise_protocol_text.txt", context.allocator)
    if read_error != os.General_Error.None {
        fmt.println(read_error)
        return
    }
    protocol := DEFAULT_PROTOCOL
    zeroslice : [internals.DHLEN]u8
    initiator_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        true,
        nil,
        internals.TEST_INI_KEYPAIR(DEFAULT_PROTOCOL),
        internals.keypair_empty(protocol),
        zeroslice,
        zeroslice,
        protocol_name = internals.DEFAULT_PROTOCOL_NAME,
    )

    responder_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
        false,
        nil,
        internals.TEST_RES_KEYPAIR(DEFAULT_PROTOCOL),
        internals.keypair_empty(DEFAULT_PROTOCOL),
        zeroslice,
        zeroslice,
        protocol_name = internals.DEFAULT_PROTOCOL_NAME,
    )

    
    message, ic1, ic2, istatus := internals.handshakestate_write_message(&initiator_handshake_state, {})
    
    rc1, rc2, rstatus := internals.handshakestate_read_message(&responder_handshake_state, message)

    message, rc1, rc2, rstatus = internals.handshakestate_write_message(&responder_handshake_state, {})

    ic1, ic2, istatus = internals.handshakestate_read_message(&initiator_handshake_state, message)

    message, ic1, ic2, istatus = internals.handshakestate_write_message(&initiator_handshake_state, {})
    
    rc1, rc2, rstatus = internals.handshakestate_read_message(&responder_handshake_state, message)
    
    // fmt.println(istatus)
    // fmt.println(rstatus)

    // assert(istatus == .Handshake_Complete)
    // assert(rstatus == .Handshake_Complete)

    fmt.println("rc1: ", rc1.k)
    fmt.println("rc2: ", rc2.k)
    fmt.println("ic1: ", ic1.k)
    fmt.println("ic2: ", ic2.k)


}
