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

when ODIN_OS == .Linux {
    main :: proc() {
        address, _ := net.parse_ip4_address("127.0.0.1")
        endpoint := net.Endpoint{address = address, port = 3001}
        listener, _ := net.listen_tcp(endpoint)
        
        fmt.println("Listening for connections...")
        new_socket, peer, _ := net.accept_tcp(listener)
        keypair := keypair_random(DEFAULT_PROTOCOL)
        connection, status := accept_connection_all_the_way(new_socket, peer, keypair)
        fmt.println("Connection status: %v", status)
        fmt.println(connection)
        data, connection_status := connection_receive(&connection)
        fmt.println("status of connection_receive: %v", connection_status)
        message := strings.clone_from_bytes(data)
        fmt.println(message)
    
    }
} else when ODIN_OS == .Windows {
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
            internals.TESTING_KEYPAIR_INITIATOR,
            internals.keypair_empty(protocol),
            zeroslice,
            zeroslice,
            protocol_name = internals.DEFAULT_PROTOCOL_NAME,
        )

        responder_handshake_state, _ := internals.handshakestate_Initialize(  // Should always have a valid protocol name due to previous if check
            false,
            nil,
            internals.TESTING_KEYPAIR_RESPONDER,
            internals.keypair_empty(protocol),
            zeroslice,
            zeroslice,
            protocol_name = internals.DEFAULT_PROTOCOL_NAME,
        )

        
        message, ic1, ic2, istatus := internals.handshakestate_write_message(&initiator_handshake_state, {})
        fmt.println(initiator_handshake_state.symmetricstate.cipherstate.k)
        
        rc1, rc2, rstatus := internals.handshakestate_read_message(&responder_handshake_state, message)
        fmt.println(responder_handshake_state.symmetricstate.cipherstate.k)
        
        message, rc1, rc2, rstatus = internals.handshakestate_write_message(&responder_handshake_state, {})
        fmt.println(responder_handshake_state.symmetricstate.cipherstate.k)

        ic1, ic2, istatus = internals.handshakestate_read_message(&initiator_handshake_state, message)
        fmt.println(initiator_handshake_state.symmetricstate.cipherstate.k)
        
        message, ic1, ic2, istatus = internals.handshakestate_write_message(&initiator_handshake_state, {})
        fmt.println(initiator_handshake_state.symmetricstate.cipherstate.k)
        
        rc1, rc2, rstatus = internals.handshakestate_read_message(&responder_handshake_state, message)
        fmt.println(responder_handshake_state.symmetricstate.cipherstate.k)
        
        fmt.println(istatus)
        fmt.println(rstatus)

        assert(istatus == .Handshake_Complete)
        assert(rstatus == .Handshake_Complete)

        fmt.println(rc1.k)
        fmt.println(rc2.k)
        fmt.println(ic1.k)
        fmt.println(ic2.k)


    }
}