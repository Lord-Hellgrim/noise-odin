package noise

import "core:fmt"
import "core:net"
import "core:strings"
import "core:slice"
import "core:time"


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
        message := "This is a message that is longer than 128 bytes. Definately longer than 128 bytes by now. I probably don't have to keep typing"
        message_bytes := slice.clone(transmute([]u8)message)
        connection, connection_error := initiate_connection_all_the_way("127.0.0.1:3001")
        fmt.println(connection_error)
        fmt.println(connection)
        send_status := connection_send(&connection, message_bytes)
        fmt.println(send_status)
        time.sleep(time.Second)
    }
}