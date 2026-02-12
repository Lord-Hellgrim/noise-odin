package noise

import "core:crypto/aead"
import "core:os"
import "core:fmt"
import "core:crypto"
import "core:slice"
import "core:strings"
import "core:time"
import "core:net"


when ODIN_OS == .Linux {
    main :: proc() {
        address, _ := net.parse_ip4_address("127.0.0.1")
        endpoint := net.Endpoint{address = address, port = 3001}
        listener := net.listen_tcp(address)
        keypair := keypair_random()
        connection, status := ACCEPT_CONNECTION(listener, keypair)
        data := connection_receive(&connection)
        fmt.println(data)
    
    }
} else when ODIN_OS == .Windows {
    main :: proc() {
        message := make([]u8, 200)
        message = {3}
        connection, connection_error := initiate_connection("127.0.0.1:3001")
        fmt.println(connection_error)
        connection_send(&connection, message)

    }
}