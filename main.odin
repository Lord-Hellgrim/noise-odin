package noise

import "core:crypto/aead"
import "core:os/os2"
import "core:fmt"
import "core:crypto"
import "core:slice"
import "core:strings"
import "core:time"
import "core:net"

test_u64_from_slice :: proc() {
    le_num :u64 = 0x123456
    le_bytes := to_le_bytes(le_num)
    le_parsed := u64_from_le_slice(le_bytes[:])
    assert(le_num == le_parsed)


    be_num :u64 = 0x123456
    be_bytes := to_le_bytes(be_num)
    be_parsed := u64_from_le_slice(be_bytes[:])
    assert(be_num == be_parsed)
}

testing_copy_vs_zero_copy :: proc() {
    plaintext, _ := os2.read_entire_file("Noise_protocol_text.txt", context.allocator)
    
    backup := make([]u8, len(plaintext))
    copy_slice(backup, plaintext)

    tag : [16]u8

    ad : [32]u8

    key: [32]u8 = {1,2,3,4,5,6,7,8,9,0,11,12, 13, 14, 15, 16,
                   1,2,3,4,5,6,7,8,9,0,11,12, 13, 14, 15, 16}

    ctx : aead.Context
    iv := nonce_from_u64(5)
    crypto.rand_bytes(iv[:])

    stopwatch1 : time.Stopwatch
    time.stopwatch_start(&stopwatch1)
    aead.init(&ctx, aead.Algorithm.AES_GCM_256, key[:])
    aead.seal_ctx(&ctx, plaintext, tag[:], iv[:], ad[:], plaintext)

    ctx2 : aead.Context

    aead.init(&ctx2, aead.Algorithm.AES_GCM_256, key[:])
    if aead.open_ctx(&ctx2, plaintext, iv[:], ad[:], plaintext, tag[:]) {
        assert(slice.equal(backup, plaintext))
    }
    time.stopwatch_stop(&stopwatch1)
    
    
    fmt.println("Success!!")
    fmt.println(plaintext)
    fmt.println(stopwatch1._accumulation)

}

when ODIN_OS == .Linux {
    main :: proc() {
        address := net.parse_ip4_address("127.0.0.1")
        endpoint := net.Endpoint{address = address, port = 3001}
        listener := net.listen_tcp(address)
        connection, status := ESTABLISH_CONNECTION()
        
    
    }
} else when ODIN_OS == .Windows {
    main :: proc() {
            // k : [32]u8
            // n : u64 = 5
            // ad := str_to_slice("Double check me!")
            // unencrypted := str_to_slice("This is an unencrypted block of text that is longer than 128 bits!!!")
            // backup := slice.clone(unencrypted)
            // encrypted, enc_error := ENCRYPT(k, n, ad, unencrypted)
            // decrypted, dec_error := DECRYPT(k, n, ad, encrypted)
            // assert(slice.equal(backup, decrypted))

            testing_copy_vs_zero_copy()

            // fmt.println("SUCCESS!")

    }
}