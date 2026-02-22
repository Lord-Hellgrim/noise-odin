package test


import "core:testing"
import "core:os"
import "core:slice"
import "core:crypto"
import "core:crypto/x25519"
import "core:fmt"
import "core:log"

import "../../noise"
import "../../noise/internals"


@(test)
testing_encryption :: proc(t: ^testing.T) {
    test_bytes, read_error := os.read_entire_file("Noise_protocol_text.txt", context.allocator)

    backup_bytes := slice.clone(test_bytes)

    key := [32]u8{0..<32 = 1}

    ciphertext, error := internals.ENCRYPT(key, 1, {}, test_bytes, internals.DEFAULT_PROTOCOL)
    testing.expect(t, !slice.equal(ciphertext.main_body, backup_bytes))
    decrypted, status := internals.DECRYPT(key, 1, {}, ciphertext, internals.DEFAULT_PROTOCOL)
    testing.expect(t, slice.equal(decrypted, backup_bytes))
}

@(test)
testing_dh :: proc(t: ^testing.T) {
    private_key := [32]u8{0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 
        0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a}

    public_key : [32]u8;
    x25519.scalarmult_basepoint(public_key[:], private_key[:])
    testing.expect(t, public_key == {133, 32, 240, 9, 137, 48, 167, 84, 116, 139, 125, 220, 180, 62, 247, 90, 13, 191, 58, 13, 38, 56, 26, 244, 235, 164, 169, 142, 170, 155, 78, 106})
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