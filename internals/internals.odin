package internals

import "core:crypto"
import "core:crypto/hash"
import "core:crypto/aead"
import "core:crypto/ecdh"

import "core:slice"
import "core:strings"

import "core:mem"

import "core:fmt"


MAX_PACKET_SIZE :: 65535;

NoiseStatus :: enum {
    Ok,
    Decryption_failed_to_authenticate,
    Protocol_could_not_be_parsed,
    Pending_Handshake,
    Handshake_Complete,
    rs_not_set_for_s_pre_message,
    out_of_memory,
    invalid_message_passed_to_read_message,
    tried_to_encrypt_message_bigger_than_MAX_PACKET_SIZE,
}

DhType :: enum u8 {
    x25519,
    x448,
}

CipherType :: enum u8 {
    AES256gcm,
    ChaChaPoly,
}

HashType :: enum u8 {
    SHA256,
    SHA512,
    Blake2s,
    Blake2b,
}

MAX_DHLEN :: 56
MAX_HASHLEN :: 64
MAX_BLOCKLEN :: 128

DhLen :: proc(dh: ecdh.Curve) -> int {
    #partial switch dh {
        case .X25519: return 32
        case .X448: return 56
    }
    return 0
}

HashLen :: proc(hash: HashType) -> int {
    switch hash {
        case .SHA256: return 32
        case .SHA512: return 64
        case .Blake2s: return 32
        case .Blake2b: return 64
    }
    return 0
}

BlockLen ::  proc(hash: HashType) -> int {
    switch hash {
        case .SHA256: return 64
        case .SHA512: return 128
        case .Blake2s: return 64
        case .Blake2b: return 128
    }
    return 0
}

/// The HMAC padding strings
@(rodata)
IPAD : [MAX_BLOCKLEN]u8 = {0..<MAX_BLOCKLEN = 0x36}
@(rodata)
OPAD : [MAX_BLOCKLEN]u8 = {0..<MAX_BLOCKLEN = 0x5c} 


// Supported handshake patterns will be listed here.
HandshakePattern :: enum {
    // One way patterns
    N,
    K,
    X,
    // Fundamental patterns
    XX,
    NK,
    NN,
    KN,
    KK,
    NX,
    KX,
    XN,
    IN,
    XK,
    IK,
    IX,
    // psk patterns
    NNpsk0,
    NNpsk2,
    NKpsk0,
    NKpsk2,
    NXpsk2,
    XNpsk3,
    XKpsk3,
    XXpsk3,
    KNpsk0,
    KNpsk2,
    KKpsk0,
    KKpsk2,
    KXpsk2,
    INpsk1,
    INpsk2,
    IKpsk1,
    IKpsk2,
    IXpsk2,
}

MessagePattern :: struct {
    pre_messages : []PreToken,
    messages : [][]Token,
}

Protocol :: struct {
    dh: ecdh.Curve,
    handshake_pattern: HandshakePattern,
    cipher: CipherType,
    hash: HashType,
}

DEFAULT_PROTOCOL_NAME :: "Noise_XX_25519_AESGCM_SHA256";

DEFAULT_PROTOCOL :: Protocol {
    handshake_pattern = .XX,
    dh = .X25519,
    cipher = .AES256gcm,
    hash = .SHA256
}

ERROR_PROTOCOL :: Protocol {
    handshake_pattern = nil,
    dh = nil,
    cipher = nil,
    hash = nil
}


parse_protocol_string :: proc (protocol_string: string) -> (Protocol, NoiseStatus) {
    
    if len(protocol_string) > 255 {
        return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    protocol : Protocol
    underline : [4]u8

    count := 0
    for i in 0..<len(protocol_string) {
        if protocol_string[i] == '_' {
            underline[count] = u8(i)
            count += 1
        }
    }

    if count != 4 {
        return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch protocol_string[underline[0]+1 : underline[1]] {
        case "N" : protocol.handshake_pattern = .N
        case "K" : protocol.handshake_pattern = .K
        case "X" : protocol.handshake_pattern = .X
        case "XX": protocol.handshake_pattern = .XX
        case "NK": protocol.handshake_pattern = .NK
        case "NN": protocol.handshake_pattern = .NN
        case "KN": protocol.handshake_pattern = .KN
        case "KK": protocol.handshake_pattern = .KK
        case "NX": protocol.handshake_pattern = .NX
        case "KX": protocol.handshake_pattern = .KX
        case "XN": protocol.handshake_pattern = .XN
        case "IN": protocol.handshake_pattern = .IN
        case "XK": protocol.handshake_pattern = .XK
        case "IK": protocol.handshake_pattern = .IK
        case "IX": protocol.handshake_pattern = .IX
        case "NNpsk0": protocol.handshake_pattern = .NNpsk0
        case "NNpsk2": protocol.handshake_pattern = .NNpsk2
        case "NKpsk0": protocol.handshake_pattern = .NKpsk0
        case "NKpsk2": protocol.handshake_pattern = .NKpsk2
        case "NXpsk2": protocol.handshake_pattern = .NXpsk2
        case "XNpsk3": protocol.handshake_pattern = .XNpsk3
        case "XKpsk3": protocol.handshake_pattern = .XKpsk3
        case "XXpsk3": protocol.handshake_pattern = .XXpsk3
        case "KNpsk0": protocol.handshake_pattern = .KNpsk0
        case "KNpsk2": protocol.handshake_pattern = .KNpsk2
        case "KKpsk0": protocol.handshake_pattern = .KKpsk0
        case "KKpsk2": protocol.handshake_pattern = .KKpsk2
        case "KXpsk2": protocol.handshake_pattern = .KXpsk2
        case "INpsk1": protocol.handshake_pattern = .INpsk1
        case "INpsk2": protocol.handshake_pattern = .INpsk2
        case "IKpsk1": protocol.handshake_pattern = .IKpsk1
        case "IKpsk2": protocol.handshake_pattern = .IKpsk2
        case "IXpsk2": protocol.handshake_pattern = .IXpsk2
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch protocol_string[underline[1]+1 : underline[2]] {
        case "25519": protocol.dh = .X25519
        case "448": protocol.dh = .X448
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch protocol_string[underline[2]+1 : underline[3]] {
        case "AESGCM": protocol.cipher = .AES256gcm
        case "ChaChaPoly": protocol.cipher = .ChaChaPoly
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch protocol_string[underline[3]+1 : ] {
        case "SHA512": protocol.hash = .SHA512
        case "SHA256": protocol.hash = .SHA256
        case "Blake2s": protocol.hash = .Blake2s
        case "Blake2b": protocol.hash = .Blake2b
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    return protocol, .Ok
}

map_pattern :: proc(p: HandshakePattern) -> MessagePattern {
    message_pattern : MessagePattern
    switch p {
        case .N : message_pattern = PATTERN_N
        case .K : message_pattern = PATTERN_K
        case .X : message_pattern = PATTERN_X
        case .XX: message_pattern = PATTERN_XX
        case .NK: message_pattern = PATTERN_NK
        case .NN: message_pattern = PATTERN_NN
        case .KN: message_pattern = PATTERN_KN
        case .KK: message_pattern = PATTERN_KK
        case .NX: message_pattern = PATTERN_NX
        case .KX: message_pattern = PATTERN_KX
        case .XN: message_pattern = PATTERN_XN
        case .IN: message_pattern = PATTERN_IN
        case .XK: message_pattern = PATTERN_XK
        case .IK: message_pattern = PATTERN_IK
        case .IX: message_pattern = PATTERN_IX
        case .NNpsk0: message_pattern = PATTERN_NNpsk0
        case .NNpsk2: message_pattern = PATTERN_NNpsk2
        case .NKpsk0: message_pattern = PATTERN_NKpsk0
        case .NKpsk2: message_pattern = PATTERN_NKpsk2
        case .NXpsk2: message_pattern = PATTERN_NXpsk2
        case .XNpsk3: message_pattern = PATTERN_XNpsk3
        case .XKpsk3: message_pattern = PATTERN_XKpsk3
        case .XXpsk3: message_pattern = PATTERN_XXpsk3
        case .KNpsk0: message_pattern = PATTERN_KNpsk0
        case .KNpsk2: message_pattern = PATTERN_KNpsk2
        case .KKpsk0: message_pattern = PATTERN_KKpsk0
        case .KKpsk2: message_pattern = PATTERN_KKpsk2
        case .KXpsk2: message_pattern = PATTERN_KXpsk2
        case .INpsk1: message_pattern = PATTERN_INpsk1
        case .INpsk2: message_pattern = PATTERN_INpsk2
        case .IKpsk1: message_pattern = PATTERN_IKpsk1
        case .IKpsk2: message_pattern = PATTERN_IKpsk2
        case .IXpsk2: message_pattern = PATTERN_IXpsk2
        }
    return message_pattern
}

dhtype_to_curve :: proc(dh: DhType) -> ecdh.Curve {
    crv : ecdh.Curve
    switch dh {
        case .x25519:   crv = .X25519
        case .x448:     crv = .X448
    }
    return crv
}

// This function will panic if passed an unsupported dh curve
protocol_text_from_struct :: proc(protocol: Protocol, allocator := context.allocator) -> string {
    s := strings.builder_make()

    hp := protocol.handshake_pattern
    dh : string
    #partial switch protocol.dh {
        case .X25519: dh = "25519"
        case .X448: dh = "448"
        case .Invalid: panic("Unsupported DH curve passed to printer function")    
    }

    c : string
    switch protocol.cipher {
        case .AES256gcm: c = "AESGCM"
        case .ChaChaPoly: c = "ChaChaPoly"
    }

    h := protocol.hash
    
    fmt.sbprintf(&s, "Noise_%v_%v_%v_%v", hp, dh, c, h)

    return strings.to_string(s)
}

/// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements. 
/// A public_key represents an encoding of a DH public key into a byte sequence of length DHLEN. 
/// The public_key encoding details are specific to each set of DH functions.
GENERATE_KEYPAIR :: proc(protocol: Protocol) -> KeyPair {
    return keypair_random(protocol)
}

KeyPair :: struct {
    public: ecdh.Public_Key,
    private: ecdh.Private_Key,
}

keypair_random :: proc(protocol: Protocol) -> KeyPair {
    curve : ecdh.Curve
    #partial switch protocol.dh {
        case .X25519:   curve = .X25519
        case .X448:     curve = .X448
        case: panic("unsupported DH curve in protocol")
    }
    private : ecdh.Private_Key
    public : ecdh.Public_Key
    ecdh.private_key_generate(&private, curve)
    ecdh.public_key_set_priv(&public, &private)
    return KeyPair{
        public = public,
        private = private,
    }
}

/// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key 
/// and returns an output sequence of bytes of length DHLEN. 
/// For security, the Gap-DH problem based on this function must be unsolvable by any practical cryptanalytic adversary [2].

/// The public_key either encodes some value which is a generator in a large prime-order group 
/// (which value may have multiple equivalent encodings), or is an invalid value. 
/// Implementations must handle invalid public keys either by returning some output which is purely a function of the public key 
/// and does not depend on the private key, or by signaling an error to the caller. 
/// The DH function may define more specific rules for handling invalid values.
/// DEV NOTE: This function does not return any error but simply panics on invalid input
///             Invalid input signals an implementation error which should be caught in testing
DH :: proc(key_pair: ^KeyPair, their_public_key: ^ecdh.Public_Key, allocator: mem.Allocator) -> []u8 {

    dst := make([]u8, DhLen(key_pair.private._curve), )
    success := ecdh.ecdh(&key_pair.private, their_public_key, dst[:])

    if !success {
        s: strings.Builder
        fmt.sbprintfln(&s, "ecdh failed. Inputs were:\nprivate_key: %v\npublic_key: %v", key_pair.private, their_public_key)
        panic(strings.to_string(s))
    }

    return dst
}

// Keeps track of the 16 byte tag without relying on the input plaintext having a spare 16 byte capacity
CryptoBuffer :: struct {
    main_body: []u8,
    tag: [16]u8,
}

/// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique for the key k. 
/// Returns the ciphertext. Encryption must be done with an "AEAD" encryption mode with the associated data ad 
/// (using the terminology from [1]) and returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication data. 
/// The entire ciphertext must be indistinguishable from random if the key is secret 
/// (note that this is an additional requirement that isn't necessarily met by all AEAD schemes).
/// DEV NOTE: This function overwrites the plaintext with the cipertext. If you want to preserve the plaintext
///             it must be copied to a separate buffer before calling this function
ENCRYPT :: proc(k: [32]u8, n: u64, ad: []u8, plaintext: []u8, protocol: Protocol) -> (CryptoBuffer, NoiseStatus) {
    k := k
    plaintext := plaintext

    tag : [16]u8
    ciphertext : CryptoBuffer
    ctx : aead.Context

    iv := nonce_from_u64(n)

    algo : aead.Algorithm
    switch protocol.cipher {
        case .AES256gcm: algo = .AES_GCM_256
        case .ChaChaPoly: algo = .CHACHA20POLY1305
    }
    
    aead.init(&ctx, algo, k[:])
    aead.seal_ctx(&ctx, plaintext, tag[:], iv[:], ad, plaintext)
    
    ciphertext.tag = tag
    ciphertext.main_body = plaintext

    return ciphertext, .Ok
}

/// Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n,
/// and associated data ad. Returns the plaintext, unless authentication fails, 
/// in which case an error is signaled to the caller.
/// DEV NOTE: This function overwrites the main_body of the ciphertext with the plaintext.
DECRYPT :: proc(k: [32]u8, n: u64, ad: []u8, ciphertext: CryptoBuffer, protocol: Protocol) -> ([]u8, NoiseStatus) {
    k := k

    ctx : aead.Context
    iv := nonce_from_u64(n)
    tag := ciphertext.tag

    algo : aead.Algorithm
    switch protocol.cipher {
        case .AES256gcm: algo = .AES_GCM_256
        case .ChaChaPoly: algo = .CHACHA20POLY1305
    }

    aead.init(&ctx, algo, k[:])
    if aead.open_ctx(&ctx, ciphertext.main_body, iv[:], ad, ciphertext.main_body, tag[:]) {
        return ciphertext.main_body, .Ok
    } else {
        return nil, .Decryption_failed_to_authenticate
    }
}

/// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of HASHLEN bytes.
HASH :: proc(allocator: mem.Allocator, protocol: Protocol, data: ..[]u8) -> []u8 {

    algo : hash.Algorithm
    switch protocol.hash {
        case .SHA256: algo = .SHA256
        case .SHA512: algo = .SHA512
        case .Blake2s: algo = .BLAKE2S
        case .Blake2b: algo = .BLAKE2B
    }
    
    ctx : hash.Context
    hash.init(&ctx, algo)
    for datum in data {
        hash.update(&ctx, datum)
    }
    result, allocerror := make([]u8, HashLen(protocol.hash), allocator)
    hash.final(&ctx, result)

    return result
}

/// Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not specifically defined for some set of cipher functions, 
/// then it defaults to returning the first 32 bytes from ENCRYPT(k,    maxnonce, zerolen, zeros), 
/// where maxnonce equals (2^64)-1, zerolen is a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
REKEY :: proc(k: [32]u8, protocol: Protocol) -> [32]u8 {
    zeros : [32]u8 
    //         1  2  3  4  5  6  7  8 
    n :u64 = 0xFF_FF_FF_FF_FF_FF_FF_FF
    ENCRYPT(k, n, nil, zeros[:], protocol)
    new_key : [32]u8
    copy(new_key[:], zeros[:])
    return new_key
}

// HMAC-HASH(key, data): Applies HMAC from http://www.ietf.org/rfc/rfc5869.txt using the HASH() function. 
// This function is only called as part of HKDF(), below
HMAC_HASH :: proc(K: []u8, text: []u8, protocol: Protocol, allocator: mem.Allocator) -> []u8 {

    new_K := make([]u8, BlockLen(protocol.hash), allocator)
    copy(new_K, K)
    
    temp1 := array_xor(new_K, IPAD[ : BlockLen(protocol.hash)], allocator)
    temp2 := array_xor(new_K, OPAD[ : BlockLen(protocol.hash)], allocator)

    inner := HASH(allocator, protocol, temp1[:], text)
    outer := HASH(allocator, protocol, temp2[:], inner[:])
    return outer
}

/// Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte sequence with length either zero bytes, 
/// 32 bytes, or DHLEN bytes. Returns a pair or triple of byte sequences each of length HASHLEN, depending on whether num_outputs is two or three:
///  - Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
///  - Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
///  - Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
///  - If num_outputs == 2 then returns the pair (output1, output2).
///  - Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
///  - Returns the triple (output1, output2, output3).
///  - Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in length. Also note that the HKDF() function is simply HKDF from [4] with the chaining_key as HKDF salt, and zero-length HKDF info.
HKDF :: proc(chaining_key: []u8, input_key_material: []u8, protocol: Protocol, allocator: mem.Allocator) -> ([]u8, []u8, []u8) {
    assert(len(input_key_material) == 0 || len(input_key_material) == 32 || len(input_key_material) == DhLen(protocol.dh))
    temp_key := HMAC_HASH(chaining_key, input_key_material, protocol, allocator)
    output1 :=  HMAC_HASH(temp_key[:], {0x01}, protocol, allocator)
    temp_bytes_2 := concat_bytes(output1[:], {0x02}, allocator)
    output2 :=  HMAC_HASH(temp_key[:], temp_bytes_2 , protocol, allocator)
    
    temp_bytes_3 := concat_bytes(output2[:], {0x03}, allocator)
    output3 :=  HMAC_HASH(temp_key[:], temp_bytes_3, protocol, allocator)

    return output1, output2, output3
} 

PreToken :: enum {
    res_s,
    ini_s,
}

Token :: enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
}

is_psk_pattern :: proc(pattern: MessagePattern) -> bool {
    for p in pattern.messages {
        for m in p {
            if m == .psk {
                return true
            }
        }
    }

    return false
}

CipherState :: struct {
    protocol: Protocol,
    k: [32]u8,
    n: u64,
}

SymmetricState :: struct {
    cipherstate: CipherState,
    ck: []u8,
    h: []u8,
    allocator: mem.Allocator,
    backing: ^mem.Dynamic_Arena,
}

HandshakeState :: struct {
    symmetricstate: SymmetricState,
    s: Maybe(KeyPair),
    e: Maybe(KeyPair), 
    rs: Maybe(ecdh.Public_Key),
    re: Maybe(ecdh.Public_Key),
    initiator: bool,
    message_patterns: MessagePattern,
    current_pattern: int,
    psk: [32]u8,
}

get_curve :: proc(handshake_state: ^HandshakeState) -> ecdh.Curve {
    return handshake_state.symmetricstate.cipherstate.protocol.dh
}

/// Sets k = key. Sets n = 0.
cipherstate_InitializeKey :: proc(key: [32]u8, protocol: Protocol) -> CipherState {
    return CipherState {
        protocol = protocol,
        k = key,
        n = 0,
    }
}

/// Returns true if k is non-empty, false otherwise.
cipherstate_HasKey :: proc(self: ^CipherState) -> bool {
    zeroslice : [32]u8
    if slice.equal(self.k[:], zeroslice[:]) {
        return false
    } else {
        return true
    }
}

///If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
cipherstate_EncryptWithAd :: proc(self: ^CipherState, ad: []u8, plaintext: []u8) -> (CryptoBuffer, NoiseStatus) {

    if len(plaintext) > MAX_PACKET_SIZE - 16 {
        return {}, .tried_to_encrypt_message_bigger_than_MAX_PACKET_SIZE
    }

    if cipherstate_HasKey(self) {
        temp, encrypt_error := ENCRYPT(self.k, self.n, ad, plaintext, self.protocol)
        if encrypt_error != .Ok {
            return temp, encrypt_error
        }
        self.n += 1;
        return temp, .Ok
    } else {
        return CryptoBuffer {main_body = plaintext}, .Ok
    }
}

/// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. 
/// If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
cipherstate_DecryptWithAd :: proc(self: ^CipherState, ad: []u8, ciphertext: CryptoBuffer) -> ([]u8, NoiseStatus) {

    if cipherstate_HasKey(self) {
        plaintext, decrypt_error := DECRYPT(self.k, self.n, ad, ciphertext, self.protocol)
        if decrypt_error != .Ok {
            return plaintext, decrypt_error
        }
        self.n += 1;
        return plaintext, .Ok
    } else {
        return ciphertext.main_body, .Ok
    }
}

/// Sets k = REKEY(k).
cipherstate_Rekey :: proc(self: ^CipherState) {
    if cipherstate_HasKey(self) {
        self.k = REKEY(self.k, self.protocol)
    }
}

/// : Takes an arbitrary-length protocol_name byte sequence (see Section 8). Executes the following steps:
/// If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes. 
/// Otherwise sets h = HASH(protocol_name).
/// Sets ck = h.
/// Calls InitializeKey(empty).
symmetricstate_initialize_symmetric :: proc(protocol_name: string) -> (SymmetricState, NoiseStatus) {
    zeroslice : [32]u8

    backing := new(mem.Dynamic_Arena)
    mem.dynamic_arena_init(backing)
    allocator := mem.dynamic_arena_allocator(backing)

    protocol, parse_error := parse_protocol_string(protocol_name)
    if parse_error == .Protocol_could_not_be_parsed {
        return SymmetricState{}, .Protocol_could_not_be_parsed
    }

    if len(protocol_name) < HashLen(protocol.hash) {
        protocol_name_bytes := make([]u8, HashLen(protocol.hash), allocator)
        copy(protocol_name_bytes[:], protocol_name[:])
        h := HASH(allocator, protocol, protocol_name_bytes[:])
        
        cipherstate := cipherstate_InitializeKey(zeroslice, protocol)
        return SymmetricState {cipherstate = cipherstate, ck = h, h = h, allocator = allocator, backing = backing}, .Ok
    } else {
        h := HASH(allocator, protocol, transmute([]u8)protocol_name)
        cipherstate := cipherstate_InitializeKey(zeroslice, protocol)
        return SymmetricState {cipherstate = cipherstate, ck = h, h = h, allocator = allocator, backing = backing}, .Ok
    }
}

/// Sets h = HASH(h || data).
symmetricstate_MixHash :: proc(self: ^SymmetricState, data: ..[]u8, ) {
    if len(data) == 1 {
        self.h = HASH(self.allocator, self.cipherstate.protocol, self.h, data[0])
    } else if len(data) == 2 {
        self.h = HASH(self.allocator, self.cipherstate.protocol, self.h, data[0], data[1])
    } else if len(data) == 3 {
        self.h = HASH(self.allocator, self.cipherstate.protocol, self.h, data[0], data[1], data[2])
    }
}

///     : Executes the following steps:
/// Sets ck, temp_k = HKDF(ck, input_key_material, 2).
/// If HASHLEN is 64, then truncates temp_k to 32 bytes.
/// Calls InitializeKey(temp_k).
symmetricstate_MixKey :: proc(self: ^SymmetricState, input_key_material: []u8) {
    input_key_material := input_key_material
    ck, temp_k, _ := HKDF(self.ck[:], input_key_material[:], self.cipherstate.protocol, self.allocator)
    self.ck = ck
    self.cipherstate = cipherstate_InitializeKey(array32_from_slice(temp_k[:]), self.cipherstate.protocol)
}

/// This function is used for handling pre-shared symmetric keys, as described in Section 9. It executes the following steps:
/// Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
/// Calls MixHash(temp_h).
/// If HASHLEN is 64, then truncates temp_k to 32 bytes.
/// Calls InitializeKey(temp_k).
symmetricstate_MixKeyAndHash :: proc(self: ^SymmetricState, input_key_material: []u8) {
    input_key_material := input_key_material
    ck, temp_h, temp_k := HKDF(self.ck[:], input_key_material[:], self.cipherstate.protocol, self.allocator)
    self.ck = ck
    symmetricstate_MixHash(self, temp_h[:])
    self.cipherstate = cipherstate_InitializeKey(array32_from_slice(temp_k[:]), self.cipherstate.protocol);
}

/// Returns h. This function should only be called at the end of a handshake, i.e. after the Split() function has been called. 
/// This function is used for channel binding, as described in Section 11.2
symmetricstate_GetHandshakeHash :: proc(self: SymmetricState) -> []u8 {
    if true {
        panic("GetHandshakeHash is not a supported function in this implementation")
    }
    return self.h
}

/// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. 
/// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
symmetricstate_EncryptAndHash :: proc(self:  ^SymmetricState, plaintext: []u8) -> (CryptoBuffer, NoiseStatus) {
    ciphertext, status := cipherstate_EncryptWithAd(&self.cipherstate, self.h[:HashLen(self.cipherstate.protocol.hash)], plaintext)
    symmetricstate_MixHash(self, ciphertext.main_body, ciphertext.tag[:])
    return ciphertext, status
}

/// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. 
/// Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
symmetricstate_DecryptAndHash :: proc(self:  ^SymmetricState, ciphertext: CryptoBuffer) -> ([]u8, NoiseStatus) {
    ciphertext := ciphertext
    hash_text := CryptoBuffer {
        main_body = slice.clone(ciphertext.main_body, self.allocator),
        tag = ciphertext.tag,
    }
    result, decrypt_error := cipherstate_DecryptWithAd(&self.cipherstate, self.h[:HashLen(self.cipherstate.protocol.hash)], ciphertext)
    if decrypt_error != .Ok {
        return nil, decrypt_error
    }
    symmetricstate_MixHash(self, hash_text.main_body, hash_text.tag[:])
    return result, .Ok
}

/// Returns a pair of CipherState objects for encrypting transport messages. Executes the following steps, where zerolen is a zero-length byte sequence:
/// Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
/// If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
/// Creates two new CipherState objects c1 and c2.
/// Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
/// Returns the pair (c1, c2).
symmetricstate_Split :: proc(self: ^SymmetricState) -> (CipherState, CipherState) {
    temp_k1, temp_k2, _ := HKDF(self.ck[:], nil, self.cipherstate.protocol, self.allocator)
    c1 := cipherstate_InitializeKey(array32_from_slice(temp_k1[:]), self.cipherstate.protocol)
    c2 := cipherstate_InitializeKey(array32_from_slice(temp_k2[:]), self.cipherstate.protocol)
    return c1, c2
}

/// : Takes a valid handshake_pattern (see Section 7) and an initiator boolean specifying this party's role as either initiator or responder.
/// Takes a prologue byte sequence which may be zero-length, or which may contain context information that both parties want to confirm is identical 
/// (see Section 6).

/// Takes a set of DH key pairs (s, e) and public keys (rs, re) for initializing local variables, any of which may be empty. 
/// Public keys are only passed in if the handshake_pattern uses pre-messages (see Section 7). The ephemeral values (e, re) are typically left empty, 
/// since they are created and exchanged during the handshake; but there are exceptions (see Section 10).

/// Performs the following steps:

/// Derives a protocol_name byte sequence by combining the names for the handshake pattern and crypto functions, as specified in Section 8. 
/// Calls InitializeSymmetric(protocol_name).

/// Calls MixHash(prologue).

/// Sets the initiator, s, e, rs, and re variables to the corresponding arguments.

/// Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, 
/// with the specified public key as input (see Section 7 for an explanation of pre-messages). 
/// If both initiator and responder have pre-messages, the initiator's public keys are hashed first. 
/// If multiple public keys are listed in either party's pre-message, the public keys are hashed in the order that they are listed.

/// Sets message_patterns to the message patterns from handshake_pattern.
handshakestate_initialize :: proc(
    initiator: bool,
    prologue: []u8,
    s: Maybe(KeyPair),
    e: Maybe(KeyPair),
    rs: Maybe(ecdh.Public_Key),
    re: Maybe(ecdh.Public_Key),
    protocol_name := DEFAULT_PROTOCOL_NAME,
    psk : [32]u8 = 0,
) -> (HandshakeState, NoiseStatus) {

    s  := s
    rs := rs
    re := re

    
    symmetricstate, status := symmetricstate_initialize_symmetric(protocol_name)
    if status == .Protocol_could_not_be_parsed {
        return HandshakeState{}, status
    }

    message_pattern := map_pattern(symmetricstate.cipherstate.protocol.handshake_pattern)

    if message_pattern.pre_messages != nil {
        if initiator {
            if slice.contains(message_pattern.pre_messages, PreToken.res_s) {
                if rs == nil {
                    return {}, .rs_not_set_for_s_pre_message
                }
            }
        } else {
            if slice.contains(message_pattern.pre_messages, PreToken.ini_s) {
                if rs == nil {
                    return {}, .rs_not_set_for_s_pre_message
                }
            }
        }
    } else {
        rs = nil
        re = nil
    }

    symmetricstate_MixHash(&symmetricstate, prologue)

    if message_pattern.pre_messages != nil {
        if initiator {
            if slice.contains(message_pattern.pre_messages, PreToken.ini_s) {
                dst : [MAX_DHLEN]u8
                temp_s := s.?
                ecdh.public_key_bytes(&temp_s.public, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
                symmetricstate_MixHash(&symmetricstate, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
            }
            if slice.contains(message_pattern.pre_messages, PreToken.res_s) {
                dst : [MAX_DHLEN]u8
                temp_rs := rs.?
                ecdh.public_key_bytes(&temp_rs, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
                symmetricstate_MixHash(&symmetricstate, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
            }
        } else {
            if slice.contains(message_pattern.pre_messages, PreToken.ini_s) {
                dst : [MAX_DHLEN]u8
                temp_rs := rs.?
                ecdh.public_key_bytes(&temp_rs, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
                symmetricstate_MixHash(&symmetricstate, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
            }   
            if slice.contains(message_pattern.pre_messages, PreToken.res_s) {
                dst : [MAX_DHLEN]u8
                temp_s := s.?
                ecdh.public_key_bytes(&temp_s.public, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
                symmetricstate_MixHash(&symmetricstate, dst[:DhLen(symmetricstate.cipherstate.protocol.dh)])
            }
        }
    }

    if s == nil {
        s = GENERATE_KEYPAIR(symmetricstate.cipherstate.protocol)
    }

    output := HandshakeState {
        symmetricstate = symmetricstate,
        s = s,
        e = e,
        rs = rs,
        re = re,
        initiator = initiator,
        message_patterns = message_pattern,
        current_pattern = 0,
        psk = psk,
    };

    return output, .Ok
}

print_handshakestate :: proc(hs: HandshakeState) {
    fmt.println(hs.symmetricstate.cipherstate.protocol)
    fmt.println("Initiator: ", hs.initiator)
    if hs.e == nil {
        fmt.println("hs.e = nil")
    } else {
        fmt.println("hs.e = SET")
    }
    if hs.s == nil {
        fmt.println("hs.s = nil")
    } else {
        fmt.println("hs.s = SET")
    }
    if hs.re == nil {
        fmt.println("hs.re = nil")
    } else {
        fmt.println("hs.re = SET")
    }
    if hs.rs == nil {
        fmt.println("hs.rs = nil")
    } else {
        fmt.println("hs.rs = SET")
    }
}

handshakestate_destroy :: proc(state: ^HandshakeState) {
    free_all(state.symmetricstate.allocator)
    mem.dynamic_arena_destroy(state.symmetricstate.backing)
}

/// Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into. 
/// Performs the following steps, aborting if any EncryptAndHash() call returns an error:

/// Fetches and deletes the next message pattern from message_patterns, 
/// then sequentially processes each token from the message pattern:

/// For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key).
/// For "s": Appends EncryptAndHash(s.public_key) to the buffer.
/// For "ee": Calls MixKey(DH(e, re)).
/// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
/// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
/// For "ss": Calls MixKey(DH(s, rs)).

/// Appends EncryptAndHash(payload) to the buffer.

/// If there are no more message patterns returns two new CipherState objects by calling Split().
handshakestate_write_message :: proc(self: ^HandshakeState, payload: []u8, allocator := context.allocator) -> ([]u8, CipherState, CipherState, NoiseStatus) {
    // fmt.println("WRITE MESSAGE")
    message_buffer := make([dynamic]u8, allocator)
    pattern := self.message_patterns.messages[self.current_pattern]
    self.current_pattern += 1;
    for token in pattern {
        // fmt.println("token: ", token)
        switch token {

            case .e: {
                self.e = GENERATE_KEYPAIR(self.symmetricstate.cipherstate.protocol)
                e_public, allocerror := make([]u8, DhLen(get_curve(self)), self.symmetricstate.allocator)
                if allocerror == .Out_Of_Memory {
                    fmt.eprintln("OOM")
                    return {}, {},{}, .out_of_memory
                }
                switch &e in self.e {
                    case KeyPair: {
                        ecdh.public_key_bytes(&e.public, e_public)
                    }
                    case nil: panic("There must be a bug in the compiler. e is generated a few lines before this check")
                }
                assert(len(e_public) == DhLen(get_curve(self)))
                elems_added, append_error := append(&message_buffer, ..e_public)
                if append_error == .Out_Of_Memory {
                    fmt.eprintln("OOM")
                    return {}, {},{}, .out_of_memory
                }
                symmetricstate_MixHash(&self.symmetricstate, e_public)
                if is_psk_pattern(self.message_patterns) {
                    symmetricstate_MixKey(&self.symmetricstate, e_public)
                }
            }

            case .s: {
                dst := make([]u8, DhLen(get_curve(self)), self.symmetricstate.allocator)
                ecdh.public_key_bytes(&unwrap(self.s).public, dst)
                temp, status := symmetricstate_EncryptAndHash(&self.symmetricstate, dst)
                if status != .Ok {
                    return {},{}, {}, status
                }
                
                _, append_error := append(&message_buffer, ..temp.main_body)
                if cipherstate_HasKey(&self.symmetricstate.cipherstate) {
                    _, append_error = append(&message_buffer, ..temp.tag[:])
                }
                if append_error == .Out_Of_Memory {
                    fmt.eprintln("OOM")
                    return {}, {},{}, .out_of_memory
                }
            }

            case .ee: {
                dh := DH(&self.e.?, &self.re.?, self.symmetricstate.allocator)
                symmetricstate_MixKey(&self.symmetricstate, dh)
            }

            case .es: {
                if self.initiator {
                    dh := DH(&self.e.?, &self.rs.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh)
                } else {
                    dh := DH(&self.s.?, &self.re.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh)
                }
            }
            
            case .se: {
                if self.initiator {
                    dh := DH(&self.s.?, &self.re.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh)
                } else {
                    dh := DH(&self.e.?, &self.rs.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh)
                    
                }
            }
            
            case .ss: {
                dh := DH(&self.s.?, &self.rs.?, self.symmetricstate.allocator)
                symmetricstate_MixKey(&self.symmetricstate, dh)
            }

            case .psk: {
                symmetricstate_MixKeyAndHash(&self.symmetricstate, self.psk[:])
            }
        };
    }

    if len(payload) != 0 {
        encrypted_payload, status := symmetricstate_EncryptAndHash(&self.symmetricstate, payload)
        if status != .Ok {
            return {},{},{}, status
        }
        append(&message_buffer, ..encrypted_payload.main_body)
        elems_added, append_error := append(&message_buffer, ..encrypted_payload.tag[:])
        if append_error == .Out_Of_Memory {
            return {}, {},{}, .out_of_memory
        }
    }
    
    if self.current_pattern == len(self.message_patterns.messages) {
        c1, c2 := symmetricstate_Split(&self.symmetricstate)
        self.current_pattern = 0
        free_all(self.symmetricstate.allocator)
        return message_buffer[:], c1, c2, .Handshake_Complete
    } else {
        return message_buffer[:], {}, {}, .Pending_Handshake
    }
}

/// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into. 
/// Performs the following steps, aborting if any DecryptAndHash() call returns an error:

/// Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:

/// For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
/// For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. 
///     Sets rs (which must be empty) to DecryptAndHash(temp).
/// For "ee": Calls MixKey(DH(e, re)).
/// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
/// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
/// For "ss": Calls MixKey(DH(s, rs)).

/// Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.

/// If there are no more message patterns returns two new CipherState objects by calling Split().
handshakestate_read_message :: proc(self: ^HandshakeState, message: []u8)  -> ([]u8, CipherState, CipherState, NoiseStatus) {
    // fmt.println("READ MESSAGE")
    if len(message) < 32 {
        return {},{},{}, .invalid_message_passed_to_read_message
    }
    pattern := self.message_patterns.messages[self.current_pattern]
    self.current_pattern += 1
    message_cursor := 0
    for token in pattern {
        // fmt.println("token: ", token)
        switch token {
            case .e: {
                re := make([]u8, DhLen(get_curve(self)), self.symmetricstate.allocator)
                copy(re[:], message[message_cursor : message_cursor + DhLen(get_curve(self))])
                message_cursor += DhLen(get_curve(self))
                switch &self_re in self.re {
                    case nil: {
                        temp2 : ecdh.Public_Key
                        ecdh.public_key_set_bytes(&temp2, get_curve(self), re)
                        self.re = temp2
                        symmetricstate_MixHash(&self.symmetricstate, re)
                    }
                    case ecdh.Public_Key: {
                        fmt.eprintln("Implementation error: re was not empty when processing token 'e' during read_message.\nre = %v", self.re)
                        panic("Implementation error: re was not empty when processing token 'e' during read_message")
                    }
                }
                if is_psk_pattern(self.message_patterns) {
                    symmetricstate_MixKey(&self.symmetricstate, re)
                }
            }
            case .s: {
                rs_size : int
                if cipherstate_HasKey(&self.symmetricstate.cipherstate) {
                    rs_size = DhLen(get_curve(self)) + 16
                } else {
                    rs_size = DhLen(get_curve(self))
                }
                rs := make([]u8, rs_size, self.symmetricstate.allocator)
                copy(rs[:], message[message_cursor : message_cursor + rs_size])
                message_cursor += rs_size
                temp : []u8
                if cipherstate_HasKey(&self.symmetricstate.cipherstate) {
                    rs_buffer := cryptobuffer_from_slice(rs)
                    temp, _ = symmetricstate_DecryptAndHash(&self.symmetricstate, rs_buffer)
                } else {
                    rs_buffer := CryptoBuffer{main_body = rs[:], tag = 0}
                    temp, _ = symmetricstate_DecryptAndHash(&self.symmetricstate, rs_buffer)
                }
                switch &self_rs in self.rs {
                    case nil: {
                        temp2 : ecdh.Public_Key
                        ecdh.public_key_set_bytes(&temp2, get_curve(self), temp)
                        self.rs = temp2 
                    }
                    case ecdh.Public_Key: {
                        fmt.eprintln("Implementation error: rs was not empty when processing token 's'.\nre = %v", self.rs)
                        panic("Implementation error: rs was not empty when processing token 's'")
                    } 
                }
            }
            
            case .ee: {
                dh := DH(&self.e.?, &self.re.?, self.symmetricstate.allocator)
                symmetricstate_MixKey(&self.symmetricstate, dh)
            }

            case .es: {
                if self.initiator {
                    dh := DH(&self.e.?, &self.rs.?,self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh);  
                } else {
                    dh := DH(&self.s.?, &self.re.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh);
                }
            }
            
            case .se: {
                if self.initiator {
                    dh := DH(&self.s.?, &self.re.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh);  
                } else {
                    dh := DH(&self.e.?, &self.rs.?, self.symmetricstate.allocator)
                    symmetricstate_MixKey(&self.symmetricstate, dh);
                }
            }
            
            case .ss: {
                dh := DH(&self.s.?, &self.rs.?, self.symmetricstate.allocator)
                symmetricstate_MixKey(&self.symmetricstate, dh)
            }

            case .psk: {
                symmetricstate_MixKeyAndHash(&self.symmetricstate, self.psk[:])
            }
        };
    }

    payload_buffer :[]u8
    
    if message_cursor < len(message) {
        payload_buffer = make([]u8, len(message) - message_cursor, self.symmetricstate.allocator)
        copy(payload_buffer, message[message_cursor:])
        rest_buffer := cryptobuffer_from_slice(payload_buffer)
        payload_buffer, payload_status := symmetricstate_DecryptAndHash(&self.symmetricstate, rest_buffer)
        if payload_status != .Ok {
            return {},{},{}, payload_status
        }
    }

    if self.current_pattern == len(self.message_patterns.messages) {
        c1, c2 := symmetricstate_Split(&self.symmetricstate)
        self.current_pattern = 0
        free_all(self.symmetricstate.allocator)
        return payload_buffer, c1, c2, .Handshake_Complete
    } else {
        return payload_buffer, {}, {}, .Pending_Handshake
    }
}

array32_from_slice :: proc(slice: []u8) -> [32]u8 {
    buf : [32]u8
    copy(buf[:], slice[0 : min(len(slice), 32)])
    return buf
}

unwrap :: proc(m: Maybe($T)) -> ^T {
    switch &x in m {
        case T: {
            return &x
        }
        case nil: panic("Unwrap called on nil value")
    }
    return nil
}

random_psk :: proc() -> [32]u8 {
    psk : [32]u8
    crypto.rand_bytes(psk[:])
    return psk
}


cryptobuffer_from_slice :: proc(slice: []u8) -> CryptoBuffer {
    assert(len(slice) > 16)
    length := len(slice)-16
    return CryptoBuffer{
        main_body = slice[:len(slice)-16],
        tag = {slice[length +0], slice[length +1], slice[length +2], slice[length +3],
                slice[length +4], slice[length +5], slice[length +6], slice[length +7],
                slice[length +8], slice[length +9], slice[length +10],slice[length +11],
                slice[length +12],slice[length +13],slice[length +14],slice[length +15],
            },
    }
}

to_be_bytes :: proc(n: u64) -> [8]u8 {
    n0 := u8(n >> 0)
    n1 := u8(n >> 8)
    n2 := u8(n >> 16)
    n3 := u8(n >> 24)
    n4 := u8(n >> 32)
    n5 := u8(n >> 40)
    n6 := u8(n >> 48)
    n7 := u8(n >> 56)
    return {n7, n6, n5, n4, n3, n2, n1, n0}
}


to_le_bytes :: proc(n: u64) -> [8]u8 {
    n0 := u8(n >> 0)
    n1 := u8(n >> 8)
    n2 := u8(n >> 16)
    n3 := u8(n >> 24)
    n4 := u8(n >> 32)
    n5 := u8(n >> 40)
    n6 := u8(n >> 48)
    n7 := u8(n >> 56)
    return {n0, n1, n2, n3, n4, n5, n6, n7}
}

nonce_from_u64 :: proc(n: u64) -> [12]u8 {
    n := to_be_bytes(n)
    return {0,0,0,0,n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]}
}

array_xor :: proc(a: []u8, b: []u8, allocator: mem.Allocator) -> []u8 {
    assert(len(a) == len(b))
    c := make([]u8, len(a), allocator)
    for i in 0..<len(a) {
        c[i] = a[i] ~ b[i]
    }
    return c
}

zeropad128 :: proc(input: []u8) -> [128]u8 {
    assert(len(input) <= 128)
    output : [128]u8
    copy(output[:], input[:])
    return output
}

zeropad64 :: proc(input: []u8) -> [64]u8 {
    assert(len(input) <= 64)
    output : [64]u8
    copy(output[:], input[:])
    return output
}

zeropad32 :: proc(input: []u8) -> [32]u8 {
    assert(len(input) <= 32)
    output : [32]u8
    copy(output[:], input[:])
    return output
}

zeropad :: proc(input: []u8, pad_to_size: int, allocator := context.allocator) -> []u8 {
    output := make([]u8, pad_to_size)
    copy(output, input)
    return output
}

concat_bytes :: proc(b1: []u8, b2: []u8, allocator := context.allocator) -> []u8 {
    output := make_slice([]u8, len(b1) + len(b2), allocator);
    copy(output[0:len(b1)], b1)
    copy(output[len(b1):], b2)
    return output
}

slices_do_not_overlap :: proc(a: []$A, b: []$B) -> bool {
    a_address := transmute(u64)raw_data(a)
    b_address := transmute(u64)raw_data(b)

    if a_address > b_address {
        return b_address + u64(len(b)*size_of(B)) < a_address
    } else {
        return a_address + u64(len(a)*size_of(A)) <= b_address
    }
}
