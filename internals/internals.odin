package internals


import "core:crypto"
import "core:crypto/x25519"
import "core:crypto/aead"
import "core:crypto/sha2"

import "core:slice"
import "core:strings"

import "core:simd"

import "core:fmt"

import "core:net"


/// A constant specifying the size in bytes of public keys and DH outputs. For security reasons, DHLEN must be 32 or greater.
DHLEN : int :  32;
/// A constant specifying the size in bytes of the hash output. Must be 32 or 64.
HASHLEN: int : 64;

/// A constant specifying the size in bytes that the hash function uses internally to divide its input for iterative processing. 
/// This is needed to use the hash function with HMAC (BLOCKLEN is B in [3]).
BLOCKLEN: int : 128;
/// The HMAC padding strings
IPAD: [BLOCKLEN]u8 : 0x36
OPAD: [BLOCKLEN]u8 : 0x5c

MAX_PACKET_SIZE: u64 : 65535;

DEFAULT_PROTOCOL_NAME :: "Noise_NK_25519_AESGCM_SHA512";


DhType :: enum {
    x25519,

}

CipherType :: enum {
    AES256gcm,
}

HashType :: enum {
    SHA512,
}

HandshakePattern :: enum {
    XX,
    NK
}

@(private)
PATTERN_XX : [][]Token = {
                {.e},
                {.e, .ee, .s, .es},
                {.s, .se}
            }

@(private)
PATTERN_NK : [][]Token = {
                {.s},
                {.e, .es},
                {.e, .ee}
            }



Protocol :: struct {
    handshake_pattern: HandshakePattern,
    dh: DhType,
    cipher: CipherType,
    hash: HashType,
}

@(private)
DEFAULT_PROTOCOL := Protocol {
    handshake_pattern = .XX,
    dh = .x25519,
    cipher = .AES256gcm,
    hash = .SHA512
}

@(private)
ERROR_PROTOCOL := Protocol {
    handshake_pattern = {},
    dh = nil,
    cipher = nil,
    hash = nil
}

parse_protocol_string :: proc(protocol_string: string) -> (Protocol, NoiseStatus) {
    // Default protocol string "Noise_XX_25519_AESGCM_SHA512"

    if len(protocol_string) > 50 {
        return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    protocol : Protocol
    split := strings.split(protocol_string, "_")
    defer delete(split)
    if len(split) != 5 {
        return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch split[1] {
        case "XX": protocol.handshake_pattern = .XX
        case "NK": protocol.handshake_pattern = .NK
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch split[2] {
        case "25519": protocol.dh = .x25519
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch split[3] {
        case "AESGCM": protocol.cipher = .AES256gcm
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    switch split[4] {
        case "SHA512": protocol.hash = .SHA512
        case: return ERROR_PROTOCOL, .Protocol_could_not_be_parsed
    }

    return protocol, .Ok

}




KeyPair :: struct {
    public_key: [DHLEN]u8,
    private_key: [DHLEN]u8,
}

keypair_empty :: proc(protocol: Protocol) -> KeyPair {
    public : [DHLEN]u8
    private: [DHLEN]u8
    return KeyPair {
        public_key = public, 
        private_key = private,
    }
    
}

keypair_random :: proc(protocol: Protocol) -> KeyPair {
    private_key: [DHLEN]u8;
    crypto.rand_bytes(private_key[:])

    public_key : [DHLEN]u8;
    x25519.scalarmult_basepoint(public_key[:], private_key[:])

    return KeyPair {
        private_key = private_key,
        public_key = public_key,
    }
}

NoiseStatus :: enum {
    Ok,
    Decryption_failed_to_authenticate,
    Protocol_could_not_be_parsed,
    Io,
    Pending_Handshake,
    Handshake_Complete,
    invalid_address,
}



/// Generates a new Diffie-Hellman key pair. A DH key pair consists of public_key and private_key elements. 
/// A public_key represents an encoding of a DH public key into a byte sequence of length DHLEN. 
/// The public_key encoding details are specific to each set of DH functions.
GENERATE_KEYPAIR :: proc(protocol: Protocol) -> KeyPair {
    return keypair_random(protocol)
}


/// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key 
/// and returns an output sequence of bytes of length DHLEN. 
/// For security, the Gap-DH problem based on this function must be unsolvable by any practical cryptanalytic adversary [2].

/// The public_key either encodes some value which is a generator in a large prime-order group 
/// (which value may have multiple equivalent encodings), or is an invalid value. 
/// Implementations must handle invalid public keys either by returning some output which is purely a function of the public key 
/// and does not depend on the private key, or by signaling an error to the caller. 
/// The DH function may define more specific rules for handling invalid values.
DH :: proc(key_pair: KeyPair, public_key: [DHLEN]u8, protocol: Protocol) -> [DHLEN]u8 {
    key_pair := key_pair
    public_key := public_key
    assert(key_pair.private_key != 0 && key_pair.public_key != 0);
    x25519.scalarmult_basepoint(public_key[:], key_pair.private_key[:])
    shared_secret : [DHLEN]u8
    x25519.scalarmult(shared_secret[:], key_pair.private_key[:], public_key[:])
    return shared_secret
} 


CryptoBuffer :: struct {
    iv: [12]u8,
    main_body: []u8,
    tag: [16]u8,
}

/// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n which must be unique for the key k. 
/// Returns the ciphertext. Encryption must be done with an "AEAD" encryption mode with the associated data ad 
/// (using the terminology from [1]) and returns a ciphertext that is the same size as the plaintext plus 16 bytes for authentication data. 
/// The entire ciphertext must be indistinguishable from random if the key is secret 
/// (note that this is an additional requirement that isn't necessarily met by all AEAD schemes).
ENCRYPT :: proc(k: [DHLEN]u8, n: u64, ad: []u8, plaintext: []u8, protocol: Protocol) -> (CryptoBuffer, NoiseStatus) {

    plaintext := plaintext

    k := k
    tag : [16]u8

    ciphertext : CryptoBuffer

    ctx : aead.Context
    iv := nonce_from_u64(n)
    crypto.rand_bytes(iv[:])
    
    aead.init(&ctx, aead.Algorithm.AES_GCM_256, k[:])
    aead.seal_ctx(&ctx, plaintext, tag[:], iv[:], ad, plaintext)
    
    ciphertext.iv = iv
    ciphertext.tag = tag
    ciphertext.main_body = plaintext

    return ciphertext, .Ok
}


/// Decrypts ciphertext using a cipher key k of 32 bytes, an 8-byte unsigned integer nonce n,
/// and associated data ad. Returns the plaintext, unless authentication fails, 
/// in which case an error is signaled to the caller.
DECRYPT :: proc(k: [DHLEN]u8, n: u64, ad: []u8, ciphertext: CryptoBuffer, protocol: Protocol) -> ([]u8, NoiseStatus) {
    
    k := k
    
    ctx : aead.Context
    iv := ciphertext.iv
    tag := ciphertext.tag

    aead.init(&ctx, aead.Algorithm.AES_GCM_256, k[:])
    if aead.open_ctx(&ctx, ciphertext.main_body, iv[:], ad, ciphertext.main_body, tag[:]) {
        return ciphertext.main_body, .Ok
    } else {
        return nil, .Decryption_failed_to_authenticate
    }
}

/// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function and returns an output of HASHLEN bytes.
HASH :: proc(protocol: Protocol, data: ..[]u8) -> [HASHLEN]u8 {
    ctx : sha2.Context_512
    sha2.init_512(&ctx)

    for datum in data {
        sha2.update(&ctx, datum)
    }
    hash : [HASHLEN]u8
    sha2.final(&ctx, hash[:])

    return hash
}


/// Returns a new 32-byte cipher key as a pseudorandom function of k. If this function is not specifically defined for some set of cipher functions, 
/// then it defaults to returning the first 32 bytes from ENCRYPT(k,    maxnonce, zerolen, zeros), 
/// where maxnonce equals 264-1, zerolen is a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with zeros.
REKEY :: proc(k: [DHLEN]u8, protocol: Protocol) -> [DHLEN]u8 {
    zeros : [32]u8
    n :u64 = 0xFFFFFFFFFFFFFFFF
    ENCRYPT(k, n, nil, zeros[:], protocol)
    new_key : [DHLEN]u8
    copy(new_key[:], zeros[:])
    return new_key
}

HMAC_HASH :: proc(K: [HASHLEN]u8, text: []u8, protocol: Protocol) -> [HASHLEN]u8 {
    K := K
    new_K := zeropad128(K[:])
    temp1 := array_xor(new_K, IPAD)
    temp2 := array_xor(new_K, OPAD)

    inner: [HASHLEN]u8 = HASH(protocol, temp1[:], text);
    outer: [HASHLEN]u8 = HASH(protocol, temp2[:], inner[:]);
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
HKDF :: proc(chaining_key: [HASHLEN]u8, input_key_material: []u8, protocol: Protocol) -> ([HASHLEN]u8, [HASHLEN]u8, [HASHLEN]u8) {
    assert(len(input_key_material) == 0 || len(input_key_material) == 32)
    temp_key := HMAC_HASH(chaining_key, input_key_material, protocol)
    output1 :=  HMAC_HASH(temp_key, {0x01}, protocol)
    output2 :=  HMAC_HASH(temp_key, concat_bytes(output1[:], {0x02}), protocol)
    output3 :=  HMAC_HASH(temp_key, concat_bytes(output2[:], {0x03}), protocol)

    return output1, output2, output3
} 


Token :: enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
}

CipherState :: struct {
    protocol: Protocol,
    k: [DHLEN]u8,
    n: u64,
}

SymmetricState :: struct {
    cipherstate: CipherState,
    ck: [HASHLEN]u8,
    h: [HASHLEN]u8,
}

HandshakeState :: struct {
    symmetricstate: SymmetricState,
    s: KeyPair,
    e: KeyPair, 
    rs: [DHLEN]u8,
    re: [DHLEN]u8,
    initiator: bool,
    message_patterns: [][]Token,
    current_pattern: int,
}


/// Sets k = key. Sets n = 0.
cipherstate_InitializeKey :: proc(key: [DHLEN]u8, protocol: Protocol) -> CipherState {
    return CipherState {
        protocol = protocol,
        k = key,
        n = 0
    }
}

/// Returns true if k is non-empty, false otherwise.
cipherstate_HasKey :: proc(self: ^CipherState) -> bool {
    zeroslice : [HASHLEN]u8
    if slice.equal(self.k[:], zeroslice[:]) {
        return false
    } else {
        return true
    }
}

///If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
cipherstate_EncryptWithAd :: proc(self: ^CipherState, ad: []u8, plaintext: []u8) -> CryptoBuffer {
    if cipherstate_HasKey(self) {
        temp, encrypt_error := ENCRYPT(self.k, self.n, ad, plaintext, self.protocol)
        self.n += 1;
        return temp
    } else {
        return CryptoBuffer {main_body = plaintext}
    }
}

/// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. 
/// If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
cipherstate_DecryptWithAd :: proc(self: ^CipherState, ad: []u8, ciphertext: CryptoBuffer) -> ([]u8, NoiseStatus) {
    if cipherstate_HasKey(self) {
        plaintext, decrypt_error := DECRYPT(self.k, self.n, ad, ciphertext, self.protocol)
        self.n += 1;
        return plaintext, decrypt_error
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

// impl SymmetricState {

/// : Takes an arbitrary-length protocol_name byte sequence (see Section 8). Executes the following steps:

/// If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes. 
/// Otherwise sets h = HASH(protocol_name).

/// Sets ck = h.

/// Calls InitializeKey(empty).
symmetricstate_InitializeSymmetric :: proc(protocol_name: string) -> (SymmetricState, NoiseStatus) {
    zeroslice : [DHLEN]u8
    protocol, parse_error := parse_protocol_string(protocol_name)
    if parse_error == .Protocol_could_not_be_parsed {
        return SymmetricState{}, .Protocol_could_not_be_parsed
    }
    if len(protocol_name) < HASHLEN {
        protocol_name_bytes : [HASHLEN]u8
        copy(protocol_name_bytes[:], protocol_name[:])
        h := HASH(protocol, protocol_name_bytes[:]);
        cipherstate := cipherstate_InitializeKey(zeroslice, protocol);
        return SymmetricState {cipherstate = cipherstate, ck = h, h = h}, .Ok
    } else {
        h := HASH(protocol, transmute([]u8)protocol_name);
        cipherstate := cipherstate_InitializeKey(zeroslice, protocol);
        return SymmetricState {cipherstate = cipherstate, ck = h, h = h}, .Ok
    }
}

/// Sets h = HASH(h || data).
symmetricstate_MixHash :: proc(self: ^SymmetricState, data: ..[]u8, ) {

    if len(data) == 1 {
        self.h = HASH(self.cipherstate.protocol, self.h[:], data[0])
    } else if len(data) == 2 {
        self.h = HASH(self.cipherstate.protocol, self.h[:], data[0], data[1])
    } else if len(data) == 3 {
        self.h = HASH(self.cipherstate.protocol, self.h[:], data[0], data[1], data[2])
    }
}

///     : Executes the following steps:

/// Sets ck, temp_k = HKDF(ck, input_key_material, 2).
/// If HASHLEN is 64, then truncates temp_k to 32 bytes.
/// Calls InitializeKey(temp_k).
symmetricstate_MixKey :: proc(self: ^SymmetricState, input_key_material: []u8) {
    input_key_material := input_key_material
    ck, temp_k, _ := HKDF(self.ck, input_key_material[:], self.cipherstate.protocol)
    self.ck = ck
    self.cipherstate = cipherstate_InitializeKey(array32_from_slice(temp_k[:32]), self.cipherstate.protocol)
}

/// This function is used for handling pre-shared symmetric keys, as described in Section 9. It executes the following steps:

/// Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
/// Calls MixHash(temp_h).
/// If HASHLEN is 64, then truncates temp_k to 32 bytes.
/// Calls InitializeKey(temp_k).
symmetricstate_MixKeyAndHash :: proc(self: ^SymmetricState, input_key_material: []u8) {
    input_key_material := input_key_material
    ck, temp_h, temp_k := HKDF(self.ck, input_key_material[:], self.cipherstate.protocol)
    self.ck = ck
    symmetricstate_MixHash(self, temp_h[:])
    self.cipherstate = cipherstate_InitializeKey(array32_from_slice(temp_k[:]), self.cipherstate.protocol);
}

/// Returns h. This function should only be called at the end of a handshake, i.e. after the Split() function has been called. 
/// This function is used for channel binding, as described in Section 11.2
symmetricstate_GetHandshakeHash :: proc(self: ^SymmetricState) -> [HASHLEN]u8 {
    return self.h
}

/// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext. 
/// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
symmetricstate_EncryptAndHash :: proc(self:  ^SymmetricState, plaintext: []u8) -> CryptoBuffer{
    ciphertext := cipherstate_EncryptWithAd(&self.cipherstate, self.h[:], plaintext)
    symmetricstate_MixHash(self, ciphertext.iv[:], ciphertext.main_body, ciphertext.tag[:])
    return ciphertext
}

/// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. 
/// Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
symmetricstate_DecryptAndHash :: proc(self:  ^SymmetricState, ciphertext: CryptoBuffer) -> ([]u8, NoiseStatus) {
    ciphertext := ciphertext
    result, decrypt_error := cipherstate_DecryptWithAd(&self.cipherstate, self.h[:], ciphertext)
    symmetricstate_MixHash(self, ciphertext.iv[:], ciphertext.main_body, ciphertext.tag[:])
    return result, .Ok
}

/// Returns a pair of CipherState objects for encrypting transport messages. Executes the following steps, where zerolen is a zero-length byte sequence:
/// Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
/// If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
/// Creates two new CipherState objects c1 and c2.
/// Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
/// Returns the pair (c1, c2).
symmetricstate_Split :: proc(self: ^SymmetricState) -> (CipherState, CipherState) {
    temp_k1, temp_k2, _ := HKDF(self.ck, nil, self.cipherstate.protocol)
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
handshakestate_Initialize :: proc(
    initiator: bool,
    prologue: []u8,
    s: KeyPair,
    e: KeyPair,
    rs: [DHLEN]u8,
    re: [DHLEN]u8,
    protocol_name := DEFAULT_PROTOCOL_NAME
) -> (HandshakeState, NoiseStatus) {
    
    symmetricstate, status := symmetricstate_InitializeSymmetric(protocol_name)
    if status == .Protocol_could_not_be_parsed {
        return HandshakeState{}, status
    }

    message_pattern : [][]Token
    switch symmetricstate.cipherstate.protocol.handshake_pattern {
        case .XX: message_pattern = PATTERN_XX
        case .NK: message_pattern = PATTERN_NK
    }

    symmetricstate_MixHash(&symmetricstate, prologue)
    output := HandshakeState {
        symmetricstate = symmetricstate,
        s = s,
        e = e,
        rs = rs,
        re = re,
        initiator = initiator,
        message_patterns = message_pattern,
        current_pattern = 0,
    };

    return output, .Ok
}

/// Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into. 
/// Performs the following steps, aborting if any EncryptAndHash() call returns an error:

/// Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:

/// For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key).

/// For "s": Appends EncryptAndHash(s.public_key) to the buffer.

/// For "ee": Calls MixKey(DH(e, re)).

/// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.

/// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.

/// For "ss": Calls MixKey(DH(s, rs)).

/// Appends EncryptAndHash(payload) to the buffer.

/// If there are no more message patterns returns two new CipherState objects by calling Split().
handshakestate_write_message :: proc(self: ^HandshakeState, message_buffer: net.TCP_Socket) -> (CipherState, CipherState, NoiseStatus) {
    pattern := self.message_patterns[self.current_pattern]
    self.current_pattern += 1;
    for token in pattern {
        switch token {
            case .e: {
                self.e = GENERATE_KEYPAIR(self.symmetricstate.cipherstate.protocol)
                net.send_tcp(message_buffer, self.e.public_key[:])
                symmetricstate_MixHash(&self.symmetricstate, self.e.public_key[:])
            }
            case .s: {
                temp := symmetricstate_EncryptAndHash(&self.symmetricstate, self.s.public_key[:])
                net.send_tcp(message_buffer, temp.iv[:])
                net.send_tcp(message_buffer, temp.main_body)
                net.send_tcp(message_buffer, temp.tag[:])
            }
            case .ee: {
                dh := DH(self.e, self.re, self.symmetricstate.cipherstate.protocol)
                symmetricstate_MixKey(&self.symmetricstate, dh[:])
            }

            case .es: {
                if self.initiator {
                    dh := DH(self.e, self.rs, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:])
                } else {
                    dh := DH(self.s, self.re, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:])
                }
            }
            
            case .se: {
                if self.initiator {
                    dh := DH(self.s, self.re, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:])
                } else {
                    dh := DH(self.e, self.rs, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:])
                    
                }
            }
            
            case .ss: {
                dh := DH(self.s, self.rs, self.symmetricstate.cipherstate.protocol)
                symmetricstate_MixKey(&self.symmetricstate, dh[:])
            }
        };
    }
    
    if self.current_pattern > len(self.message_patterns) {
        sender, receiver := symmetricstate_Split(&self.symmetricstate)
        self.current_pattern = 0
        return sender, receiver, .Ok
    } else {
        return CipherState{}, CipherState{}, .Pending_Handshake
    }
}

/// Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into. 
/// Performs the following steps, aborting if any DecryptAndHash() call returns an error:

/// Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:

/// For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).

/// For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. 
/// Sets rs (which must be empty) to DecryptAndHash(temp).

/// For "ee": Calls MixKey(DH(e, re)).

/// For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.

/// For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.

/// For "ss": Calls MixKey(DH(s, rs)).

/// Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.

/// If there are no more message patterns returns two new CipherState objects by calling Split().
handshakestate_read_message :: proc(self: ^HandshakeState, message: net.TCP_Socket)  -> (CipherState, CipherState, NoiseStatus) {
    zeroslice: [DHLEN]u8
    pattern := self.message_patterns[self.current_pattern]
    self.current_pattern += 1
    for token in pattern {
        switch token {
            case .e: {
                e : [DHLEN]u8
                net.recv_tcp(message, e[:])
                if self.re == zeroslice {
                    self.re = e
                    symmetricstate_MixHash(&self.symmetricstate, self.re[:])
                } else {
                    fmt.println("Implementation error: re was not empty when processing token 'e'.\nre = %v", self.re)
                    panic("Implementation error: re was not empty when processing token 'e'")
                }
            }
            case .s: {
                if cipherstate_HasKey(&self.symmetricstate.cipherstate) {
                    rs : [DHLEN+16]u8
                    net.recv_tcp(message, rs[:])
                    rs_buffer := cryptobuffer_from_slice(rs[:])
                    temp, temp_err := symmetricstate_DecryptAndHash(&self.symmetricstate, rs_buffer)
                    new_rs := array32_from_slice(temp[:])
                    if self.rs == zeroslice {
                        self.rs = new_rs
                    } else {
                        fmt.println("Implementation error: rs was not empty when processing token 's'.\nre = %v", self.rs)
                        panic("Implementation error: rs was not empty when processing token 's'")
                    }
                }
            }
            
            case .ee: {
                dh := DH(self.e, self.re, self.symmetricstate.cipherstate.protocol)
                symmetricstate_MixKey(&self.symmetricstate, dh[:])
            }

            case .es: {
                if self.initiator {
                    dh := DH(self.e, self.rs, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:]);  
                } else {
                    dh := DH(self.s, self.re, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:]);
                }
            }
            
            case .se: {
                if self.initiator {
                    dh := DH(self.s, self.re, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:]);  
                } else {
                    dh := DH(self.e, self.rs, self.symmetricstate.cipherstate.protocol)
                    symmetricstate_MixKey(&self.symmetricstate, dh[:]);
                }
            }
            
            case .ss: {
                dh := DH(self.s, self.rs, self.symmetricstate.cipherstate.protocol)
                symmetricstate_MixKey(&self.symmetricstate, dh[:])
            }
        };
    }
    if self.current_pattern > len(self.message_patterns) {
        sender, receiver := symmetricstate_Split(&self.symmetricstate)
        return sender, receiver, .Handshake_Complete
    } else {
        return CipherState{}, CipherState{}, .Pending_Handshake
    }
}

array32_from_slice :: proc(slice: []u8) -> [32]u8 {
    buf : [32]u8
    copy(buf[:], slice[0 : min(len(slice), 32)])
    return buf
}



extend_from_slice :: proc(array: ^[dynamic]u8, slice: []u8) {
    for byte in slice {
        append(array, byte)
    }
}


/// Creates a uintptr from a &[u8] of length 8. Panics if len is different than 8.
u64_from_le_slice :: proc(slice: []u8) -> u64 {
    assert(len(slice) >= 8)
    l: u64 = u64(slice[0]) | u64(slice[1])<<8 | u64(slice[2])<<16 | u64(slice[3])<<24 | u64(slice[4])<<32 | u64(slice[5])<<40 | u64(slice[6])<<48 | u64(slice[7])<<56
    return l
}

/// Creates a uintptr from a &[u8] of length 8. Panics if len is different than 8.
u64_from_be_slice :: proc(slice: []u8) -> u64 {
    assert(len(slice) >= 8)
    l: u64 = u64(slice[7]) | u64(slice[6])<<8 | u64(slice[5])<<16 | u64(slice[4])<<24 | u64(slice[3])<<32 | u64(slice[2])<<40 | u64(slice[1])<<48 | u64(slice[0])<<56
    return l
}

cryptobuffer_from_slice :: proc(slice: []u8) -> CryptoBuffer {
    assert(len(slice) > 28)
    length := len(slice)-28
    return CryptoBuffer{
        iv = {slice[0], slice[1], slice[2], slice[3],
                slice[4], slice[5], slice[6], slice[7], 
                slice[8], slice[9], slice[10], slice[11]
            },
        main_body = slice[12:length],
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


array_xor :: proc(a: [BLOCKLEN]u8, b: [BLOCKLEN]u8) -> [BLOCKLEN]u8 {
    a := a
    b := b
    output: [BLOCKLEN]u8
    for i in 0..<8 {
        blocka : simd.u8x16 = simd.from_slice(simd.u8x16, a[i*16:i*16+16]);
        blockb : simd.u8x16 = simd.from_slice(simd.u8x16, b[i*16:i*16+16]);
        temp := simd.to_array(blocka ~ blockb)
        copy(output[i*16 : i*16+16], temp[:])
    }
    return output
}

zeropad128 :: proc(input: []u8) -> [BLOCKLEN]u8 {
    assert(len(input) <= BLOCKLEN)
    output : [BLOCKLEN]u8
    copy(output[:], input[:])
    return output
}

zeropad32 :: proc(input: []u8) -> [HASHLEN]u8 {
    assert(len(input) <= HASHLEN)
    output : [HASHLEN]u8
    copy(output[:], input[:])
    return output
}

concat_bytes :: proc(b1: []u8, b2: []u8) -> []u8 {
    output := make_slice([]u8, len(b1) + len(b2));
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

