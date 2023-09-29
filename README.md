# Ronnie Crypto

Wrapped based on OpenSSL, including interfaces for AES, HASH, RSA, HMAC, HKDF, ECDH, etc.

## Examples 

aes cbc
```rust
let key = b"abcdefghijklmnop";
let iv = b"abcdefghijklmnop";
let data  = b"Hello, world! This is a test of the openssl encryptor.";
let ciphertext = aes_cbc_encrypt(key, iv, data).unwrap();
```

