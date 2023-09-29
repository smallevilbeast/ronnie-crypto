use ronnie_crypto::aes::{aes_cbc_encrypt, aes_cbc_decrypt};
use hex;

fn main() {
    let key = b"abcdefghijklmnop";
    let out = aes_cbc_encrypt(
        key,
        key,
        b"Hello, world! This is a test of the AES CBC encryptor."
    ).unwrap();

    let plaintext = aes_cbc_decrypt(key, key, &out).unwrap();
    println!("AES CBC encrypted: {}\nplaintext: {}", hex::encode(out), String::from_utf8(plaintext).unwrap());
}