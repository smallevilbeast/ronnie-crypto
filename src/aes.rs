use openssl::symm::{Cipher, Crypter, Mode};
use crate::error::CryptoError;

/// Encrypts data using AES-128 in CBC mode.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    crypter.pad(true);  // Enable PKCS7 padding

    let mut ciphertext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);
    Ok(ciphertext)
}

/// Decrypts data using AES-128 in CBC mode.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    crypter.pad(true);  // Enable PKCS7 padding

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"abcdefghijklmnop";
    const IV: &[u8] = b"abcdefghijklmnop";
    const DATA: &[u8] = b"Hello, world! This is a test of the openssl encryptor.";

    #[test]
    fn test_aes_cbc_crypto_should_ok() {
        let ciphertext = aes_cbc_encrypt(KEY, IV, DATA).unwrap();
        let plaintext = aes_cbc_decrypt(KEY, IV, &ciphertext).unwrap();
        assert_eq!(DATA, &plaintext[..]);
    }
}