use crate::error::CryptoError;
use openssl::symm::{Cipher, Crypter, Mode};

/// Encrypts data using AES in CBC mode.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    crypter.pad(true); // Enable PKCS7 padding

    let mut ciphertext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);
    Ok(ciphertext)
}

/// Decrypts data using AES in CBC mode.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    crypter.pad(true); // Enable PKCS7 padding

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);
    Ok(plaintext)
}

/// Encrypts data using AES in ECB mode.
pub fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_ecb(),
        24 => Cipher::aes_192_ecb(),
        32 => Cipher::aes_256_ecb(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    crypter.pad(true); // Enable PKCS7 padding

    let mut ciphertext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut ciphertext)?;
    count += crypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count);
    Ok(ciphertext)
}

/// Decrypts data using AES in ECB mode.
pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_ecb(),
        24 => Cipher::aes_192_ecb(),
        32 => Cipher::aes_256_ecb(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    crypter.pad(true); // Enable PKCS7 padding

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext)?;
    count += crypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count);
    Ok(plaintext)
}

/// Encrypts data using AES in GCM mode.
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        24 => Cipher::aes_192_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    crypter.pad(false);

    crypter.aad_update(aad)?;

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = crypter.update(plaintext, &mut ciphertext)?;

    let rest = crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count + rest);

    let mut tag = vec![0; 16];
    crypter.get_tag(&mut tag)?;
    Ok((ciphertext, tag))
}

/// Decrypts data using AES in GCM mode.
pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        24 => Cipher::aes_192_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => return Err(CryptoError::InvalidKeyLength),
    };

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    decrypter.pad(false); // GCM does not use padding

    // Add associated data (AAD)
    decrypter.aad_update(aad)?;

    let mut decrypted = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = decrypter.update(ciphertext, &mut decrypted)?;

    // Set tag before calling final
    decrypter.set_tag(tag)?;

    count += decrypter.finalize(&mut decrypted[count..])?;
    decrypted.truncate(count);

    Ok(decrypted)
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

    #[test]
    fn test_aes_ecb_crypto_should_ok() {
        let ciphertext = aes_ecb_encrypt(KEY, DATA).unwrap();
        let plaintext = aes_ecb_decrypt(KEY, &ciphertext).unwrap();
        assert_eq!(DATA, &plaintext[..]);
    }

    #[test]
    fn test_aes_gcm_crypto_should_ok() {
        let aad = b"authenticated but unencrypted data";
        let (ciphertext, tag) = aes_gcm_encrypt(KEY, IV, aad, DATA).unwrap();
        let plaintext = aes_gcm_decrypt(KEY, IV, aad, &ciphertext, &tag).unwrap();
        assert_eq!(DATA, &plaintext[..]);
    }

    #[test]
    fn test_key_error_should_ok() {
        let key = b"abc";
        let iv = b"abc";
        let data = b"Hello, world! This is a test of the openssl encryptor.";
        let ciphertext = aes_cbc_encrypt(key, iv, data);
        assert!(ciphertext.is_err());
    }
}
