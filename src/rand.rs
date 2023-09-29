use openssl::rand::rand_bytes;

use crate::error::CryptoError;

/// Generates a random salt of the specified length.
pub fn rand_salt(bytes: usize) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0; bytes];
    rand_bytes(&mut salt)?;
    Ok(salt)
}