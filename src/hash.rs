use openssl::hash::{hash, MessageDigest};
use crate::error::CryptoError;

/// Generates a MD5 hash.
pub fn md5(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(hash(MessageDigest::md5(), data)?.to_vec())
}

/// Generates a SHA1 hash.
pub fn sha1(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(hash(MessageDigest::sha1(), data)?.to_vec())
}

/// Generates a SHA256 hash.
pub fn sha256(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(hash(MessageDigest::sha256(), data)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let data = b"hello world";
        let md5 = md5(data).unwrap();
        let test_md5 = hex::decode("5eb63bbbe01eeed093cb22bb8f5acdc3").unwrap();
        assert_eq!(md5, test_md5);
        assert_eq!(md5.len(), 16);
    }
}