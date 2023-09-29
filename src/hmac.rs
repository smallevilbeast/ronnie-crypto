use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::error::CryptoError;

/// Generates a SHA256 HMAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

/// Generates a SHA1 HMAC.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac_sha256() {  
        let key = b"abcdefghijklmnop";
        let data = b"Hello, world! This is a test of the openssl encryptor.";
        let hmac = hmac_sha256(key, data).unwrap();
        let test_hmac = hex::decode("108525931fa509124e7045c76d56148b4771d0108300762d9e31a012fbf9dea0").unwrap();
        assert_eq!(hmac, test_hmac);
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_hmac_sha1() {     
        let key = b"abcdefghijklmnop";
        let data = b"Hello, world! This is a test of the openssl encryptor.";
        let hmac = hmac_sha1(key, data).unwrap();
        let test_hmac = hex::decode("36596b80ba8a25a99b26823d4d8264bfaa8164ae").unwrap();
        assert_eq!(hmac, test_hmac);    
        assert_eq!(hmac.len(), 20);     
    }
}

